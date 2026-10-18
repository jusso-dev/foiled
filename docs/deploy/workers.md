# Central backend on Cloudflare Workers

Status: Draft for the MVP. Owner: #7. The platform decision is ADR 0009 (#40), [ADR 0009](../adr/0009-axum-workers-and-front-end.md). Related: #21 (API), #31 (ingest auth), #41 (host agent).

The central backend is the trusted side of Foiled. It runs entirely on Cloudflare Workers and Cloudflare data services:

- `foiled-api`: the Axum API Worker in `crates/api` (Rust, workers-rs). It serves the control-plane API, the ingest endpoints for sandbox hosts and edge sensors, and the Queue consumer.
- `foiled-web`: the operator console Worker in `web/` (React Router on Workers with static assets). It calls `foiled-api` over a Service Binding.
- `foiled-site`: the public exploit pages Worker in `site/` (Astro), planned in #35.

Decoys never run here. They run on sandbox hosts ([vps.md](vps.md)), driven by the host agent (#41).

## Assumptions

- **Workers Paid plan.** The Free plan's 10 ms CPU per request is too tight for confidence scoring and exports (#40). No Enterprise-only feature is on the MVP path; mTLS uses the Cloudflare-managed CA, which is available on all plans.
- A domain in a Cloudflare zone for the control-plane hostnames. Decoys use a separate domain ([cloudflare.md](cloudflare.md)).
- A Postgres database reachable from Hyperdrive. Picking a Postgres host is out of scope (#40).

## This repository never deploys

- CI has no Cloudflare credentials and no deploy job ([docs/ci.md](../ci.md)). It builds and tests only. A pull request that adds a deploy step or a Cloudflare secret to CI will be rejected.
- No Cloudflare account ID, zone name, route, real hostname, resource ID or token lives in the tree. The committed Wrangler configs hold binding names and placeholders only.
- Deploys are a manual operator action from the operator's own machine, with their own scoped token, as described below.

## Bindings

Every binding the Workers use, with the issue that owns the code that reads or writes it. ADR 0009 (#40) owns the binding names and the Wrangler config shape.

| Worker | Binding | Type | Resource name (example) | Owning issue | What it is for |
| --- | --- | --- | --- | --- | --- |
| `foiled-api` | `DB` | D1 database | `foiled-config` | #21 (also #5 catalogue, #31 sensor and host registry) | Config, decoy catalogue, tenants, users and roles, sensor and host registry with certificate fingerprints. |
| `foiled-api` | `HYPERDRIVE` | Hyperdrive config | `foiled-pg` | #25 (also #21 audit, #27, #33, #34, #35) | Pooled connection to Postgres: attempts, IOCs, campaigns, confidence evidence, review queue, audit log, radar rollups. |
| `foiled-api` | `INGEST` | Queue producer | `foiled-ingest` | #9 (envelope format), #31 (ingest auth) | Accepted capture envelopes and attempt summaries from hosts and sensors, and correlation jobs (#28). |
| `foiled-api` | (consumer, no binding name) | Queue consumer | `foiled-ingest`, dead letters to `foiled-ingest-dlq` | #9 | Validates and writes envelopes to Postgres, fans out to `LIVE_STREAM` and `RADAR`. |
| `foiled-api` | `EVIDENCE` | R2 bucket | `foiled-evidence` | #9 (retention #16) | Pcaps, file diffs, quarantined payloads and export bundles by `payload_ref`. Private: no public bucket URL, no custom domain. |
| `foiled-api` | `LIVE_STREAM` | Durable Object namespace (class `LiveStream`) | migration tag `v1` | #14 | Live attempt stream to console clients over hibernating WebSockets. |
| `foiled-api` | `AI` | Workers AI, called through AI Gateway (`AI_GATEWAY_ID` var) | gateway created in the dashboard | #28 | LLM correlation, with the logging policy from #16 and #28. |
| `foiled-api` | `RADAR` | Analytics Engine dataset | `foiled_radar` | #35 | High-volume radar counters (3 months retention). |
| `foiled-web` | `API` | Service Binding to `foiled-api` | `foiled-api` | #14 (decision in #40) | Every console call to the API. No public API call from the browser is needed. |
| `foiled-site` | none yet | | | #35 | Reads published, confidence-gated data only. If it later gets a binding, it must reach a read-only published-data route and nothing else. |

Vars (not secrets, still kept out of the tree where they identify the account):

| Worker | Var | Owning issue | Notes |
| --- | --- | --- | --- |
| `foiled-api` | `AI_GATEWAY_ID` | #28 | Placeholder in the committed config. |
| `foiled-api` | `CF_ZONE_ID` | #31 | The ingest zone, for client certificate issue and revocation ([edge-sensor.md](edge-sensor.md)). |

## Secrets

Secrets are Worker secrets set with `wrangler secret put`, and nothing else. They are never in the repo, never in `wrangler.jsonc` `vars`, never passed as command-line arguments, and never in CI. For local development, Wrangler reads `.dev.vars`, which is git-ignored; use fake values there.

```sh
cd crates/api
wrangler secret put JOB_SIGNING_KEY   # prompts for the value; nothing lands in shell history
```

Proposed names. The owning issue finalises each one.

| Worker | Secret | Owning issue | Purpose |
| --- | --- | --- | --- |
| `foiled-api` | `JOB_SIGNING_KEY` | #41 | Private key that signs host jobs. Hosts hold only the public key. |
| `foiled-api` | `CF_CLIENT_CERT_API_TOKEN` | #31 | Cloudflare API token with only *Zone, SSL and Certificates, Edit* on the ingest zone. Signs enrolment and renewal CSRs with the Cloudflare-managed CA and revokes certificates. Without it enrolment is disabled; ingest still works. |
| `foiled-api` | `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | #9 | R2 API token, scoped to the `foiled-evidence` bucket with object read and write only, used to mint short-lived single-object upload URLs. The R2 binding cannot presign. |
| `foiled-api` | `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | #21, #14 | Validate Cloudflare Access JWTs in the Worker. Not strictly secret, but they identify your account, so they stay out of the tree. |
| `foiled-api` | `TOKEN_PEPPER` | #21 | Pepper for hashing API tokens at rest in D1. |
| `foiled-api` | One secret per enrichment provider | #11 | Provider API keys. Names set in #11. |
| `foiled-api` | `LLM_PROVIDER_API_KEY` (if an external model is used) | #28 | Key for an external model behind AI Gateway. |
| `foiled-api` | `SHODAN_API_KEY` (optional) | #18 | Operator-supplied Shodan key for the Honeyscore self-check. Only set it if you enable the check ([fingerprint-resistance.md](../fingerprint-resistance.md)). |
| `foiled-web` | `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | #14 | Same Access check in the console Worker. |

Postgres credentials are not a Worker secret: they live in the Hyperdrive configuration, set when you create it.

## Entry points and auth

The control plane is never publicly reachable without auth.

| Entry point | Who uses it | Auth |
| --- | --- | --- |
| Console hostname on `foiled-web` | Operators in a browser | **Cloudflare Access** application with your identity provider and MFA. Both Workers validate the `Cf-Access-Jwt-Assertion` JWT (issuer and audience) as well, so a missing or misconfigured Access policy fails closed. |
| Service Binding `API` | `foiled-web` only | Not reachable from the internet. `foiled-web` forwards the operator's Access JWT and the API Worker validates it itself; it does not trust the console to have done so. |
| API hostname on `foiled-api` | MCP server (#24), scripts | Cloudflare Access (service tokens for automation) plus scoped bearer tokens checked in the Worker (#21). |
| Ingest hostname on `foiled-api` | Sandbox hosts (#41), edge sensors (#31) | **mTLS required.** Two separate layers (#31): a WAF custom rule blocks any request without a verified, unrevoked client certificate, then the Worker checks `tlsClientAuth` on the request's `cf` object and maps the certificate fingerprint to a host or sensor identity in D1. Only ingest and job-lease routes answer on this hostname. Admin and token routes return 404 there. |
| `*.workers.dev` and preview URLs | Nobody | **Turned off** for every Foiled Worker (`"workers_dev": false`, `"preview_urls": false`). A `workers.dev` URL bypasses the Access application and the mTLS WAF rule on your zone. |

WAF custom rule for the ingest hostname (Security, WAF, custom rules), action **Block**:

```text
(http.host eq "ingest.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
```

The in-Worker check repeats the verification (`certVerified` must be `SUCCESS`, `certRevoked` must be `0`), looks up `certFingerprintSHA256` in the D1 registry, and stamps the identity from the certificate onto every accepted event. Identity is never taken from the request body (threat model C20).

## Deploy (manual, operator only)

Run from your own machine, never from CI. Use an API token scoped to the one account and only the permissions the step needs (Workers Scripts, D1, R2, Queues, Hyperdrive). Put the account ID in your environment, not in a file in the repo.

```sh
export CLOUDFLARE_ACCOUNT_ID=...      # your account; never committed
export CLOUDFLARE_API_TOKEN=...       # scoped deploy token; never committed
```

1. **Create resources** (once):
   ```sh
   wrangler d1 create foiled-config
   wrangler r2 bucket create foiled-evidence
   wrangler queues create foiled-ingest
   wrangler queues create foiled-ingest-dlq
   read -rs PG_URL   # paste the Postgres connection string; not echoed or saved to history
   wrangler hyperdrive create foiled-pg --connection-string="$PG_URL"
   unset PG_URL
   ```
   Create the AI Gateway in the dashboard and note its ID. The Analytics Engine dataset is created on first write. Do not enable a public `r2.dev` URL or a custom domain on the evidence bucket.
2. **Fill in a private copy of the API config.** Copy `crates/api/wrangler.jsonc` (sketched in ADR 0009) to `crates/api/wrangler.private.jsonc` next to it, fill in the resource IDs and add your routes or custom domains there. Keep it out of git with a local exclude (`echo 'wrangler.private.jsonc' >> .git/info/exclude`) or a private fork. The console config `web/wrangler.jsonc` has no resource IDs (its only binding is the Service Binding), so it needs no private copy; attach its custom domain in the dashboard. Both configs must set `"workers_dev": false` and `"preview_urls": false`.
3. **Set secrets** with `wrangler secret put` for each secret in the table above.
4. **Protect before you publish.** Create the Access applications for the console and API hostnames. Turn on mTLS for the ingest hostname and add the WAF rule. Do this before any hostname is attached to a Worker.
5. **Deploy the API Worker, then the console Worker** (the Service Binding needs its target):
   ```sh
   (cd crates/api && wrangler deploy --config wrangler.private.jsonc)
   (cd web && pnpm build && wrangler deploy)
   ```
   The console is built by the Cloudflare Vite plugin, which writes the deploy config into the build output, so deploy it from `web/` after `pnpm build`.
6. **Check** that the console hostname redirects to Access, the API hostname rejects a request without an Access token, the ingest hostname returns 403 without a client certificate, and the `workers.dev` URLs do not resolve.

## Related

- Deployment modes and the MVP topology: [modes.md](modes.md).
- Research sensor bring-up: [vps.md](vps.md).
- Why decoys are never behind the proxy: [cloudflare.md](cloudflare.md).
- Enrolment, certificate issue and revocation, sensor and host roles: [edge-sensor.md](edge-sensor.md) (#31).
- Token scopes: #21. Threat model controls C30 to C33 (operator credential theft): [threat model](../threat-model.md) (#2).

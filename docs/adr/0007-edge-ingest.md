# ADR 0007: Edge ingest: enrolment, mTLS identity, signed builds and tenancy

## Status

Accepted (18 Oct 2026). Issue #31. Related: #7 ([deploy modes](../deploy/modes.md), [VPS guide](../deploy/vps.md)), #9 and [ADR 0005](0005-capture-layer.md) (capture), #21 ([API](../api/control-plane.md)), #30 and [ADR 0006](0006-emulation-plugins.md) (emulations), #37 ([contribute-back](../contribute-back.md)), #40 and [ADR 0009](0009-axum-workers-and-front-end.md) (Workers), #41 and [ADR 0008](0008-sandbox-host-agent.md) (host agent). Operator guide: [deploy/edge-sensor.md](../deploy/edge-sensor.md).

## Context

Research sensors on a VPS (#7) are the MVP. A single VPS sees only a small slice of the internet, so edge sensors run decoys on other people's hosts (customers, fleet partners) and forward telemetry to the central control plane on Cloudflare Workers. The owner of an edge host can read everything on it and forge anything it sends. We need:

- a strong identity for each sensor that is bound to one tenant and cannot be turned into operator access;
- a way to issue, renew and revoke that identity without shipping long-lived secrets;
- builds the sensor can verify before it runs them;
- an offline buffer with known limits and replay semantics;
- tenancy rules that make cross-tenant writes impossible rather than unlikely.

The control plane runs on Workers (ADR 0009). The only managed CA available on every plan is the Cloudflare-managed client CA; bring-your-own CA is Enterprise only. Sandbox hosts (#41) need the same identity machinery with a different role.

## Decision

### 1. Identity is a Cloudflare-managed client certificate, keyed by fingerprint

Each sensor and host holds one ECDSA P-256 key, generated on the machine, and a client certificate signed by the zone's Cloudflare-managed CA. The control plane stores the SHA-256 fingerprint of the certificate's DER in D1 (`identities`, one row per certificate) with the identity id, role (`host` or `sensor`), tenant and scopes. The fingerprint is the only thing that maps a request to an identity. The certificate subject is not trusted for anything.

Scopes are fixed by role (`foiled_core::auth::agent_scopes`), side by side:

| Capability | Host role (#41) | Sensor role (#31) | Human or MCP token (#21) |
| --- | --- | --- | --- |
| Lease and acknowledge its own placed jobs | `host:lease` | `sensor:lease` | no |
| Heartbeat, renew its own certificate | `host:report` | `sensor:report` | no |
| Send capture envelopes for its own decoys | `host:ingest` | `sensor:ingest` | no |
| Mint upload URLs for its own decoys | `host:upload` | `sensor:upload` | no |
| Take unplaced jobs | yes | **no** | no |
| Register, revoke or re-enrol agents | no | no | `hosts:write`, `sensors:write` |
| Read anything else (decoys, attempts, audit) | no | no | by scope |
| Mint tokens, admin | no | no | `admin` via Access with MFA |

A role can never hold another family's scopes; `Principal::new` drops them even if the table says otherwise.

### 2. Enrolment: one-time token, CSR, Worker asks the CA

1. A tenant admin registers a sensor (`POST /v0/sensors`, `sensors:write`). The control plane creates a `pending` record and a one-time enrolment token `foe_<id>.<secret>` (default lifetime 1 hour, 5 minutes to 24 hours). Only the SHA-256 of the secret is stored. The token is shown once and never audited.
2. The sensor generates its key pair and sends `{token, csr_pem}` to `POST /v0/enrol` on the ingest hostname. This is the only path the mTLS WAF rule lets through without a certificate.
3. The Worker rate limits by source IP, finds the token, compares the secret in constant time, checks it is unused and unexpired, checks the CSR (one request, under 8 KiB, no private key in the body, and a key the CA will sign: ECDSA P-256 or P-384, or RSA 2048 to 4096 bits), then marks the token used in one compare-and-set statement. Only one request can ever redeem a token. If the CA then fails to issue, the claim is released and the token can be retried; it is never reopened for a revoked agent.
4. The Worker sends the CSR to the Cloudflare client certificate API (`POST /zones/{zone}/client_certificates`) with an API token that can only edit SSL and certificates on that zone, fingerprints the returned certificate itself, and binds it to the token's identity in one D1 transaction that refuses to bind if the identity was revoked meanwhile.
5. The response gives the certificate, the identity and its scopes. The sensor checks the identity matches its config, installs the key and certificate owner-only, and deletes the token file.

The identity (id, role, tenant, scopes) comes only from the token record. Nothing in the request can choose it.

### 3. mTLS is checked in two separate layers

1. **WAF custom rule on the ingest hostname**: block when the client certificate is not verified or is revoked, except for `POST /v0/enrol`. This stops unauthenticated traffic and revoked certificates at the edge.
2. **The Worker** copies `cf.tlsClientAuth` (presented, verified, SHA-256 fingerprint) into a request extension and checks it again: verified, fingerprint known in D1 with only scope names the code knows, not revoked, and not past `valid_until` or the stored certificate expiry. Then the route checks the scope, that the role matches the path family (`/v0/hosts` or `/v0/sensors`), and that the path id is the caller's own id.

Either layer alone would be enough against a random client. Both together mean a mistake in one (a WAF rule edited away, a missed revocation at the CA) does not open ingest.

### 4. Rotation and revocation

- **Renewal**: a sensor renews over mTLS (`POST /v0/sensors/{id}/certificate:renew`) with a CSR for a fresh key at two thirds of the certificate's life (default validity 90 days). The previous certificate keeps working for 24 hours, then stops (`valid_until`). Rate limited (default 4 a day).
- **Re-enrolment**: for a lost key, the admin mints a new token for the same sensor id (`:reenrol`). Redeeming it retires every older certificate immediately.
- **Revocation**: `:revoke` with a reason marks the sensor and all its certificates revoked in D1 first (the Worker refuses them from that request on), closes any unused token, then revokes each certificate at the CA so the WAF rule's `cert_revoked` check blocks it at the edge. Revocation is final; a revoked sensor is replaced by registering a new one.

### 5. Edge sensors run `foiled-hostd` with `role = "sensor"`

One binary for hosts and sensors. A sensor uses the same signed job protocol (ADR 0008) on its own path family and differs in what it is allowed to receive:

- Decoys are placed on a sensor explicitly (`sensor_id` on `POST /v0/decoys`), and only in the sensor's tenant. A sensor never leases unplaced jobs, so it cannot pick up work meant for research hosts.
- Emulations (#30) are the default. Full sandbox decoys need `sandbox_allowed` set on the sensor by the tenant admin, and are documented as heavy: KVM, Firecracker and the network boundary from ADR 0003 on someone else's host.

### 6. Signed builds

Each release publishes a manifest (`schemas/release-manifest.schema.json`) listing every artefact by target triple with its size and SHA-256, signed with an Ed25519 release key that is kept offline and is separate from the job signing key. The agent pins release public keys in its config and, before staging an update, verifies in order: signature by a pinned key over the exact manifest bytes; `kind` (`foiled.release.v1`) and product; a `MAJOR.MINOR.PATCH` version strictly newer than both the running version and the highest version it has ever staged (kept under `state_dir`), so an attacker cannot walk it back to an older signed build; artefact size and digest. Release keys and job keys must be different keys; the agent refuses a config that pins one key as both. The manifest `kind` gives domain separation, so a signed job body can never pass as a manifest. In v0.2 the agent verifies and stages (`foiled-hostd verify-update`); swapping the binary is left to the service manager.

### 7. Offline buffer and replay

The host agent's segment buffer (ADR 0008) serves sensors too, with a 256 MiB default cap on sensors (1 GiB on hosts). Over the cap, whole oldest segments are dropped and counted. Delivery on the wire is at least once; the store keeps one row per `(tenant_id, source_kind, source_id, event_id)`, with the source stamped from the certificate, so storage is exactly once per event and one sensor cannot pre-claim another sensor's event ids. A 429 or 5xx stops the drain until the next tick. A 401, or a 403 about the caller (missing scope, wrong id), stops it and keeps every event (the identity is the problem, not the data). Any other refusal, including a 403 `not_assigned` for a decoy that is no longer this sensor's, splits the batch and drops only the refused events, logged and counted in `dropped_events`. Ingest is rate limited per identity (default 120 batches a minute).

### 8. Tenancy rules

1. Every sensor, decoy, job, event and attempt carries a `tenant_id`, and it is always the one bound to the caller's certificate or token.
2. Ingest replaces any `source` or `tenant_id` in an event with the certificate identity.
3. A sensor can only send events, upload evidence and lease jobs for decoys placed on itself.
4. Placement checks the sensor is in the caller's tenant; other tenants get 404, never 403, so they learn nothing.
5. Registry reads and actions are tenant scoped like every other operator route.
6. A sensor certificate holds no operator scope and no host scope.

### 9. Network change flag

On every authenticated request from an enrolled agent (lease, acknowledgement, heartbeat, ingest, upload, renewal) the Worker compares the source IP (`CF-Connecting-IP`) and ASN (`cf.asn`) with the last values seen; it writes only when they change, when the last sighting is over five minutes old, or on a heartbeat. A change of ASN, or without ASNs a move out of the same IPv4 /16 or IPv6 /32, sets `network_changed_at` and writes a `sensor.network_changed` audit record. A copied certificate used from another network shows up this way.

## Consequences

- A stolen sensor certificate can ingest only as that sensor, for its own decoys, in its own tenant, until revoked. It cannot reach operator routes, mint tokens, read data or act as another sensor or a host. This is tested in `crates/api/tests/sensors.rs` against the tabletop in [modes.md](../deploy/modes.md).
- The Worker holds one more secret: a Cloudflare API token limited to SSL and certificates on the ingest zone. Losing it lets an attacker mint client certificates, but a certificate is useless until its fingerprint is bound to an identity in D1, which only `/v0/enrol` with a valid token does.
- A token is claimed before the CA call and released again if the CA fails, so a CA outage does not cost an enrolment; a successful bind spends it for good. CSRs with keys the CA will not sign are refused before the claim.
- Enrolment and renewal depend on the Cloudflare API being up. Ingest does not.
- The real Cloudflare issuer (`worker_glue::CloudflareIssuer`) is compiled and linted for `wasm32` but cannot be exercised in CI without an account; tests and the local mock use `FakeIssuer`. The operator steps in the guide are the acceptance check for that path.
- Event deduplication is keyed on the sending identity as well as the tenant and `event_id` (Postgres migration `0004`), so replays from one sensor are dropped but no sensor can suppress another's events.
- Identities that existed before migration `0003` get registry rows in the migration and can be listed, renewed and revoked through the API; their certificates have no CA reference and are revoked at the CA by hand (the revoke response lists them).
- The Worker checks the stored certificate expiry as well as `certVerified`, and a stored scope name the code no longer knows makes the credential a clean 401 rather than a server error.

## Alternatives considered

- **Bring-your-own CA (Enterprise) or a Foiled-run CA.** More control over certificate contents and CRLs, but Enterprise only, or a CA private key we would have to run safely. Not on the MVP path; revisit if Cloudflare-managed revocation proves too slow.
- **Long-lived bearer tokens for sensors.** Simple, but a bearer token is copied as easily as read and has no edge enforcement. Rejected; human and MCP tokens stay separate from ingest auth.
- **The control plane generates the key and ships it.** The private key would cross the network and touch the Worker. Rejected: the key is generated on the sensor and never leaves it.
- **A separate enrolment hostname.** Keeps the ingest hostname strictly certificate-only, but needs another hostname, Access policy and WAF rule. We exempt exactly one path instead, and rate limit it. Either is valid; operators who prefer a separate hostname can route `/v0/enrol` there unchanged.
- **Sensors push without leasing jobs (fixed decoy set at enrolment).** Simpler, but changing what a sensor runs would need re-enrolment, and the contribute-back channel decisions (#37) travel in jobs. We reuse the signed job protocol with stricter placement instead.
- **Automatic binary swap on update.** Convenient, but a bad build would brick a fleet we cannot reach. v0.2 verifies and stages; the service manager swaps.

# Control plane API

The contract is [`api/openapi.yaml`](../../api/openapi.yaml) (OpenAPI 3.1, `/v0` prefix, no GraphQL). It is linted with Redocly in CI, and a contract test in `crates/api/tests/openapi.rs` fails if an operation marked `x-foiled-status: implemented` is not routed, or one marked `planned` is. Each operation also names its backing store in `x-foiled-store` and, when planned, its owning issue in `x-foiled-issue`.

The control plane is a **trusted interface only**. It runs as an Axum Worker on Cloudflare ([ADR 0009](../adr/0009-axum-workers-and-front-end.md)) and is never served from a honeypot IP or reachable from a decoy network ([ADR 0003](../adr/0003-network-isolation.md)).

## Who calls it

| Client | Hostname | Credential | Scopes |
| --- | --- | --- | --- |
| Operator console (#14) | Service Binding from the `web` Worker | Operator session mapped to a bearer token ([console.md](../ui/console.md#sign-in-and-sessions)) | Operator scopes |
| CLI and scripts | API hostname, behind Cloudflare Access | `Authorization: Bearer fo_<id>.<secret>` | Operator scopes |
| MCP server (#24), `POST /v0/mcp` | API hostname | Bearer token for an `mcp` role | At most `catalogue:read`, `decoys:read`, `decoys:write`, `decoys:elevate`, `attempts:read`, `audit:read`, `events:read`; never `admin` |
| Sandbox host agent (#41) | Ingest hostname | mTLS client certificate | `host:*` only |
| Edge sensor (#31) | Ingest hostname | mTLS client certificate | `sensor:*` only |

Roles can never hold scopes from another family: a host or sensor certificate is mapped to an identity whose `admin` or `decoys:write` entries are dropped on load (`foiled_core::auth`). The mTLS check happens twice, once in the WAF rule on the ingest hostname and again in the Worker from `cf.tlsClientAuth` (fingerprint looked up in D1). Enrolment, renewal and revocation are in [edge-sensor.md](../deploy/edge-sensor.md) and [ADR 0007](../adr/0007-edge-ingest.md).

Bearer tokens are `fo_<id>.<secret>`. D1 stores only the SHA-256 of the secret, and comparison is constant time. Tokens can expire and be revoked.

## Rules every endpoint follows

- **Writes are audited.** Every create, action and refusal writes an audit record (`/v0/audit`) with actor, role, action, target, reason, job id, idempotency key and outcome. The audit log is append-only in Postgres; updates are refused by trigger.
- **Destructive actions need a reason.** `:stop`, `:rotate`, `:reset`, `:mark-compromised` and `:destroy` take `{"reason": {"code": ..., "text": ...}}`. Codes match `docs/rotation.md`.
- **The API never touches a host.** Decoy actions write a job for the host agent to lease. Only host reports move a decoy out of `pending` (`docs/rotation.md`).
- **Idempotency.** `Idempotency-Key` on creates and actions returns the original result on retry, and refuses a key reused for a different request.
- **Rate limits and caps.** Defaults: 10 decoy creates per principal per hour, 30 destructive actions per principal per hour, 5 live decoys per tenant, lifetime at most 7 days (default 24 hours).
- **Safe launch defaults.** Draft catalogue entries need `allow_draft` and `decoys:elevate`; deprecated entries and Docker-runtime entries are refused; every decoy inherits deny-by-default egress (#4).
- **Tenancy.** Every query is scoped to the caller's tenant. Another tenant's decoy is a 404, not a 403.
- **Errors** are `{"error": {"code": "...", "message": "..."}}` and never include SQL, host paths or other internals.
- **CPU-heavy work goes to Queues.** Bulk re-scoring is enqueued and runs on Queue consumers so request handlers stay inside Workers CPU limits. Exports are built on request from the same bounded window as attempts (at most 31 days and 20,000 events); queued exports for larger windows are later work ([intel-outputs.md](../intel-outputs.md#limits-and-what-is-not-built)).

## Where data lives

| Data | Store |
| --- | --- |
| Tokens, host and sensor identities, decoys, jobs, rate-limit counters | D1 (`migrations/d1/`) |
| Audit log, capture events, link overrides, the TAXII object log (#13), and later campaigns and the review queue | Postgres via Hyperdrive (`migrations/postgres/`) |
| Catalogue | Bundled into the Worker at build time from `catalogue/entries/` (already reviewed and linted in git) |
| Pcaps, file diffs, quarantine | R2, by `payload_ref` (#9) |
| Live event stream | Durable Object (#14) |

## What is served today

`GET /healthz`, `GET /v0/whoami` (the caller's id, role, tenant and scopes, used by the console at sign-in, #14), `GET /v0/catalogue/entries`, `GET /v0/catalogue/entries/{id}`, `GET`/`POST /v0/decoys` (alias `/v0/sandboxes`), `GET /v0/decoys/{id}`, the five decoy actions, `GET /v0/audit`, attempts, their timeline and links (#25, #10, #27), the intel exports (STIX 2.1, MISP, IOC CSV and JSON) and the read-only TAXII 2.1 server under `/taxii2/` with its materialiser (#13, [intel-outputs.md](../intel-outputs.md)), evidence ingest and upload URLs (#9), the host agent channel: job lease, ack and heartbeat (#41, [protocol](../agent/protocol.md)), the sensor and host registry with enrolment, renewal, re-enrolment, revocation and the sensor agent channel (#31, [edge-sensor.md](../deploy/edge-sensor.md)), the MCP endpoint `POST /v0/mcp` (#24, [foiled-mcp.md](../mcp/foiled-mcp.md)), the IOC reads `GET /v0/iocs`, `GET /v0/iocs/{id}` and `GET /v0/attempts/{id}/iocs` (#34), and campaigns: `GET /v0/campaigns`, `GET /v0/campaigns/{id}` with its attempts, evidence and analyst actions (#33, [campaigns.md](../campaigns.md)). Everything else in the spec is `planned` with its owning issue. Mapping to consumers:

| Consumer | Needs | Status |
| --- | --- | --- |
| Dashboard (#14) | Catalogue, decoys, attempts, links, review queue, campaigns, IOCs, exports, events | Served except quarantine (#9) and events, and the review queue, write-ups and radar (#35) until its pull request merges; the console says "not served yet" for those ([console.md](../ui/console.md#api-coverage)) |
| MCP (#24) | Create, list, get, reset, destroy, query attempts, events, audit | Served at `POST /v0/mcp` as a pure client of these routes ([foiled-mcp.md](../mcp/foiled-mcp.md)) |
| Sensors (#31) and hosts (#41) | Registry, enrolment, renewal, revocation, heartbeat, job lease and ack, uploads, ingest | Served |
| IOCs (#34) | Search, get, per attempt | Served ([iocs.md](../iocs.md)) |
| Campaigns (#33) | List, get, member attempts, evidence, analyst actions | Served ([campaigns.md](../campaigns.md)) |
| Radar and review queue (#35) | Their resources | Planned |

## Local mock server

The mock serves the real router over the in-memory store on loopback, for console and MCP contract tests:

```sh
cargo run -p foiled-mock-api -- 127.0.0.1:8787
# prints a one-off admin token: fo_dev.<secret>
curl -H "Authorization: Bearer fo_dev.<secret>" http://127.0.0.1:8787/v0/catalogue/entries
```

## Running against a database locally

Postgres tests need a disposable database:

```sh
FOILED_TEST_PG_URL=postgres://user:pass@localhost:5432/foiled_test \
  cargo test -p foiled-pg -- --include-ignored
```

Apply schemas with `wrangler d1 migrations apply` (D1, from `crates/api/`) and, for Postgres, each file in order, stopping at the first error:

```sh
for f in migrations/postgres/*.sql; do
  psql -v ON_ERROR_STOP=1 "$DATABASE_URL" -f "$f" || break
done
```

`foiled_pg::migrate` applies the same files and records each in `schema_migrations`; the tests use it. This repository's automation never deploys.

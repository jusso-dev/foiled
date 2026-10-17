# Control plane API

The contract is [`api/openapi.yaml`](../../api/openapi.yaml) (OpenAPI 3.1, `/v0` prefix, no GraphQL). It is linted with Redocly in CI, and a contract test in `crates/api/tests/openapi.rs` fails if an operation marked `x-foiled-status: implemented` is not routed, or one marked `planned` is. Each operation also names its backing store in `x-foiled-store` and, when planned, its owning issue in `x-foiled-issue`.

The control plane is a **trusted interface only**. It runs as an Axum Worker on Cloudflare ([ADR 0009](../adr/0009-axum-workers-and-front-end.md)) and is never served from a honeypot IP or reachable from a decoy network ([ADR 0003](../adr/0003-network-isolation.md)).

## Who calls it

| Client | Hostname | Credential | Scopes |
| --- | --- | --- | --- |
| Operator console (#14) | Service Binding from the `web` Worker | Operator session mapped to a bearer token | Operator scopes |
| CLI and scripts | API hostname, behind Cloudflare Access | `Authorization: Bearer fo_<id>.<secret>` | Operator scopes |
| MCP server (#24) | API hostname | Bearer token for an `mcp` role | Operator scopes, kept narrow |
| Sandbox host agent (#41) | Ingest hostname | mTLS client certificate | `host:*` only |
| Edge sensor (#31) | Ingest hostname | mTLS client certificate | `sensor:*` only |

Roles can never hold scopes from another family: a host or sensor certificate is mapped to an identity whose `admin` or `decoys:write` entries are dropped on load (`foiled_core::auth`). The mTLS check happens twice, once in the WAF rule on the ingest hostname and again in the Worker from `cf.tlsClientAuth` (fingerprint looked up in D1). Details of enrolment and revocation are in #31.

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
- **CPU-heavy work goes to Queues.** Exports and bulk re-scoring are enqueued and run on Queue consumers so request handlers stay inside Workers CPU limits.

## Where data lives

| Data | Store |
| --- | --- |
| Tokens, host and sensor identities, decoys, jobs, rate-limit counters | D1 (`migrations/d1/`) |
| Audit log, and later attempts, IOCs, campaigns, review queue | Postgres via Hyperdrive (`migrations/postgres/`) |
| Catalogue | Bundled into the Worker at build time from `catalogue/entries/` (already reviewed and linted in git) |
| Pcaps, file diffs, quarantine | R2, by `payload_ref` (#9) |
| Live event stream | Durable Object (#14) |

## What is served today

`GET /healthz`, `GET /v0/catalogue/entries`, `GET /v0/catalogue/entries/{id}`, `GET`/`POST /v0/decoys` (alias `/v0/sandboxes`), `GET /v0/decoys/{id}`, the five decoy actions, `GET /v0/audit`, evidence ingest and upload URLs (#9), and the host agent channel: job lease, ack and heartbeat (#41, [protocol](../agent/protocol.md)). Everything else in the spec is `planned` with its owning issue. Mapping to consumers:

| Consumer | Needs | Status |
| --- | --- | --- |
| Dashboard (#14) | Catalogue, decoys, attempts, links, review queue, campaigns, IOCs, exports, events | Catalogue and decoys served; the rest planned with owners |
| MCP (#24) | Create, list, get, reset, destroy, query attempts, events, audit | Decoy tools served; attempts and events planned |
| Sensors (#31) and hosts (#41) | Heartbeat, job lease and ack, uploads, ingest | Served for hosts; sensor enrolment planned (#31) |
| Campaigns (#33), IOCs (#34), radar and review queue (#35) | Their resources | Planned |

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

Apply schemas with `wrangler d1 migrations apply` (D1, from `crates/api/`) and `psql -f migrations/postgres/*.sql` (Postgres). This repository's automation never deploys.

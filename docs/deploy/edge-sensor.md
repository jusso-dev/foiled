# Edge sensors

Status: built for v0.2 (#31). Decision record: [ADR 0007](../adr/0007-edge-ingest.md). Related: #7 ([deployment modes](modes.md), [VPS guide](vps.md)), #9 (capture), #21 ([API](../api/control-plane.md)), #30 (emulations), #37 ([contribute-back](../contribute-back.md)), #40 ([Workers](workers.md)), #41 ([host agent protocol](../agent/protocol.md)).

An edge sensor is `foiled-hostd` running with `role = "sensor"` on a host we do not control, usually a customer's. It runs decoys (emulations by default), buffers evidence on disk and forwards it to the central control plane over mTLS. Research sensors on a VPS (#7) stay the MVP path; everything here also applies to sandbox hosts, which enrol through the same flow with the `host` role.

What is real and what is not:

| Part | State |
| --- | --- |
| Registry, enrolment, renewal, re-enrolment and revocation API | Built and tested against the in-memory store and SQLite (D1 SQL). |
| Two-layer mTLS check in the Worker, role and tenant binding | Built and tested. The WAF rule is an operator step below. |
| Cloudflare client certificate issue and revoke (`CloudflareIssuer`) | Built and checked for `wasm32`, **not exercised in CI**: it needs a Cloudflare account. Tests and the local mock use a fake CA (`FakeIssuer`). |
| Sensor-side key generation, enrolment, renewal, offline buffer, signed build verification | Built and tested (`crates/hostd`). Swapping the running binary after verification is left to the service manager. |
| Network change flag | Built: checked on every agent request, audit record and `network_changed_at`. Routing it to alerts (#15) is follow-up work. |

## What runs on an edge sensor

- **Emulations (#30)**: the default. A sensor only accepts decoys placed on it, and the control plane refuses `sandbox` catalogue entries for a sensor unless the tenant admin set `sandbox_allowed` when registering it.
- **Full sandboxes**: optional and heavy. They need KVM, Firecracker, the jailer and the network boundary from [ADR 0003](../adr/0003-network-isolation.md) on someone else's machine, with the same containment duties as a research host ([vps.md](vps.md)). Only enable them where the host owner can meet those.
- **Contribute-back**: off by default on edge sensors; the sensor's `share_opt_in` and its local veto decide ([contribute-back.md](../contribute-back.md)).

## Roles side by side

| Capability | Host role (#41) | Sensor role (#31) | Human or MCP token (#21) |
| --- | --- | --- | --- |
| Lease and acknowledge its own placed jobs | `host:lease` | `sensor:lease` | no |
| Heartbeat, renew its own certificate | `host:report` | `sensor:report` | no |
| Send capture envelopes for its own decoys | `host:ingest` | `sensor:ingest` | no |
| Mint upload URLs for its own decoys | `host:upload` | `sensor:upload` | no |
| Take unplaced jobs | yes | no | no |
| Register, revoke, re-enrol | no | no | `hosts:write` / `sensors:write` |
| List and read the registry | no | no | `hosts:read` / `sensors:read` |
| Anything else (decoys, attempts, audit, tokens) | no | no | by scope; `admin` only through Access with MFA |

Host and sensor certificates map to identities that can only hold their own family's scopes (`foiled_core::auth::agent_scopes`). There is no path from a certificate to an operator scope.

## Cloudflare setup (operator steps)

Do these once per deployment, after [workers.md](workers.md). Use placeholders in anything you commit.

1. **Apply the migrations**: D1 `migrations/d1/0003_enrolment.sql` (sensor and host registry, enrolment tokens, one row per certificate; existing hosts get registry rows and the retired `sensor:heartbeat` scope name is stripped) and Postgres `migrations/postgres/0004_capture_events_source_key.sql` (deduplicate events per sending identity).
2. **Turn on mTLS for the ingest hostname** (SSL/TLS, Client Certificates, add the hostname). Certificates come from the Cloudflare-managed CA; no bring-your-own CA is needed.
3. **Layer 1, the WAF custom rule** on the zone, action **Block**:

   ```txt
   (http.host eq "ingest.example.invalid"
     and not (http.request.uri.path eq "/v0/enrol" and http.request.method eq "POST")
     and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   This blocks every request on the ingest hostname without a verified, unrevoked client certificate, except enrolment. Revoked Cloudflare-managed certificates are only blocked because of the `cert_revoked` clause; Cloudflare does not block them on its own.
4. **Optional: a rate limiting rule** on `POST /v0/enrol` (for example 10 requests a minute per IP). The Worker also limits enrolment attempts per source IP (default 30 an hour).
5. **An API token for the CA**: create a token with only *Zone, SSL and Certificates, Edit* on the ingest zone. Store it with `wrangler secret put CF_CLIENT_CERT_API_TOKEN` and set the var `CF_ZONE_ID`. Without both, `/v0/enrol` and renewal return 503 `enrolment_disabled`; ingest is unaffected.
6. **Check**: a request to the ingest hostname without a certificate returns 403 from the WAF, except `POST /v0/enrol`, which returns 401 for a made-up token.

### Layer 2: the Worker's own check

The Worker never relies on the WAF alone. For every request it copies `cf.tlsClientAuth` (presented, verified, SHA-256 fingerprint) into the request, then:

| Check | Where | Fails with |
| --- | --- | --- |
| Certificate presented and `certVerified == "SUCCESS"` | `crates/api/src/auth.rs` | 401 |
| Fingerprint is a known identity in D1, with only scope names the code knows | `identity_by_cert` | 401 |
| Identity not revoked, certificate not past `valid_until` (retired by renewal or re-enrolment) or its stored expiry | `auth.rs` | 401 |
| Scope held, and the role matches the path family (`/v0/hosts` or `/v0/sensors`) | `routes/hosts.rs`, `routes/agents.rs` | 403 |
| Path id is the caller's own id | same | 403 `wrong_sensor` / `wrong_host` |
| Decoy placed on the caller, in the caller's tenant | `routes/ingest.rs` | 404 or 403 `not_assigned` |

So the two layers are separate: the WAF is the coarse gate at Cloudflare's edge, and the Worker maps the fingerprint to exactly one identity, role and tenant and refuses everything else.

### mTLS and transport requirements

- The sensor only dials out, over HTTPS (`https_only`), presenting its client certificate. `http://` is accepted only for a loopback mock on a box that is not publicly exposed ([config.rs](../../crates/hostd/src/config.rs)). No plaintext telemetry crosses the internet.
- One ECDSA P-256 key per sensor, generated on the sensor. The private key never leaves it; files are written owner-only (0600) and replaced atomically.
- Certificate lifetime 90 days by default (`cert_validity_days`). Renewal at two thirds of the lifetime.
- The certificate subject is ignored. The fingerprint is the identity.
- The sensor holds no database credentials, no API tokens, no Cloudflare tokens and no R2 keys. Its certificate is the only credential on the box.

## Enrolment, step by step

1. **Register.** A tenant admin calls `POST /v0/sensors` (scope `sensors:write`) with an optional `label`, `sandbox_allowed` and `share_opt_in`. The response holds the sensor record (status `pending`) and `enrolment.token`, a one-time `foe_<id>.<secret>` valid for one hour by default (`enrolment_ttl_seconds`, 300 to 86400). Only the token's hash is stored, and the token is not written to the audit log (`sensor.create`).
2. **Hand over the token** to whoever installs the sensor, over a channel you trust. Treat it like a password for its short life.
3. **Configure the sensor.** Copy [`deploy/sensor.example.toml`](../../deploy/sensor.example.toml), set `host_id` to the sensor id from step 1, `api_base` to the ingest hostname, and the job and release public keys.
4. **Enrol.** Write the token to a root-only file and run:

   ```sh
   foiled-hostd enrol /etc/foiled/sensor.toml /root/enrolment-token
   ```

   The agent generates a P-256 key, sends only a CSR with the token to `POST /v0/enrol`, checks that the certificate it gets back was issued for the sensor id and role in its config and matches its fingerprint, installs key and certificate owner-only, writes `identity.json` (identity, fingerprint, issue and expiry times) under `state_dir`, and deletes the token file.
5. **Control plane side** of step 4: rate limit by source IP; find the token; constant-time compare of the secret; refuse if used or expired (401, audited as `sensor.enrol` denied); refuse a malformed CSR, one that contains a private key, or one for a key the CA will not sign (ECDSA P-256 or P-384, or RSA 2048 to 4096 bits) (400, token not spent); mark the token used in one compare-and-set; have the Cloudflare-managed CA sign the CSR; fingerprint the returned certificate; bind it to the sensor in one transaction that binds nothing if the sensor was revoked meanwhile; audit `sensor.enrol` with the fingerprint, source IP and ASN.
6. **Start the agent** (`foiled-hostd /etc/foiled/sensor.toml`). It heartbeats, leases jobs placed on it, and sends evidence.

If the CA fails to issue (502 `issuer_failed`), the claim on the token is released and the same token can be retried until it expires. `foiled-hostd enrol` keeps the token file on a network error, 429, 5xx or 400 and deletes it only after success or a definitive 401 (spent, expired, revoked or wrong).

## Placing decoys

`POST /v0/decoys` with `sensor_id` places the decoy and its create job on that sensor:

- the sensor must be in the caller's tenant and not revoked, otherwise 422 `sensor_unavailable`;
- `sandbox` entries need `sandbox_allowed` on the sensor, otherwise 422 `sandbox_not_allowed`;
- the sensor leases it from `POST /v0/sensors/{id}/jobs:lease`; research hosts never see it, and the sensor never sees unplaced jobs.

## Renewal, re-enrolment and revocation

### Renewal

The agent checks hourly. At two thirds of the certificate's life it generates a new key, calls `POST /v0/sensors/{id}/certificate:renew` with a CSR over its current mTLS identity, installs the new pair (staged and renamed key first, then certificate; an interrupted install is finished on the next start) and reconnects. The old certificate keeps working for 24 hours, then the Worker refuses it. Renewal is only as itself, only while active, and limited to 4 a day.

### Re-enrolment (lost key, rebuilt box)

1. Admin: `POST /v0/sensors/{id}:reenrol` with a `reason`. Any unused token is closed and a new one is returned. Audited as `sensor.reenrol`.
2. Sensor: `foiled-hostd enrol` again with the new token.
3. Redeeming the token retires every older certificate of that sensor at once, with no grace period.

Use revocation, not re-enrolment, if the old key may be in someone else's hands.

### Revocation

1. Admin: `POST /v0/sensors/{id}:revoke` with a `reason` (scope `sensors:write`).
2. In one D1 transaction the sensor becomes `revoked` with the reason and time, every certificate it holds is marked revoked, and any unused enrolment token is closed. From this point the Worker answers 401 to that sensor.
3. The Worker then revokes each certificate at the Cloudflare-managed CA (`DELETE /zones/{zone}/client_certificates/{id}`), so the WAF rule's `cert_revoked` clause blocks it at the edge. The response counts `ca_revoked` and `ca_failed`, and the audit record (`sensor.revoke`) lists any CA errors and, under `revoke_in_dashboard`, the fingerprint of every certificate the CA did not revoke. Hosts registered before migration `0003` have certificates without a CA reference; they always land in that list.
4. If `ca_failed` is not zero, finish in the dashboard: SSL/TLS, Client Certificates, select each certificate with the sensor's fingerprint, **Revoke**. Until then the WAF lets the certificate through, but the Worker still refuses it.
5. Destroy or reassign the sensor's decoys. Jobs placed on a revoked sensor are never leased again.
6. Revocation is final. Cloudflare-managed certificates can be restored in the dashboard, but the D1 identity stays revoked, so a restored certificate still gets 401. Replace the sensor by registering a new one.

## Sequence: enrol, create decoy, forward events, revoke

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Tenant admin (console)
    participant S as Edge sensor (foiled-hostd)
    participant WAF as Cloudflare edge (mTLS + WAF)
    participant API as API Worker
    participant D1 as D1
    participant CA as Cloudflare-managed CA
    participant Q as Ingest Queue

    Admin->>API: POST /v0/sensors {label}
    API->>D1: sensor pending + token hash
    API-->>Admin: sensor id, one-time token (shown once)
    Admin-->>S: token, out of band
    S->>S: generate P-256 key, build CSR
    S->>WAF: POST /v0/enrol {token, csr} (no client cert, exempt path)
    WAF->>API: forwarded
    API->>D1: check hash, unused, unexpired; mark used (CAS)
    API->>CA: sign CSR
    CA-->>API: certificate, id
    API->>D1: bind fingerprint to sensor, tenant, sensor scopes
    API-->>S: certificate, identity
    S->>S: install key and cert (0600), delete token
    Admin->>API: POST /v0/decoys {catalogue_id, sensor_id}
    API->>D1: decoy + job placed on the sensor
    loop every 5 s
        S->>WAF: POST /v0/sensors/{id}/jobs:lease (client cert)
        WAF->>API: verified, not revoked
        API->>D1: fingerprint -> sensor; lease placed jobs only
        API-->>S: signed jobs
    end
    S->>S: verify signature, run emulation
    Note over S: attacker touches the decoy
    S->>S: envelope to the on-disk buffer
    S->>WAF: POST /v0/ingest/events (client cert)
    WAF->>API: verified
    API->>API: validate, check decoy is this sensor's, stamp sensor id and tenant
    API->>Q: stamped envelopes
    Admin->>API: POST /v0/sensors/{id}:revoke {reason}
    API->>D1: sensor and certificates revoked, tokens closed
    API->>CA: revoke certificate
    S->>WAF: POST /v0/ingest/events (client cert)
    WAF-->>S: 403 (cert_revoked)
    Note over S: events stay in the buffer, nothing is dropped
```

## Offline buffer

| Setting | Default | Notes |
| --- | --- | --- |
| Location | `<state_dir>/buffer/seg-*.jsonl` | Append-only JSON line segments, fsync on every write. |
| Cap | 256 MiB on a sensor, 1 GiB on a host | `buffer_max_bytes` overrides. |
| Segment size | 1 MiB | Dropping happens a whole segment at a time. |
| Over the cap | Oldest whole segments are deleted | Counted in `dropped_events` in every heartbeat. |
| Drain | Oldest first, batches of up to 100 | Each poll tick (default 5 s). |
| 5xx, 429 or network error | Stop, keep everything, retry next tick | This is the back-pressure path. |
| 401, or 403 about the caller (`forbidden`, `wrong_sensor`) | Stop, keep everything | The certificate is revoked, retired, expired or unknown, or lacks a scope; the data is not at fault. |
| Other 4xx, including 403 `not_assigned` (decoy moved to another sensor) and 404 | Resend the batch one event at a time, drop only the refused ones | Logged and counted in `dropped_events`, so one stale event cannot stall the buffer. |
| Ingest rate limit | 120 batches a minute per identity | Returns 429. |

**Semantics.** Delivery on the wire is at least once: an event is removed from the buffer only after the control plane accepted it, so a crash between send and commit resends it. The store keeps one row per `(tenant_id, source_kind, source_id, event_id)` (`ON CONFLICT DO NOTHING` in Postgres), with the source stamped from the certificate, so each event is stored exactly once and no sensor can pre-claim another sensor's event ids, in its own tenant or any other.

### Buffer test plan

Automated in `crates/hostd/tests/sensor_e2e.rs` (no network beyond loopback):

1. Enrol a sensor and place an emulation on it; the sensor leases and runs it.
2. Kill the control plane. Generate N = 250 events, plus one event for a decoy that is not the sensor's.
3. Flush fails with "unavailable"; the buffer holds all 251.
4. Bring the control plane back on a new address. Flush drains in batches; the invalid event is dropped on its own and counted (`dropped_events = 1`); exactly 250 distinct events arrive, every one stamped with the sensor id and tenant.
5. Resend 10 already-delivered events (a crash between send and commit). The store still holds 250.
6. Revoke the sensor. New events stay buffered; flush stops with an identity error and drops nothing.

Manual check on a real sensor: stop outbound HTTPS with a firewall rule, let traffic hit a decoy for an hour, watch `buffered_events` rise in the console, restore, and watch it fall to zero with `dropped_events` unchanged (or, if the cap was hit, rising by whole segments).

## Signed builds

Requirements:

1. Every release publishes `manifest.json`: a signed manifest `{body, sig, key_id}` where `body` is the JSON text of a [release manifest](../../schemas/release-manifest.schema.json) (`kind: "foiled.release.v1"`, product, `MAJOR.MINOR.PATCH` version, release time, and per target triple the file name, size and SHA-256), and `sig` is a hex Ed25519 signature over the exact bytes of `body`.
2. The release key is kept offline. It is never a Worker secret and is never the job signing key: the agent refuses a config where a `release_keys` entry matches a `trusted_keys` entry. Its public half is pinned in each sensor's `release_keys`; pin the next key before rotating.
3. The agent verifies, in order: signature by a pinned release key; `kind` and `product`; version strictly newer than both the running one and the highest version ever staged on this machine (`<state_dir>/updates/floor`; no downgrade, no replay, no walk back to an older signed build); size, then SHA-256, of the downloaded file for its own target. Nothing in the manifest is read before the signature verifies.
4. Only then is the file staged under `<state_dir>/updates/<version>/foiled-hostd`. Swapping it in and restarting is the service manager's job, so a bad build can be rolled back.

```sh
foiled-hostd verify-update /etc/foiled/sensor.toml manifest.json foiled-hostd-x86_64-unknown-linux-gnu
```

Signing in the release workflow uses `foiled_core::release::ReleaseSigner` with the offline key; publishing releases is not automated yet.

## Tenancy isolation rules

| Rule | Tested by (`crates/api/tests/sensors.rs` unless noted) |
| --- | --- |
| A certificate maps to exactly one identity, role and tenant, chosen by the enrolment token, never by the request or CSR. | `enrolment_binds_the_certificate_to_the_tokens_identity_only` |
| A sensor certificate holds no operator scope and no host scope. | `a_sensor_certificate_cannot_reach_operator_routes`, `hosts_enrol_through_the_same_flow_with_the_host_role` |
| A sensor only acts as itself. | `sensors_lease_only_their_own_placed_jobs`, `renewal_overlaps_for_the_grace_period_only` |
| A sensor only receives jobs placed on it, never unplaced work. | `sensors_lease_only_their_own_placed_jobs`, D1 `sensors_never_lease_unplaced_jobs` |
| Ingested events are stamped with the sensor id and its tenant, whatever the body claims. | `ingest_is_stamped_with_the_sensor_and_limited_to_its_decoys` |
| A sensor only sends evidence for its own decoys; another tenant's decoy is 404. | same |
| Decoys can only be placed on a sensor of the caller's tenant. | `placement_is_tenant_scoped_and_emulation_first` |
| Registry reads and actions are tenant scoped; other tenants get 404. | same |
| Tokens are single use, expire and are closed by re-enrolment or revocation. | `enrolment_binds_...`, `expired_tokens_and_missing_issuer_are_refused`, `revoking_a_pending_sensor_kills_its_token`, D1 `enrolment_tokens_are_single_use_and_expire` |
| Revocation is immediate in the Worker and final. | `revocation_is_immediate_final_and_reaches_the_ca`, D1 `certificates_bind_rotate_and_revoke` |

## Compromise tabletop: stolen sensor certificate

The tabletop in [modes.md](modes.md#tabletop-edge-sensor-compromise) is the acceptance test. Each step's control is now implemented:

| Step | Control | Test |
| --- | --- | --- |
| 1. Key and certificate copied elsewhere | Network change flag on ASN or prefix jump, audited as `sensor.network_changed`. | `a_network_jump_is_flagged_and_audited` |
| 2. Admin routes on the ingest hostname | Sensor scopes only; operator routes need operator scopes. Serve only ingest routes on that hostname ([workers.md](workers.md)). | `a_sensor_certificate_cannot_reach_operator_routes` |
| 3. Console or API hostname | Cloudflare Access; a client certificate is not a credential there. | Operator check in [workers.md](workers.md) |
| 4. Mint tokens or register sensors | 403: `sensors:write` and `admin` cannot be held by a sensor. | `a_sensor_certificate_cannot_reach_operator_routes` |
| 5. Reuse the enrolment token | Single use, deleted from disk after enrolment, reuse audited as denied. | `enrolment_binds_the_certificate_to_the_tokens_identity_only`, `sensor_e2e` |
| 6. Claim another sensor or tenant | Identity and tenant stamped from the certificate. | `ingest_is_stamped_with_the_sensor_and_limited_to_its_decoys` |
| 7. Set confidence or CVE links | Confidence is computed centrally from evidence (#27); unknown event fields are refused. | `capture` unit tests |
| 8. Flood ingest | Per-identity rate limit, schema and size checks before enqueue. | `ingest_is_rate_limited_per_identity` |
| 9. Look for credentials on the box | Only the sensor's own key and certificate are there. | Config refuses unknown keys such as `database_url` (`config.rs`). |
| 10. Keep using the key | Revocation in D1 (Worker, immediate) and at the CA (WAF). | `revocation_is_immediate_final_and_reaches_the_ca` |

Result: a stolen sensor certificate can ingest only as that sensor, for its own decoys, in its own tenant, until revoked. It cannot become admin.

## Local testing without Cloudflare

The mock server signs CSRs with the fake CA and accepts a test-mode header in place of `cf.tlsClientAuth`. It only listens on loopback.

```sh
cargo run -p foiled-mock-api -- 127.0.0.1:8787
# register a sensor with the printed admin token
curl -s -X POST http://127.0.0.1:8787/v0/sensors -H "authorization: Bearer fo_dev.<secret>" \
  -H 'content-type: application/json' -d '{"label":"lab sensor"}'
# enrol with a CSR (or run foiled-hostd enrol against http://127.0.0.1:8787 on a non-public lab box)
# then act as the sensor by sending its fingerprint from identity.json:
curl -s -X POST http://127.0.0.1:8787/v0/sensors/<id>/jobs:lease \
  -H 'x-foiled-test-client-cert: <cert_sha256>'
```

The production Worker has no header path: identity only comes from `cf.tlsClientAuth`.

## Limits and follow-up

- The Cloudflare CA calls are untested against a real account in CI. The first real deployment should walk the setup and revocation steps above and confirm the 403 from the WAF after revocation.
- `sensor.network_changed` is an audit record and a field on the sensor. Raising it as an alert type through the delivery worker belongs with #15.
- Automatic binary swap after a verified update is not built; v0.2 stages verified builds only.
- The edge sensor console page (#14) is not built; the API and audit log carry everything it needs.

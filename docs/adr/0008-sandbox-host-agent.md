# ADR 0008: Sandbox host agent

## Status

Accepted (18 Oct 2026). Issue #41. Related: #3 and [ADR 0002](0002-sandbox-runtime.md) (runtime), #4 and [ADR 0003](0003-network-isolation.md) (network), #7 ([deploy guide](../deploy/vps.md)), #8 ([rotation](../rotation.md)), #9 and [ADR 0005](0005-capture-layer.md) (capture), #21 ([API](../api/control-plane.md)), #31 (enrolment), [ADR 0009](0009-axum-workers-and-front-end.md).

## Context

The control plane runs on Cloudflare Workers, which cannot run decoys (no KVM, raw sockets or arbitrary listeners). Decoys run on VPS or bare-metal hosts we control. Something on each host has to turn control-plane decisions into runtime actions and ship evidence back, without giving the control plane a shell on the host or the host any admin power over the control plane.

## Decision

`foiled-hostd` (`crates/hostd`), a native Rust binary running as the unprivileged `foiled-agent` user (see the systemd unit in `deploy/systemd/`).

### Connection model: outbound only

The agent dials the ingest hostname over HTTPS with an mTLS client certificate issued through the #31 enrolment flow (`host` role). Nothing on the host listens for management traffic on any interface. Cloudflare checks the certificate at the edge (WAF rule) and the Worker checks it again from `cf.tlsClientAuth` before mapping it to a host identity in D1.

### Job intake: option A, lease from the API

The agent calls `POST /v0/hosts/{id}/jobs:lease` (short poll, every 5 seconds by default), runs what it gets, and reports each result with `POST /v0/hosts/{id}/jobs/{job_id}:ack`.

Why A and not a Queues HTTP pull consumer (B):

- **Per-host authorisation.** Pulling from a Queue over HTTP needs a Cloudflare API token that can read the whole queue, so a stolen host would see other hosts' jobs. The lease endpoint authorises by the host's own certificate and only returns jobs placed on that host.
- **No Cloudflare credentials on hosts.** Option B puts an account-scoped API token on every sandbox host. Option A needs only the host's certificate, which is useless for anything except this API.
- **Placement in one place.** The lease statement places unplaced jobs atomically on the leasing host, so the control plane needs no separate scheduler for the MVP.
- Cost: polling rather than push. At one request every 5 seconds per host it is small, and leases are cheap D1 statements.

### Jobs are signed

Every leased job is a JSON body signed with an Ed25519 key held as the Worker secret `JOB_SIGNING_KEY` (seed) and named by `JOB_SIGNING_KEY_ID`. The host pins the public key(s) in `hostd.toml`; two keys may be trusted at once for rotation. The signature covers the exact body bytes, so there is no canonicalisation step. Mutual TLS protects the channel; the signature protects the job itself, so a compromised edge, proxy or replayed response cannot inject work.

Before the runtime sees a job, the gate (`crates/hostd/src/gate.rs`) refuses:

| Check | Refusal |
| --- | --- |
| Signature by a trusted key | Forged or edited jobs |
| `host_id` is this host | Jobs for other hosts |
| `expires_at` in the future | Expired jobs |
| `issued_at` at most 5 minutes ahead | Jobs from the future (clock attack) |
| Idempotency key not seen before (persisted across restarts) | Replays |
| `reason` present on destructive kinds | Destroy, stop or rotate without a reason |
| Artefact pinned and on the local allow-list | Anything not explicitly approved for this host |

Refused jobs are acknowledged as `rejected` with the reason, and the control plane audits them as denied.

### Job types and runtime mapping

Fixed kinds only: `decoy.create`, `decoy.start`, `decoy.stop`, `decoy.rotate`, `decoy.reset`, `decoy.mark_compromised`, `decoy.destroy`, `decoy.snapshot`, `capture.flush`, `host.drain`. Each maps onto the `Runtime` interface from ADR 0002 (`crates/hostd/src/executor.rs`). There is no free-form command. Rebuilds always destroy and recreate from the pinned artefact; a guest is never restarted from its own disk. If a containment step fails the decoy is reported stopped, never republished. Request and result schemas: [`schemas/agent/`](../../schemas/agent/); protocol: [docs/agent/protocol.md](../agent/protocol.md).

### Evidence

Small events go up as capture envelopes in batches through `POST /v0/ingest/events`. Pcaps, file diffs and quarantined payloads go straight to R2 with presigned URLs from `POST /v0/uploads` and are cited by `payload_ref` (ADR 0005). Large artefacts never pass through a Worker request body.

### Heartbeat

Every 30 seconds: agent version, KVM present, public exposure, free disk, running decoys, buffered and dropped event counts, and the host clock. The control plane records clock skew.

### Offline buffer

Envelopes are written to an on-disk segment buffer (default cap 1 GiB) before sending. Over the cap, whole oldest segments are dropped and counted in heartbeats. Delivery is at least once; the control plane deduplicates on `event_id`, so a crash between send and commit causes no duplicates downstream. If the control plane is gone for 30 minutes, running decoys keep running, events buffer, and the backlog drains in batches when it returns (tested in `crates/hostd/tests/agent_e2e.rs`).

### Self-update

Only from signed releases, using the rules in [ADR 0007](0007-edge-ingest.md) (#31): `foiled-hostd verify-update` checks the signed manifest and stages the build; the service manager swaps it in.

### Least privilege

- `foiled-agent` runs with no capabilities. Network setup for each decoy (ADR 0003) is done by the `foiled-jailer@` unit's root `ExecStartPre` step, which only applies fixed, validated policy; the agent starts and stops those units through a polkit rule that allows nothing else ([deploy guide](../deploy/vps.md)).
- The agent never holds database credentials, Cloudflare API tokens or R2 keys. Its certificate is the only credential on the host.
- `publicly_exposed` defaults to true, and the agent refuses to start with the Docker runtime on a public host.

### How "no management port" is checked

1. The agent opens no listening sockets; its only network calls are outbound HTTPS from `ControlPlane` (`crates/hostd/src/client.rs`).
2. After install, `ss -ltnup` on the host must show no listener owned by `foiled-agent`, and only published decoy ports on public addresses.
3. The host firewall (ADR 0003 and the deploy guide) drops inbound traffic to the host's own addresses except published decoy ports and the private admin path (WireGuard or Tailscale).
4. The operator checklist in the deploy guide repeats these checks after every upgrade.

### What a stolen host certificate can do

Lease and acknowledge jobs placed on that host, send heartbeats as that host, send evidence for decoys assigned to that host, and mint upload URLs for those decoys only. It cannot read other hosts' jobs, other tenants' data, decoys, the audit log, or any operator endpoint: host identities can only hold `host:*` scopes (`foiled_core::auth`), and every host route checks the path's host id against the certificate. The API tests cover each of these. Revocation is through #31.

## Consequences

- Hosts are cattle: a compromised host is revoked, rebuilt and re-enrolled, with no shared secret to rotate elsewhere.
- The MVP binary uses a recording runtime: the Firecracker and module drivers that implement the `Runtime` trait on a real KVM host are follow-up work under #3, and cannot be tested in this repository's CI. Everything above the trait (gate, executor, protocol, buffer, client) is real and tested.
- Polling adds up to one poll interval of latency to operator actions.

## Alternatives considered

- **B: Cloudflare Queues HTTP pull consumer.** Rejected for the credential and scoping reasons above.
- **Control plane pushes to an agent API on the host.** Rejected: needs an inbound management port and puts the control plane one hop from a hostile network.
- **SSH from an orchestrator.** Rejected: a shell on every honeypot host is exactly what we do not want reachable.
- **Unsigned jobs relying on mTLS alone.** Rejected: TLS authenticates the channel, not the job, and gives no protection against replay after the fact.

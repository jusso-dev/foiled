# ADR 0005: Capture layer

## Status

Accepted (18 Oct 2026). Issue #9. Related: #32 (hooks), #30 (emulators and modules), #31 (edge sensors), #41 (host agent), #16 (retention), #25 (attempts), [ADR 0002](0002-sandbox-runtime.md), [ADR 0003](0003-network-isolation.md), [ADR 0009](0009-axum-workers-and-front-end.md).

## Context

A decoy without evidence is only a liability. We need to record what attackers do around every decoy (sandbox, emulator or module) in a store the guest cannot alter, in one envelope format so attempts (#25) look the same whatever produced them, and without pushing pcaps through Worker request bodies. Payloads can be personal information (#16) and can be live malware.

## Decision

### Where capture runs

Capture is host-side or boundary-side. In-guest agents are optional and untrusted. Nothing in the guest can write to the capture buffer or the quarantine directory.

| Decoy | Network | Application | Filesystem | Process | Hooks (#32) |
| --- | --- | --- | --- | --- | --- |
| Firecracker sandbox | `tcpdump`/AF_PACKET on the host side of the decoy's tap (`foil-<id8>`, ADR 0003) | App logs read from the guest's serial or vsock log channel, or from the frontend proxy | Overlay diff of the guest disk image on rotate, taken from the host after the guest is stopped | eBPF on the host is not possible inside a micro-VM; v0.2 adds an optional in-guest auditd forwarder, treated as untrusted | Hook lines from instrumented apps on the log channel |
| Docker lab fallback | Host side of the container veth | `docker logs` stream | `docker diff` plus a copy of changed files on rotate | Falco or auditd on the host, v0.2 | As above |
| Emulator (#30) | Host side of the emulator namespace veth | The emulator's own JSON event stream | "Virtual FS write" events from the emulator | Not applicable | Emulator-native checkpoints |
| Decoy module (#30) | Host side of the module network | Module JSON logs tailed by the host agent and mapped by its manifest (ADR 0002) | Module-specific (for example Cowrie downloads) | Not applicable | Not applicable |
| Boundary (all decoys) | | | | | DNS queries from the internal resolver (`dns`) and requests from the egress proxy (`egress`), ADR 0003 |

### Channels by milestone

| Channel | MVP | v0.2 | Edge-forwarded subset (#31) |
| --- | --- | --- | --- |
| `network` (flows, pcap by reference) | Yes | Zeek or Suricata on the host, optional | Flow summaries only; pcaps stay local unless requested |
| `application` (HTTP access lines, protocol events) | Yes | Yes | Yes |
| `filesystem` (diff on rotate) | Yes, for sandboxes | Emulator virtual FS writes | Hashes only |
| `quarantine` | Yes | YARA tagging (#11) | Hashes and metadata only |
| `process` | No | eBPF/auditd where the runtime allows | No |
| `hook` | Demo app hook (#32) | All instrumented decoys | Yes |
| `dns`, `egress` | Yes | Yes | Yes |

### Event envelope

One JSON object per event, specified in [`schemas/capture-event.schema.json`](../../schemas/capture-event.schema.json) and mirrored by `foiled_core::capture::CaptureEvent`:

`{event_id, ts, decoy_id, catalogue_id, decoy_kind, generation?, channel, severity, src, dst?, payload_ref?, attempt_id?, source, tenant_id, hook?, data}`

- `channel`: `network`, `application`, `filesystem`, `process`, `quarantine`, `hook`, `dns`, `egress`.
- `hook` is present exactly when `channel` is `hook`. Its fields come from #32: `hook_id`, `catalogue_id`, `cve_id?`, `stage` (`trigger`, `post_exploit`, `cleanup`), `request_slice_ref`, `sequence_no`, `t_offset_ms`, `cmd_lines[]`, `file_writes[]`, `implant_refs[]`, `notes`.
- `source` and `tenant_id` are always set by the ingest API from the client certificate; whatever the sender put there is replaced.
- An envelope is at most 16 KB serialised. Request bodies are hashed by default (`store_payloads: false`, #16) and anything larger is referenced.
- Examples: [`testdata/capture/`](../../testdata/capture/). CI validates them against the schema and parses them into the Rust type, so the two cannot drift.

### Queue or R2

| What | Path |
| --- | --- |
| Envelopes (every channel) | `POST /v0/ingest/events` on the mTLS ingest hostname, batches of up to 100, then the `INGEST` Queue. The Queue consumer writes them to Postgres (`capture_events`, idempotent on `event_id`) and adds a counter to Analytics Engine. |
| Pcaps, file diffs, quarantined payloads, request slices over the inline cap | Straight to R2 with a presigned PUT from `POST /v0/uploads`. Never through a Worker request body. The envelope carries `payload_ref`. |

### `payload_ref` and the R2 key layout

`r2://<bucket>/<tenant>/<decoy-id>/<attempt-id or _>/<channel>/<sha256>`

The object key is everything after the bucket. Every segment is checked (no `..`, no slashes, a fixed character set) and the last segment is the object's SHA-256, so an object is content-addressed within its decoy. Ingest refuses an envelope whose `payload_ref` points outside the sender's own tenant and decoy.

### Upload URLs

- Scope: one object, one host. `POST /v0/uploads` checks the decoy is assigned to the calling host or sensor, builds the key from the verified tenant, the decoy, the channel and the SHA-256, and signs a SigV4 PUT for that key only.
- Integrity: the object's SHA-256 is a signed `x-amz-checksum-sha256` header, so R2 rejects a body that does not match the hash in the key.
- Lifetime: 5 minutes. Single PUT up to 5 GiB; multipart above that is not offered yet.
- Credentials: an R2 S3 API token scoped to the evidence bucket, held as Worker secrets (`R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`). Hosts never hold R2 credentials. If the secrets are absent, uploads return 503.

### Quarantine

- Host buffer: `data/quarantine/<sha256>/` with the file and `meta.json` ([schema](../../schemas/quarantine-meta.schema.json), [sample](../../testdata/quarantine/meta.json)). `executed` is always `false`.
- The quarantine directory is never bind-mounted into any decoy, writable or not. Capture artefacts live on host paths outside every guest.
- In R2 the object is private, never given a public URL, and only downloadable through the double-confirm flow in the console (#14), off by default.

### Local buffer and disk caps

On the host, capture writes append-only segments under `data/captures/<decoy-id>/<attempt-id or _>/<channel>/`. Segments are uploaded or sent, then pruned once the API confirms receipt. Default caps: pcap ring of 20 x 100 MB per decoy; at 80 % of the capture volume the host agent stops accepting new decoys and raises `capture_disk_pressure` (#15); at 95 % it stops the oldest pcap captures. Edge sensors use the same layout with the offline buffer rules in #31.

### Retention

R2 objects and Postgres rows follow [privacy and retention](../privacy-and-retention.md) (#16): pcaps 14 days, access logs 30, quarantine files 30 and metadata 90, by the purge job and an R2 lifecycle rule as backstop. Capture rows are append-only; the purge job is the only deleter.

## Consequences

- One envelope for sandbox, emulator, module and edge events; attempts (#25) group them without caring where they came from.
- A host that is compromised can forge events for its own decoys only, and cannot write evidence under another decoy or tenant. Confidence is never taken from event fields (#27).
- Large evidence costs R2 storage but no Worker CPU or request-body limits.
- Process tracing inside Firecracker guests is weak until an in-guest forwarder exists; that gap is recorded.

## Alternatives considered

- **Inline payloads in Queue messages.** Rejected: 128 KB message cap and personal information in every hop.
- **Uploads through a Worker.** Rejected: request body limits and CPU cost for pcaps.
- **In-guest capture agent as the primary source.** Rejected: the guest is hostile and can lie or stop it.
- **Suricata or Zeek inside the guest.** Rejected by #9 constraints; they may run host-side later.

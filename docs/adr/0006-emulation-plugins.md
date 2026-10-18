# ADR 0006: Emulation plug-ins and decoy modules

## Status

Accepted (18 Oct 2026). Issue #30. Related: #5 ([catalogue](../catalogue.md#decoy-kinds), `decoy_kind=emulation`), #3 and [ADR 0002](0002-sandbox-runtime.md) (supervision and isolation), #4 and [ADR 0003](0003-network-isolation.md) (deny-by-default egress), #9 and [ADR 0005](0005-capture-layer.md) (capture envelope), #32 (vulnerable-path hooks), #18 ([fingerprint resistance](../fingerprint-resistance.md)), #17 (canaries), #38 ([licence register](../compliance/licence-register.md)), [landscape reuse plan](../research/landscape.md#reuse-plan).

## Context

Full sandboxes (#3) run real vulnerable software in Firecracker. They are the most convincing decoys and the most expensive: a micro-VM, a pinned image (#6) and a rotation cycle per decoy. They do not scale to every appliance, VPN portal or database an operator wants to watch, and some products cannot be run at all because their firmware is proprietary.

The catalogue (#5) therefore has a second decoy kind, `emulation`, in two shapes:

- **Custom emulators.** Foiled code that fakes enough of one product's banners, routes and opcodes to draw and record exploit attempts.
- **Decoy modules.** Reused open source honeypots (Cowrie, OpenCanary, SNARE and TANNER, and later Heralding, Conpot, SentryPeer, ADBHoney and Dionaea) run as their own containers, as planned in the [landscape reuse plan](../research/landscape.md#reuse-plan).

Both face hostile input from the internet, both must produce the same capture envelope as sandboxes (#9), and neither may change Foiled's MIT licence. The emulators must look real enough to survive a casual fingerprint (#18) without pretending to be complete reimplementations.

## Decision

### Plug-in interface

Custom emulators are Rust plug-ins in the `foiled-emulators` crate (`crates/emulators`, native, Tokio). The issue sketched a Go-style `pkg/emulator/`; the workspace is Rust, so the same shape is a trait:

```rust
pub trait Emulator: Send {
    fn name(&self) -> &'static str;          // matches `plugin` in profiles
    fn profiles(&self) -> Vec<&'static str>; // shipped profile ids
    fn start(&mut self, profile: &Profile, listener: TcpListener, sink: EventSink)
        -> Result<(), EmulatorError>;
    fn stop(&mut self) -> BoxFuture<'_, ()>;  // end every session, release the sink
    fn health(&self) -> Health;               // NotStarted | Serving | Stopped | Failed
}
```

- The supervisor binds the listener and passes it in, so a plug-in never chooses its own ports and never needs bind privileges.
- `start` refuses a profile for another plug-in, a profile that fails validation, and a profile that still holds canary placeholders.
- `stop` closes the listener, aborts open sessions and waits for them. A stopped plug-in cannot be started again: the supervisor builds a fresh one, matching the "never restart in place" rule in ADR 0002.
- `Health::Failed` means the serving task ended without `stop`. The supervisor rotates the decoy with reason `health_failed`; it does not restart it.
- Every emulator shares one accept loop with a session cap (128 per decoy), an idle timeout and back-off on accept errors.

The contract test (`crates/emulators/tests/contract.rs`) drives a fake plug-in and both real plug-ins through the same sequence: start, one request, exactly one `application` envelope that passes `CaptureEvent::problems`, stop, listener closed, sink released, restart refused.

### Events: the `EventSink`

The `EventSink` turns what an emulator sees into `foiled_core::capture::CaptureEvent` envelopes (#9):

- `decoy_kind` is `emulation`, `src` is the peer address (IPv4-mapped IPv6 shown as IPv4) and `dst` is the local address.
- Event ids are `<prefix>-<sequence>`. The prefix is random per start so ids stay unique across restarts; tests pin it so ids are deterministic.
- The queue is bounded and `emit` never blocks. When it is full the event is dropped and counted, so a flood cannot stall a protocol loop.
- Envelopes stay under the 16 KB cap. Emulators clip their own fields (arguments to 256 bytes, paths to 1 KB); the sink drops oversized `data` values and marks the envelope `truncated` as a backstop.
- Request bodies, `SET` values and passwords are stored as SHA-256 and length only, following `store_payloads: false` ([privacy and retention](../privacy-and-retention.md#payload-storage-and-redaction)). Simple markers (`cron_line`, `ssh_key`, `url`, `shell`) record what a stored value looked like without keeping it.
- `write_jsonl` writes envelopes as JSON lines into the per-generation log directory. The host agent tails it, stamps the fields a decoy may not set and ships the envelopes, exactly as for modules (ADR 0002).

### Profiles

Each product persona is a YAML profile under `emulators/<emulator_id>/profiles/<id>.yaml`, validated by [`schemas/emulator-profile.schema.json`](../../schemas/emulator-profile.schema.json) in CI (`foiled-lint`) and by `Profile::problems` for the rules a schema cannot express. Catalogue entries point at it with `artefact.emulator_id` and `artefact.emulator_profile`.

| Field | Meaning |
| --- | --- |
| `id`, `emulator_id`, `plugin` | Profile id (the file stem), the directory under `emulators/`, and the plug-in that serves it. |
| `catalogue_ids` | Catalogue entries that use this profile. A test checks each entry points back. |
| `listen` | Ports, protocol and service. TLS ports set `tls: true`. |
| `tls` | `none`, or `operator_cert`: a TLS frontend on the host terminates with a certificate the operator supplies for a name they control (FR-04). The emulator itself speaks plain TCP. |
| `jitter` | Delay before each reply (FR-17). Defaults to 2 to 15 ms when absent; capped at 2 s. |
| `claimed_cves` | Catalogue CVEs the profile answers for. `claim: illustrative` must use a placeholder id (`CVE-2099-*`, `FOILED-DEMO-*`); `claim: matched` needs a `matcher` (#12) and a `harness`. A real CVE can never be claimed without both. |
| `hooks` | Hook points (#32), below. |
| `canaries` | Canary slots (#17), below. |
| `fingerprint_checks` | Which checklist items from [fingerprint-resistance.md](../fingerprint-resistance.md#checklist) were applied and how they came out. |
| `redis` or `http` | The plug-in's own section: commands, INFO text, config and seed keys for Redis; routes, headers and error pages for HTTP. |

### Shipped plug-ins and example profiles

| Plug-in | Profile | Catalogue entry (draft) | Claimed id |
| --- | --- | --- | --- |
| `redis` | [`emulators/redis/profiles/redis-7.0.yaml`](../../emulators/redis/profiles/redis-7.0.yaml) | [`emulator/redis/7.0`](../../catalogue/entries/emulator/redis/7.0.yaml) | CVE-2099-0001 (illustrative) |
| `http_portal` | [`emulators/ssl-vpn/profiles/portal-generic.yaml`](../../emulators/ssl-vpn/profiles/portal-generic.yaml) | [`emulator/ssl-vpn/portal-generic`](../../catalogue/entries/emulator/ssl-vpn/portal-generic.yaml) | CVE-2099-0002 (illustrative) |

- **`redis`** parses RESP2 multibulk and inline commands and answers `PING`, `ECHO`, `INFO`, `CONFIG GET/SET/RESETSTAT/REWRITE`, `AUTH`, `SET`, `GET`, `KEYS`, `DBSIZE`, `SELECT`, `SAVE`, `BGSAVE`, `FLUSHALL`, `COMMAND`, `QUIT`, `MODULE` and `SLAVEOF`/`REPLICAOF`. `MODULE LOAD` is always refused with Redis's own load-failure error. `SLAVEOF` and `REPLICAOF` are acknowledged and logged; INFO then shows the link as down, and no connection is ever made. `CONFIG SET dir` and `dbfilename` are logged as `high` and fire a hook, and a following `SAVE` records the rewritten path. Credentials never reach an event: `AUTH` is logged as a SHA-256 and length, and other credential arguments (`HELLO ... AUTH`, `MIGRATE ... AUTH`, `CONFIG SET requirepass`, `ACL SETUSER` rules, secret keywords in unknown commands) are masked in `args`, `error`, `config_set` and hook notes, with their hashes in `redacted_args` ([privacy-and-retention.md](../privacy-and-retention.md#payload-storage-and-redaction)). Replies are unchanged.
- **`http_portal`** is a small HTTP/1.1 server with a hand-written parser (no `hyper`). It serves the profile's routes and nginx-style error pages, supports keep-alive and `HEAD`, normalises paths the way nginx does (decoding, merging slashes, refusing `..` above the root) and logs every request, including the ones it refuses. The example persona is a fictional "Gateway Portal": a plain login page, a JSON API that wants a session, an admin area that refuses, a diagnostics endpoint and a stray settings backup. Every path is invented and neutral; no vendor names, logos, assets or vendor-specific paths.

Both entries stay `draft`. They become `verified` only after the emulator host is packaged (#41) and the [staging audit](../fingerprint-resistance.md#staging-audit-procedure) passes.

### How banners and responses are made realistic

Fidelity means the surface a scanner and a first-stage exploit touch, not the product's internals:

1. **Exact version strings.** The banner (`redis_version:7.0.11`, `Server: nginx`, the page title) is copied into the catalogue entry's `banner_hints`, and a test fails if the emulator's output and the entry disagree (FR-05).
2. **One coherent persona.** The Redis profile is the Debian 12 `redis-server` package (`os`, `gcc_version`, `executable`, `config_file`, `/var/lib/redis`), the same release as the Cowrie `debian-openssh` persona, so a host that publishes both tells one story (FR-06). A test checks the kernel string matches the Cowrie persona's.
3. **Real error text.** Unknown commands, wrong arity, `NOAUTH`, `WRONGPASS`, protocol errors, protected-config refusals and module load failures use Redis 7.0 wording; HTTP uses nginx reason phrases, header order and default error pages for 400, 404, 405, 413 and 414 (FR-10). Emulators usually get the success path right and the errors wrong, so the errors are tested byte for byte.
4. **Values that move.** Uptime starts at a random offset (2 to 40 days for Redis) and advances with the clock, `server_time_usec` and `Date` come from the host clock, and counters, process id and run id differ per start (FR-11).
5. **Timing.** Every reply waits a jittered delay, and slow operations stay slow: a failed portal login waits another 180 to 450 ms like a password hash check (FR-17). The checklist describes jitter as optional and off by default; for emulators we turn it on by default with a small range because a constant microsecond reply is a stronger tell than a few milliseconds of delay. Tests set it to zero.
6. **Plausible state.** Seed keys, config values and pages are mundane and synthetic. Nothing names Foiled, a honeypot or a tool (FR-01); tests scan every reply for those words.
7. **Hardened parsing.** Every size is capped (Redis: 64 arguments, 64 KiB bulk strings, 16 KiB inline lines, 512 KiB query buffer, 1024 keys; HTTP: 8 KiB head, 4 KiB request line, 100 headers, 64 KiB bodies by default). Property-style tests feed thousands of arbitrary byte strings, split at arbitrary points, through both parsers and the Redis executor and assert they never panic.

### Fingerprint smoke items applied to the Redis profile

| Item | Result | How it is checked |
| --- | --- | --- |
| FR-01 Mundane text | Pass | No hostname in INFO; INFO, `CONFIG GET *`, `KEYS *` and error replies are scanned for tool and project words. |
| FR-05 Banner matches hints | Pass | `redis_version:7.0.11` from INFO is in the entry's `banner_hints`, and `version` matches. |
| FR-06 One OS story | Pass | `os` is `Linux 6.1.0-18-amd64 x86_64`, the kernel in the Cowrie persona; Debian 12 toolchain and paths. |
| FR-07 Service mix | Accepted tell | One port per emulator. Publish it next to an SSH decoy; that is a placement choice. |
| FR-08 Stack matches OS | Pass | Linux persona on the host's Linux stack. |
| FR-10 Errors match | Pass | Redis 7.0 error wording, asserted byte for byte. |
| FR-11 Uptime and clock | Pass | Uptime at least two days and moving; `server_time_usec` within 2 s of the host clock. |
| FR-17 Timing jitter | Pass | 1 to 12 ms per reply, one delay per pipelined read. A test confirms a configured delay is applied. |
| FR-19 Egress failures | Pass | `REPLICAOF` is acknowledged and INFO reports `master_link_status:down`, as for a firewalled replica. |

These are recorded in the profile's `fingerprint_checks` and asserted in `crates/emulators/tests/repo.rs`. The full audit still runs against a staging decoy before the entry is verified.

### Hook points (#32)

A profile lists hook points with an id, a stage (`trigger`, `post_exploit`, `cleanup`), a severity, an optional claimed CVE id and a match (`on`): Redis matches command words and an argument (`CONFIG SET` with `dir|dbfilename`, `MODULE LOAD`, `SLAVEOF|REPLICAOF`); HTTP matches a normalised path and method (`POST /portal/cgi-bin/diagnostics`). When a request reaches a matching handler, the emulator emits a `hook` envelope alongside the `application` one, with `hook_id`, `catalogue_id`, `cve_id`, a per-session `sequence_no`, `t_offset_ms` since the session started and a short note of the request line. Request bodies are referenced by hash, not copied. A hook never changes the reply.

### Canaries (#17)

A profile declares canary slots (`name`, `kind`) and uses `{{canary.<name>}}` placeholders where the value belongs: a Redis key holding a billing API key, a settings backup in the portal's static directory. Profiles in the repository never hold canary values. At start the supervisor renders per-decoy values from the canary service with `Profile::render`, which fails if a declared slot has no value or a placeholder has no slot, and `start` refuses a profile that still contains placeholders. Reads of a canary route are logged as `high` with the `canary` tag; use of the value anywhere else is the canary service's signal (#17).

### Supervision and egress

Emulators run under the emulation supervisor in ADR 0002: a host process per decoy in a transient systemd unit with a per-decoy UID, systemd sandboxing, two seccomp layers (no `execve`, no process creation after the listeners are bound), Landlock (read-only profile directory, write only to the log directory) and the decoy's own network namespace. Egress is denied by default (#4, [ADR 0003](0003-network-isolation.md)). No code path in `foiled-emulators` opens an outbound connection, so any egress attempt from an emulator namespace is treated as a compromise signal (`egress_blocked`).

### Decoy modules: the manifest

Reused honeypots run one per container, never inside Foiled processes and never inside a sandbox guest (ADR 0002). Each has a manifest at `modules/<module_id>/manifest.yaml`, validated by [`schemas/module-manifest.schema.json`](../../schemas/module-manifest.schema.json) and `ModuleManifest::problems`:

| Field | Meaning |
| --- | --- |
| `protocols`, `ports` | What the module speaks, published ports and the container ports behind them. |
| `personas` | Per-persona banners (must be in the catalogue entry's `banner_hints`), the ports that persona opens, upstream config overrides, and `hostname: identity_store` so no upstream default hostname survives (FR-01, FR-05). |
| `licence`, `licence_files`, `source_offer`, `distribution` | Upstream SPDX id, the licence files kept in any image we build, whether images must offer corresponding source (required for GPL), and `separate_container`, the only allowed value. |
| `image` | Reference and `sha256` digest. `pinned: false` marks a placeholder digest; an entry cannot be verified until it is real. |
| `isolation`, `health` | `runc` or `runsc` (gVisor), and the host-side health probe and failure count. |
| `log`, `event_mapping` | The module's JSON log file, a line cap, and the mapping from its event names and fields to envelope channel, severity and `data` keys, with `sha256` transforms for passwords. Unmapped events are counted and dropped. |

The first manifest is [`modules/cowrie/manifest.yaml`](../../modules/cowrie/manifest.yaml) for the draft [`module/cowrie/2.6`](../../catalogue/entries/module/cowrie/2.6.yaml) entry: BSD-3-Clause, persona `debian-openssh` (SSH only, no Telnet listener), and mappings for `cowrie.session.connect`, `cowrie.client.version`, `cowrie.client.kex`, `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.command.failed`, `cowrie.session.file_download` (to `quarantine`), `cowrie.session.file_upload`, `cowrie.direct-tcpip.request` (to `egress`) and `cowrie.session.closed`. Its image digest is an all-zero placeholder marked `pinned: false` until a reviewed image is pinned. `ModuleManifest::map_line` applies the mapping; tests run sample Cowrie lines through it and check the envelopes.

### Licence boundary

- Foiled core stays MIT. GPL modules (SNARE, TANNER, Heralding, Conpot, SentryPeer, ADBHoney, Dionaea) are never imported, vendored, linked or copied into Foiled source. Foiled starts their images and reads the JSON they write; mappers are written from documented output formats, not from module source.
- Any module image we build and distribute ships the upstream licence text and, for GPL modules, offers the corresponding source, with our patches published under the module's own licence. The schema enforces `source_offer: true` for GPL licences.
- The manifest licence must match the catalogue entry, and both feed the [licence and data-terms register](../compliance/licence-register.md) (#38).

### Non-goals

- **Protocol completeness.** The emulators answer a chosen subset with realistic replies. They are not Redis, not nginx and not any vendor's firmware, and a determined researcher with time will tell. Commands outside the profile get the product's own "unknown command" error.
- **Running attacker input.** No Lua, no module loading, no replication, no shell, no file writes outside the log directory.
- **Claiming real CVEs without proof.** A real CVE needs a documented matcher and a tested harness (#12) before a profile may claim it.
- **Every product family at once.** Appliance portals and collaboration or admin surfaces stay on the backlog.

## Consequences

- Operators get cheap decoys for products that cannot run as sandboxes, with the same envelope, the same hook and canary model and the same rotation rules.
- Adding a persona for an existing plug-in is a YAML change that CI validates. Adding a protocol is a new plug-in that must pass the shared contract test.
- Emulators can be fingerprinted by anyone who goes past the profiled surface. That is accepted; the staging audit and `fingerprint_checks` keep the visible surface honest.
- TLS for `operator_cert` profiles depends on a host-side TLS frontend that is not built yet (#41). Until then a TLS profile is only published behind that frontend.
- Chunked request bodies are refused with 400 by the HTTP plug-in, a known difference from nginx.
- Module decoys depend on upstream release quality and licences. The register and the manifest licence fields keep that visible; pinning by digest keeps upgrades deliberate.

## Alternatives considered

- **Run every product as a sandbox.** Rejected: too costly per decoy, and impossible for proprietary appliances.
- **Embed or vendor open source honeypots.** Rejected: GPL code cannot enter the MIT core, and in-process modules would share Foiled's address space with hostile parsers.
- **Plug-ins as dynamically loaded libraries or scripts.** Rejected: dynamic loading would conflict with the seccomp and `MemoryDenyWriteExecute` rules in ADR 0002, and a scripting runtime is attack surface. Plug-ins are compiled into the pinned emulator host; non-Rust emulators run on the module container path.
- **`hyper` for the HTTP plug-in.** Not needed: a small parser gives full control over nginx-like quirks, error pages and size caps, with less code exposed to hostile input.
- **High-interaction LLM responders.** Deferred to #28 and #32; they are a different risk and cost profile from scripted personas.

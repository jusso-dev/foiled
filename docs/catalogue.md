# Catalogue

The catalogue lists every decoy an operator can launch. One entry says "run product X at version Y, known to be affected by CVE Z" and tells the runtime what to start. The contract is the JSON Schema at [`catalogue/schema/entry.schema.json`](../catalogue/schema/entry.schema.json). Entries live under [`catalogue/entries/`](../catalogue/entries/), one file per entry, and the file path must match the entry `id` (`catalogue/entries/foiled/demo-app/1.0.0.yaml` holds `id: foiled/demo-app/1.0.0`).

The catalogue is curated. It does not claim complete CVE coverage for any product, and an entry listing a CVE means only that the decoy is a plausible target for it, not that every exploit for that CVE will work against it.

## Decoy kinds

`decoy_kind` decides how the decoy runs and what shape `artefact` must take.

| Kind | Artefact shape | Runs as | Owner |
| --- | --- | --- | --- |
| `sandbox` | `image` pinned by `@sha256:` digest, or `recipe_id` under `build/recipes/`, or both. Optional `runtime` (`firecracker` default, `docker` only for labs). | A real build of the software in a Firecracker micro-VM. | #3, #6 |
| `emulation` (custom) | `emulator_id` plus `emulator_profile`. The profile file lives at `emulators/<emulator_id>/profiles/<profile>.yaml`. | A Foiled emulator plug-in supervised by the host agent. | #30 |
| `emulation` (module) | `module_id`, `module_profile` and the upstream SPDX `licence`, optional digest-pinned `image`. The manifest lives at `modules/<module_id>/manifest.yaml`. | A reused open source honeypot (Cowrie, OpenCanary and so on) in its own container. GPL modules are never imported into Foiled code. | #30, #38 |

Module-backed decoys are `emulation` entries rather than a third kind: from the control plane's point of view they behave the same way (lightweight, no guest OS of ours, emit capture envelopes), and the artefact shape is enough to tell them apart. See the reuse table in [the landscape research](research/landscape.md).

## Fields

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Stable slug, for example `foiled/demo-app/1.0.0` or `emulator/redis/7.0`. |
| `product`, `vendor`, `version` | yes | `version_constraint` optional, for example `>=7.0.0, <7.0.12`. |
| `decoy_kind` | yes | `sandbox` or `emulation`. |
| `artefact` | once `verified` | Shape depends on the kind, as above. |
| `cves` | yes (may be empty) | `{cve_id, severity, sources[], auth_requirement?, notes?}`. `sources` are `nvd`, `kev`, `osv`, `vendor` or `synthetic`. Synthetic demo ids use `FOILED-DEMO-NNNN`. |
| `listen_ports` | yes | `{port, protocol, service, tls?}`. The same port and protocol may not appear twice. |
| `default_credentials` | no | Decoy-only values. Replaced by per-decoy canaries at start (#17). Never real secrets. |
| `fingerprint_hints`, `banner_hints` | no | Inputs for realism and the fingerprint checklist (#18). |
| `expected_techniques` | no | ATT&CK ids as priors only (#26). |
| `instrumentation_hooks` | no | Ids of vulnerable-path hooks (#32). Each needs `hooks/<id>.yaml`, see [instrumentation.md](instrumentation.md). |
| `canary_slots` | no | Guest paths rewritten with canary values at start (#17). |
| `sources` | yes | Public advisory, KEV, OSV or NVD links. Links only, never exploit code. |
| `status` | yes | `draft`, `verified` or `deprecated`. |
| `risk_notes` | yes | Why the decoy is useful and any known wormable behaviour. |

## Rules enforced in CI

`foiled-lint` (see [ci.md](ci.md)) runs on every pull request and fails when:

- an entry does not validate against the schema, for example a `sandbox` entry whose artefact only has `emulator_id`, or a `verified` entry with no artefact;
- the entry `id` does not match its file path;
- the artefact shape does not match `decoy_kind`, or the same port is listed twice;
- a `verified` custom emulation entry points at a profile that does not exist, or a `verified` module entry has no module manifest;
- an id in `instrumentation_hooks` has no hook manifest at `hooks/<id>.yaml`.

Draft emulation entries may point at a profile that is still being written. Launching a draft needs an explicit override (#24).

Fixtures that must be rejected live in [`catalogue/testdata/invalid/`](../catalogue/testdata/invalid/) and are exercised by the lint's tests.

## Proposing an entry

1. Copy the closest existing entry and change it. Keep `status: draft`.
2. Link public advisories only. Do not add exploit code, Metasploit modules or proof-of-concept payloads.
3. For `sandbox` entries, add or reuse a recipe under `build/recipes/` (#6). Check the upstream licence allows redistribution.
4. For module entries, record the upstream SPDX licence and check the licence register (#38).
5. Run `cargo run -p foiled-lint -- .` and open a pull request. A maintainer moves the entry to `verified` after review.

CVE sync from public sources is described in [catalogue-sync.md](catalogue-sync.md).

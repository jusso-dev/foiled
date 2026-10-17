# Foiled docs

Start here. New contributors should also read [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md). The roadmap is tracked in [#23](https://github.com/jusso-dev/foiled/issues/23) and the first milestone is the MVP slice, [#22](https://github.com/jusso-dev/foiled/issues/22).

## Available now

| Doc | What it covers |
| --- | --- |
| [mvp-walkthrough.md](mvp-walkthrough.md) | Run the MVP loop: launch, exploit, capture, rotate, export. Lab track runnable today. |
| [attempts.md](attempts.md) | Exploit attempts: grouping, state machine, noise score and the attempts API. |
| [glossary.md](glossary.md) | Terms used across issues, docs and code. |
| [ci.md](ci.md) | CI jobs and how to run the same checks locally. |
| [research/landscape.md](research/landscape.md) | Honeypot, deception and threat intel references that Foiled builds on. |
| [research/lessons.md](research/lessons.md) | Lessons from commercial honeypot platforms. |
| [design/design-direction.md](design/design-direction.md) | Design direction for the operator console. |
| [threat-model.md](threat-model.md) | Containment, egress, breakout and Australian legal and ethical limits. |
| [adr/README.md](adr/README.md) | Architecture Decision Records index, including [ADR 0002](adr/0002-sandbox-runtime.md) on the sandbox and emulation runtime and [ADR 0009](adr/0009-axum-workers-and-front-end.md) on Axum and Workers. |
| [api/control-plane.md](api/control-plane.md) | Control plane API: clients, auth, rules, stores, the OpenAPI contract and the local mock server. |
| [agent/protocol.md](agent/protocol.md) | Host agent protocol: signed jobs, leases, results, heartbeats, evidence and outage behaviour. |
| [catalogue.md](catalogue.md) | Catalogue entry fields, decoy kinds and CI rules. |
| [adr/0006-emulation-plugins.md](adr/0006-emulation-plugins.md) | Emulation plug-ins and decoy modules: the plug-in trait, profiles, hooks, canaries, fingerprint realism and module manifests. |
| [Emulator profile](../schemas/emulator-profile.schema.json) and [module manifest](../schemas/module-manifest.schema.json) schemas | Formats for `emulators/<id>/profiles/*.yaml` and `modules/<id>/manifest.yaml`, checked by `foiled-lint`. |
| [catalogue-sync.md](catalogue-sync.md) | How KEV, OSV and NVD feed draft catalogue entries. |
| [rotation.md](rotation.md) | Rotation and reset of compromised or aged sandboxes, and the decoy lifecycle. |
| [fingerprint-resistance.md](fingerprint-resistance.md) | Fingerprint resistance checklist, known remaining tells and the Shodan Honeyscore self-check runbook. |
| [contribute-back.md](contribute-back.md) | Sharing with DShield, CrowdSec and SentryPeer, delayed public IOCs, opt-in defaults and what is never shared. |
| [deploy/modes.md](deploy/modes.md) | Deployment modes (research, edge, central) and the MVP topology. |
| [deploy/vps.md](deploy/vps.md) | Bringing up a research sensor on a VPS. |
| [instrumentation.md](instrumentation.md) | Vulnerable-path hooks: kinds, manifest, event fields, sandbox and emulator wiring, post-exploit capture and redaction. |
| [attack-mapping.md](attack-mapping.md) | MITRE ATT&CK mapping: the pinned version and update process, mapping rules, the technique link object, and how links feed confidence, STIX export and the console. |
| [enrichment.md](enrichment.md) | Enrichment providers, the Fact schema, the async `foiled-enrich` pipeline and D1 cache, YARA on quarantine, and the never-resell rule. |
| [privacy-and-retention.md](privacy-and-retention.md) | Personal information in capture data, default TTLs, the purge job and metadata-only mode. |
| [deploy/workers.md](deploy/workers.md), [deploy/cloudflare.md](deploy/cloudflare.md), [deploy/cloud-sketch.md](deploy/cloud-sketch.md) | The control plane on Workers, Cloudflare-in-front trade-offs, multi-region sketch. |

## Planned

These docs do not exist yet. Each is owned by the issue listed.

| Path | What it will cover | Issue |
| --- | --- | --- |
| Remaining ADRs | One file per decision under `docs/adr/` (`NNNN-slug.md`). | #28, #31 |
| `docs/deploy/edge-sensor.md` | Enrolling and running an edge sensor. | #31 |
| `docs/radar.md` | Radar feed, review queue and research write-ups. | #35 |
| `docs/compliance/licence-register.md` | Licence and data-terms compliance register. | #38 |

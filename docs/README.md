# Foiled docs

Start here. New contributors should also read [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md). The roadmap is tracked in [#23](https://github.com/jusso-dev/foiled/issues/23) and the first milestone is the MVP slice, [#22](https://github.com/jusso-dev/foiled/issues/22).

## Available now

| Doc | What it covers |
| --- | --- |
| [glossary.md](glossary.md) | Terms used across issues, docs and code. |
| [ci.md](ci.md) | CI jobs and how to run the same checks locally. |
| [research/landscape.md](research/landscape.md) | Honeypot, deception and threat intel references that Foiled builds on. |
| [research/lessons.md](research/lessons.md) | Lessons from commercial honeypot platforms. |
| [design/design-direction.md](design/design-direction.md) | Design direction for the operator console. |
| [threat-model.md](threat-model.md) | Containment, egress, breakout and Australian legal and ethical limits. |
| [adr/README.md](adr/README.md) | Architecture Decision Records index, including [ADR 0009](adr/0009-axum-workers-and-front-end.md) on Axum and Workers. |
| [catalogue.md](catalogue.md) | Catalogue entry fields, decoy kinds and CI rules. |
| [catalogue-sync.md](catalogue-sync.md) | How KEV, OSV and NVD feed draft catalogue entries. |
| [rotation.md](rotation.md) | Rotation and reset of compromised or aged sandboxes, and the decoy lifecycle. |
| [fingerprint-resistance.md](fingerprint-resistance.md) | Fingerprint resistance checklist, known remaining tells and the Shodan Honeyscore self-check runbook. |
| [deploy/modes.md](deploy/modes.md) | Deployment modes (research, edge, central) and the MVP topology. |
| [deploy/vps.md](deploy/vps.md) | Bringing up a research sensor on a VPS. |
| [deploy/workers.md](deploy/workers.md), [deploy/cloudflare.md](deploy/cloudflare.md), [deploy/cloud-sketch.md](deploy/cloud-sketch.md) | The control plane on Workers, Cloudflare-in-front trade-offs, multi-region sketch. |
| [compliance/licence-register.md](compliance/licence-register.md) | Licence and data-terms register for every module, data source and service. |

## Planned

These docs do not exist yet. Each is owned by the issue listed.

| Path | What it will cover | Issue |
| --- | --- | --- |
| Remaining ADRs | One file per decision under `docs/adr/` (`NNNN-slug.md`). | #1, #3, #4, #6, #9, #28, #30, #31, #41 |
| `docs/deploy/edge-sensor.md` | Enrolling and running an edge sensor. | #31 |
| `docs/privacy-and-retention.md` | Data retention and personal information handling. | #16 |
| `docs/agent/protocol.md` | Protocol between the control plane and the sandbox host agent. | #41 |
| `docs/radar.md` | Radar feed, review queue and research write-ups. | #35 |

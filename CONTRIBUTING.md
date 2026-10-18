# Contributing to Foiled

Thanks for helping. Foiled is a public, MIT licensed honeypot platform: it runs pinned, sandboxed copies of vulnerable software and lightweight emulations as decoys, captures exploit attempts and maps them to MITRE ATT&CK, CVEs and public threat actor groups with a confidence layer.

The roadmap and tracking live in the epic, [#23](https://github.com/jusso-dev/foiled/issues/23). The first thing we want working end to end is the MVP slice, [#22](https://github.com/jusso-dev/foiled/issues/22). Start there if you want to know what matters right now.

Before you start, read [SECURITY.md](SECURITY.md) (how to report a containment bug privately), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and the [docs index](docs/README.md). The [glossary](docs/glossary.md) explains the terms used in issues and docs.

## Setup

You need:

- Rust stable, with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`).
- Node 22.22 or later.
- pnpm 10.

You do not need a Cloudflare account, a cloud provider or a public IP address to contribute. You do not need to run honeypots on the public internet. Code, schemas, tests and docs can all be worked on locally against fixtures and example data. Please do not expose a vulnerable decoy to the internet while developing: that is an operator decision with its own legal and containment requirements, covered by the threat model (`docs/threat-model.md`, #2).

## Running checks

CI runs Rust formatting, clippy and tests, a `wasm32` build of the API Worker, front end lint, typecheck, tests and build, schema validation and an offline Markdown link check. [docs/ci.md](docs/ci.md) lists every job and the exact commands to run the same checks locally.

Never skip, weaken or delete a test or check to get a pull request green. Fix the code or the test.

## Language mix

- **Rust** for the control plane and API (Axum on Cloudflare Workers via workers-rs, `crates/api`), shared types (`crates/core`, which must build for `wasm32`) and the sandbox host agent (`crates/hostd`).
- **TypeScript** for the operator front end and the public exploit pages (`web/`, React Router on Workers; the public pages are the same build deployed as a separate Worker, [ADR 0011](docs/adr/0011-public-pages-on-the-web-worker.md)).

Decoys themselves run off Workers, on sandbox hosts driven by the Rust host agent (#41).

## Architecture decisions (ADRs)

Significant design choices are recorded as Architecture Decision Records in `docs/adr/`, one file per decision, named `docs/adr/NNNN-slug.md` (for example `docs/adr/0002-sandbox-runtime.md`). Each ADR has the sections Status, Context, Decision, Consequences and Alternatives considered.

To propose a change to the architecture:

1. Open an issue describing the problem and the options you see.
2. Open a pull request adding a new ADR with the next free number and Status `Proposed`.
3. Once agreed, the Status becomes `Accepted`. If a later ADR replaces it, mark the old one `Superseded by NNNN` rather than deleting it.

Do not reopen an accepted decision inside an unrelated pull request. Write a new ADR instead.

## Issue labels

| Label | Use it for |
| --- | --- |
| `bug` | Something that does not work as documented. |
| `enhancement` | New feature or improvement. |
| `docs` | Documentation only. |
| `security` | Security hardening work that is safe to discuss in public. Exploitable problems go through [SECURITY.md](SECURITY.md), not an issue. |
| `capture` | Capture layer, events, payloads and evidence. |
| `intel` | Enrichment, CVE and ATT&CK mapping, confidence, exports. |
| `infra` | Sandbox hosts, isolation, deployment, CI. |
| `ui` | Operator dashboard and public pages. |
| `research` | Investigation or design work without a code deliverable yet. |
| `epic` | Tracking issue that groups other issues. |
| `blocked` | Waiting on another issue or an outside decision. |

## Branches, commits and pull requests

- One issue per branch and one issue per pull request. Keep changes focused on that issue.
- Commit subjects use the imperative mood and stay short, for example `Add capture event schema`, not `Added` or `Adds`.
- The pull request description says `Closes #N` for the issue it resolves.
- Pull requests are squash merged, so the pull request title becomes the commit on `main`. Make it a good imperative subject.
- CI must pass before merge.

## Writing rules for human-facing copy

These apply to docs, UI text, exports, commit messages and issue text.

- Australian English: organise, behaviour, analyse, catalogue, licence (noun) and license (verb).
- No em dashes. Use a comma, colon or full stop, or reword the sentence.
- No emoji.
- Plain words and a flat tone. Say what a thing does. Avoid hype.
- Be careful with claims. A link between an attempt and a CVE that an analyst has not confirmed is worded "we assess as", for example "we assess as an attempt against `CVE-2099-0001`". A link to a threat actor is worded "possible association". Do not write "confirmed" unless an analyst has confirmed it.
- Legal notes are framed as design constraints the project follows, not legal advice. Point operators to their own counsel.

## Example data rules

- IP addresses in examples, fixtures and tests come from the RFC 5737 documentation ranges only: `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.
- CVE ids in examples are clearly fake, for example `CVE-2099-0001` or `FOILED-DEMO-0001`.
- No real customer data, real attacker captures with personal information, real credentials, tokens, Cloudflare account ids or zone names. Secrets live only in Wrangler secrets or environment variables.

## Licensing

- Foiled core is MIT licensed. See [LICENSE](LICENSE). By contributing you agree your contribution is released under the same licence.
- GPL licensed decoy modules (for example Conpot, SNARE and TANNER, Dionaea, Heralding, SentryPeer and ADBHoney) only ever run as separate container images and are never imported, linked or copied into Foiled source. Those images keep their upstream licences.
- Check the [licence and data-terms register](docs/compliance/licence-register.md) before adding a module, data source or dependency.
- Threat intel sources used for enrichment (for example GreyNoise, CrowdSec, DShield, Shadowserver and Hunt.io) are enrichment only. Their data is never resold or republished. Respect each source's terms.
- If you add a dependency, check its licence is compatible with MIT and mention it in the pull request.

## Proposing a catalogue entry

A catalogue entry describes one decoy: a product at a pinned version, whether it runs as a real `sandbox` or an `emulation`, and which CVEs it is believed to be affected by. The schema is defined in #5 (planned path `catalogue/schema/entry.schema.json`, entries under `catalogue/entries/`).

1. Open an issue with the `enhancement` label naming the product, version, `decoy_kind` and the CVE ids with public sources (NVD, CISA KEV, OSV or the vendor advisory).
2. Say why the decoy is useful (for example, active exploitation listed in KEV) and note any known wormable or self-propagating behaviour.
3. Explain how the artefact is obtained: an OCI image pinned by digest or a build recipe for `sandbox` entries, or an emulator profile for `emulation` entries (#30). The software must be legally redistributable or buildable by the operator.
4. Open a pull request adding the entry with `status: draft`. CI validates it against the schema. A maintainer reviews and tests it before it moves to `verified`.

Default credentials in an entry must be canary-friendly values, never real secrets. The catalogue is curated: we do not claim complete CVE coverage.

## Questions

Open an issue with the `research` label, or comment on the relevant issue.

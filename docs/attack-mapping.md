# ATT&CK mapping

How Foiled maps exploit attempts (#25) to MITRE ATT&CK techniques and sub-techniques (#26), which ATT&CK version it pins, and how the resulting links feed confidence (#27), export (#13) and the console (#14).

CVE links (#12) say what was weak. ATT&CK links say what the attacker appeared to do. Both sit on the same attempt and both go through the same confidence layer, so operators and exporters share one technique vocabulary.

## Pinned version

ADR-style record for the ATT&CK edition and version Foiled uses.

### Status

Accepted (18 Oct 2026). Issue #26. Review on every ATT&CK release (see [Update and review](#update-and-review)).

### Context

ATT&CK changes twice a year or so. Techniques are renamed, split into sub-techniques, moved between tactics, revoked or deprecated. If Foiled tracked "latest" silently, a link written in March could point at a different technique by October, exports would disagree with the console, and rule authors would not know which ids are valid. Sub-techniques matter: `T1059.004` (Unix Shell) says much more than `T1059`.

The full Enterprise STIX bundle is about 47 MB. Committing it would bloat the repository and make it easy to edit MITRE content by accident. MITRE's terms allow copies only when the copyright designation and licence travel with them.

### Decision

| Item | Value |
| --- | --- |
| Domain | Enterprise ATT&CK only. ICS and mobile are out of scope until a decoy needs them. |
| Version | ATT&CK v20.0, released 13 Oct 2026 |
| Source | `enterprise-attack/enterprise-attack.json` at tag `ATT&CK-v20.0` in the [mitre/cti](https://github.com/mitre/cti) repository (STIX 2.0) |
| Size | 49,253,343 bytes |
| SHA-256 | `66f3fe3f07ef1a2de0bd2fe4b3e8a9ea06c1d0bb2c46171bdbb57c7f7b666524` (the same digest GitHub reports for the `enterprise-attack.json` release asset) |
| Version record | [`data/attack/VERSION`](../data/attack/VERSION) holds `20.0` |
| Digest record | [`data/attack/SHA256`](../data/attack/SHA256) |
| Fetch | [`scripts/fetch-attack.sh`](../scripts/fetch-attack.sh) downloads the bundle by tag into `target/attack/` (git-ignored) and refuses it unless the SHA-256 matches |
| What ships | [`data/attack/techniques.json`](../data/attack/techniques.json), a small sidecar holding only the techniques our rules and catalogue priors reference |

v20.0 is the newest release. Every technique Foiled uses was checked against it with `scripts/fetch-attack.sh --check`: none is revoked or deprecated, and names, tactics and STIX ids in the sidecar match the bundle.

The sidecar holds, per technique, `id`, `name`, `tactics` and `stix_id` copied unchanged from the bundle, plus `url`, which is MITRE's page for the pinned major version (`https://attack.mitre.org/versions/v20/techniques/T1059/004/`). Parents of every sub-technique are included so the console can always name both. The file also carries MITRE's notice and licence (see [Licence and notices](#licence-and-notices)).

The fetch script is a maintainer tool. It is never run in CI and exits if `CI` is set. CI only reads the committed sidecar and stays offline.

### Consequences

- Rules, links and exports all name one version. Every stored link records `attack_version`, so old links stay interpretable after a bump.
- Adding a rule for a technique not in the sidecar fails `cargo test` until the technique is added from the pinned bundle.
- The repository holds a few kilobytes of MITRE content, not 47 MB, and never a modified copy of the bundle.
- Bumping the version is a reviewed pull request, not a silent change.
- Features that need the full bundle (a full heatmap of every technique, mitigation text) must fetch it with the script, or a build step that does the same check, rather than relying on the sidecar.

### Alternatives considered

- **Commit the full bundle.** Simple lookups, but a 47 MB blob in every clone, noisy diffs on each bump and an easy path to silent edits. Rejected.
- **Track "latest" at runtime.** No pin, so ids drift under existing links and exports. Rejected.
- **Use the STIX 2.1 bundles from mitre-attack/attack-stix-data.** A reasonable later switch, since #13 exports STIX 2.1. Today we only use ids, names, tactics and STIX ids. If we switch, verify the attack-pattern ids match before changing the source, and record the switch as a version bump.
- **Pin v19.2 and wait for v20 to settle.** v20.0 already holds every id we use unchanged, so waiting buys nothing. A later point release is a normal bump.

## What lives where

| Path | What it is |
| --- | --- |
| [`data/attack/VERSION`](../data/attack/VERSION) | Pinned ATT&CK version. |
| [`data/attack/SHA256`](../data/attack/SHA256) | SHA-256 of the pinned `enterprise-attack.json`. |
| [`data/attack/techniques.json`](../data/attack/techniques.json) | Curated sidecar with MITRE's notice and licence. |
| [`scripts/fetch-attack.sh`](../scripts/fetch-attack.sh) | Fetch and verify the pinned bundle; `--check` compares the sidecar with it. |
| [`rules/attack/`](../rules/attack/) | Mapping rules, one per file. |
| [`schemas/attack-rule.schema.json`](../schemas/attack-rule.schema.json) | Rule schema, enforced by `foiled-lint`. |
| [`schemas/technique-link.schema.json`](../schemas/technique-link.schema.json) | Attempt to technique link schema. |
| [`crates/core/src/attack.rs`](../crates/core/src/attack.rs) | Rule types, `validate`, `evaluate`, link and sidecar types. Pure, builds for wasm32. |
| [`testdata/attack/`](../testdata/attack/) | Demo attempt envelopes (validated against the capture schema). |
| [`testdata/technique-links/`](../testdata/technique-links/) | Example stored link. |
| [`crates/lint/tests/attack.rs`](../crates/lint/tests/attack.rs) | Loads every rule, checks ids against the sidecar and runs the rules over the demo attempts. |

## Licence and notices

ATT&CK is © The MITRE Corporation and is used under MITRE's [terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), which grant a non-exclusive, royalty-free licence for research, development and commercial use provided MITRE's copyright designation and the licence are reproduced in any copy. Rules the project follows (design constraints, not legal advice; operators should ask their own counsel):

- The sidecar carries MITRE's copyright designation in `notice` and the licence grant in `licence`, with `licence_url`. A unit test fails if the notice is missing.
- Any export that includes ATT&CK names or objects (#13) carries the same notice.
- ATT&CK content is never edited. Names, tactics and ids in the sidecar are byte-for-byte copies from the pinned bundle, and `--check` proves it. Foiled's own notes about a technique (why a rule exists, known false positives) live in the rule files or in this doc, never in the sidecar and never in a copy of the bundle.
- "MITRE ATT&CK" and "ATT&CK" are MITRE trademarks. Foiled says it maps to ATT&CK; it does not claim MITRE endorsement.
- The full bundle is fetched, not redistributed.

## Update and review

When MITRE publishes a release:

1. A maintainer reads the release notes for renamed, moved, revoked or deprecated techniques that the sidecar or any rule uses (`rules/attack/`, catalogue `expected_techniques`).
2. Update `data/attack/VERSION`, put the new file's SHA-256 in `data/attack/SHA256` (cross-check it against the digest GitHub shows for the release asset), and run `scripts/fetch-attack.sh --check` locally.
3. Regenerate or hand-update `data/attack/techniques.json` from the fetched bundle: new `attack_version`, the versioned `url`s, and any name or tactic changes copied exactly. Run `--check` again until it reports a match.
4. If a technique was revoked or split, update the affected rules to the replacement id, and say so in the pull request.
5. Run `cargo test --workspace` and `cargo run -p foiled-lint -- .`. The lint test fails if any rule or catalogue prior names an id missing from the sidecar.
6. A second maintainer reviews the pull request. Existing links keep their recorded `attack_version`; they are not rewritten.

Adding a technique without a version bump follows steps 3 and 5 only: copy the entry from the pinned bundle, never from memory or the website.

## Rule-based mapping is primary

Technique links come from deterministic rules over capture evidence. The same events and rules always give the same links.

- **Rules** in `rules/attack/*.yaml` are the only thing that creates links in this layer.
- **Catalogue priors.** A catalogue entry may list `expected_techniques[]` ([catalogue.md](catalogue.md)) when an exploit chain is well known. They are evidence with source `catalogue_prior` for #27, never proof, and never create a link on their own.
- **LLM suggestions** go through the LLM worker (#28) and arrive at the confidence layer (#27) as evidence with source `llm`, hard-capped so they cannot alone reach `high`. They are not rules and never write to `rules/attack/`. In the heatmap, LLM-only techniques are hatched ([design-direction.md](design/design-direction.md)).
- **Analysts** confirm or reject links through #27 overrides, which are audited.

## Rules

A rule maps conditions over one capture envelope ([ADR 0005](adr/0005-capture-layer.md), [`schemas/capture-event.schema.json`](../schemas/capture-event.schema.json)) to one official technique id. One rule per file; the file name equals the `id`.

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | `^[a-z0-9][a-z0-9.-]*$`, equal to the file name. |
| `technique` | yes | Official id from the pinned version, technique (`T1105`) or sub-technique (`T1059.004`). Must be in the sidecar, and so must its parent. |
| `weight` | yes | Signal strength 0 to 100 for #27. Not a confidence score. |
| `evidence_summary` | yes | One line for the evidence list. |
| `description` | no | Why the rule exists and its known false positives. |
| `channels` | no | The event's `channel` must be one of these. |
| `all` | one of `all`/`any` | Every condition must hold. |
| `any` | one of `all`/`any` | At least one condition must hold. |

A condition is `{field, <operator>, ignore_case?}` with exactly one operator:

| Operator | Holds when |
| --- | --- |
| `equals: s` | A value equals `s`. |
| `contains: s` | A value contains `s`. |
| `prefix: s` | A value starts with `s`. |
| `contains_any: [..]` | A value contains any needle. |
| `prefix_any: [..]` | A value starts with any needle. |
| `exists: true/false` | The field is present and not null (or absent). |

Fields: `channel`, `decoy_kind`, `catalogue_id`, `severity`, `hook.hook_id`, `hook.catalogue_id`, `hook.cve_id`, `hook.stage`, `hook.cmd_lines`, `hook.file_writes`, `hook.implant_refs`, `hook.notes`, and `data.<key>` (dotted for nested objects). List fields match when any element matches; numbers and booleans compare as their JSON text. A missing field never matches except `exists: false`. There is no regex: needles are plain strings so rules stay cheap on Workers and cannot blow up on hostile input. Empty needles are rejected because they would match everything. `ignore_case` compares ASCII case-insensitively. YAML anchors may share needle lists between conditions.

Example ([`rules/attack/t1059-004-hook-shell.yaml`](../rules/attack/t1059-004-hook-shell.yaml), shortened):

```yaml
id: t1059-004-hook-shell
technique: T1059.004
weight: 80
evidence_summary: Unix shell command ran after the vulnerable path fired
channels: [hook]
all:
  - field: hook.stage
    equals: post_exploit
  - field: hook.cmd_lines
    contains_any: ["sh -c", "bash -c", "| sh", "|sh"]
```

### Shipped rules

| Rule | Technique | Signal | Weight |
| --- | --- | --- | --- |
| `t1190-hook-trigger` | T1190 Exploit Public-Facing Application | A #32 hook fired at stage `trigger`. | 85 |
| `t1190-matcher-hit` | T1190 | `data.matcher_id` set by a #12 signature match. | 55 |
| `t1059-004-hook-shell` | T1059.004 Unix Shell | Post-exploitation hook `cmd_lines` invoke a shell or pipe into one. | 80 |
| `t1059-004-module-shell-input` | T1059.004 | Command typed into Cowrie's emulated shell (intent, not real execution). | 50 |
| `t1505-003-web-root-write` | T1505.003 Web Shell | Hook or filesystem write under a web root or app code directory. | 70 |
| `t1105-egress-download` | T1105 Ingress Tool Transfer | GET through the egress proxy, allowed or blocked ([ADR 0003](adr/0003-network-isolation.md)). | 60 |
| `t1105-hook-download` | T1105 | `curl`, `wget`, `tftp` or `ftpget` in hook `cmd_lines`. | 55 |
| `t1071-001-egress-http-post` | T1071.001 Web Protocols | HTTP POST out through the egress proxy, possible C2 check-in. | 35 |
| `t1053-003-cron-write` | T1053.003 Cron | Write to `/var/spool/cron`, `/etc/cron.d/`, `/etc/crontab` and similar. | 75 |
| `t1053-003-redis-config-dir` | T1053.003 | Redis `CONFIG SET dir` to a cron directory. | 70 |
| `t1496-001-miner-strings` | T1496.001 Compute Hijacking | `xmrig` or `stratum+tcp://` style strings in commands, arguments or URLs. | 70 |
| `t1082-system-info` | T1082 System Information Discovery | `uname -a`, `cat /proc/cpuinfo` and similar. | 40 |
| `t1083-file-discovery` | T1083 File and Directory Discovery | `ls -la`, `find /`. | 25 |
| `t1046-scanner-tools` | T1046 Network Service Discovery | `nmap`, `masscan` or `zmap` run from the decoy. | 50 |
| `t1110-001-ssh-login-failed` | T1110.001 Password Guessing | Failed SSH or Telnet login on Cowrie, one signal per failure. | 30 |

Miner activity maps to the sub-technique T1496.001 rather than T1496, because the pinned version splits Resource Hijacking and mining is compute hijacking.

### Evaluation

`foiled_core::attack::evaluate(rules, events)` runs every rule over one attempt's events and returns one `TechniqueLink` per technique or sub-technique:

- Links are deduplicated by official id and ordered by technique then sub-technique.
- Each link lists every `{rule_id, event_id, weight, summary}` that fired, ordered by event time, event id and rule id. A duplicated envelope counts once. `max_weight` is the largest signal weight.
- A malformed rule (bad technique id, no conditions, two operators in one condition, unknown field, empty needle) never matches. `validate(rules, known_ids)` reports these, plus duplicate ids, weights above 100 and ids missing from the sidecar. Callers must refuse a rule set with problems; the lint test enforces this for the shipped rules.
- `T1059` and `T1059.004` are separate links if separate rules name them. Rules should name the most specific id the evidence supports.

### Demo fixtures

[`testdata/attack/`](../testdata/attack/) holds three demo attempts. CI checks that the shipped rules map them as follows:

| Attempt | Events | Techniques |
| --- | --- | --- |
| `atm-demo-1` (sandbox, demo app) | Signature hit, hook trigger writing to `/app/`, post-exploitation shell with `curl ... \| sh`, blocked egress GET and POST | T1059.004, T1071.001, T1082, T1083, T1105, T1190, T1505.003 |
| `atm-redis-1` (Redis emulator) | `CONFIG SET dir /var/spool/cron`, a cron line launching a miner, `CONFIG SET dbfilename` | T1053.003, T1496.001 |
| `atm-ssh-1` (Cowrie) | Two failed logins, system discovery, a `masscan` run | T1046, T1059.004, T1082, T1110.001 |

The issue's validation case, a post-exploitation hook with a shell exec producing a `T1059.004` link, is tested in both `crates/core` and `crates/lint/tests/attack.rs`, and the expected stored link is [`testdata/technique-links/demo-unix-shell.json`](../testdata/technique-links/demo-unix-shell.json).

## Link object

Stored links follow [`schemas/technique-link.schema.json`](../schemas/technique-link.schema.json) (`foiled_core::attack::AttemptTechniqueLink`):

```json
{
  "attempt_id": "atm-demo-1",
  "attack_version": "20.0",
  "technique_id": "T1059",
  "subtechnique_id": "T1059.004",
  "matched_signals": [
    { "rule_id": "t1059-004-hook-shell", "event_id": "atk-demo-03", "weight": 80,
      "summary": "Unix shell command ran after the vulnerable path fired" }
  ],
  "max_weight": 80,
  "confidence_ref": "conf-0001"
}
```

- `technique_id` is always the parent technique; `subtechnique_id` is set when the rule named a sub-technique. Both are official ids from `attack_version`.
- `matched_signals` is never empty.
- `confidence_ref` points at the #27 record once the link is scored. Until then it is absent and the link is not shown as asserted.
- Links are re-evaluated when an attempt gains events. Rule changes apply to new evaluations; existing links keep the evidence they were scored on.

### Feeding confidence (#27)

Each link becomes an #27 link of kind `attempt_technique`. Each matched signal becomes one evidence item:

| #27 evidence field | From |
| --- | --- |
| `signal_id` | `attack:<rule_id>:<event_id>` |
| `source` | `rule` |
| `weight` | The rule's `weight` |
| `summary` | The rule's `evidence_summary` |
| `ref` | `event_id` |

Catalogue priors add `catalogue_prior` evidence and LLM suggestions add `llm` evidence to the same link. #27 owns the score, band and thresholds; `max_weight` is an input, not the score. Noise score evidence from #25 applies to technique links as it does to CVE links.

### Export as STIX (#13)

Published links (score at or above `publish_min` in #27) export as STIX 2.1 objects:

- An `attack-pattern` object with the sidecar's `stix_id` as its id, the technique `name`, and `external_references` of `{source_name: "mitre-attack", external_id, url}`. Sub-techniques use the sub-technique's own object. Bundles that include ATT&CK names carry MITRE's notice.
- A `relationship` from the attempt's exported object (as #13 defines it) to the `attack-pattern`, with `confidence` from #27 and a description that names the ATT&CK version and summarises the matched signals.
- Links below `publish_min`, or carried only by LLM or catalogue prior evidence, are not exported.

### Console (#14)

Attempt detail shows one chip per link: the official id in mono (for example `T1059.004`), the sidecar name, and the tactic on hover. Each chip links to the sidecar `url`, MITRE's page for the pinned version, so the page matches the id even after a later version renames it. Chip styling and the confidence word follow [design-direction.md](design/design-direction.md); the ATT&CK heatmap uses the same links and hatches LLM-only cells.

## Limits

- Emulated shells (Cowrie, Redis emulator) show intent. Weights are lower than for sandbox hooks, and the evidence summary says so.
- Scanners and shared kits trip the same signals as targeted attackers (see [lessons.md](research/lessons.md)). Weights are signal strengths, not verdicts; #27 combines them with the noise score.
- Links say what an attempt appeared to do. They are not attribution: actor and group association is #29.
- Rules do not replace CVE matchers (#12) and there is no trained classifier.

## Related

- #12 CVE mapping tiers (`docs/exploit-attribution.md`, planned): CVE links on the same attempt and the `data.matcher_id` signatures.
- #25 Attempts (`docs/attempts.md`, planned): the object links hang off.
- #27 Confidence (`docs/confidence.md`, planned): scoring, thresholds, overrides.
- #28 LLM worker: the only path for LLM technique suggestions.
- #13 Intel outputs (`docs/intel-outputs.md`, planned): STIX `attack-pattern` relationships.
- #14 Console: technique chips and heatmap.
- #32 Vulnerable-path hooks: `hook.stage`, `cmd_lines` and `file_writes`.
- [ADR 0005](adr/0005-capture-layer.md) capture envelope, [catalogue.md](catalogue.md) `expected_techniques`, [landscape.md](research/landscape.md) for outside ATT&CK sources used as a cross-check.

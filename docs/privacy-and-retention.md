# Privacy and retention

Status: Policy and purge planner in place. The purge cron and the API behaviour after purge land with the data layer. Owner: #16.

Related: threat model ([threat-model.md](threat-model.md)), capture layer and R2 key layout (#9), YARA and enrichment (#11), intel exports (#13), operator UI and quarantine download (#14), control API (#21), attempts (#25), LLM correlation and AI Gateway logging (#28), radar and contribute-back (#35, #37), host agent (#41).

Config: [configs/retention.yaml](../configs/retention.yaml), validated in CI against [schemas/retention-config.schema.json](../schemas/retention-config.schema.json). Purge planner: [crates/core/src/retention.rs](../crates/core/src/retention.rs).

**This is operator policy language, not a legal opinion.** It describes what Foiled does by default and the knobs it gives you. It does not tell you what the law requires of you. IP addresses and payloads may be personal information under the Privacy Act 1988 (Cth). Whether and how that Act, or any other law, applies to you depends on who you are and what you do with the data. Get your own advice before you expose a decoy or change these defaults.

## Contents

- [What Foiled holds and why it matters](#what-foiled-holds-and-why-it-matters)
- [Principles](#principles)
- [Default retention](#default-retention)
- [Payload storage and redaction](#payload-storage-and-redaction)
- [Metadata-only mode](#metadata-only-mode)
- [Purge job](#purge-job)
- [R2 lifecycle rules as a second layer](#r2-lifecycle-rules-as-a-second-layer)
- [Legal holds](#legal-holds)
- [Exports after purge](#exports-after-purge)
- [Copies the purge job does not reach](#copies-the-purge-job-does-not-reach)
- [Access and encryption](#access-and-encryption)
- [Operator checklist](#operator-checklist)
- [What Foiled does not do](#what-foiled-does-not-do)
- [Test plan](#test-plan)
- [Future expansion](#future-expansion)

## What Foiled holds and why it matters

A decoy records whatever is sent to it. That includes:

- **Source IP addresses**, ports, timing and user agents. An IP address can identify, or help identify, a person, for example a home connection or a compromised device whose owner has no idea it is scanning.
- **Request bodies and payloads.** Attackers send credentials they have harvested elsewhere, web shells holding stolen data, and dropper scripts with other victims' hostnames in them. Some of that is personal information about people who are not the attacker.
- **Attempted credentials** on login decoys. These are often real leaked username and password pairs.
- **Files written to the decoy** (quarantine), filesystem diffs, packet captures and, after some rotations, forensic snapshots (#8).

So capture data may be personal information under the Privacy Act 1988 even though it was sent by an attacker. The [threat model](threat-model.md#legal-and-ethical-limits-australia) sets out the design constraints that follow. This document turns them into defaults.

## Principles

1. **Minimise by default.** Store hashes of request bodies, not the bodies. Keep raw evidence for days or weeks, not forever.
2. **Keep the summary, drop the raw.** Attempt rows, IOCs and quarantine metadata outlive the pcaps and payload bytes they came from.
3. **Private storage only.** Evidence lives in a private R2 bucket with no public URL, behind the control API (#9, #21).
4. **The operator owns the data.** Nothing in this document sends capture data, retention data or audit records anywhere outside the operator's own accounts.
5. **Every deletion is accounted for.** Each purge run writes an audit record with counts, never the deleted content.

## Default retention

TTLs are whole days counted from when the control plane received the item (or R2 stored the object), not from the host's clock. `0` means "delete at the next purge run".

| Data class (`ttl_days` key) | Where it lives | Default | Why |
| --- | --- | --- | --- |
| Packet captures (`pcap`) | R2 | 14 days | The bulkiest and most intrusive record (full packets, including bodies). Two weeks covers triage, a weekly review and a second look; anything worth keeping is extracted into attempt rows and IOCs first. |
| Access logs (`access_log`) | R2, summarised into Postgres | 30 days | IPs, paths, status codes and user agents, no bodies. A month is enough to see repeat sources and short campaigns. |
| Filesystem diffs (`fs_diff`) | R2 | 30 days | Shows what an attacker changed on rotate (#8). Same window as access logs, so one rotation's evidence ages out together. |
| Quarantine files (`quarantine_file`) | R2 | 30 days | Payload bytes can hold stolen data. A month gives YARA (#11) and an analyst time to look; the hash stays. |
| Quarantine metadata (`quarantine_meta`) | Postgres | 90 days | Hash, size, type, YARA hits, first and last seen, no bytes. Lets you recognise a returning payload after the bytes are gone. |
| Enrichment cache (`enrichment_cache`) | Postgres or D1 (#11) | 7 days, or per provider | Reputation goes stale, and a cached lookup should not drive confidence (#27) for long. Set a shorter per-provider TTL where a provider's terms ask for it. Enrichment is never resold or republished. |
| Attempts and sessions index (`attempt`) | Postgres | 90 days | Attempt rows and their capture event rows hold source IPs. One quarter covers campaign clustering (#33) and trend questions. Long-term counts survive as rollups without IPs (#35). |
| Forensic snapshots (`forensic_snapshot`) | Separate private R2 bucket | 7 days | Memory and disk images are the most intrusive data Foiled can hold. Rotation (#8) keeps them shorter than ordinary evidence: pull what you need in the first week. |
| Export bundles (`export_bundle`) | R2 | 1 day | Bundles are copies. Keeping them a day stops them outliving their sources by more than that; regenerate from live rows instead. |
| Audit log (`audit`) | Postgres | 365 days | See below. |

**Why the audit log keeps a year.** The audit log is how you answer "who looked at this, who deleted what, and when" long after the evidence is gone, for example when a complaint, an access request or an incident review arrives months later, or at an annual review. Purge records hold counts only, so a long TTL costs little privacy. Other audit rows can carry operator identities and free-text reasons that may themselves be personal information (rotation reasons, forensic read reasons), which is why it is a year and not forever. The planner never lets the audit TTL drop below 30 days, so a purge cannot delete its own record straight away, and the schema rejects lower values.

## Payload storage and redaction

`store_payloads: false` is the default.

- **Request bodies are hashed.** For HTTP and protocol requests the capture layer stores a SHA-256 of the body, its length and content type, not the body. CVE matchers and vulnerable-path hooks (#12, #32) run on the body in flight, before it is dropped, so detection does not depend on keeping it.
- **Quarantine still happens.** Files an attacker writes to the decoy are the core malware evidence, so they are still quarantined under the `quarantine_file` TTL. Set that TTL to `0` if you want none kept.
- **Pcaps still contain bodies.** Turning payload storage off does not strip packet captures. Use a short pcap TTL, a short snap length on the host (see [deploy/vps.md](deploy/vps.md#pcap-disk-caps)), or metadata-only mode.
- **The LLM sees redacted text.** Correlation (#28) sends hashes and short redacted extracts through AI Gateway, with gateway logging and caching off ([llm-correlation.md](llm-correlation.md#redaction-rules)). Payload bytes never go to a provider.

Set `store_payloads: true` only with a reason you can explain, for example a time-boxed investigation. Full bodies then follow the TTL of the class that holds them.

## Metadata-only mode

For operators who want detection and trends without holding raw evidence:

1. Set the raw-evidence TTLs to `0`: `pcap`, `fs_diff`, `quarantine_file`, `forensic_snapshot` and `export_bundle`. Set `access_log` to `1`. The commented example at the bottom of [configs/retention.yaml](../configs/retention.yaml) is the full block and is tested in CI.
2. Keep `store_payloads: false`.
3. Set a short snap length (for example `-s 256`) on the host capture units so pcaps hold headers only even before upload.

What remains: attempt rows, IOCs, quarantine hashes and metadata, enrichment cache and the audit log, each under its own TTL. Raw evidence is uploaded, used for detection and gone at the next purge run. If you run the purge hourly, raw evidence lives at most about an hour in R2, plus however long the host buffer takes to upload.

## Purge job

The purge job is a **Workers cron trigger** on the control plane (ADR 0001 lists it as "Cron Worker for D1, Postgres and R2"). It calls the purge planner, `plan_purge` in [crates/core/src/retention.rs](../crates/core/src/retention.rs), which decides what has expired. The planner is pure: it takes the current time as a parameter, so it builds for wasm32 and is tested with a fixed and a skewed clock. The cron wiring in `crates/api` lands with the data layer; it is not in this change. An hourly schedule is a sensible starting point.

Each run:

1. **Loads the policy** (`configs/retention.yaml`). If `purge.enabled` is `false`, it writes an audit record saying so and stops.
2. **Lists candidates** from each store:
   - **Postgres:** attempt and session rows, capture event rows, quarantine metadata, enrichment cache rows and audit rows older than the shortest relevant cutoff.
   - **R2:** objects under `<tenant>/<decoy-id>/<attempt-id>/<channel>/<sha256>` (the #9 key layout, without the `r2://<bucket>/` part). The channel segment maps to a data class (network to `pcap`, application and hook to `access_log`, filesystem to `fs_diff`, quarantine to `quarantine_file`). Forensic snapshots use the forensics bucket layout from #8. Export bundles use their own prefix.
   - **D1:** any table holding capture-derived data, such as the enrichment cache if #11 puts it there.
3. **Plans.** `plan_purge(config, now_ms, items)` returns the keys to delete, counts per class, how many expired items were kept for a legal hold, and how many items were future-dated.
4. **Deletes, unless `purge.dry_run` is `true`.** R2 objects first, by key in batches, or by prefix `<tenant>/<decoy-id>/<attempt-id>/<channel>/` when a whole channel of an attempt has expired. Then rows that point at them are marked as evidence-purged, and finally expired rows are deleted. Doing evidence before index means a failure part way leaves rows pointing at missing objects (the API returns 404 for those), never orphaned objects nobody can find.
5. **Writes one audit record** (`retention.purge`) with `dry_run`, total planned, counts per class, `kept_for_hold`, `future_dated`, failures per store, and start and finish times. It never records keys, IPs, hashes or content. `PurgePlan::summary()` produces exactly this shape.

Runs are idempotent. A run that hits the 15 minute cron wall time (ADR 0009) stops, records what it did, and the next run picks up the rest.

**Dry run.** `purge.dry_run: true` is the shipped default so a new install only reports for its first runs. A dry run does steps 1 to 3 and 5, deletes nothing, and the audit record says `dry_run: true` with the counts it would have deleted. Read a few of those, then set `dry_run: false`.

**Disabling purge.** `purge.enabled: false` stops all purging (for example during an incident). It does not stop R2 lifecycle rules (next section).

**Clock skew.** Hosts and edge sensors stamp events with their own clocks, which can be wrong. TTLs should run from a trusted time: the control plane's receipt time for rows, and R2's upload time for objects. Where only a host or sensor timestamp is available (for example an event replayed from an offline buffer, #31), it may be ahead of the control plane. If an item's creation time is still in the future when the purge runs, the planner treats it as **not expired**, never deletes it on that run, and counts it in `future_dated`. A non-zero `future_dated` count in the audit log means a clock is wrong somewhere and should be fixed. Retention is never shortened by skew: a future-dated item keeps its full TTL from its stamp.

## R2 lifecycle rules as a second layer

The cron is the primary mechanism. R2 object lifecycle rules are a blunt backstop in case the cron is broken, disabled or misses a key it does not recognise.

- On the evidence bucket, add a rule that deletes objects older than the longest R2-held TTL plus a margin. With the defaults that is 30 days plus 7, so **37 days**. On the forensics bucket, 7 plus 7, so **14 days**. Raise the rule if you raise a TTL.
- Add a rule that aborts incomplete multipart uploads after 1 day.
- The #9 keys start with the tenant, so a lifecycle rule cannot target one channel by prefix. If you want per-class lifecycle rules, give each class its own bucket or a class prefix. That is an operator choice; Foiled does not require it.
- Lifecycle rules do not know about legal holds or `purge.enabled`. See [Legal holds](#legal-holds).
- If you use R2 bucket lock rules on the forensics bucket (#8), the lock period must be shorter than `forensic_snapshot`, or the purge job's deletes fail. Failures show up in the purge audit record.

## Legal holds

Foiled's legal hold is deliberately simple: **stop purging one decoy, or raise the TTL.** A fuller holds workflow is out of scope.

- Add the decoy id to `legal_holds` in [configs/retention.yaml](../configs/retention.yaml). The planner keeps every expired item tagged with that decoy and counts it in `kept_for_hold`. Items with no decoy (such as the enrichment cache) are unaffected.
- Or raise the relevant TTLs for everyone, if the hold is broad.
- Raise or remove the R2 lifecycle rule too, or copy the held decoy's objects to a separate private hold bucket with no lifecycle rule. Otherwise the backstop deletes what the hold was meant to keep.
- Record who asked, why and until when, in your own records. Remove the hold when it ends; held data then purges on the next run.

## Exports after purge

- **Exports read only live rows and live objects.** Once a row or object is purged it cannot appear in a later export. Nothing keeps a shadow copy for exporting.
- **Export bundles are short-lived** (`export_bundle`, 1 day). A bundle generated before a purge can contain data purged afterwards, which is why bundles expire quickly. Copies someone has already downloaded are outside Foiled's control.
- **STIX `include_payloads` defaults to false** (#13). With `store_payloads: false` there are only hashes to include anyway. With it on, only live payloads are included.
- **The API returns 404** for an attempt id older than the `attempt` TTL, and for evidence (a pcap, a quarantined file) whose object has been purged even while the attempt row is still live. This lands with the attempts API (#21, #25).
- Contribute-back to a central radar (#35, #37) is opt-in, separate, and has its own redaction and delay rules.

## Copies the purge job does not reach

The purge job deletes live data. These copies need separate handling:

- **D1 Time Travel** can restore a database to any point in the last 30 days, which includes rows the purge deleted.
- **Postgres backups and point-in-time recovery** at your Postgres host. Set backup retention no longer than your longest Postgres TTL, or accept that backups hold purged rows until they expire.
- **Host buffers.** The host agent deletes local capture and quarantine copies once R2 confirms the upload (#9, #41). A host that cannot upload keeps its buffer up to the spool cap. Volume snapshots and provider backups of the capture volume need the same retention as the data on it ([deploy/cloud-sketch.md](deploy/cloud-sketch.md)).
- **AI Gateway logs** are off for the LLM correlation gateway, so the gateway keeps no prompt text ([ADR 0010](adr/0010-llm-provider-and-ai-gateway.md#ai-gateway-setup)). An operator who turns logging on for debugging owns that retention.
- **Queues** hold messages until the consumer acknowledges them (up to 14 days if consumers fall behind). Large evidence is never in a message.

## Access and encryption

**Who can read capture data.** Decide and write down who can read pcaps, logs, quarantined files and forensic snapshots, and keep that list short.

- In the console and API: scoped roles (#21). Quarantine downloads need the double-confirm (#14). Forensic reads need a `forensics:read` scope and a reason, and are audited (#8).
- In R2: only the control plane Worker holds the binding. No public bucket URL, no custom domain. Upload URLs are short-lived and scoped to one object and one host (#9).
- On the sandbox host: the capture volume under `/var/lib/foiled` is owned by `foiled-agent`. Only named admin accounts with `sudo` can read it. Guests never mount it ([deploy/vps.md](deploy/vps.md#linux-users)).

**Encryption at rest.** Confirm it for every store that holds capture data: R2 and D1 on Cloudflare's side, your Postgres host, and the host capture volume. On a VPS, use the encrypted capture volume in [deploy/vps.md](deploy/vps.md#encrypted-capture-volume-option). Encryption at rest protects against lost disks, snapshots and backups, not against someone with access to the running system.

## Operator checklist

Before exposing a decoy, and again when you change these settings:

- [ ] You have considered your lawful basis and obligations for collecting and holding this data in your jurisdiction, and taken advice where you are unsure. In Australia that includes whether the Privacy Act 1988 and the Australian Privacy Principles apply to you, and what a leak of capture data would mean under the notifiable data breaches scheme.
- [ ] TTLs in `configs/retention.yaml` are set to what you need, not more. `store_payloads` is `false` unless you have a reason.
- [ ] You have read the dry-run audit records and switched `purge.dry_run` to `false`.
- [ ] R2 lifecycle rules are in place as a backstop.
- [ ] Backup and Time Travel retention for D1 and Postgres is known and acceptable.
- [ ] You know who can read the capture volume, R2 evidence and quarantined files, and access is limited to them.
- [ ] Encryption at rest is confirmed for each store and the host capture volume.
- [ ] Any legal hold is recorded with who asked, why and until when.

## What Foiled does not do

- **No compliance claims.** Foiled does not claim any compliance certification or attestation, and following this document does not make an operator compliant with anything.
- **No data to the project authors.** Foiled has no telemetry and no phone-home. Capture data, retention config, purge results and audit records stay in the operator's own accounts. Contribute-back (#35, #37) is opt-in and separate.
- **Not legal advice.** See the note at the top.

## Test plan

**Done (unit tests in [crates/core/src/retention.rs](../crates/core/src/retention.rs) and [crates/lint/tests/retention.rs](../crates/lint/tests/retention.rs)):**

- Defaults match this document, and the shipped YAML parses to exactly those defaults.
- Items expire at their class TTL and not one millisecond before. TTL `0` deletes at the next run, including an item created that instant.
- Clock skew: items stamped 1 ms, 1 hour and 10 years in the future are kept and counted in `future_dated`; once the clock passes the stamp plus the TTL they are deleted; skew never shortens retention.
- Legal hold keeps only the held decoy's expired items; purge disabled plans nothing; dry run still reports.
- Metadata-only mode drops raw evidence at the next run and keeps attempts and quarantine metadata; the commented YAML example parses and passes the schema.
- Per-provider enrichment TTLs; the audit floor; no overflow at extreme timestamps; the audit summary contains counts and no keys.

**With the data layer (fixture store and clock skew):**

1. Seed a fixture store: local Postgres, D1 and R2 (Wrangler local mode) with items at known ages relative to a fixed clock, across every data class and two decoys, one on legal hold.
2. Run the purge with `dry_run: true`. Nothing is deleted; one audit record holds the expected counts and no keys.
3. Run with `dry_run: false`. Expired R2 objects are gone, expired rows are gone, held items remain, and the audit counts match. A second run deletes nothing.
4. Clock skew: stamp items with a host clock 1 hour ahead and 1 hour behind. Future-dated items survive and are counted; they purge once the control plane clock passes their stamp plus the TTL.
5. After TTL, the API returns 404 for old attempt ids and for purged evidence of a live attempt, and an export run afterwards contains none of the purged data. This part lands with the attempts API (#21, #25).

## Future expansion

- Fuller GDPR tooling for operators in the EU (records of processing, data subject request handling, transfer notes) is a future expansion of this document, not current scope.
- Per-decoy TTL overrides and a holds workflow beyond the `legal_holds` list.

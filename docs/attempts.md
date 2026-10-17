# Exploit attempts

An **attempt** is everything one source did to one decoy in one burst of activity (#25). It is the object CVE mapping (#12), ATT&CK mapping (#26), confidence (#27), LLM correlation (#28), actor association (#29), campaigns (#33), IOCs (#34) and the radar (#35) all hang their links on. Attempts replace "sessions" from earlier drafts; the timeline view of an attempt is #10.

The contract is [`schemas/attempt.schema.json`](../schemas/attempt.schema.json). The grouping lives in `foiled_core::attempt` and is deterministic: the same evidence always produces the same attempts with the same ids, in any input order. Raw capture events are never changed or deleted; analyst labels, merges and splits (planned, `PATCH /v0/attempts/{id}`) are stored separately and audited.

## Fields

| Field | Meaning |
| --- | --- |
| `attempt_id` | `att_` plus 24 hex characters, a hash of tenant, decoy, source and the first event id. Stable for the same evidence. |
| `tenant_id`, `decoy_id`, `catalogue_id`, `decoy_kind` | Where it happened. |
| `sensor_id` | Set when the events came from an edge sensor (#31). |
| `src` | The attacker's address as the decoy saw it. |
| `first_seen`, `last_seen` | Unix ms. |
| `state`, `state_history` | `probe`, `exploit` or `post-exploitation`, and every move with the signal and event that caused it. |
| `event_ids`, `payload_refs` | The capture events and R2 objects that make up the attempt. |
| `hook_hits` | Vulnerable-path hooks that fired (#32), with stage and CVE id. |
| `ioc_refs`, `campaign_id` | Filled by #34 and #33. |
| `labels` | Analyst labels. |
| `noise` | Targeted versus mass score for the source (below). |

## Grouping

1. Sort the tenant's events by time, then event id.
2. **Attacker-facing events** (`network`, `application`, `hook` channels) are keyed by decoy and source address. A new attempt starts when the same source has been quiet on the same decoy for more than the idle gap (default 30 minutes).
3. **Guest-side events** (`egress`, `dns`, `filesystem`, `process`, `quarantine`) come from inside the decoy, so their `src` is the guest. They join the most recently active attempt on the same decoy within the idle gap. If there is none, they are reported as orphans rather than dropped.
4. Attempts stay per decoy. Cross-decoy and cross-sensor grouping is the campaign layer (#33).

Examples, both in the [golden test](../testdata/attempts/demo-fleet.input.json):

- **Sandbox decoy.** `203.0.113.7` loads `/admin`, posts an upload with `../` in the path, the demo hook fires at `trigger` and then `post_exploit`, and the guest tries to fetch a second stage (egress, blocked). One attempt, five events, state `post-exploitation`, two hook hits.
- **Emulation decoy.** `198.51.100.23` sends `INFO` to the Redis emulator and `GET /` to the sandbox decoy a few seconds apart. Two attempts (one per decoy), both `probe`. `192.0.2.44` later sends `CONFIG SET dir /var/spool/cron`: its own `probe` attempt until the #12 signature pass marks it.

## State machine

State only moves forward: `probe` to `exploit` to `post-exploitation`.

| Signal | Source | Moves to |
| --- | --- | --- |
| First contact | Any attacker-facing event | `probe` |
| Matcher or sequence hit | #12 tier 1 and 2 | `exploit` |
| Hook at `trigger` | #32 | `exploit` |
| Hook at `post_exploit` or `cleanup` | #32 | `post-exploitation` |
| Egress or DNS from the guest | #4 boundary | `post-exploitation` |
| File write or quarantine | #9 | `post-exploitation` |
| Process exec | #9 (v0.2) | `post-exploitation` |
| YARA match | #11 | `post-exploitation` |
| Canary used | #17 | `post-exploitation` |

Matcher, YARA and canary signals are computed outside the grouping and passed in by event id, so this module never needs to know their rule formats. The API passes tier 1 signature hits ([exploit-attribution.md](exploit-attribution.md)) today.

## Noise score

Every attempt carries a score for its source, from 0 (looks targeted) to 100 (looks like mass scanning), computed over the tenant's events in the same window. It is an input to confidence (#27), never a replacement for CVE confidence, and is shown next to the source address in the console (#14). The idea follows [lessons.md](research/lessons.md): broad, shallow activity across many products is scanning; narrow, deep activity is more interesting.

| Input | Effect |
| --- | --- |
| Distinct catalogue products touched | 1: base 10. 2 to 3: base 40. 4 or more: base 70. |
| Decoys touched | 5 or more: +10 |
| Events in the window | 1,000 or more: +10 |
| GreyNoise `noise` (#11) | +20 |
| GreyNoise `riot` (#11) | at least 90 (known business service) |

Bands: 0 to 29 `targeted`, 30 to 59 `mixed`, 60 and above `mass`. `evidence` lists every reason in words, and `fleet_scope` says what the score could see (`tenant` today, `fleet` once shared research sensors report through #31 and #35).

Examples: one source, one product, a handful of requests scores 10 (`targeted`). A source that touched five different products scores 80 (`mass`). A source GreyNoise marks as RIOT scores at least 90.

## API

- `GET /v0/attempts`: filters `since`, `until`, `decoy_id`, `decoy_kind`, `sensor_id`, `src`, `state`, `cve`, `campaign_id`, `limit`. Newest activity first.
- `GET /v0/attempts/{attempt_id}`.

Attempts are a read model built on request from Postgres capture events over a bounded window (default 7 days, at most 31 days and 20,000 events, with `truncated` set when the cap is hit) so request handlers stay inside Workers CPU limits. A table materialised by the ingest consumer can replace this later without changing the contract or the ids.

## Related

- #10 timeline and pcap extract for one attempt.
- #12 CVE tiers, #26 ATT&CK techniques, #27 confidence, #28 LLM, #29 actors: links per attempt.
- #32 hooks, #33 campaigns, #34 IOCs.

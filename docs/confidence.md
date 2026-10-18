# Confidence

One scoring model for every link Foiled asserts (#27): attempt to CVE, attempt to ATT&CK technique, attempt to actor (#29), attempt to campaign (#33) and attempt to indicator (`attempt_ioc`, scored per IOC, [iocs.md](iocs.md#confidence), #34). Producers add evidence; the model turns evidence into a score, a band, wording and publish decisions. Consumers (exports #13, the console #14, the radar and review queue #35) only ever read the result.

The model is deterministic: the same evidence and config always give the same score. Every contribution and every cap is part of the link, so LLM or pre-disclosure involvement can never be hidden. Code: `foiled_core::confidence`. Contract: [`schemas/confidence-link.schema.json`](../schemas/confidence-link.schema.json). Config: [`configs/confidence.yaml`](../configs/confidence.yaml).

## Evidence

`{signal_id, source, weight, summary, ref}`. `weight` is how strong the signal is on its own (0 to 100). A link must have at least one item.

| Source | Producer | Example |
| --- | --- | --- |
| `vuln_path_hook` | #32 hooks, #12 tier 3 | The demo upload hook fired at `trigger` |
| `sequence` | #12 tier 2 | Probe, upload, file write in order |
| `rule` | #12 tier 1 signatures, #26 ATT&CK rules | `foiled-demo-0001-upload-traversal` matched |
| `vendor_desc` | #12 tier 5 | Advisory says unauthenticated; the attempt was unauthenticated |
| `catalogue_prior` | #5 | The decoy was stood up for this CVE |
| `predisclosure_backmatch` | #12 tier 4 | Traffic seen before the advisory matched it later |
| `enrichment` | #11 | CrowdSec reports the source exploiting this CVE |
| `llm` | #28 | The model proposed this CVE |
| `campaign_cluster` | #33 | Two attempts share a payload hash, so they join one campaign ([campaigns.md](campaigns.md)) |
| `actor_ttp_overlap` | #29 | A public actor profile uses the techniques seen, weighted by rarity ([actor-attribution.md](actor-attribution.md#matching)) |
| `actor_indicator_overlap` | #29 | A callback domain seen on a decoy is listed in a public report about the actor |
| `actor_targeting` | #29 | The CVE hit is one the report says the actor targets |
| `actor_payload_overlap` | #29 | A URL the attacker sent in a request is listed in a public report (weak: a false flag can plant it) |
| `actor_asn_overlap` | #29 | A source ASN is listed in a public report (weak context) |
| `noise_score` | #25 | Source noise score (a penalty, below) |
| `analyst` | console, API | Recorded through overrides, not as points |

## Scoring

1. Group evidence by source. For each source, the strongest signal adds `points x weight / 100`; each further signal from the same source adds a quarter of its share. The source total is capped at `cap`.
2. Sum the sources.
3. **Noise penalty.** The noise score takes off up to `noise_max_penalty` points (20 by default) in proportion, but never below what a vulnerable-path hook or a signature established on its own. Mass scanning lowers confidence that something was targeted; it does not erase a hook.
4. **LLM-only cap.** If the only evidence is `llm` (plus a catalogue prior), the score stays below `high`. With the default weights the LLM adds at most 20 points.
5. **Pre-disclosure cap.** If the only evidence is `predisclosure_backmatch` (plus a prior), the score stays below `publish_min` until an analyst reviews it.
6. **Actor caps (#29).** Every `attempt_actor` link, whatever its evidence and whatever the config, stays below `medium` without `actor_indicator_overlap` evidence, and below `high`, never publishable and never promoting state until an analyst confirms it ([actor-attribution.md](actor-attribution.md#confidence-and-caps)).
7. **Analyst override.** `true_positive` sets 100 and flips the wording to confirmed; `false_positive` sets 0 and suppresses every downstream use; `unsure` records feedback and changes nothing. Overrides are stored per link, replace earlier ones, and are written to the audit log.

Default tier weights (normative, tunable in `configs/confidence.yaml`):

| Source | Points | Cap |
| --- | --- | --- |
| `vuln_path_hook` | 60 | 60 |
| `sequence` | 40 | 45 |
| `rule` | 30 | 40 |
| `vendor_desc` | 15 | 15 |
| `catalogue_prior` | 10 | 10 |
| `predisclosure_backmatch` | 25 | 25 |
| `enrichment` | 10 | 15 |
| `llm` | 20 | 20 |
| `campaign_cluster` | 45 | 55 |
| `actor_ttp_overlap` | 25 | 30 |
| `actor_indicator_overlap` | 30 | 40 |
| `actor_targeting` | 10 | 10 |
| `actor_payload_overlap` | 10 | 15 |
| `actor_asn_overlap` | 5 | 5 |

The config checks itself: the LLM cap must stay below `high`, the pre-disclosure cap below `publish_min`, and the `campaign_cluster` cap below both, so clustering alone never publishes a campaign or reaches `high` (#33). `campaign_cluster` evidence counts only for `attempt_campaign` links: on any other kind (a CVE, technique, indicator or actor link) it adds nothing and the explanation says so in `caps_applied`, because attempts belonging together says nothing about an actor or a CVE.

## Bands, wording and thresholds

| Score | Band |
| --- | --- |
| 0 to 39 | `low` |
| 40 to 69 | `medium` |
| 70 to 100 | `high` |

| Link | Unconfirmed | Analyst confirmed |
| --- | --- | --- |
| CVE, technique | "we assess as" | "confirmed" |
| Actor (#29) | "possible association" | "confirmed association" only when also high |
| Campaign (#33, [campaigns.md](campaigns.md#confidence-and-wording)) | "possible" | "confirmed" |

| Threshold | Default | Use |
| --- | --- | --- |
| `publish_min` | 60 | Exports and public pages never auto-publish below this. LLM-only, pre-disclosure-only and catalogue-only links never auto-publish at any score. |
| `ui_highlight_min` | 50 | Console highlights. |
| `auto_state_promote_min` | 70 | May promote an attempt's state; never from LLM-only evidence. |
| `radar_queue_min` | 40 | Candidates for the review queue (#35). |

## Worked examples

These are tests (`crates/core/src/confidence.rs` and `crates/lint/tests/confidence.rs`), and the resulting links are stored under [`testdata/confidence-links/`](../testdata/confidence-links/) and schema-checked in CI.

| Evidence | Result |
| --- | --- |
| Hook (100) + sequence (90) + catalogue prior | `high`, publishable, "we assess as" |
| Signature (100) + catalogue prior | 40, `medium`, not publishable |
| Pre-disclosure back-match alone | below 60, not publishable |
| LLM alone, even with a misconfigured weight of 100 | capped at 69, not publishable, cannot promote state |
| Any of the above + analyst `true_positive` | 100, "confirmed" |
| Hook alone + a mass-scanning noise score of 100 | 60: the penalty stops at the hook's own contribution |
| Actor link with full-strength TTP, indicator and targeting overlap, even with weights of 100 | capped at 69, `medium`, "possible association", not publishable |
| Actor link with TTP and targeting overlap but no shared indicator | capped at 39, `low` |

## What the API computes today

`GET /v0/attempts/{id}/links` builds evidence from vulnerable-path hook hits (#32), the catalogue entry's CVEs and expected techniques as priors (#5; the CVE prior is only attached once the attempt got past probing or has other CVE evidence), the attempt's noise score (#25) and the bundled ATT&CK rules (#26). `POST` records an analyst override. Tier 1 and 2 CVE evidence (#12), enrichment (#11), LLM proposals (#28) add evidence to the same lists as they land. Actor links (#29) are served per campaign or lone attempt at `GET /v0/actor-links` ([actor-attribution.md](actor-attribution.md#api-and-the-review-queue)). Campaign membership links (#33) are served per campaign at `GET /v0/campaigns/{id}/evidence` ([campaigns.md](campaigns.md#confidence-and-wording)).

## Explainability

The console's confidence panel (#14) shows the score, band and wording, then every contribution with its points, every cap that applied, the evidence ledger with links to the events, and the noise band with `decoy_types_touched` when present. STIX exports (#13) carry the score as the relationship's `confidence` and the wording in the description, and only publishable links leave unless an analyst asks for more ([intel-outputs.md](intel-outputs.md#the-gate)).

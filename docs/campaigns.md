# Campaigns

Status: clustering, schema, API, analyst actions, alert helper and golden fixtures in place. Owner: #33.

Related: attempts ([attempts.md](attempts.md), #25), IOCs and behaviour fingerprints ([iocs.md](iocs.md), #34), confidence ([confidence.md](confidence.md), #27), enrichment and ASN context ([enrichment.md](enrichment.md), #11), CVE mapping and advisory dates ([exploit-attribution.md](exploit-attribution.md), #12), ATT&CK techniques ([attack-mapping.md](attack-mapping.md), #26), LLM correlation ([llm-correlation.md](llm-correlation.md), #28), alerting ([alerting.md](alerting.md), #15), edge sensors (#31). Consumers: actor possible-association (#29), the console (#14) and the radar (#35).

A **campaign** is a group of attempts, across decoys and sensors, that share infrastructure, behaviour, targeting or payloads closely enough that they probably belong to one wave of activity. Single-attempt views miss mass exploitation waves and selective targeting after an advisory; campaigns make the fleet readable as one picture and are a radar input for #35.

A campaign is a first-class object with a stable id, its own confidence, a status, and audited analyst actions. It is not attribution: it says "these attempts look like one wave", never "this is actor X".

The contract is [`schemas/campaign.schema.json`](../schemas/campaign.schema.json), with analyst actions in [`schemas/campaign-action.schema.json`](../schemas/campaign-action.schema.json). The code is `foiled_core::campaign` ([crates/core/src/campaign.rs](../crates/core/src/campaign.rs)). Golden fixtures are under [testdata/campaigns](../testdata/campaigns/fleet-wave.input.json).

## Contents

- [Principles](#principles)
- [The campaign object](#the-campaign-object)
- [Features](#features)
- [Clustering](#clustering)
- [Merge and split rules](#merge-and-split-rules)
- [Ids and the campaign registry](#ids-and-the-campaign-registry)
- [Confidence and wording](#confidence-and-wording)
- [Status](#status)
- [Targeting pattern](#targeting-pattern)
- [Analyst actions](#analyst-actions)
- [Actor suggestions](#actor-suggestions)
- [Tenant isolation and shared research sensors](#tenant-isolation-and-shared-research-sensors)
- [API](#api)
- [Alerts](#alerts)
- [Worked examples](#worked-examples)
- [Limits](#limits)
- [Retention](#retention)
- [Tests](#tests)
- [Not built yet](#not-built-yet)

## Principles

1. **Deterministic and stable.** The same attempts, IOCs, signals, analyst actions and registry always give the same campaigns, ids, evidence and order, in any input order. The [campaign registry](#ids-and-the-campaign-registry) remembers which campaign each attempt was in, so ids, labels, merges and splits hold as the read window moves.
2. **Explainable.** Every member lists the features that joined it and the member it shares each one with. Every campaign carries its #27 score with every evidence item and cap.
3. **Bounded cost.** No pairwise comparison of attempts. Features are blocked into an inverted index and joined with union-find, so the work is linear in (attempt, feature) pairs. 20,000 attempts cluster in under 0.2 s in a native release build; routes that do not need campaigns skip clustering ([API](#api)).
4. **Tenant-scoped.** A campaign only ever holds one tenant's attempts ([below](#tenant-isolation-and-shared-research-sensors)).
5. **Cautious.** Wording is "possible" until an analyst confirms. Clustering alone never reaches `high` and never publishes. Actor labels are a separate, later step (#29) with "possible association" wording.
6. **Derived.** Raw capture events and attempts are never changed. Analyst actions are stored separately, append-only, audited and replayed.

## The campaign object

| Field | Meaning |
| --- | --- |
| `campaign_id` | `cmp_` plus 24 hex characters, kept by the registry ([ids](#ids-and-the-campaign-registry)). |
| `tenant_id`, `tenant_scope` | The owning tenant. `tenant_scope` is always `tenant` today. |
| `title` | The analyst's title when set, otherwise generated from the strongest shared feature, for example `Stage-2 URL hxxp://stage2[.]example[.]invalid/m.sh on 2 decoys`. Escaped. |
| `status` | `emerging`, `active` or `closed` ([status](#status)). |
| `first_seen`, `last_seen` | Unix ms over the members. |
| `seed` | The earliest member in the window and the features that joined it. A new cluster's id is derived from it; afterwards the registry keeps the id. |
| `attempt_ids`, `decoy_ids`, `sensor_ids`, `catalogue_ids` | Every member attempt (oldest first) and where they happened. |
| `members[]` | Per member: attempt id, decoy, sensor, source, times, state, noise score, `joined_by[]` (up to 8 features, strongest first, each with the member it is shared with and the IOC id where there is one) `added_by` when an analyst action put it there, and `carried_over` when it is in the campaign from an earlier window and what joined it is outside this one. |
| `feature_summary` | `infrastructure`, `ttp`, `targeting` and `payload`. Values seen in at least two members, except source addresses and ASNs, which list every member's. Display-safe (defanged and escaped). |
| `shared_ioc_ids` | IOC ids (#34) seen in at least two members, for pivoting. |
| `confidence_ref` | `/v0/campaigns/{campaign_id}/evidence`: the full #27 explanation. |
| `confidence` | Score, band, wording, publishable, evidence and caps for the campaign as a whole. |
| `suggested_actor_links[]` | Attachment point for #29. Always empty from clustering. |
| `analyst` | Analyst title, status override, latest feedback, `merged_from`, `split_from` and the action ids applied. |
| `notes` | Plain-language notes, for example when a member had more features than were used. |

Display strings are hostile text that has been defanged and escaped. Never parse them; pivot on `ioc_id` or `shared_ioc_ids` instead.

## Features

Every feature is a join key: two attempts that share the key, close enough in time, join. Features come from the attempt (#25), its IOCs (#34), its CVE and technique signals (#12, #26) and enrichment (#11). A key held by only one attempt in the window can join nothing and is ignored.

| Feature | Family | Strength | From | Used when |
| --- | --- | --- | --- | --- |
| `payload_sha256` | payload | strong | `payload_sha256` IOC: what was sent | always, except the hash of an empty body |
| `file_sha256` | payload | strong | `file_sha256` IOC: what was left | always |
| `stage2_url` | infrastructure | strong | `url` IOC with role `stage2` or `callback` | always |
| `callback_domain` | infrastructure | strong | `domain` or `dns_query` IOC with role `callback` or `stage2` | always |
| `callback_ip` | infrastructure | strong | `ip` or `ipv6` IOC with role `callback` or `stage2` | always |
| `behaviour_fingerprint` | TTP | medium | `bf2:` IOC (exploit or later, two or more steps) | only when distinctive (below) |
| `cmdline` | TTP | medium | `cmdline` IOC | always |
| `request_substring` | payload | medium | exact request string IOC | attempt at exploit or later |
| `src_ip` | infrastructure | weak | the attempt's source address | attempt at exploit or later |
| `asn_cve` | infrastructure, targeting | weak | source ASN (#11) and one CVE (hook hits, tiers 1, 2 and 5 of #12) | attempt at exploit or later |
| `asn_techniques` | infrastructure, TTP | weak | source ASN and the attempt's ATT&CK technique set (#26) | attempt at exploit or later |
| `request_shape` | payload | weak | request path and user agent together (up to 4 pairs) | attempt at exploit or later |

Strength sets both the join rule and the [evidence weight](#confidence-and-wording): strong 100, medium 70, weak 40.

- **Strong** features are artefacts that are hard to share by chance: the same hash, the same stage-2 location, the same callback infrastructure.
- **Medium** features are overlapping behaviour. A public exploit used by unrelated people can also explain them, so two checks apply:
  - **Distinctive fingerprints only.** A behaviour fingerprint is a key only when at least one of its steps comes after exploitation: a command, a DNS lookup or egress from the decoy, a file write or quarantine, or a hook at `post_exploit` or `cleanup`. Plain requests (`http GET /admin`) and a hook firing at `trigger` are what every user of a public exploit shares, so a fingerprint made only of those never joins.
  - **Rarity, for fingerprints only.** A behaviour fingerprint held by more than 10 distinct sources in the window, or (with at least 8 sources in the window) by more than a quarter of them, is common: it looks like a public exploit or tool, not one operator, and joins only as weak. Command lines and request strings keep their strength however many sources share them, because a botnet wave sharing one command is exactly a campaign.
- **Weak** features are always two facts at once (an address that reached exploit; an ASN and a CVE; a path and a user agent) or a common medium feature. They never bridge two clusters that strong or medium features already formed, and a campaign held together by weak features only stays below `medium` and `emerging` ([confidence](#confidence-and-wording)).

What never joins attempts on its own, by design:

- A shared ASN or hosting organisation. Large providers host unrelated people.
- A generic probe (`GET /`, a banner grab). Probe-only attempts only join through strong artefacts.
- The same catalogue product or the same CVE from unrelated sources. Everyone exploiting a CVE is not one campaign; the CVE only joins together with the ASN.
- The same source address while it only probes. Scanners touch everything.
- Geography, reputation or third-party labels.
- An LLM proposal (#28). LLM-only clustering is out of scope; see [Not built yet](#not-built-yet).

## Clustering

1. Take the tenant's attempts in the window, sorted by first seen then id. Attempts from any other tenant are dropped.
2. For each attempt, collect its candidate keys, and count how many attempts and distinct sources hold each one. Demote common behaviour fingerprints to weak.
3. **Key cap.** Keep only keys held by two or more attempts. Rank first the keys the attempt shares with other attempts recorded in its campaign (the evidence that joined it before, never crowded out), then strongest first, then by how many distinct sources hold the key (more first: evidence that joins more of the fleet wins), at most 16 per feature and 64 in all. Junk values an attacker sends are held by that attacker's own attempts only, so they rank below a value many sources share and cannot push it out; no feature can crowd out the others. Every attempt that hit the cap is named in the response `notes`, member or not.
4. **Blocking.** Build an inverted index: one posting list per kept key, in time order.
5. **Pass 1 (strong and medium).** Walk each posting list and union each attempt with the previous one when it started within the join gap (7 days) of the previous one ending.
6. **Registry.** After pass 1, attempts the [registry](#ids-and-the-campaign-registry) recorded in the same campaign are unioned, so a campaign stays whole when the attempts that joined it have left the window. The registry only holds joins made by strong or medium features, so this re-applies earlier evidence; a recorded attempt counts as established, so the weak pass can never join it to another recorded campaign. Each cluster takes its id from its established core: the oldest recorded id, or a new id from the core's earliest attempt.
7. **Pass 2 (weak).** The same, except a union that would join two established clusters (formed in pass 1 or by the registry, or holding a recorded attempt) is refused. Weak keys may add stragglers or form new weak clusters, never bridge established ones. Refusals are counted in the response `notes`.
8. Replay stored [analyst actions](#analyst-actions) in `(at, action_id)` order.
9. Build each campaign with two or more attempts in the window: member joins (only to members of the same campaign), feature summary, targeting pattern, confidence and status. A campaign with one attempt in the window is not listed, but that attempt still carries its `campaign_id`.
10. On a read of the canonical window only, record what live clustering changed in the registry (memberships joined by a strong or medium feature, new or widened campaigns, campaigns folded into another by a strong or medium bridge). Steady state writes nothing.

Every union records the key and the neighbour on both attempts. That record is `joined_by`, so the explanation is exactly what the algorithm used.

## Merge and split rules

Automatic:

| Rule | Effect |
| --- | --- |
| Shared key within the join gap | Merge (single linkage through consecutive attempts on the key). |
| More than the join gap between consecutive attempts on a key | No join on that key. A key reused months apart starts a new campaign. |
| Weak key between two established clusters | No join. |
| Key too generic by construction | Not a key at all (empty-body hash, probe-only paths, bare ASN, bare CVE, a fingerprint of requests and a trigger only). |
| Behaviour fingerprint common to many sources | Joins only as weak. |
| Attempts recorded in one campaign | Stay together across windows (the registry). A new attempt that bridges two recorded campaigns with a strong or medium feature folds the newer one into the older; the newer id resolves with `merged_into`. A weak feature never does. |

Manual, through [analyst actions](#analyst-actions): `merge` folds campaigns together, `split` moves attempts out. Both are replayed on every read, so they hold as new attempts arrive.

## Ids and the campaign registry

A new cluster's id is `cmp_` plus the first 24 hex characters of SHA-256 over `foiled-campaign/v1`, the tenant id and the **seed**: its earliest member attempt. Attempt ids are themselves derived from the evidence (#25). The seed's features are recorded in `seed.features` but not hashed, so the id does not change as the campaign grows through other features.

Ids must outlive the read window: a wave that lasts longer than the default 7-day window would otherwise lose its seed and get a new id, its labels and merges would stop applying, and alerts would see a "new" campaign. The **campaign registry** (`migrations/postgres/0006_campaign_registry.sql`) prevents that:

- `campaign_members` records the campaign live clustering put each attempt in; `campaigns` records each id with `created_at` (when it was first recorded), first and last seen, and `merged_into`.
- **Only established memberships are recorded**: an attempt joined to its campaign by a strong or medium feature. Weak joins, registry carry-overs and analyst actions never write memberships (merges and splits are replayed from the actions on every read). So the registry can only re-apply evidence that would join the attempts on its own, and can never glue two campaigns that live clustering keeps apart.
- Clustering unions attempts recorded in the same campaign before the weak pass, and a recorded attempt counts as established there, so a weak feature never bridges two recorded campaigns. A cluster takes the **oldest recorded id** in its established core (smallest `created_at`, then id). Only a cluster with no recorded member takes a new seed id.
- When a new attempt bridges two recorded campaigns with a strong or medium feature, the newer one is recorded as `merged_into` the older. Ids are followed through `merged_into` (at most 8 hops).
- **Only reads of the canonical window write.** `GET /v0/campaigns`, `GET /v0/attempts` and `POST .../actions` record changes only when the caller passed no `since` or `until` (the default 7 days up to now). Reads of any other window use the registry but never write it, so ids never depend on which window someone read first.
- **Writes converge.** Each write is two multi-row upserts in one transaction, and only rows that changed are sent. `created_at` keeps the oldest value, first and last seen only widen, `merged_into` is write-once (`COALESCE`) and a CHECK keeps it off the campaign itself, and a membership only moves to an older campaign. Concurrent or stale writers end in the same state in any commit order. The in-memory store applies the same rules.
- `GET /v0/campaigns/{campaign_id}` resolves any recorded id. When fewer than two of its attempts are in the window, or it was merged away (by a bridge or an analyst merge), it answers with a stub: `stub: true`, first and last seen, the recorded `attempt_count` and `merged_into`.

Analyst actions name the campaign id, which the registry keeps stable. Each action also stores up to 16 of the campaign's newest member attempts as `anchor_attempt_ids`, used only if the id is not in the window.

A campaign created by a split gets `cmp_` plus 24 hex characters of SHA-256 over `foiled-campaign/v1`, `split`, the tenant id and the action id, so it is stable too.

## Confidence and wording

Each campaign is scored with the #27 model as a link of kind `attempt_campaign` (attempt: the seed, target: the campaign id). Evidence:

| Evidence | Source | Weight |
| --- | --- | --- |
| Each distinct key shared inside the campaign (at most 16, strongest and most shared first) | `campaign_cluster` | 100 strong, 70 medium, 40 weak |
| The lowest member noise score (#25) | `noise_score` | the score (subtracts up to 20) |
| Members in the campaign from an earlier window, with nothing joining them inside this one | `campaign_cluster` | 40 (as weak) |
| Members added by an analyst merge or split | `analyst` | recorded, adds nothing |

`campaign_cluster` adds 45 points for a full-strength signal and at most 55 in total (`configs/confidence.yaml`). The config check refuses a cap at or above `publish_min` or `high`, so **clustering alone always stays below publishing and below `high`**. A campaign (or membership) whose clustering evidence is all weak is capped below `medium` (39, "weak features only" in `caps_applied`), so a shared ASN with generic requests can only ever be `low`. Only analyst feedback (`true_positive`) takes a campaign to 100 and "confirmed".

| Link | Unconfirmed | Analyst confirmed |
| --- | --- | --- |
| Campaign and membership | "possible" | "confirmed" |

`GET /v0/campaigns/{id}/evidence` also returns one link per member: the features that joined that member, its own noise score, and an analyst confirmation when a merge or split put it there.

Worked numbers: one shared payload hash is 45 points, less 2 for a targeted source (noise 10): 43, `medium`. A hash plus a request shape is 48. Many shared strong artefacts hit the cap: 55, less 2: 53. An ASN and a CVE alone is 18, less 2: 16, `low`.

## Status

| Status | When |
| --- | --- |
| `closed` | No member attempt for 7 days (`last_seen` older than now minus 7 days), or an analyst closed it. |
| `emerging` | Confidence is `low`, fewer than three attempts, or only weak features join it. |
| `active` | Otherwise. |

An analyst status override wins until cleared.

## Targeting pattern

`feature_summary.targeting` says whether the wave looks like mass exploitation or selective targeting. The visible fleet is what the window shows: decoys with attacker-facing traffic that run a product the campaign touched.

| Metric | Definition |
| --- | --- |
| `attempts`, `sources` | Member attempts and distinct source addresses. |
| `decoys_touched`, `sensors_touched`, `products_touched` | Distinct decoys, edge sensors (#31) and catalogue products among the members. |
| `visible_decoys` | Decoys in the window running any product the campaign touched. |
| `coverage_pct` | `decoys_touched` as a percentage of `visible_decoys` (decoy fan-out). |
| `noise_bands` | Members by their source's noise band (#25): `targeted`, `mixed`, `mass`, `unknown`. |
| `cves`, `catalogue_ids` | What was targeted. |
| `advisory_timing[]` | Per CVE with a known advisory (#12): publication time, the first member attempt on it, the offset in whole hours and `before_disclosure`. Activity before publication is a pre-disclosure signal for the review queue (#35). |

| Pattern | Rule |
| --- | --- |
| `mass` | Coverage of 60 % or more across at least 3 decoys, or more than half the members come from mass-scanning sources. |
| `selective` | At least 3 visible decoys, coverage of 34 % or less, and no member from a mass-scanning source: the actor left most matching decoys alone. |
| `mixed` | Anything else. |

`evidence` gives every reason in words, for example "touched 2 of 6 visible decoy(s) running the same products (33%)" and "first attempt on FOILED-DEMO-0001 came 142 hour(s) before its advisory".

## Analyst actions

`POST /v0/campaigns/{campaign_id}/actions` with scope `campaigns:write`, rate limited per token (60 an hour by default, `Limits::campaign_actions_per_hour`). Every action needs a `note` (may be empty, at most 1,000 characters), is stored append-only, and is written to the audit log as `campaign.<action>` with the whole action as detail.

| Action | Fields | Effect |
| --- | --- | --- |
| `label` | `title` (1 to 120 characters) | Sets the title. Escaped before display. |
| `status` | `status` (`emerging`, `active`, `closed`, or null to clear) | Overrides the computed status. |
| `merge` | `campaign_ids` (1 to 20, same window) | Folds those campaigns into this one. This campaign keeps its id; the others are listed in `merged_from`. Moved members get `added_by` and a confirmed membership link. |
| `split` | `attempt_ids` (1 to 500 members, not all) | Moves the named attempts into a campaign of their own with a split id and `split_from`; the rest keep the id. The split is replayed on every read, so a split attempt keeps the split campaign's id even when it is alone in a window. |
| `feedback` | `feedback` (`true_positive`, `false_positive`, `unsure`) | The #27 override for the campaign: confirm (100, "confirmed"), suppress (0, never published or highlighted) or record. |

Fields that do not belong to the action are refused. Actions are replayed in `(at, action_id)` order on every read and resolve by campaign id (through `merged_into`), then by `anchor_attempt_ids`. An action whose campaign has nothing in the current window waits; it applies again when the campaign is back in view. **Structural actions (label, status, merge, split) are always replayed in full**; only feedback is capped, at the newest 500 per tenant, and shed feedback is counted in `notes`. Structural actions therefore accumulate without bound (the per-token rate limit slows that down, it does not cap it); compacting superseded labels and statuses into one action per campaign is a follow-up. Actions never change attempts, events or IOCs, and never delete anything.

## Actor suggestions

`suggested_actor_links[]` is the attachment point for #29 and is always empty from clustering. When #29 lands, each item is `{label, wording, confidence_ref, report_urls}`:

- Labels prefer a nexus or a named public cluster ("nexus overlapping TTPs reported in <public report>") over hard numbering without sources.
- `wording` is "possible association" unless the actor link is `high` and analyst-confirmed (#27), when it may read "confirmed association".
- `report_urls` link the public reports the suggestion rests on.
- The suggestion's confidence is a separate `attempt_actor` link through #27. Campaign confidence never feeds actor confidence above `medium` without an analyst, and a campaign is never labelled with an actor automatically at high confidence.

What campaigns will not say: that an actor, country or organisation is behind a campaign; that a campaign is "confirmed" without an analyst; that a shared ASN, hosting provider or geography means a shared operator.

## Tenant isolation and shared research sensors

Edge sensors (#31) are bound to one tenant by their certificate, and every event they send is stamped with that tenant ([edge-sensor.md](deploy/edge-sensor.md#tenancy-isolation-rules)), so `sensor_ids` on a campaign are always the tenant's own sensors. Clustering runs on one tenant's attempts at a time, inside the request for that tenant, and drops any attempt whose `tenant_id` differs. Campaign ids hash the tenant id, so the same evidence in two tenants gives two unrelated ids. Analyst actions are stored and read per tenant. Every route uses the caller's authenticated tenant only.

**Shared research sensors.** A research operator may run sensors whose traffic several tenants would like to see clustered fleet-wide (#31, #35). That needs an explicit fleet scope, which does not exist yet (`tenant_scope` is always `tenant`, and the noise score's `fleet_scope` is `tenant` too). When it is added it must:

- run as its own research tenant over events that tenants have explicitly opted in to share, never over another tenant's events directly. That opt-in is its own setting: the sensor's `share_opt_in` governs contribute-back to public feeds ([contribute-back.md](contribute-back.md)), not fleet clustering;
- return fleet campaigns only to the research operator, with `tenant_scope: fleet` and ids hashed under a separate fleet namespace;
- show a tenant only its own members of a fleet campaign, never other tenants' attempt ids, decoys, sources or analyst notes;
- keep tenant-scoped clustering unchanged, so turning fleet clustering on or off never changes a tenant's own campaigns or ids.

Until then, shared research sensors report into the research operator's tenant like any other sensor, and their campaigns are that tenant's.

## API

All tenant-scoped ([OpenAPI](../api/openapi.yaml)). Like attempts and IOCs, campaigns are built on request from the capture events in a window (default the last 7 days, at most 31 days and 20,000 events, `truncated` set when the cap is hit). Campaign ids come from the [registry](#ids-and-the-campaign-registry), so they hold as the window moves; pass `since` and `until` to see a campaign's older attempts.

| Method and path | Scope | What |
| --- | --- | --- |
| `GET /v0/campaigns` | `campaigns:read` | Filters `since`, `until`, `status`, `attempt_id`, `sensor_id`, `decoy_id`, `cve`, `ioc_id`, `min_confidence`, `limit`. Newest activity first. `notes` lists actions that did not apply. |
| `GET /v0/campaigns/{campaign_id}` | `campaigns:read` | One campaign, or a stub (`stub: true`, first and last seen, `attempt_count`, `merged_into`) for a recorded campaign with fewer than two attempts in the window. |
| `GET /v0/campaigns/{campaign_id}/attempts` | `campaigns:read` and `attempts:read` | Member attempts in the window with `campaign_id` set. |
| `GET /v0/campaigns/{campaign_id}/evidence` | `campaigns:read` | The campaign link and one link per member (#27). |
| `GET /v0/campaigns/{campaign_id}/actions` | `campaigns:read` | Stored actions naming the campaign. |
| `POST /v0/campaigns/{campaign_id}/actions` | `campaigns:write` | Record an [analyst action](#analyst-actions); returns the action and the campaign as it is now. The window is built once and clustered again with the new action. Rate limited. |

Campaign ids reach attempts and IOCs in three ways, so routes that do not need clustering do not pay for it:

| Route | Campaign ids |
| --- | --- |
| `GET /v0/campaigns*`, `GET /v0/attempts`, `GET /v0/iocs?campaign_id=` | Full clustering: actions replayed, registry updated, `campaign_id` and `campaign_ids` filled. |
| `GET /v0/attempts/{id}`, `GET /v0/iocs` (no `campaign_id`), `GET /v0/iocs/{id}`, `GET /v0/attempts/{id}/iocs` | From the registry only: one read, no clustering and no actions. Ids are as of the last full read. |
| Timeline, links and overrides | None (they do not show campaigns). |

Inputs per full read: the attempts and their IOCs, CVE and technique signals from the bundled rule packs, ASN numbers from cached enrichment Facts (`asn.number`, newest per address), advisory dates from the bundled advisories, the tenant's stored actions (every structural one, the newest 500 feedback) and the registry entries for the window's attempts.

```sh
curl -sS -H "authorization: Bearer $FOILED_TOKEN" \
  "$FOILED_API/v0/campaigns?status=active&min_confidence=40"

curl -sS -X POST -H "authorization: Bearer $FOILED_TOKEN" \
  -H "content-type: application/json" \
  -d '{"action": "label", "title": "Demo upload wave", "note": "reviewed"}' \
  "$FOILED_API/v0/campaigns/cmp_0123456789abcdef01234567/actions"
```

## Alerts

`foiled_core::campaign::alerts(previous, current)` turns two snapshots (campaign id to member count) into `campaign_updated` alerts (#15) for campaigns that are new or grew. Closed campaigns raise nothing. Emerging campaigns raise `low`, so they land in the review queue rather than paging; active ones raise the type's default `medium`. The alert id hashes tenant, campaign and member count, so a retried producer raises the same alert, and the usual campaign id plus day dedupe applies. Summaries carry the campaign wording ("possible" or "confirmed") and score.

The producer that keeps the previous snapshot runs with the alert delivery worker, which is not deployed yet ([alerting.md](alerting.md)); the function and its tests are in place for it.

## Worked examples

Illustrative only; these are the golden fixtures in [testdata/campaigns](../testdata/campaigns/fleet-wave.input.json), with expected output in `testdata/campaigns/expected/`.

**Same payload on three sensors (validation).** Three edge sensors receive the same upload body (`payload_sha256`) from three sources in seven minutes. One campaign: seed features `payload_sha256` and `request_shape`, confidence 48 (`medium`, "possible", not publishable), status `active`, three sensors, pattern `mixed` (3 of 6 visible decoys), and advisory timing 143 hours before the FOILED-DEMO-0001 advisory.

**Shared stage 2.** An hour later two sources run the demo chain on two sandbox decoys and fetch the same stage 2. One campaign joined by `stage2_url`, `callback_domain`, `callback_ip`, `behaviour_fingerprint` (distinctive: it has the `exec`, `dns` and `egress` steps), `cmdline`, `asn_cve`, `asn_techniques` and `request_shape`. The clustering cap applies: 53 (`medium`). Two attempts, so `emerging`. Pattern `selective`: 2 of 6 visible decoys.

**Shared ASN and generic probe only (validation).** Two addresses in one ASN send `GET /` to three decoys. No campaign.

**Generic hook hits from one cloud ASN (unit test).** Three sources on three days send `GET /admin` with a common user agent and fire the same public hook at `trigger`. The fingerprint has no post-exploitation step, so it is not a key; only `asn_cve` and `request_shape` join them. One campaign, capped below medium ("weak features only"), `emerging`.

**A fingerprint common to twelve sources (unit test).** Twelve sources run the same chain including egress. The fingerprint is distinctive but common, so it joins only as weak: `emerging`, below 40.

**Analyst replay.** The recorded actions in `testdata/campaigns/actions/` label the first campaign and merge the second into it: one campaign of five attempts, the first campaign's id, the label as title, the second id in `merged_from`.

## Limits

| Limit | Value |
| --- | --- |
| Join gap | 7 days |
| Closed after | 7 days without a new member |
| Join keys per attempt | 64, at most 16 per feature, joinable keys only |
| Common behaviour fingerprint | more than 10 sources, or more than a quarter of 8 or more |
| Request shapes per attempt | 4 |
| Joins listed per member | 8 (all count) |
| Values per summary list | 16 (with `count`) |
| Shared IOC ids listed | 64 |
| Clustering evidence items scored | 16 |
| Analyst actions replayed | every structural action; the newest 500 feedback actions |
| Analyst actions recorded | 60 per token per hour |
| Registry `merged_into` hops | 8 |
| Title, note | 120, 1,000 characters |
| Merge, split | 20 campaigns, 500 attempts |

## Retention

Campaigns are derived, not stored: they are recomputed from live capture events, so once the purge job removes attempts (`attempt` TTL, 90 days by default, [privacy-and-retention.md](privacy-and-retention.md)) they leave their campaigns too, and a campaign with fewer than two attempts left disappears. Analyst actions (`campaign_actions`, `migrations/postgres/0005_campaign_actions.sql`) hold attempt ids, analyst ids and free-text titles and notes, no addresses; they stay with the tenant like the audit log, and an action applies whenever its campaign is in view. The registry (`campaigns` and `campaign_members`, `migrations/postgres/0006_campaign_registry.sql`) holds campaign ids, attempt ids and times, no addresses. **Registry rows are not purged yet.** When the purge job (#16) covers them, member rows go with the `attempt` TTL (they carry `attempt_first_seen` for that), and a campaign row goes once it has no members left and its `last_seen` is older than the `attempt` TTL; until then a purged campaign still resolves to a stub with first and last seen and nothing else.

## Tests

- `crates/core/src/campaign.rs`: payload-hash wave, ASN-only probes, ASN and CVE only is low and emerging, generic hook hits from one ASN stay low and emerging, a common fingerprint joins only weakly, junk bodies cannot push out a shared hash and cap hits are noted, join gap, closed, tenant isolation, weak-bridge refusal, label, feedback, merge and split replay, ids, labels and merges surviving the seed leaving the window, a lone member keeping its id, feedback spam never shedding structural actions, a weak join in a narrow window never merging recorded campaigns, stale registry writes never undoing newer ones, a botnet wave still forming on a shared command or stage 2, junk shared by two attackers never splitting a wave, action validation, `attach`, alerts, and 2,000 attempts on one key.
- `crates/lint/tests/campaigns.rs`: golden campaigns for both fixtures (`FOILED_BLESS=1` to regenerate) and the recorded actions; the repository lint validates `testdata/campaigns/expected/` and `testdata/campaigns/actions/` against the schemas.
- `crates/api/tests/campaigns.rs`: tenant scoping, scopes, filters, member attempts, evidence, `campaign_id` on attempts and IOCs, action validation, audit, merge and split, merged ids resolving as stubs, an id and label holding past the default window, only the canonical window writing the registry, and the per-token rate limit.
- `crates/pg/tests/campaign_actions.rs`: append-only actions, structural actions loaded in full with feedback capped, and the registry (kept `created_at`, widened times, member counts, tenant scoping, write-once `merged_into`, memberships only moving to older campaigns, and a 6,000-row batch) against Postgres.

## Not built yet

- **Console views (#14).** The campaign list, campaign page and merge and split controls belong to the console work.
- **Materialised campaigns.** Campaigns are a read model over a bounded window, with the registry keeping ids. A table maintained by the ingest consumer can replace the read model later without changing ids or the contract.
- **Registry purge.** Registry rows are not purged yet; see [Retention](#retention) for how #16 will apply.
- **Action compaction.** Structural actions accumulate; compacting superseded labels and statuses is a follow-up.
- **Alert producer.** The `alerts` function is ready; the scheduled producer that keeps snapshots runs with the alert delivery worker (#15).
- **LLM merge proposals (#28).** An LLM may propose that two campaigns belong together; that proposal goes to the review queue (#35) as a suggestion for an analyst `merge`, never as a join. LLM-only clustering is out of scope.
- **Actor suggestions (#29)** and **fleet scope** ([above](#tenant-isolation-and-shared-research-sensors)).
- **MCP tools (#24).** Agents can already read `campaign_id` on attempts through `query_attempts`; a campaign tool is not exposed.

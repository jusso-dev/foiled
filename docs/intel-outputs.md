# Intel outputs

Status: STIX 2.1, MISP, IOC CSV and JSON downloads in place, with golden fixtures. The read-only TAXII 2.1 server is designed below and follows in its own pull request, served from a materialised object log. Owner: #13.

Related: IOCs ([iocs.md](iocs.md), #34), attempts ([attempts.md](attempts.md), #25), confidence ([confidence.md](confidence.md), #27), CVE mapping ([exploit-attribution.md](exploit-attribution.md), #12), ATT&CK mapping ([attack-mapping.md](attack-mapping.md), #26), enrichment ([enrichment.md](enrichment.md), #11), privacy and retention ([privacy-and-retention.md](privacy-and-retention.md), #16), contribute-back ([contribute-back.md](contribute-back.md), #37). Consumers and later producers: campaigns (#33), actor association (#29), the radar (#35).

Foiled's intel has to leave in formats other tools already read. This page says what each export contains, how Foiled objects map onto STIX 2.1 and MISP, how confidence and cautious wording survive the trip, who may export what, and where campaigns and actors plug in.

The code is `foiled_core::intel` ([crates/core/src/intel/](../crates/core/src/intel/mod.rs)), served by [crates/api/src/routes/exports.rs](../crates/api/src/routes/exports.rs). Contracts: [api/openapi.yaml](../api/openapi.yaml), [schemas/stix-bundle.schema.json](../schemas/stix-bundle.schema.json) and [schemas/misp-event.schema.json](../schemas/misp-event.schema.json). Golden outputs are under [testdata/exports](../testdata/exports/synthetic.input.json).

## Contents

- [Principles](#principles)
- [Endpoints](#endpoints)
- [Auth model](#auth-model)
- [The gate](#the-gate)
- [Filters and options](#filters-and-options)
- [Mapping table](#mapping-table)
- [STIX 2.1](#stix-21)
- [MISP](#misp)
- [IOC CSV and JSON](#ioc-csv-and-json)
- [TAXII 2.1](#taxii-21)
- [Validation](#validation)
- [Wording](#wording)
- [Campaigns and actors](#campaigns-and-actors)
- [Privacy, retention and redaction](#privacy-retention-and-redaction)
- [Determinism and ids](#determinism-and-ids)
- [Limits and what is not built](#limits-and-what-is-not-built)
- [Tests](#tests)

## Principles

1. **One gate for every format.** `intel::select` applies the filters, the confidence gate, analyst suppressions, the actor and payload opt-ins and export redaction. STIX, MISP, CSV and JSON (and the TAXII object log, once built) all read its output, so no format can leak what another holds back.
2. **Never auto-publish weak links.** Only links and IOCs that #27 marks `publishable` leave by default: score at or above `publish_min` (60), and not carried only by LLM, pre-disclosure or catalogue evidence. An analyst can ask for more; that export is audited, marked TLP:AMBER+STRICT or stricter, and is never public.
3. **Wording survives.** Every claim carries its #27 score as `confidence` and its wording in prose: "we assess as" for unconfirmed CVE and technique links (#12), "possible association" for actors (#29), "confirmed" only after an analyst said so.
4. **Honest gaps.** A memory-only attempt exports its command line, behaviour fingerprint and callbacks, and says why there is no file hash. No export invents one ([iocs.md](iocs.md#memory-only-implants)).
5. **Deterministic.** The same evidence and options give the same bytes and the same ids, so consumers can deduplicate and re-import safely.
6. **Built on request, stored nowhere.** Exports read the same live window as `/v0/attempts`, so purged data never returns (#16), and no export bundle is written to R2.

## Endpoints

| Endpoint | Output | Media type |
| --- | --- | --- |
| `GET /v0/exports/stix` | STIX 2.1 bundle | `application/stix+json;version=2.1` |
| `GET /v0/exports/misp` | MISP event JSON | `application/json` |
| `GET /v0/exports/iocs.json` | IOC JSON (#34 objects) | `application/json` |
| `GET /v0/exports/iocs.csv?fields=ioc` | IOC CSV (#34 columns) | `text/csv; charset=utf-8` |
| `GET /v0/exports/iocs.csv` | Source address CSV (#22, unchanged) | `text/csv; charset=utf-8` |
| `GET /taxii2/` and below | TAXII 2.1, read-only (planned, [below](#taxii-21)) | `application/taxii+json;version=2.1` |

Downloads carry `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `x-foiled-truncated`. An export reads at most 4,000 capture events, oldest first, so it stays well inside the Workers memory limit ([limits](#limits-and-what-is-not-built)). When the window held more, `x-foiled-truncated` is `true` and `x-foiled-next-cursor` names the last event read, in the `(ts, event_id)` order every store reads events in (the JSON export also has `next_cursor`). Pass it back as `cursor`, with the same `until` and filters, for the next part: it reads strictly after that event, so parts never overlap or skip, even when more than 4,000 events share one millisecond. The cursor is opaque (`<ts>.<hex of the event id>`).

**Attempts split at a cut.** Attempts are rebuilt per part, so an attempt whose events straddle a cut becomes two attempts with different ids, one in each part. A link whose evidence needs events from both halves (for example a sequence matcher, or a hook in one part and the post-exploitation step in the other) can be weaker or missing in both. Narrow the window, or filter by `catalogue_id` or `decoy_kind`, so a busy period fits in one part; the TAXII object log ([below](#taxii-21)) is built over full windows and does not have this limit.

```sh
curl -sS -H "authorization: Bearer $FOILED_TOKEN" \
  "$FOILED_API/v0/exports/stix?since=1792200000000&min_confidence=70" -o foiled-stix.json
```

## Auth model

| Who | How | What they get |
| --- | --- | --- |
| Operator or integration with `exports:read` | Bearer token (`fo_<id>.<secret>`) | Every export (and TAXII once served), for their own tenant only, gated. |
| Analyst with `exports:read` and `review:write` | Bearer token | The same, plus `include_unreviewed=true`. Each such request writes an `export.unreviewed` audit record (format, window, threshold, label). |
| MCP agent (#24) | `mcp` token | Nothing: `exports:read` is not an MCP scope, so agents cannot pull intel in bulk. |
| Sandbox host or sensor | mTLS identity | Nothing: host and sensor identities only hold `host:*` and `sensor:*` scopes. |
| Anyone without a token | | 401. TAXII discovery is authenticated too. |

Tenant isolation comes from the token: every export is built from `who.tenant_id`'s events only, and TAXII will serve only `who.tenant_id`'s rows of the object log. TAXII clients will authenticate with the same bearer header; clients that only support HTTP Basic will not be served.

## The gate

`select` keeps, for attempts that pass the [filters](#filters-and-options):

- **Links** (CVE, technique, campaign, actor) that are not suppressed by an analyst (`false_positive`), are not actor links without `include_actors`, score at least `min_confidence`, and are `publishable` (or `include_unreviewed` is set).
- **IOCs** seen in a kept attempt that score at least `min_confidence`, are `publishable` (or `include_unreviewed` is set), and are not payload request strings without `include_payloads`. Enrichment refs pass through `ioc::export_refs`.
- **Attempts** with at least one kept link or IOC.

`min_confidence` only ever narrows. Setting it to 0 does not widen the default gate, because `publishable` already includes `publish_min`.

What was left out is counted in `dropped` (JSON export) so a reader can tell a quiet window from a filtered one.

**A consequence worth knowing.** Under the shipped #27 weights a technique link backed only by ATT&CK rules tops out at 40 (`rule` cap) plus 10 (catalogue prior), below `publish_min`. So technique links do not leave by default: an analyst confirms them (`POST /v0/attempts/{id}/links` with `true_positive`, which makes them publishable and switches the wording to "confirmed"), or exports with `include_unreviewed`. The synthetic golden fixture shows the first path; `synthetic-unreviewed` shows the second.

## Filters and options

All exports and the IOC CSV with `fields=ioc` take:

| Parameter | Meaning |
| --- | --- |
| `since`, `until` | Window in Unix ms. Default the 7 days to now; at most 31 days. |
| `min_confidence` | 0 to 100. Drop links and IOCs below this. |
| `catalogue_id` | Attempts against this catalogue entry. |
| `state` | `probe`, `exploit` or `post-exploitation`. |
| `campaign_id` | Attempts in this campaign (#33). |
| `decoy_kind` | `sandbox` or `emulation`. |
| `include_unreviewed` | Analyst only, see [auth](#auth-model). |
| `include_actors` | Include actor links (#29). Off by default. |
| `include_payloads` | Include request strings taken from bodies and request slices. Off by default; they only exist when `store_payloads` is on (#16). |
| `tlp` | `clear`, `green`, `amber` (default), `amber+strict` or `red`. `amber_strict` and `amber strict` are accepted because `+` becomes a space in query strings. |

## Mapping table

| Foiled | STIX 2.1 | MISP | CSV and JSON |
| --- | --- | --- | --- |
| Attempt (#25) | `observed-data` over the attempt's exported observables (the source address only when its own IOC passed the gate), or a `grouping` of its indicators and link targets when none did; `x_foiled_attempt_id`, `x_foiled_state`, `x_foiled_decoy_kind`, `x_foiled_catalogue_id` | Event comment for its notes | `attempts[]` in JSON (id, state, `file_ioc_limited`, notes) |
| Tier evidence summary | `x_foiled_summary` on `observed-data` (state path and signals, hooks that fired, noise score); `x_foiled_evidence` (points per evidence source) and `x_foiled_caps_applied` on each relationship | Link comments | `confidence`, `band`, `wording` columns |
| Attempt notes, memory-only (#34) | `note` on the `observed-data`; `x_foiled_file_ioc_limited` | `foiled:file-ioc-limited` tag and an event comment | `file_ioc_limited`, `note` columns |
| CVE link (#12, #27) | `vulnerability` and `relationship` (`related-to`) with `confidence` and "we assess as" | `vulnerability` attribute, comment with wording | `attempt_ids` link back |
| Technique link (#26, #27) | A Foiled-created `attack-pattern` with `external_references` to MITRE (`mitre-attack`, technique id, URL) and `relationship` with `confidence` | `mitre-attack-pattern` galaxy tag and a `text` attribute with wording | |
| IOC (#34) | `indicator` with pattern, `confidence`, `sighting`, and an observable where STIX has one | Attribute or `file` object | One row or item per IOC |
| File hash | `file` observable, `[file:hashes.'SHA-256' = ...]`, unclassified `malware` (`is_family: false`) with the file as sample, `indicates` relationship | `file` object with `sha256` | |
| ASN context (#11) | `autonomous-system` observable via `belongs_to_refs`, `x_foiled_enrichment` | Attribute comment | `asn`, `as_org`, `country` |
| Campaign link (#33, from clustering) | `campaign` and `relationship` with `confidence` and "possible" | `campaign-id` attribute | `campaign_ids` |
| Actor link (#29, opt-in) | `intrusion-set` and `relationship`, "possible association" | `threat-actor` attribute, wording in comment, no galaxy tag | |
| TLP and review state | OASIS TLP 2.0 `marking-definition` on every Foiled object; `x_foiled_publishable` on indicators and relationships | `tlp:` tag, `foiled:unreviewed` tag | `tlp` and `review` columns (CSV); `tlp`, `marking`, `unreviewed` and `review` fields (JSON) |

## STIX 2.1

A bundle holds, in this order: the Foiled `identity`, the TLP marking, the MITRE notice marking (when techniques are present), observables, indicators, malware, attack patterns, vulnerabilities, campaigns, intrusion sets, observed data, notes, relationships and sightings.

**Indicators and patterns.** `indicator_types: ["malicious-activity"]`, `valid_from` is the first sighting, `confidence` is the IOC's #27 score, `labels` carries `foiled-band:<band>`, and the description says "We assess as malicious activity: ..." with the attempt and sighting counts. Custom properties: `x_foiled_ioc_id`, `x_foiled_ioc_type`, `x_foiled_roles`, `x_foiled_wording`, `x_foiled_publishable`, `x_foiled_redacted`, `x_foiled_file_ioc_limited`, `x_foiled_campaign_ids` and, for fingerprints, `x_foiled_fingerprint` (version and steps).

| IOC type | Pattern |
| --- | --- |
| `ip`, `ipv6` | `[ipv4-addr:value = '...']`, `[ipv6-addr:value = '...']` |
| `domain` | `[domain-name:value = '...']` |
| `url` | `[url:value = '...']` |
| `http_path` | `[network-traffic:extensions.'http-request-ext'.request_value = '...']` |
| `http_ua` | `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '...']` |
| `payload_sha256` | `[artifact:hashes.'SHA-256' = '...']` (a request body, not a file) |
| `file_sha256` | `[file:hashes.'SHA-256' = '...']` |
| `cmdline` | `[process:command_line = '...']` |
| `request_substring` | `pattern_type: "foiled-request-substring"`, the exact string |
| `behaviour_fingerprint` | `pattern_type: "foiled-bf"`, the `bf1:` value |
| `dns_query` | None: the same name is a `domain` indicator |

Values in patterns are hostile text: `\` and `'` are escaped, nothing else is changed, and `name` uses the defanged, escaped `display`.

**Sightings.** One `sighting` per indicator: `count` is the IOC's `sightings`, `first_seen` and `last_seen` cover them, `observed_data_refs` names the attempts' `observed-data`, and `where_sighted_refs` is the Foiled identity.

**Observed data.** One per exported attempt, over the observables of its exported IOCs. The source address is one of them only when its own IOC passed the gate; otherwise it is not named anywhere, and `x_foiled_summary` says "from an address below the export gate". `number_observed` is the attempt's event count. When none of an attempt's IOCs has an observable (for example only links passed, or only a command line), the attempt is a `grouping` instead (`context: "suspicious-activity"`, `object_refs` its indicators and link targets), and its relationships start there.

**Relationships.** `related-to` from the attempt's `observed-data` (or `grouping`) to each linked `vulnerability`, `attack-pattern`, `campaign` or `intrusion-set`, with `confidence`, the [wording](#wording) in `description`, `foiled-band:<band>` in `labels`, and `x_foiled_link_kind`, `x_foiled_wording`, `x_foiled_publishable`, `x_foiled_confirmed`, `x_foiled_evidence` and `x_foiled_caps_applied`. Technique relationships also carry `x_foiled_attack_version`.

**ATT&CK objects.** Foiled never emits MITRE's own `attack-pattern` id. Only the creator of an object may version it (STIX 2.1 section 3.6), and an object under MITRE's id with Foiled's content would overwrite MITRE's in a TIP. Each technique is instead a Foiled-created `attack-pattern` (`uuid5(FOILED_NAMESPACE, "attack-pattern|T1190")`, `created_by_ref` the Foiled identity) with the sidecar `name`, `kill_chain_phases` from the sidecar tactics, `external_references` of `{source_name: "mitre-attack", external_id, url}`, MITRE's id in `x_foiled_mitre_stix_id`, and a statement marking that reproduces MITRE's notice and licence ([attack-mapping.md](attack-mapping.md#licence-and-notices)) next to the TLP marking. This is the common practice for third-party ATT&CK references: OpenCTI, MISP's STIX converters and other TIPs merge attack patterns on the `mitre-attack` external id, so the Foiled object lands on the same technique without touching MITRE's.

**Vulnerabilities.** `name` is the id; `external_references` is `{source_name: "cve", external_id}` for `CVE-` ids and `source_name: "foiled"` for others (`FOILED-DEMO-0001`).

**Markings.** The TLP marking is the OASIS TLP 2.0 object (`extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`) copied verbatim, for example `marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421` for TLP:AMBER.

Validation is described [below](#validation).

## MISP

One event per export with `published: false` and `distribution: 0` (your organisation only), so nothing propagates until someone at the receiving end decides. Attribute `distribution` is 5 (inherit).

**Ids and re-import.** The event uuid is `uuid5(FOILED_NAMESPACE, "misp-event|<scope>")`, where the scope is a SHA-256 over the tenant, the filters and options, and the window (`since`, `until`); the tenant id itself never appears. Every attribute and object uuid is derived from the event uuid and the IOC id. So importing the same export twice updates one event, and two overlapping exports (different windows or filters) are two events whose attribute uuids never clash, which MISP requires because attribute uuids are unique across an instance.

| IOC type | Attribute | Category | `to_ids` when publishable |
| --- | --- | --- | --- |
| `ip`, `ipv6` | `ip-src` (role `source`), else `ip-dst` | Network activity | yes |
| `domain` | `domain` | Network activity | yes |
| `url` | `url` | Network activity | yes |
| `http_path` | `uri` | Network activity | yes |
| `http_ua` | `user-agent` | Network activity | no: user agents collide with legitimate clients |
| `request_substring` | `pattern-in-traffic` | Payload delivery | yes |
| `payload_sha256` | `text`, comment "SHA-256 of a request body sent to the decoy, not a file hash" | Payload delivery | no |
| `file_sha256` | `file` object with `sha256` | Payload installation | yes |
| `cmdline` | `text`, comment "command line" | Payload installation | yes |
| `behaviour_fingerprint` | `text`, comment "foiled behaviour fingerprint" | Other | no |
| `dns_query` | covered by its `domain` | | |

`to_ids` is never set for anything that is not `publishable` on its own, so an analyst's unreviewed export cannot switch detection on. Every attribute carries `foiled:confidence`, `foiled:band` and `foiled:wording` tags and the #27 sentence in its comment. Payload hashes are `text` rather than `sha256` so they are never mistaken for file hashes.

Links: CVEs are `vulnerability` attributes (External analysis), techniques are `misp-galaxy:mitre-attack-pattern="<name> - <id>"` event tags plus a `text` attribute holding the wording, campaigns are `campaign-id` and actors `threat-actor` attributes (Attribution). Actor galaxy tags are never added, because a tag cannot carry "possible association". Event tags: `tlp:<label>`, `foiled:export`, `foiled:unreviewed` when applicable, and `foiled:file-ioc-limited` when an attempt was memory-only. Attempt notes and the MITRE notice are one `comment` attribute.

`intel::misp::problems` checks every category and type pair against MISP's `describeTypes` and the object relations; golden events also validate against `schemas/misp-event.schema.json`.

## IOC CSV and JSON

**JSON** (`/v0/exports/iocs.json`): `{format: "foiled-iocs", version: 1, tlp, marking, unreviewed, review, dropped, attempts, items, truncated}`, plus `next_cursor` when the window was cut. `marking` is the label as written (`TLP:AMBER+STRICT`) and `review` is `published` or `unreviewed`, as in the CSV. `items` are `schemas/ioc.schema.json` objects, the #34 field list unchanged, after the gate and export redaction. `attempts` carries each attempt's state, `file_ioc_limited` and notes.

**CSV** (`/v0/exports/iocs.csv?fields=ioc`): one row per IOC, columns

```text
indicator_type,indicator,first_seen,last_seen,file_ioc_limited,note,ioc_id,value,roles,sightings,confidence,band,wording,publishable,redacted,attempt_ids,campaign_ids,decoy_ids,catalogue_ids,asn,as_org,country,tlp,review
```

`tlp` (for example `TLP:AMBER+STRICT`) and `review` (`published`, or `unreviewed` when an analyst lifted the gate) repeat on every row, so the marking survives a download, a copy into a spreadsheet or a split file.

The first six are the columns [iocs.md](iocs.md#export-examples) fixed for memory-only attempts. `indicator` is the defanged `display`; `value` is the exact string. Lists are `;`-separated. Every cell is RFC 4180 quoted, and a cell starting with `=`, `+`, `-`, `@`, tab or carriage return gets a leading `'` so spreadsheets do not run it.

**Source address CSV.** Without `fields` (or with `fields=source`), `/v0/exports/iocs.csv` keeps the #22 shape and the MVP walkthrough keeps working ([mvp-walkthrough.md](mvp-walkthrough.md)). It is not confidence-gated, because it lists addresses seen at the tenant's own decoys rather than claims; use `fields=ioc` or STIX to share.

## TAXII 2.1

Planned, in a follow-up pull request for #13. The paths are in [api/openapi.yaml](../api/openapi.yaml) as `planned` and are not routed.

A first version rebuilt STIX objects from a sliding event window on every TAXII request. Review found that this cannot keep STIX's versioning rules: `created` moved with the window, the same id and `modified` came back with different content, long attempts were re-identified across window edges, and pages could skip objects. TAXII will instead serve a materialised, append-only object log:

- **Table.** One row per STIX object version: tenant, collection, id, `modified`, `created`, `date_added` and the object JSON, unique on (tenant, collection, id, `modified`).
- **Materialiser.** A scheduled job (and an audited admin trigger) builds objects over the canonical full window with the same `intel::select` gate as the downloads (publishable only, TLP:AMBER, no actors, no payload strings), compares each with its latest stored version, and inserts a new version only when the content changed, with a new `modified` and the `created` of the first version.
- **Serving.** Discovery, the API root, one read-only collection, objects, a single object, the manifest and versions, paged on (`date_added`, id) with `added_after`, `next`, `limit` and `match[]`. A TAXII request reads rows and never rebuilds anything. Nothing below `publish_min` is ever written to the log.

## Validation

Three layers, each run in CI:

1. **`intel::stix::problems`** (Rust, run in tests on every golden bundle and every bundle the API tests receive): ids, required properties, timestamps, confidence ranges, property names, `observed-data` and `grouping` references, and that every `_ref` and `_refs` resolves inside the bundle. `intel::misp::problems` checks MISP category and type pairs against MISP's `describeTypes`.
2. **Vendored schemas** (`foiled-lint`): golden STIX bundles against [schemas/stix-bundle.schema.json](../schemas/stix-bundle.schema.json) and MISP events against [schemas/misp-event.schema.json](../schemas/misp-event.schema.json).
3. **The OASIS `stix2-validator`**, pinned to 3.2.0 (BSD-3-Clause; the 3.3.x wheels on PyPI ship without the STIX schemas), in strict mode over `testdata/exports/stix/`: any error or warning fails CI except these four, which are deliberate:

| Check | Why it is waived |
| --- | --- |
| 103, ids should be UUIDv4 | Foiled ids are UUIDv5 so the same evidence always gives the same ids (a SHOULD in STIX 2.1). |
| 245, `pattern_type` outside the open vocabulary | `foiled-bf` and `foiled-request-substring` have no STIX pattern. |
| 302, external reference URL without a hash | MITRE's technique pages change; a hash would go stale. |
| 401, custom properties should use an extension | `x_foiled_*` properties are still valid STIX 2.1; moving them into a property extension is later work. |

## Wording

Exports never strengthen a claim. The sentences come from `intel::link_sentence` and `intel::ioc_sentence`:

| Link | Unconfirmed | After an analyst `true_positive` |
| --- | --- | --- |
| CVE | "We assess as an attempt against CVE-2099-0001." | "An analyst confirmed this as an attempt against CVE-2099-0001." |
| Technique | "We assess as ATT&CK T1190 (Exploit Public-Facing Application)." | "An analyst confirmed this attempt as ATT&CK T1190 (...)." |
| Campaign | "Possible part of campaign ..." | "An analyst confirmed this attempt as part of campaign ..." |
| Actor | "Possible association with ... This is not an attribution." | Only when also `high`: "Confirmed association with ..., reviewed by an analyst." |
| IOC | "We assess as malicious activity: ..." | "An analyst confirmed this as malicious activity: ..." |

Each sentence ends with "Confidence N of 100 (band)." Link targets are escaped with `timeline::printable` before they go into prose. The golden fixture descriptions are checked by the tests, so a wording regression fails CI.

## Campaigns and actors

**Campaigns (#33)** come from clustering ([campaigns.md](campaigns.md)). Each export clusters its window without writing the campaign registry, so campaign ids follow the registry and are the same ids `/v0/campaigns` shows. For every exported attempt in a campaign, `routes::exports::export_input` adds the campaign's #27 link (`campaign::campaign_link`: the campaign's own evidence and analyst state), and it goes through the same gate as any other link. Weak, cluster-only campaign links stay below `publish_min`, so they leave once an analyst confirms the campaign or in an unreviewed export.

- STIX: a `campaign` (`uuid5(FOILED_NAMESPACE, "campaign|<campaign id>")`, named by the campaign id) and a `related-to` relationship from the attempt with `confidence` and "possible" (or "confirmed") wording. MISP: a `campaign-id` attribute (Attribution) with the wording in its comment.
- `campaign_id` filters attempts, and `campaign_ids` on IOCs flow into JSON, CSV and `x_foiled_campaign_ids`.
- An attempt whose campaign has no other member in the window keeps its `campaign_id` but gets no campaign link, because clustering scores only campaigns it can see.

**Actors (#29)** are not produced yet. When they are, they arrive as `ConfidenceLink`s of kind `attempt_actor` on `AttemptRecord::links`, next to the campaign link in `export_input`:

- STIX: an `intrusion-set` (`uuid5(FOILED_NAMESPACE, "intrusion-set|<label>")`) and a `related-to` relationship; MISP: a `threat-actor` attribute. Tested today with synthetic links.
- Actor links need `include_actors=true` and keep "possible association" unless `high` and analyst-confirmed. They are counted in `dropped.actor_links` otherwise.
- Later: a STIX `attributed-to` from `campaign` to `intrusion-set` once #29 can say so with confidence, and MISP galaxy clusters for campaigns. Neither is emitted today.

## Privacy, retention and redaction

- **Retention (#16).** Exports read live capture events only, through the same window as attempts and IOCs. Once the purge removes an attempt's events, nothing about it can be exported again. No export bundle is stored, so the `export_bundle` TTL has nothing to remove; copies already downloaded are outside Foiled's control ([privacy-and-retention.md](privacy-and-retention.md#exports-after-purge)).
- **Payloads.** HTTP bodies are never exported unless `include_payloads` is set, and they only exist as IOCs when `store_payloads` is on. Hashes are always exported. The API extracts with `store_payloads: false` today.
- **Enrichment.** Only refs that pass `ioc::export_refs` leave, so never-redistribute providers (`local_asn`, GreyNoise and the rest) never appear ([enrichment.md](enrichment.md)). Reputation facts are never part of an indicator.
- **Secrets and canaries.** IOC values are already redacted and canary-free from extraction ([iocs.md](iocs.md#normalisation-redaction-and-privacy)); `redacted: true` values say they are not byte-exact.
- **Tenant data.** No export contains `tenant_id`. Decoy ids appear only in the IOC CSV and JSON, which stay with the tenant.
- **Public release** is a separate channel with its own delay and TLP rules ([contribute-back.md](contribute-back.md)). Exports are the operator's own copy; nothing here publishes anywhere.

## Determinism and ids

- Foiled objects: `<type>--uuid5(FOILED_NAMESPACE, "<type>|<key>")`, where `FOILED_NAMESPACE` is `uuid5(NAMESPACE_URL, "https://github.com/jusso-dev/foiled")` = `8f76a3ac-a14d-537e-9444-887bfe367e46`. Keys: the IOC id for indicators, sightings and malware, the attempt id for observed data and notes, the upper-case id for vulnerabilities, source, type and target for relationships.
- Observables use the STIX 2.1 deterministic id rule: UUIDv5 in namespace `00abedb4-aa42-466c-9c01-fed23315a9b7` over the canonical JSON of the id-contributing properties (`value`, `hashes`, `number`), so they match other producers.
- `created` and `modified` come from the evidence (first and last seen), never from a clock. Reference objects use 2026-01-01T00:00:00.000Z.
- The bundle id is derived from the SHA-256 of its objects' canonical JSON. The MISP event uuid is derived from the export scope ([MISP](#misp)).
- Technique objects are Foiled's: `uuid5(FOILED_NAMESPACE, "attack-pattern|<technique id>")`, never MITRE's id.
- UUIDv5 needs SHA-1. It is implemented in `intel::uuid5` against the FIPS 180 test vectors rather than adding a dependency; nothing security-relevant depends on it.

## Limits and what is not built

| Limit | Value |
| --- | --- |
| Window | Default 7 days, at most 31 days |
| Events per export | 4,000, oldest first; then `x-foiled-next-cursor` |
| Memory | Worst case (every event a distinct indicator, 20,000 events stored): a STIX download peaks near 55 MB of heap, against the 128 MB isolate limit (`crates/api/tests/export_bounds.rs` fails above 64 MB) |
| Filter strings | 256 characters |

Not built, on purpose or for later:

- Queued exports that assemble a large window into one file in R2 under the `export_bundle` TTL. Today a large window is exported in parts with `x-foiled-next-cursor`. The planned `POST /v0/exports/stix` (queue) is replaced by the synchronous download.
- The TAXII 2.1 server and its object log ([above](#taxii-21)); later, Basic auth and per-collection tokens for TAXII. TAXII writes are not planned.
- Commercial threat intel platform APIs and automatic public pulses (out of scope for #13).
- STIX `malware` family names: a captured file is an unclassified instance until YARA (#11) or an analyst names it.
- Campaign and actor producers (#33, #29); the mapping is ready, see [above](#campaigns-and-actors).

## Tests

- `crates/core/src/intel/`: unit tests for SHA-1 and UUIDv5 against published vectors, the Foiled namespace, the STIX observable id rule, pattern escaping, timestamps, TLP markings, wording rules (including actors and hostile targets) and the structural validator.
- `crates/api/tests/exports_golden.rs`: golden test. [synthetic.input.json](../testdata/exports/synthetic.input.json) (the #13 validation case: an ASN-enriched address, a payload string with `include_payloads`, a DNS callback and an analyst-confirmed technique link), the [memory-only](../testdata/iocs/memory-only.input.json) and [file-drop](../testdata/iocs/file-drop.input.json) IOC fixtures, the unreviewed view, and the memory-only attempt with synthetic campaign and actor links (`memory-only-linked`), and a `min_confidence` export where only links pass, so the attempt is a `grouping` (`synthetic-grouping`), are exported to STIX, MISP, JSON and CSV and compared with `testdata/exports/{stix,misp,table}/`. It also checks that the memory-only export has no `file`, file pattern, `malware` or `sha256` attribute, that `min_confidence` drops low links, that exports are identical when the input order changes, and the campaign and actor mapping with its wording. Regenerate with `FOILED_BLESS=1` and review the diff.
- `crates/api/tests/exports_golden.rs` also checks that the source address only appears when its IOC passed the gate (otherwise a `grouping` anchors the attempt), that every referenced object is added no earlier than its referrers (groundwork for TAXII `added_after`), that technique objects never carry MITRE's id, that CSV and JSON keep TLP:AMBER+STRICT and `unreviewed` on every row, and that MISP ids are stable per scope and disjoint across scopes.
- `crates/api/tests/export_bounds.rs`: the worst-case memory bound above, measured with `peak_alloc`, and that a cut download says where to continue.
- `crates/api/tests/exports.rs`: the routes: scopes and tenant isolation, the analyst-only and audited unreviewed path, filters and bad input, the unchanged #22 CSV, and a cut export continued by cursor through more events in one millisecond than one part reads.
- `foiled-lint` validates the golden STIX and MISP files against the vendored schemas, and CI runs the OASIS validator over the STIX files ([validation](#validation)).

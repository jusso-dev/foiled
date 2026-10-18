# Licence and data-terms compliance register

Status: living document, draft. Owner: #38. Last reviewed 18 Oct 2026.

This register lists every third-party code module, data source, platform service and asset Foiled touches, how we use it, and whether anything from it may appear in a paid Foiled feed. It exists so the MIT core stays clean and so paid feeds never carry data we have no right to resell.

**Not legal advice.** This register records design constraints the project follows. It is not a legal opinion. Operators who run Foiled, and anyone planning a commercial launch, must get their own counsel to review it first. Rows and statements that need counsel or a fresh check are marked **verify**.

Related: [research landscape](../research/landscape.md) (especially [licence blockers](../research/landscape.md#licence-blockers-and-implications-summary)), decoy modules #30, enrichment #11, canaries #17, contribute-back #37, data retention #16, exports #13.

## How to read the table

- **SPDX / licence**: SPDX identifier where one exists, otherwise a short description of the terms.
- **Use mode**:
  - `embed`: compiled or bundled into Foiled's own code or shipped assets.
  - `separate container`: runs as its own process or image, talks to Foiled over JSON, a socket or a queue, never imported.
  - `separate service`: a separately hosted service (self-hosted or third party) we call over the network.
  - `API enrich`: operator-side lookups that add Facts to observables (#11).
  - `contribute`: we send our own data to them.
  - `learn-only`: we study the design; no code or files are copied.
  - `platform`: infrastructure we run on.
- **Paid feed?**: may this item, or data it produces, appear in what a paid Foiled subscriber receives (feeds, CSV, STIX, MISP, TAXII, API exports)? For decoy software, the question is about the events our sensors generate with it, which are Foiled-origin data. `n/a` is used only for platform rows, where no third-party data is redistributed.
- **Source offer?**: if we distribute it (for example in a published image), must we ship or offer corresponding source?
- **Owner**: the issue that owns the integration.

How licences were checked: honeypot and intel rows come from [landscape.md](../research/landscape.md) (researched 17 Oct 2026). Rust crate licences were read from the crates.io API for the exact versions in `Cargo.lock`. JS package licences were read from the npm registry for the versions in `web/package.json`. Data licences for KEV, ATT&CK, MISP galaxy and Natural Earth were read from the licence files in their upstream repositories on 18 Oct 2026.

## 1. Decoy and sensor modules

| Component | SPDX / licence | Use mode | Paid feed? | Source offer? | Notes | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| Cowrie | BSD-3-Clause | separate container (may embed or patch) | yes | no (keep BSD notice) | Reference event schema. Its `dshield` output plugin is how we contribute to DShield (#37). Output plugins that call third-party APIs (GreyNoise, VirusTotal and others) produce third-party data, which falls under section 2. | #30 |
| OpenCanary | BSD-3-Clause | separate container (may embed or patch) | yes | no (keep BSD notice) | Background low-interaction persona. Thinkst's commercial Canary product is not used. | #30 |
| Conpot | GPL-2.0 | separate container | yes | yes | Never import into core. Ship licence text in the image; publish our patches under GPL-2.0. | #30 |
| SNARE | GPL-3.0 | separate container | yes | yes | Stale upstream. Never import its Python into core. | #30 |
| TANNER | GPL-3.0 | separate container | yes | yes | Do not copy its emulators into Foiled; write CVE emulators clean-room (#30). | #30 |
| Heralding | GPL-3.0 | separate container | yes | yes | Stale upstream. May be replaced by Cowrie plus OpenCanary auth logs. | #30 |
| SentryPeer | GPL-2.0-only OR GPL-3.0-only | separate container; contribute (optional peer sharing) | yes | yes | Joining its peer-to-peer sharing is opt-in (#37). Data received from peers is third-party data: verify its terms before any paid use, treat as `no` until then. | #30, #37 |
| ADBHoney | GPL-3.0 | separate container | yes | yes | Low activity upstream. | #30 |
| Dionaea | GPL-2.0 | separate container (strong isolation) | yes | yes | Stale, C-based; only in a strongly isolated sandbox. Captured binaries are malware: quarantine only, never in a feed (hashes may be). | #30 |
| Endlessh (optional) | Unlicense | separate container | yes | no | Tarpit, little intel value. Optional. | #30 |
| Canarytokens | GPL-3.0 with Thinkst clarifications and exceptions | separate service (self-hosted or canarytokens.org) | yes for trigger events from our own self-hosted server; hosted service: **verify** | yes if we distribute a modified server | Never embed into core. Commercial embedding needs a Thinkst licence (out of scope). Token values themselves are never published. | #17 |
| CrowdSec Security Engine | MIT | separate container on sensor hosts; contribute | yes for local alerts from our own logs; no for anything received from CrowdSec | no (keep MIT notice) | Run unmodified Hub scenarios so signals count (#37). Community Blocklist and other CrowdSec-supplied data are third-party data (section 2). | #37 |
| T-Pot | GPL-3.0 | learn-only | no | n/a (nothing distributed) | Study compose and config patterns; do not copy T-Pot files into the repo. | #30 |
| Slips (optional) | GPL-2.0 | separate container (optional analyser on sensor PCAP) | yes for alerts it raises on our own captures | yes | Never link into Foiled code. | #11 |

## 2. Threat intel and enrichment sources

Foiled has one external intel provider, **ThreatSieve**, the operator's own threat intel platform ([enrichment.md](../enrichment.md#threatsieve)). Foiled does not call GreyNoise, CrowdSec or any other source in this table directly: ThreatSieve does, under its own keys, quotas and per-tenant source policy, and returns each source's `redistributable` and `commercial_use` terms with every answer. Those per-source terms are what decide Foiled's handling, so the rows below still apply to the data when it arrives through ThreatSieve.

| Source | SPDX / licence | Use mode | Paid feed? | Source offer? | Notes | Owner |
| --- | --- | --- | --- | --- | --- | --- |
| ThreatSieve (hub) | The operator's own platform; each answer carries the licence record of every source behind it | separate service (Service Binding `THREATSIEVE`, `POST /v1/lookup`) | only answers whose every source is `redistributable: true` and `commercial_use: true` (stored as provider `threatsieve`), with each source's attribution notice (**verify** with counsel before a paid launch); never answers with any restrictive or unknown source (stored as `threatsieve_restricted`, kept per tenant, on `NEVER_REDISTRIBUTE`, and hidden even from the tenant that asked unless the operator sets `show_restricted_to_requester`, a decision for their counsel) | n/a | The strictest source terms in an answer win, because Foiled does not split Facts by source. Unknown (`null`) terms count as restrictive. Provenance is kept on every answer as `threatsieve.sources`. | #11 |
| GreyNoise | Proprietary data and API terms (ThreatSieve records `redistributable: false`, `commercial_use: false`) | API enrich, via ThreatSieve only | no | n/a | Redistribution terms not checked, so assume none. Never shown to other tenants; shown to the tenant whose lookup fetched it only if the operator opts in (`show_restricted_to_requester`). | #11 |
| CrowdSec CTI | Proprietary data and API terms; commercial embedding needs the CrowdSec Partnership Program (ThreatSieve records `false`, `false`) | API enrich, via ThreatSieve only | no | n/a | Reputation, behaviours and linked CVEs are an outside check on our ATT&CK labels (#26). Partnership licence is out of scope. | #11 |
| IPtoASN | PDDL per ThreatSieve's licence record (`true`, `true`) (**verify**) | API enrich, via ThreatSieve | yes | n/a | ASN, AS name, prefix and registry country for routed addresses. | #11 |
| EPSS (FIRST) | Free use with attribution per ThreatSieve's licence record (`true`, `true`) (**verify** current FIRST terms) | API enrich, via ThreatSieve | yes, with attribution | n/a | `cve.epss_score` and `cve.epss_percentile`. | #11 |
| DShield (SANS ISC) | CC-BY-NC-SA-4.0 plus "Do not resell the data"; sensor code GPL-2.0 | contribute (via Cowrie plugin); not used for enrichment (the direct adapter was dropped for ThreatSieve) | no | n/a for data; yes if we ever distributed the GPL-2.0 sensor code | Commercial use only "to protect your own company's network". See the worked answer below. | #11, #37 |
| Shadowserver | Per-subscriber terms (vetted access) | contribute (if they accept partner feeds, **verify**); not used for enrichment | no | n/a | Redistribution not checked, assume none. Subscribe our own sensor ranges for remediation reports. | #11 |
| Hunt.io | Proprietary, paid | not used (the direct adapter was dropped for ThreatSieve) | no | n/a | If ThreatSieve ever adds it as a source, its licence record there decides, and it would be restricted. | #11 |
| Shodan Honeyscore | Proprietary (Shodan API terms, Labs access) | API enrich (self-check of our own sensor IPs) | no | n/a | Used only to detect burnt decoys and trigger rotation. Scores are never published. | #18 |
| NVD (CVE records and CVSS) | US government data, published by NIST for free use; NVD API terms require the notice "This product uses the NVD API but is not endorsed or certified by the NVD." (the wording ThreatSieve's contract gives). CVE descriptions also carry CVE Program terms (**verify**) | API enrich (catalogue sync; CVSS, CWE and status via ThreatSieve) | yes, with attribution notices | no | Prefer referencing CVE IDs and linking out over copying long descriptions. | #5 |
| CISA KEV | CC0-1.0 (per the `cisagov/kev-data` LICENSE) | API enrich (catalogue sync) | yes | no | Do not imply CISA or DHS endorsement or use their logo or seal. Third-party links inside records keep their own terms. | #5 |
| OSV (osv.dev) | Schema and service code Apache-2.0; records keep the licence of each upstream source (for example CC-BY-4.0 for some ecosystems) | API enrich (catalogue sync) | yes, per record, only where the source licence allows and with attribution (**verify** per source) | no | Store the source database and licence alongside each imported record so the export filter can decide. | #5 |
| MITRE ATT&CK STIX data | ATT&CK terms of use: royalty-free licence for research, development and commercial use, provided MITRE's copyright designation and the licence text travel with any copy | embed (pinned STIX bundle) | yes, with MITRE's copyright notice and licence | no | Ship the notice with the bundle and with any export that includes ATT&CK names or descriptions. `data/attack/groups.json` (group ids, names, aliases and technique uses, for #29) carries the same notice; the actor API returns it with the catalogue. | #26, #29 |
| MISP galaxy | JSON clusters dual-licensed CC0-1.0 or a BSD-style licence (per the `MISP/misp-galaxy` README) | embed (pinned cluster files) | yes | no | Some clusters summarise other vendors' reporting; check per-cluster source references before quoting long text (**verify**). | #29, #13 |
| ThreatSieve actor catalogue (imported actors, campaigns, reports) | Each contributing source's terms as ThreatSieve records them (`license`, `redistributable`; commercial use from its licence records) | separate service (operator's own ThreatSieve, service binding) | only entries whose every source is redistributable and allows commercial use; `restricted` entries never leave the console | no | Facts only (names, aliases, ATT&CK ids, technique ids, indicators, URLs, dates), checked by the same rules as curated entries ([actor-attribution.md](../actor-attribution.md#threatsieve)). | #29 |
| Vendor threat reports (curated actor profiles) | Each publisher's own terms, recorded per source in `catalogue/actors/*.yaml` (`licence`, `licence_url`) | embed (facts only: technique ids, indicators, targeting, dates, URL and a SHA-256 pin; never report text) | facts and links only, and only on analyst-confirmed actor links; **verify** per publisher | no | Public documents only; no paid, leaked or access-controlled reports. None shipped yet; the two fictional examples under `testdata/actors/reports/` contain no third-party content ([actor-attribution.md](../actor-attribution.md#curated-reports)). | #29 |
| Government advisories (CISA, ASD's ACSC and other national CERTs) | CISA advisories are US government works (**verify** per advisory, some embed third-party content); ASD's ACSC publications are Commonwealth copyright, many under CC-BY-4.0 (**verify** per publication) | embed (facts only, as for vendor reports) | facts and links only, with attribution where the licence asks; **verify** | no | Do not imply endorsement or use agency logos. | #29 |
| MaxMind GeoLite2 (if used) | GeoLite2 EULA (**verify**) | API enrich (local database, operator download) | no | n/a | Not committed to the repo; operators download it themselves (#11). Country codes in exports: **verify** before use. | #11 |
| Other Cowrie output plugins (VirusTotal, MalShare, URLhaus, AbuseIPDB) | Each provider's own terms (**verify**) | API enrich or contribute (opt-in) | no | n/a | Off by default. Treat any data pulled back as third-party data. | #11 |

## 3. Cloudflare services used by the control plane

All rows: licence is Cloudflare's service terms for the account holder (each operator's own Cloudflare account, not the Foiled project's), use mode `platform`, paid feed `n/a`, source offer `no`. Foiled code must not phone home to Foiled authors (#11). Locations below describe the Cloudflare defaults as we understand them; confirm each against current Cloudflare docs before relying on them for a residency claim (**verify**).

| Service | What Foiled puts there | Where data is stored and processed | Notes | Owner |
| --- | --- | --- | --- | --- |
| Workers | API (Axum via workers-rs) and the React Router front end | Code runs in the Cloudflare location that receives the request (or a placement location); no data at rest beyond logs if Workers Logs is enabled | Request bodies can contain attacker payloads forwarded by sensors: keep them out of logs. | #40 |
| D1 | Config and decoy catalogue | One primary SQLite database in a region chosen at creation (location hint), plus optional read replicas in other regions | No attacker payloads or personal information in D1. | #1, #5 |
| R2 | PCAPs and quarantined files | Bucket stored in the location chosen at creation (location hint, including an Oceania option) or a jurisdiction-restricted bucket where offered | Quarantined malware: private buckets only, never public URLs. Retention per #16. | #9 |
| Queues | Ingest from sensors and enrichment jobs | Messages held by Cloudflare until consumed or until the retention period ends | Payloads are transient but may include attacker data and IPs. | #31, #11 |
| Durable Objects | Live attempt stream (hibernating WebSockets) | Each object runs and stores state in one location, chosen near first use or by location hint; jurisdiction restriction available | Keep stored state small; it is a fan-out cache, not the system of record. | #40 |
| Hyperdrive | Connection pooling to Postgres (attempts and intel) | Postgres stays wherever the operator hosts it (outside Cloudflare); Hyperdrive pools connections and may cache read query results at the edge | Turn query caching off for queries that return personal information or entitlement-gated enrichment. | #1 |
| AI Gateway | Proxy in front of the LLM provider | Logs prompts and responses by default (configurable per gateway); requests forwarded to the chosen provider, whose own terms and data location then apply | Disable or limit logging for prompts that contain attacker payloads or personal information; sanitise first (#28). | #28 |
| Workers AI | Optional LLM inference | Inference runs on Cloudflare's network | Each model carries its own licence and use terms (**verify** per model before use and before putting model output in a paid feed). | #28 |
| Analytics Engine | Radar counters (aggregate counts) | Data points stored by Cloudflare for a limited retention period | Aggregates only; no raw IPs or payloads. | #35 |

Operators with Australian privacy obligations should treat Cloudflare as an overseas recipient and review cross-border disclosure with their own counsel (#16).

## 4. Foiled's own dependencies and assets

Rust crates: versions from `Cargo.lock` at the time of writing. JS packages: versions from `web/package.json`. All are bundled into Foiled builds (`embed`), may ship in a paid offering, and need no source offer, but their licence notices must be kept in distributed builds.

| Component | Version | SPDX / licence | Use mode | Paid feed? | Source offer? | Notes | Owner |
| --- | --- | --- | --- | --- | --- | --- | --- |
| workers-rs `worker` (and `worker-macros`, `worker-sys`) | 0.8.7 | Apache-2.0 | embed | yes | no | Verified on 18 Oct 2026 from crates.io metadata for 0.8.7 and the `cloudflare/workers-rs` repository licence. Keep the Apache-2.0 licence and any NOTICE text. | #40 |
| axum | 0.8.9 | MIT | embed | yes | no | | #40 |
| serde | 1.0.229 | MIT OR Apache-2.0 | embed | yes | no | | #40 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 | embed | yes | no | | #40 |
| jsonschema | 0.59.0 | MIT | embed (`foiled-lint`) | yes | no | | #19 |
| rcgen | 0.14.10 | MIT OR Apache-2.0 | embed (`foiled-hostd` only, never the Worker) | yes | no | Generates the agent's key pair and CSR for enrolment and renewal (#31). Built with the `aws_lc_rs` backend that `reqwest`'s rustls already uses. Pulls in `pem` 4.0.0 (MIT), `yasna` 0.6.0, `time` 0.3.55, `time-core` 0.1.9, `deranged` 0.5.9, `num-conv` 0.2.2 and `powerfmt` 0.2.1 (all MIT OR Apache-2.0). Licences read from each crate's `Cargo.toml` on 18 Oct 2026. | #31 |
| x509-parser, nom, asn1-rs (and `asn1-rs-derive`, `asn1-rs-impl`, `der-parser`, `oid-registry`, `rusticata-macros`, `lazy_static`, `minimal-lexical`, `bit-vec`, `untrusted` 0.7, `synstructure`, `time-macros`) | x509-parser 0.18.1, nom 7.1.3, asn1-rs 0.7.2, asn1-rs-derive 0.6.0, asn1-rs-impl 0.2.0, der-parser 10.0.0, oid-registry 0.8.1, rusticata-macros 4.1.0, lazy_static 1.5.1, minimal-lexical 0.2.1, bit-vec 0.8.0, untrusted 0.7.1, synstructure 0.13.2, time-macros 0.2.32 | x509-parser, asn1-rs, asn1-rs-derive, der-parser, oid-registry, lazy_static, time-macros: MIT OR Apache-2.0; asn1-rs-impl, rusticata-macros, minimal-lexical: MIT/Apache-2.0; bit-vec: Apache-2.0 OR MIT; nom, synstructure: MIT; untrusted: ISC | none today (listed in `Cargo.lock` as optional dependencies of `rcgen`, not compiled with the features we enable) | yes | no | Recorded because they appear in `Cargo.lock`. If a future change enables `rcgen`'s `x509-parser` feature they become embedded in `foiled-hostd`, still under permissive licences. Licences read from each crate's `Cargo.toml` on 18 Oct 2026. | #31 |
| React (`react`, `react-dom`) | 19.3.1 | MIT | embed | yes | no | | #39 |
| React Router (`react-router`, `@react-router/dev`) | 8.4.0 | MIT | embed | yes | no | | #40 |
| Vite | 8.3.4 | MIT | build tool | yes | no | Not shipped at runtime. | #40 |
| OASIS `stix2-validator` (with `stix2-patterns`) | 3.2.0 | BSD-3-Clause (repository `LICENSE` files, read 18 Oct 2026) | CI tool | yes | no | Validates the golden STIX bundles in CI (#13). Installed into a throwaway virtual environment, never shipped or imported. | #13 |
| Biome | 2.5.15 | MIT OR Apache-2.0 (npm metadata) | dev tool | yes | no | Not shipped. | #19 |
| Astro | 7.x (not yet in the repo) | MIT (npm metadata, **verify** at adoption) | embed (`site/`) | yes | no | Public exploit pages. | #35 |
| Inter font (`@fontsource/inter`) | 5.3.0 | OFL-1.1 (npm metadata and package `LICENSE`, copyright The Inter Project Authors) | embed (UI asset, self-hosted woff2, Latin subset, weights 400 to 700) | yes | no | Installed from npm, not committed. Ship the OFL text with distributed builds (it is in the package `LICENSE`; how the release bundles it is **verify**). Do not sell the font on its own. Unmodified, so Reserved Font Name rules are not triggered. | #39 |
| JetBrains Mono font (`@fontsource/jetbrains-mono`) | 5.3.0 | OFL-1.1 (npm metadata and package `LICENSE`, copyright The JetBrains Mono Project Authors) | embed (UI asset, Latin subset, weights 400 to 600) | yes | no | As for Inter. | #39 |
| Rajdhani font (`@fontsource/rajdhani`) | 5.3.0 | OFL-1.1 (npm metadata and package `LICENSE`, copyright Indian Type Foundry) | embed (wordmark only, Latin subset, weight 700) | yes | no | As for Inter. | #39 |
| Natural Earth | n/a | Public domain | embed (map land shapes) | yes | no | Land polygons sampled to a 1.5 degree run-length mask (about 4 KB) in `web/app/components/map/world-land.ts`; no Natural Earth files are committed. No permission or credit needed; credited on the map anyway. | #39 |
| Foiled UI components and icons | n/a | MIT (our own) | embed | yes | no | All components in `web/app/components/` and the icon paths are written for Foiled. No third-party UI kit, icon set or component source is in the tree (#39, [design system](../ui/design-system.md)). | #39 |

Other direct dependencies seen in manifests, for completeness: `http` (MIT OR Apache-2.0), `tower` (MIT), `tower-service` (MIT), `anyhow` (MIT OR Apache-2.0), `serde_yaml_ng` (MIT), `walkdir` (Unlicense OR MIT), dev-only `tokio` (MIT), `http-body-util` (MIT), `tempfile` (MIT OR Apache-2.0), `peak_alloc` 0.3.0 (MIT, read from its `Cargo.toml` on 18 Oct 2026; the export memory bound test in `crates/api/tests/export_bounds.rs`, #13); JS: `isbot` (Unlicense), `wrangler` (MIT OR Apache-2.0), `@cloudflare/vite-plugin` (MIT), `typescript` (Apache-2.0), `vitest` (MIT).

Transitive Rust check on 18 Oct 2026: all 158 crates.io packages in `Cargo.lock` are under permissive licences (MIT, Apache-2.0, BSD, Zlib, Unlicense, MIT-0, BSL-1.0, Unicode-3.0). `r-efi` is offered as `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; we take it under MIT or Apache-2.0. No GPL-only or AGPL crates. The JS transitive tree has not been checked yet; the planned CI check below covers it.

## Hard rules

Mirrored from [landscape.md](../research/landscape.md#licence-blockers-and-implications-summary). These are project rules, not suggestions.

1. **No GPL import into core.** Foiled's own code (control plane, API, MCP, UI, enrichment, confidence engine, host agent) stays MIT. GPL, LGPL and AGPL code is never imported, vendored, linked or copied into `crates/`, `web/` or `site/`. If we want logic from a GPL project inside Foiled, we write it clean-room. Do not copy T-Pot compose or config files wholesale.
2. **GPL modules run as separate containers only**, talking to Foiled over JSON, a socket or a queue.
3. **Ship licences with images and offer corresponding source.** Every image we distribute that contains third-party code keeps the upstream licence files, and for GPL modules we ship or offer the corresponding source and publish our changes under the same licence. The module manifest records the licence and image digest (#30).
4. **Enrichment only for non-redistributable APIs.** GreyNoise, CrowdSec CTI, DShield, Shadowserver, Hunt.io, Shodan and similar sources are shown only to the operator or subscriber who is entitled to them; through ThreatSieve, that is at most the tenant whose lookup fetched them (`threatsieve_restricted`), and only once the operator has opted in with `show_restricted_to_requester` on counsel's advice. They are never resold, republished, or copied into Foiled's own paid feed or public IOC dumps.
5. **Export by allow-list.** Every Fact carries its `provider` (#11). Exports (#13) include only providers this register marks `yes` for the paid feed, so a new provider is excluded until someone adds a row here.
6. **Canarytokens stays a separate service.** No Canarytokens code in core; commercial embedding would need Thinkst's licence.
7. **Attribution travels with data.** ATT&CK exports carry MITRE's notice; NVD-derived data carries the NVD notice; OSV records keep their source licence.

## Never include in a paid feed or public dump

The following must never appear, raw or derived, in a paid Foiled feed, a CSV, STIX, MISP or TAXII export, a public IOC dump or a public exploit page:

- Any ThreatSieve answer with a source that is not redistributable, not for commercial use, or of unknown terms (`threatsieve_restricted` Facts), including its reputation, scanner, relationship and network Facts.
- GreyNoise fields (`noise`, `riot`, `classification`, `name`, tags) and anything computed only from them.
- CrowdSec CTI fields, Community Blocklist, Platinum blocklists and Live Exploit Tracker data.
- DShield data: IP counts, attacks, first and last seen, threat feed membership, and any DShield sensor data.
- Shadowserver report contents and API responses.
- Hunt.io data: C2 pivots, AttackCapture results, HuntSQL output, actor intel.
- Shodan data, including Honeyscore values.
- MaxMind GeoLite2 data and data from opt-in Cowrie output plugins (VirusTotal, MalShare, URLhaus, AbuseIPDB) until a row here says otherwise.
- Data received from SentryPeer peers or the hosted canarytokens.org service until their terms are verified.
- Canary token values, quarantined malware binaries, operator secrets and API keys.
- Personal information beyond what #16 allows, and data from customer edge sensors that have opted out of sharing (#37).

Derived fields count. A score or flag that is computed mainly from one of these sources (for example "known scanner: yes" when only GreyNoise says so) is treated as that source's data. A Foiled score that merely uses third-party data as one weighted input (#27) may be exported as a number, without the third-party inputs or their values; counsel should confirm this before commercial launch (**verify**).

## Worked answer

**May we put DShield fields in the paid CSV?** No. DShield's API terms state the data is licensed CC BY-NC-SA 4.0 and say "Do not resell the data". A paid CSV is commercial use, which NonCommercial forbids, and it is resale, which the API terms forbid. ShareAlike would also require the CSV to be released under CC BY-NC-SA, which conflicts with paid subscription terms. The only commercial use DShield allows is protecting your own network, so DShield fields may appear as enrichment in an operator's own console but must be stripped from every export. Our own observations of the same IP (Foiled-origin attempts, timestamps, payload hashes) may go in the CSV. Contributing our Cowrie data to DShield (#37) is fine and does not change this answer.

## CI enforcement (planned)

Not implemented yet. To be built with the CI work in #19 and tracked here.

- **Rust:** a `cargo-deny` licence check (a `deny.toml` at the repo root) that allows only permissive licences (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unlicense, MIT-0, BSL-1.0, Unicode-3.0, CC0-1.0) and fails on GPL, LGPL-only, AGPL or unknown licences. `OR` expressions such as `r-efi` resolve to the permissive option. It also bans unknown registries and git sources so unreviewed code cannot slip in.
- **JS:** a licence check over the pnpm lockfile for `web/` (and `site/` once it exists), for example a small script over `pnpm licenses list --json`, with the same allow-list.
- **Vendored code:** a path check that fails any PR adding files under `crates/`, `web/` or `site/` that carry a GPL, LGPL or AGPL SPDX header, licence text or `COPYING` file. Lockfile tools do not see copied source, so this check is the one that catches vendoring.
- **Exceptions** need a row in this register in the same PR and a maintainer review. The decoy module images (#30) are exempt because they live outside the MIT source tree and ship their own licences.
- **Register drift:** later, a check that every `provider` value in the enrichment config (#11) has a row here, so a new source cannot reach exports unreviewed.

## Before any commercial launch

Counsel must review this register before Foiled offers a paid feed or any commercial service, in particular: the paid-feed column, the derived-fields rule, the NVD and CVE notice wording, OSV per-source licences, Workers AI model terms, Cloudflare data locations for Australian customers, and the out-of-scope commercial licences (Thinkst Canarytokens embedding, CrowdSec Partnership Program).

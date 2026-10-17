# Catalogue sync from KEV, OSV and NVD

Status: design. The scheduled job lands later (#19 lists `catalogue-sync.yml` as optional and disabled until this exists).

Sync proposes catalogue changes. It never publishes them. Every proposal is a `draft` that a human reviews before it becomes `verified`.

We do not claim complete CVE coverage. The catalogue is curated: sync only proposes entries for products we can actually run as a sandbox or emulate faithfully, and a reviewer can always say no.

## Inputs

| Source | What we read | Access | Notes |
| --- | --- | --- | --- |
| CISA Known Exploited Vulnerabilities (KEV) | The public JSON feed: `cveID`, `vendorProject`, `product`, `dateAdded`, `shortDescription`, `knownRansomwareCampaignUse`. | Public download, no key. | Strongest signal that a CVE is worth a decoy. Polled at most daily. |
| OSV | Records by ecosystem and id: affected package, version ranges, aliases (CVE ids), references. | Public API and bulk export, no key. | Best source of exact affected version ranges for open source software. |
| NVD | CVE records: CVSS severity, CPE matches, references. | Public API. An NVD API key raises the rate limit; it is optional, read from the `NVD_API_KEY` environment variable, and never committed. | Rate limits apply. Respect them and back off on 403 or 429. |
| Vendor advisories | Links only, added by the reviewer. | Public pages only. | We do not scrape behind logins. |

Licence and terms for each source are tracked in the licence and data-terms register (#38).

## Match rules

A KEV item becomes a draft proposal when all of these hold:

1. **Product match.** `vendorProject` and `product` match an existing catalogue product, or a product on the emulation backlog list in the sync config. Matching is case-insensitive on a normalised name table kept in the sync config, not fuzzy text search.
2. **Version range known.** OSV or NVD gives an affected range, so we can pick a concrete vulnerable version to pin.
3. **Buildable or emulable.** For `sandbox`, the upstream release can be legally fetched and rebuilt (#6). For `emulation`, an emulator or module exists, or the backlog item says one is planned.
4. **Not already present.** No existing entry lists the same `cve_id` for the same product and version.

When an existing entry's product and version fall in a newly published affected range, sync proposes adding the CVE to that entry's `cves` list instead of creating a new entry.

Each proposal records `sources` (`kev`, `osv`, `nvd`) on the CVE item and the advisory URLs in `sources`.

## Output

Sync writes files under `catalogue/entries/` with `status: draft` on a branch and opens a pull request. It does not push to `main`, and it never sets `verified`.

## Human review

A reviewer checks, before moving an entry to `verified`:

- the version is really affected (read the advisory, not just the range);
- the artefact exists: a recipe that builds, a digest that resolves, or an emulator profile that exists;
- the redistribution licence is fine for the image or module (#38);
- `risk_notes` say whether the issue is wormable and what containment matters;
- no exploit code was added anywhere.

## Worked example (illustrative only)

This uses a made-up record. `CVE-2099-0001` is not a real CVE.

1. KEV adds `CVE-2099-0001`, `vendorProject: Redis`, `product: Redis`, `dateAdded: 2099-01-10`, description "unauthenticated command abuse".
2. Product match: `Redis` is in the normalised table and maps to `emulator/redis/*`.
3. OSV lists affected `>=7.0.0, <7.0.12` for the Redis server package. NVD gives severity `high`.
4. An entry `emulator/redis/7.0` already pins `7.0.11`, which is in range. Sync proposes adding `{cve_id: CVE-2099-0001, severity: high, sources: [kev, osv, nvd]}` to it, with the KEV and OSV links in `sources`.
5. The pull request stays `draft` until a reviewer confirms the emulator profile actually answers the commands the advisory describes. If it does not, the reviewer either closes the proposal or opens an emulator issue (#30).

## Constraints

- Respect each source's licence and rate limits. Cache responses and poll at most daily.
- No scraping behind logins, no paid feeds.
- No API keys or NVD tokens in the repository. Keys come from environment variables or CI secrets by name only.
- Do not name or imply affiliation with any commercial honeypot-as-a-service vendor in generated entries.

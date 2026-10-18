# Operator console

Status: implemented in `web/` for #14. This is the dashboard plan the issue asks for (`docs/ui/dashboard.md` in the issue text). Design system: [design-system.md](design-system.md) (#39). Copy rules: [voice.md](voice.md). Hosting: [ADR 0009](../adr/0009-axum-workers-and-front-end.md) (#40).

The console is the trusted, signed-in side of Foiled: operators launch decoys, triage attempts, review links, work campaigns and IOCs, and export. It is not a marketing site and is never served from a honeypot address. It runs as its own Worker (`foiled-web`) and only talks to the control plane (#21) over the `API` Service Binding, using server loaders and actions. The browser never calls the API and never holds an API token.

## Routes

Every route except `/login` and `/design` needs a signed-in operator. Scopes are enforced by the API; the console hides controls a token cannot use so operators are not offered actions that will fail.

| Route | What it does | API calls | Scopes |
| --- | --- | --- | --- |
| `/login`, `/logout` | Sign in with an operator token; sign out. | `GET /v0/whoami` | any operator token |
| `/` | Overview: KPIs, latest attempts (live feed), decoys that need attention, API health. | `GET /v0/decoys`, `/v0/attempts`, `/v0/campaigns`, `/v0/review-queue`, `/healthz` | read scopes |
| `/live` | Live feed backfill as JSON (resource route, see [Live feed](#live-feed)). | `GET /v0/attempts?since=` | `attempts:read` |
| `/search?q=` | Jump box: attempt, campaign and IOC ids open their page; CVE and ATT&CK ids and source addresses filter attempts; anything else searches IOC values. | none | |
| `/launch` | Launch wizard: choose an entry, placement and lifetime, confirm. | `GET /v0/catalogue/entries`, `GET /v0/sensors`, `POST /v0/decoys`, `GET /v0/audit` | `catalogue:read`, `decoys:write`, `decoys:elevate` for drafts |
| `/decoys`, `/decoys/:id` | Decoy list; status until healthy, actions and teardown with a reason, audit trail. | `GET /v0/decoys`, `GET /v0/decoys/{id}`, `POST /v0/decoys/{id}:{action}`, `GET /v0/audit?target=` | `decoys:read`, `decoys:write` |
| `/attempts`, `/attempts/:id` | Attempt list with filters; detail with timeline, confidence explainability, analyst overrides and IOCs. | `GET /v0/attempts`, `/v0/attempts/{id}`, `/timeline`, `/links`, `/iocs`, `POST /v0/attempts/{id}/links` | `attempts:read`, `attempts:write`, `iocs:read` |
| `/review` | Review queue: claim, release, approve, reject, snooze and promote to a write-up, with notes. | `GET /v0/review-queue`, `POST /v0/review-queue/{id}/actions` | `review:read`, `review:write` |
| `/writeups`, `/writeups/:id` | Research write-ups: start, edit drafts, lint findings, submit, second review with checklist, publish, withdraw, versions. | `GET`/`POST /v0/write-ups`, `GET`/`PATCH /v0/write-ups/{id}`, `/transitions`, `/versions` | `review:read`, `review:write`, `review:publish` |
| `/radar` | Operator radar: counts, trends and headlines for the tenant or the fleet. Trusted side only. | `GET /v0/radar` | `review:read` |
| `/actors` | Actor possible-associations with what matched, public sources and decisions. | `GET /v0/actor-links`, `POST /v0/actor-links/{id}/decision` | `campaigns:read`, `review:write` |
| `/campaigns`, `/campaigns/:id` | Campaign list; members, shared features, evidence and bridges, actor associations, analyst actions. | `GET /v0/campaigns`, `/{id}`, `/evidence`, `/actions`, `POST /actions` | `campaigns:read`, `campaigns:write` |
| `/iocs`, `/iocs/:id` | IOC browser and detail. | `GET /v0/iocs`, `GET /v0/iocs/{id}` | `iocs:read` |
| `/exports`, `/exports/download` | Export form; the download is proxied through the Worker. | `GET /v0/exports/iocs.csv`, and from #13 `iocs.json`, `stix`, `misp` | `exports:read`, `review:write` for unreviewed |
| `/quarantine` | Quarantined file metadata; downloads off by default, double confirm when on. | `GET /v0/quarantine`, `POST /v0/quarantine/{sha256}:download` | `quarantine:read`, `quarantine:download` |
| `/registry` | Hosts and sensors: register (one-time enrolment token), re-enrol, revoke. | `GET`/`POST /v0/hosts`, `/v0/sensors`, `:revoke`, `:reenrol` | `hosts:*`, `sensors:*` |
| `/audit` | Audit log with action and target filters. | `GET /v0/audit` | `audit:read` |

### API coverage

This is the list the issue asks to match against #21, #25, #33, #34 and #35.

| Area | Issue | State of the API on `main` | Console |
| --- | --- | --- | --- |
| Catalogue, decoys, audit | #21, #8 | Served | Served |
| Caller identity, `GET /v0/whoami` | #14 | Added by this change | Sign-in |
| Attempts, timeline, links, overrides | #25, #10, #27 | Served. `PATCH /v0/attempts/{id}` (label, merge, split) is planned | Served; attempt labelling waits for #25 |
| IOCs | #34 | Served | Served |
| Campaigns and actions | #33 | Served | Served |
| Hosts and sensors | #31, #41 | Served | Served |
| Exports | #13 | IOC CSV served; IOC JSON, STIX and MISP downloads in the #13 pull request | All formats in the form; unserved ones report "not served yet" |
| Review queue, write-ups, radar | #35 | In PR #84, not on `main` yet | Built against PR #84's API and schemas, checked against copies of its golden output (`web/app/test/pr/`); marked `TODO(#35)` |
| Actor associations | #29 | In PR #83, not on `main` yet | Built against PR #83's API and `actor-link` schema; marked `TODO(#29)`. Campaigns and attempt links show any actor links the API returns, always "possible association" |
| Quarantine list and download | #9, #14 | Planned | Built against the proposal in `api-types.ts` (marked `TODO`), downloads off by default |
| Live event stream, `GET /v0/events` | #14 | Planned | Polling backfill now; see [Live feed](#live-feed) |

When an API route is not served yet, the API's router falls through with `404 not_found: route not found`. The console recognises that answer and shows "not served yet" with the owning issue instead of an error.

## Sign in and sessions

1. **Cloudflare Access** sits in front of the console hostname (docs/deploy/workers.md). When `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set, the Worker also verifies the `Cf-Access-Jwt-Assertion` JWT on every request (RS256 against the team's published keys, audience, issuer, expiry) and answers 403 without it, so a missing Access policy fails closed (`web/app/lib/access.server.ts`).
2. **Operator token.** The operator pastes an API token (`fo_<id>.<secret>`) into `/login`. The Worker calls `GET /v0/whoami` with it. Only `human` role tokens may sign in; MCP, host and sensor credentials are refused.
3. **Session cookie.** The token, the caller's id, tenant and scopes, and a random CSRF token are sealed with AES-256-GCM under a key derived (HKDF-SHA-256) from the `SESSION_SECRET` Worker secret, and set as `__Host-foiled_session` with `HttpOnly`, `Secure`, `SameSite=Strict` and `Path=/`. Sessions last at most 12 hours. The token is never sent to page scripts, never written to browser storage and never put in a loader response (`web/app/lib/session.server.ts`).
4. **Every API call** is made by the Worker with the session's token. The console never sends a tenant id: tenant scoping is the API's job, and another tenant's resource is a 404.
5. **Expiry and revocation.** When the API answers 401 (token expired or revoked), the console clears the cookie and sends the operator to `/login`, keeping the page they were on in `?next=` (same-site paths only).
6. **Sign out** is a CSRF-checked POST that clears the cookie.

### CSRF

Three layers, all required for every form post:

- `SameSite=Strict` keeps the session cookie off cross-site requests.
- The `Origin` header must be the console's own origin, and `Sec-Fetch-Site` must not name another site.
- Every form carries the session's CSRF token in a hidden field, compared in constant time.

Sign-in has no session yet, so it relies on the origin check. Export downloads are POSTs for the same reason as other writes: unreviewed exports are audited.

### Response headers

Every response gets `Content-Security-Policy: frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin` and `Cache-Control: no-store` unless the route sets its own. A `script-src` policy needs per-request nonces for React Router's hydration script and is left for later.

## Launch wizard

Three steps, each its own URL so the browser's back button works and the wizard needs no client state:

```text
+--------------------------------------------------------------------------------+
| Launch a decoy                      (1 Choose an entry) 2 Placement  3 Confirm |
| Kind: (o) All ( ) Sandbox ( ) Emulation   CVE id [            ]  [ ] Drafts   |
|--------------------------------------------------------------------------------|
| PRODUCT                       KIND       STATUS    CATALOGUE CLAIMS  PORTS     |
| Foiled demo app 1.0.0         sandbox    verified  1 CVE claim (crit) 8080/tcp [Choose]
| ExampleVPN portal generic     emulation  verified  none              443/tcp  [Choose]
+--------------------------------------------------------------------------------+

+------------------------------------+  +---------------------------------------+
| FOILED DEMO APP 1.0.0     sandbox  |  | RISK NOTES                            |
| Runs the real, vulnerable software |  | Deliberately vulnerable synthetic app |
| in an isolated sandbox ...         |  | ... Not wormable.                     |
| Catalogue claims (not attempt      |  | This entry is a draft ... (if draft)  |
| links): FOILED-DEMO-0001 critical  |  +---------------------------------------+
+------------------------------------+
| Label [          ]  Lifetime [24 hours v]                                      |
| Placement (o) Research host pool  ( ) Edge sensor [Choose a sensor v]          |
| [ ] Launch this draft entry (needs decoys:elevate)       [Back] [Review launch] |
+--------------------------------------------------------------------------------+

+------------------------------------+  +---------------------------------------+
| CONFIRM LAUNCH                     |  | RISK NOTES (again)                    |
| Entry, kind, status, label,        |  +---------------------------------------+
| lifetime, placement, egress: deny  |
| Writes decoy.create to the audit   |
| log as tok1 in tenant t1.          |
+------------------------------------+
| [x] I have read the risk notes            [Change settings] [Launch decoy]      |
| Recent launches (audit log): ...                                               |
+--------------------------------------------------------------------------------+
```

Rules (`web/app/lib/launch.ts`, enforced again by the API):

- Both `sandbox` and `emulation` entries are listed; the kind filter and each entry say which. Sandbox entries can only go to the research host pool or a sensor with `sandbox_allowed`; sensors that cannot take an entry are listed but disabled, with the reason.
- Drafts are hidden until asked for, and launching one needs an explicit tick and `decoys:elevate`. Deprecated entries cannot be launched.
- Lifetime is one of 1 hour, 6 hours, 24 hours (default), 3 days or 7 days (the API maximum).
- The confirm step needs the risk notes acknowledged. The form carries an `Idempotency-Key` minted when the page rendered, so a double submit creates one decoy.
- After launch the decoy page refreshes every 5 seconds while the decoy is `pending`, `starting` or `rotating`, paused while the tab is hidden, and stops once it settles.
- Teardown and every other decoy action (reset, rotate, stop, mark compromised, destroy) need a reason code and text, which are audited. Destroy also needs a tick box. Each action has its own idempotency key.
- Catalogue CVE lists are labelled "catalogue claims": they describe the software, not an attempt, so they are not shown with confidence chips (see [voice.md](voice.md)).

## Attempt detail and confidence explainability

```text
att_43065706a9ac936e970054e5  [post-exploitation]
+-------------------------------------+  +--------------------------------------+
| ATTEMPT                             |  | STATE AND NOISE                      |
| Source 203.0.113.7  Decoy dcy-demo-1|  | probe on first contact               |
| Entry foiled/demo-app/1.0.0 sandbox |  | exploit on hook trigger              |
| First and last seen, events,        |  | post-exploitation on hook post exp.  |
| campaign                            |  | Noise: mixed, score 40, 2 decoys     |
+-------------------------------------+  | Hook hits: upload-path-traversal     |
                                         |   FOILED-DEMO-0001 [PROBABLE 100]    |
                                         +--------------------------------------+
TIMELINE
 +0.000s  Connect   application, info: GET /admin (state probe on first contact)
 +1.010s  Hook hit  hook, high: hook ... fired at trigger      FOILED-DEMO-0001 [PROBABLE 100]
 +1.030s  Egress blocked  egress, info: egress to 192.0.2.80:80 (blocked)
 Packet capture slice: filter, from, to, R2 prefix, output path

CVE, TECHNIQUE, CAMPAIGN AND ACTOR LINKS
+--------------------------------------------------------------------------------+
| CVE FOILED-DEMO-0001                                              Band high    |
| CONFIDENCE                                                       Probable 100  |
| We assess as an attempt against FOILED-DEMO-0001. Score 100 of 100, not        |
| confirmed by an analyst.                                                       |
| [=====================================================================]        |
| AT  SIGNAL                         SOURCE                  POINTS              |
|     probe, upload, write in order  Request sequence          +36               |
|     vulnerable path ran            Vulnerable-path hook      +60               |
|     decoy stood up for this CVE    Catalogue prior           +10               |
| CAPS APPLIED: none                                                             |
| EVIDENCE: signal id, source, weight, summary for every item                   |
| Publishable in exports | Candidate for the review queue | May promote state   |
| ANALYST OVERRIDE (audited as link.override)                                    |
| ( ) Confirm  ( ) Reject  ( ) Unsure   Note [                    ] [Record]     |
+--------------------------------------------------------------------------------+
INDICATORS: type, value (defanged), roles, last seen, sightings, confidence
```

- The score, band and wording come from the API; the console never recomputes a score. The ledger lists each contribution as recorded, the caps that applied (for example "LLM-only evidence capped below high") and every evidence item.
- Wording: CVE and technique links say "we assess as" until an analyst confirms; actor links say "possible association" (only "confirmed association" when the API says so); campaign links say "possible". Chips follow `confidenceFromLink`: only an analyst confirmation is Confirmed, unconfirmed `high` is Probable, the rest Assessed.
- Overrides (`true_positive`, `false_positive`, `unsure`) need a note and are audited by the API as `link.override`. IOC links are scored per IOC and cannot be overridden per attempt.
- Detail pages pass the list page's `since` and `until` on, so attempts older than the API's default 7 day window still resolve.
- Each panel loads on its own: a failing timeline shows an error in place and the rest of the page still renders.

## Review queue

```text
REVIEW QUEUE   2 matching. Highest priority first; overdue items lead.
Status [pending v]  Kind [Any v]  Window [7 days v]  [ ] Mine  [ ] Overdue only  [Apply]
+--------------------------------------------------------------------------------+
| CVE LINK rq_15a38fb1dc8c423af7110a00                           open  overdue   |
| We assess as an attempt against FOILED-DEMO-0001 on foiled/demo-app/1.0.0 ...  |
| [PROBABLE 98] We assess as an attempt against FOILED-DEMO-0001. Score 98 ...   |
| Queued 2026-10-18 02:02 (5h 00m ago), due 2026-10-19 02:02 (24h SLA) . att_... |
| Note (audited; required to approve or reject) [                          ]     |
| Snooze for [7 days v]                                                          |
| [Claim] [Approve] [Reject] [Snooze] [Start a write-up]                         |
+--------------------------------------------------------------------------------+
```

One queue over pending CVE and technique links, pre-disclosure candidates, IOC publication candidates, campaign labels, actor possible-associations and write-ups in review (#35, PR #84). Each item is worded like the link it stands for. Claim and release take an item; approve needs a note (a campaign label also needs the title, a write-up the full second-reviewer checklist); reject needs a note; snooze is 1, 7 or 30 days (the API's limit is 30); "Start a write-up" promotes the item to a draft and opens it. Every action sends the item's `version`, so a stale page gets a 409 instead of overwriting someone else's decision, and is audited by the API as `review.<action>`. An item claimed by someone else shows who holds it and offers no actions.

## Write-ups

Drafts are edited in the console (title, summary, Markdown body, TLP, embargo, CVE and technique ids, redacted payload) with the write-up's `version`. The body is always shown as Markdown source in a text block: the console never renders it as HTML. Lint findings from the API are listed by severity; errors block submit, approve and publish. Moves follow the API: submit, send back (needs a note), approve (a reviewer who is not the author, every checklist item), reopen, publish (needs `review:publish`, TLP:CLEAR and a tick box) and withdraw. The version history lists every change.

## Radar

The operator radar is trusted side only; the console has no public radar. It shows the tenant's own counts or the fleet's (opted-in sensors behind the share policy's minimum sources, sensors and edge tenants), per CVE, technique, campaign and product: wording, best band, attempts, sources, trend and a daily sparkline, plus headline cards built from publishable counts only. The thresholds that applied and any held-back buckets are stated above the data.

## Actor associations

Each link from PR #83's matcher shows the API's own `statement` (the only sentence the API allows for it), the label and whether it is a nexus, cluster or named group, the score as "possible association" (only "confirmed association" after an analyst confirms), what matched (techniques with rarity, indicators shown defanged, targeting), what was not counted, and the public sources with publisher, date and licence. Confirm needs a note; reject and reopen are recorded too, all audited by the API. Example data is labelled. Campaign pages link to the actor evidence for that campaign.

## Campaign detail

```text
Payload hash 5e8848... on 3 decoys        cmp_2eb2760245d4b65e168cb56f [active]
+-------------------------------------+  +--------------------------------------+
| CONFIDENCE              Assessed 55 |  | SUMMARY                              |
| Possible campaign: these attempts   |  | First, last seen; attempts, decoys,  |
| may share an operator. Score 55 ... |  | sensors; targeting pattern; seed     |
| ledger of contributions             |  | Caps: CampaignCluster capped at 55   |
+-------------------------------------+  +--------------------------------------+
SHARED FEATURES: source addresses, stage 2 URLs, callbacks, ASNs, techniques ...
MEMBERS  [ ] attempt  source  decoy  state  noise  joined by (feature, strength, value)
         Note [        ]  [Split ticked attempts into a new campaign]
ACTOR ASSOCIATIONS: Possible association with <public cluster> (public reporting: link)
EVIDENCE: bridges (merges made permanent; "small halves: audit" flagged),
          possible links refused, one explainer per member link
ANALYST ACTIONS: history, then forms to set title, status, feedback and merge
```

All values from the clustering (`display`, `values`, titles) are escaped by the API and made printable again by the console. Report links for actor associations are clickable only when they are `https:`.

## IOC browser

```text
IOCS   Value [203[.]0[.]113[.]7      ] Type [Any v] Role [Any v] Window [7 days v]
       [ ] Only from attempts without a captured file                   [Search]
TYPE   VALUE (DEFANGED)        ROLES    LAST SEEN         SIGHTINGS ATTEMPTS CONFIDENCE
IPv4   203[.]0[.]113[.]7       source   2026-10-18 03:30          3        1 [ASSESSED 40] Detail
```

The value search is exact and accepts defanged input. The console renders only the API's `display` field (defanged and escaped), never `value`. Long values are shortened in the middle with the full value one click away. The detail page shows roles, origin, redaction and the file-IOC-limited note, enrichment context with its provider and shareability, fingerprint steps, the confidence ledger and where the indicator was seen.

## Exports

A form posts to `/exports/download`, which calls the API with the session's token and streams the file back with `Content-Disposition: attachment`. Formats: source IP CSV (served today), and from #13 the IOC CSV, IOC JSON, STIX 2.1 bundle and MISP event. Options follow the #13 parameters: window, TLP, minimum confidence, attempt state, decoy kind, campaign, actor links, payload strings, and unreviewed links.

Markers: the file name carries the format, the TLP, the date and `-unreviewed` and `-partial` when they apply, for example `foiled-stix-tlp-amber-strict-20261018-unreviewed.stix.json`. Unreviewed exports need `review:write`, are audited by the API and are raised to TLP:AMBER+STRICT or stricter; the console names the file with the raised TLP. A file cut at the API's read cap (`x-foiled-truncated: true`) is named `-partial`.

## Quarantine

Malware downloads are **off by default**. They turn on only when the console Worker has `QUARANTINE_DOWNLOADS=on` and the token has `quarantine:download`. Each download then needs two confirmations: choosing the file opens a confirm panel, and the analyst must tick "I will handle this file as live malware", type the full SHA-256 back and give an audited reason. Only then does the console ask the API to mint a one-time `https:` link. `TODO(#9, #14 follow-up)`: the list and download endpoints are planned; the request and response in `api-types.ts` are the console's proposal.

## Hosts and sensors

The registry lists hosts and sensors with status, sandbox permission, last seen, certificate expiry and network changes. Registering mints a one-time enrolment token that is shown once in the response and never stored by the console. Re-enrol and revoke need a reason; revoke also needs a tick box because it is final. When the CA could not revoke a certificate, the console says to finish it in the Cloudflare dashboard.

## Live feed

The overview's "Latest attempts" panel is the live feed.

- **Now (polling):** the browser asks `/live?since=<cursor>` every 15 seconds while the tab is visible. The cursor is the newest `last_seen` the feed holds. The answer is every attempt with activity since then, merged into the feed by attempt id (a returning attempt moves to the top with its new state; a stale answer never overwrites newer state). The newest 20 are kept.
- **Reconnect:** after a failure the next try waits 30 seconds, then 60, then at most 120, each with up to 20 per cent jitter so many consoles do not return together after a deploy. The indicator shows "Paused" until a poll succeeds again.
- **Backfill:** when the tab becomes visible again, or after a failure clears, the feed asks from its cursor at once, so nothing that happened while away is lost. The API reads at most 31 days; a client away longer gets what fits and the feed says some activity could not be backfilled. The same note appears when one read was truncated.
- **Later (#14 follow-up, `GET /v0/events`):** the Durable Object stream (ADR 0009) pushes events over a hibernating WebSocket. Every deploy drops those connections, so the client keeps the same cursor and on every reconnect first backfills from `/live?since=<cursor>`, then resumes the stream. The polling path stays as the fallback.

## Loading, empty and error states

- Client navigations show a thin progress rule at the top of the content, `aria-busy` on `main` and a polite "Loading" announcement. Submit buttons say "Working..." while their form is in flight.
- Every list has an empty state that says what would make something appear.
- Each API read is loaded on its own: a failure renders an error in place of that panel and the rest of the page still works. Planned routes say "not served yet" with their issue. A detail page whose main record is missing shows "Not found, or not visible to your tenant." inside the console shell.

## Attacker text

Attacker-controlled fields (sources, paths, labels, timeline summaries, IOC values, campaign values, guest paths, notes from the API) are rendered only as React text children after `toPrintable`, which shows control, bidi and invisible characters as `\xNN` or `\u{NNNN}`. No component or route uses `dangerouslySetInnerHTML` (a test scans every source). Ids taken from URLs and forms are checked against their formats before they are put into an API path, so a crafted id cannot reach another API route.

## Accessibility

- Skip link, landmarks (`nav`, `main`, labelled search), one `h1` per page, captioned tables with scoped headers.
- Every form control has a label; groups use `fieldset` and `legend`; hints and errors are tied with `aria-describedby` and `aria-invalid`; action results are announced (`role="status"` or `role="alert"`).
- The focus ring from the design system applies to every link, button, input, select and textarea. Wizard steps mark the current one with `aria-current="step"`.
- Colour never carries meaning alone: state tags spell the state, chips spell the level, notices have titles.
- Reflow: below 1280px two-column panels stack; below 720px the sidebar stacks above the content and fact lists become single column.
- New colour pairs are asserted in `web/app/lib/contrast.test.ts` and listed in [design-system.md](design-system.md#contrast).

## Configuration

| Setting | Where | Default | Purpose |
| --- | --- | --- | --- |
| `SESSION_SECRET` | Worker secret (`wrangler secret put SESSION_SECRET`), or `web/.dev.vars` locally | none: sign-in refused | At least 32 random characters. Rotating it signs everyone out. |
| `QUARANTINE_DOWNLOADS` | Worker variable | off | `on` enables the double-confirm download flow. |
| `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD` | Worker secrets | unset: check skipped | Verify Cloudflare Access JWTs in the console Worker. Set both in production. |

Local development: put `SESSION_SECRET` in `web/.dev.vars` (ignored by git) and run the API Worker locally so the `API` Service Binding resolves. Sign in with a token from the mock or a local D1. No real tokens belong in the tree.

## Tests

Route tests (`web/app/routes/*.test.tsx`) run the real route config, loaders, actions and components through React Router's static handler against a fake `API` binding (`web/app/test/harness.tsx`), using the repository's golden API output from `testdata/` as fixtures. They cover sign-in, sessions and CSRF, the wizard for both decoy kinds, decoy teardown, triage and overrides, review decisions, campaigns, IOCs, exports, quarantine, the registry, hostile attacker text and the issue's mock happy path (launch an emulator profile, see the attempt, confirm the CVE from the queue, export). `api-types.test.ts` checks the console's types against the JSON Schemas, and `client-safety.test.ts` checks that no source outside server modules reaches for the token or browser storage.

## Not in this change

- `GET /v0/events` and its Durable Object: the polling feed and its reconnect and backfill rules above are what the stream will plug into.
- The quarantine list and download endpoints in the API (#9, #14 follow-up): the console is built against a proposal and says "not served yet".
- The review queue, write-up and radar API (#35, PR #84) and actor links (#29, PR #83) are not on `main` yet: the console is built against those pull requests and says "not served yet" until they merge. Swap the copies in `web/app/test/pr/` for imports from `testdata/` and `schemas/` when they do.
- Attempt labelling, merge and split (`PATCH /v0/attempts/{id}`, #25, planned).
- Forwarding the Access JWT to the API Worker: the API does not validate Access tokens yet.
- Full RBAC, mobile layouts beyond reflow, and MCP (#24) are out of scope for #14.
- TypeScript types are written from the JSON Schemas with a drift test rather than generated from the OpenAPI spec; generation needs a new dependency.

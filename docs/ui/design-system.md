# Foiled design system (v3 red threat console)

Status: implemented for the operator console in `web/`. Owner: #39.

This is the UI source of truth for the operator dashboard (#14) and the public exploit pages (#35). Both use the same tokens and components rather than inventing a second look. The front end runs on Workers as decided in #40 ([ADR 0009](../adr/0009-axum-workers-and-front-end.md)).

- Visual direction: [design-direction.md](../design/design-direction.md) (v3 section). Where v1 or v2 rules conflict with v3, v3 wins.
- Primary target: [mockup-v3.png](../design/mockup-v3.png) and [mockup-v3.html](../design/mockup-v3.html).
- Copy rules: [voice.md](voice.md).
- Live showcase: the `/design` route in the console renders every component with labelled example data.

## Files

| Path | What it holds |
| --- | --- |
| [web/app/styles/tokens.css](../../web/app/styles/tokens.css) | CSS custom properties: palette, confidence colours, type, spacing, radius, layout, focus ring, glow. Framework neutral. |
| [web/app/styles/base.css](../../web/app/styles/base.css) | Element defaults, focus outline, `.sr-only`. |
| [web/app/styles/components.css](../../web/app/styles/components.css) | Component classes and the mockup-v3 dashboard grid. |
| `web/app/components/` | React components with typed props. No third-party UI kit. |
| [web/app/fixtures/example-data.ts](../../web/app/fixtures/example-data.ts) | Example fixtures (RFC 5737 IPs, `CVE-2099-EXAMPLEn` ids). |
| [web/app/routes/design.tsx](../../web/app/routes/design.tsx) | The `/design` showcase. |
| [web/app/components/map/world-land.ts](../../web/app/components/map/world-land.ts) | Coarse land mask for the attack map (about 4 KB). |

Astro pages (#35) can import `tokens.css` and `base.css` directly; the class names in `components.css` are plain CSS and do not depend on React.

## Tokens

### Palette

Names and values match the v3 table in design-direction.md exactly. A unit test (`web/app/styles/styles.test.ts`) parses that table and fails if `tokens.css` drifts. Biome's formatter writes hex in lower case; the test compares case-insensitively.

| Token | Hex | Use |
| --- | --- | --- |
| `--bg` | `#07080A` | Page background |
| `--side` | `#0B0C0F` | Sidebar |
| `--panel` | `#101216` | Cards and panels |
| `--panel-2` | `#14171C` | Raised controls, map overlays |
| `--line` | `#1F232A` | Card borders |
| `--line-2` | `#2A2F37` | Control borders |
| `--text` | `#E6E8EB` | Primary text, KPI values |
| `--muted` | `#8A9099` | Secondary text, table headers, placeholders |
| `--dim` | `#5B616B` | Decorative and large text only (see contrast) |
| `--red` | `#E5252A` | Primary accent: active nav rule, bars, sparklines |
| `--red-bright` | `#FF3B3F` | Hotspots, CVE ids, rising trends, live dot, focus ring |
| `--red-deep` | `#3A0D0F` | Active segment and badge fills |
| `--amber` | `#F2A93B` | Confidence: assessed; example data banner |
| `--blue` | `#4C8DF6` | Confidence: probable (chip text uses `--blue-text` `#7FC4F0`) |
| `--green` | `#3FB68B` | Confidence: confirmed; falling trends; healthy sandboxes |

Supporting tokens: `--blue-text`, `--map-land` (`#1A1D22`), `--map-dot` (`#3A3F48`), `--map-sea`, `--text-2` (table body), `--nav-text`, `--bar-from` (bar ramp start `#7A1114`), hotspot colours, `--chip-fill`, `--red-line`, and `--conf-*` fill and border tints for the three confidence levels.

### Type

| Token | Value | Use |
| --- | --- | --- |
| `--font-ui` | Inter, then system sans | UI, headings, KPI numbers (600, 30px) |
| `--font-mono` | JetBrains Mono, then system mono | IPs, CVE ids, counts, offsets, chips |
| `--font-wordmark` | Rajdhani 700 | FOILED wordmark only |

Sizes: `--text-xs` 10px, `--text-sm` 12px, `--text-md` 13px (base), `--text-lg` 15px, `--text-kpi` 30px, `--text-wordmark` 26px. Panel titles are uppercase with `--tracking-title` (0.1em).

Fonts are self-hosted from `@fontsource/inter`, `@fontsource/jetbrains-mono` and `@fontsource/rajdhani` (all OFL-1.1, recorded in the [licence register](../compliance/licence-register.md)). Only the Latin subset and the weights in use are imported (`web/app/root.tsx`). No Google Fonts requests at runtime.

### Spacing, radius and layout

- Spacing: `--space-1` to `--space-10` = 2, 4, 6, 8, 12, 14, 16, 18, 24, 32 px. Grid gap `--gap` 14px.
- Radius: `--radius-xs` 3px (code chips), `--radius-sm` 4px (confidence chips), `--radius-md` 8px (controls, nav), `--radius-lg` 10px (cards), `--radius-pill`.
- Layout: `--sidebar-width` 232px, `--rail-width` 300px, `--control-height` 40px.

### Focus and glow

- Focus: `--focus-ring` is `2px solid var(--red-bright)` with a 2px offset, applied by `:focus-visible` to links, buttons, inputs, selects and focusable regions. Inside joined controls (segmented toggle, zoom buttons) the offset is -2px so the ring is not clipped. The search box shows the ring on the whole field via `:focus-within`.
- Glow: `--glow-live` is used only by `.live__dot`. The attack map uses an SVG Gaussian blur on hotspot and sensor halos. Nothing else glows: no `text-shadow`, no scanlines. A unit test checks both rules.

## Contrast

Computed with the WCAG 2.x relative luminance formula (`web/app/lib/contrast.ts`) and asserted in `web/app/lib/contrast.test.ts`.

| Foreground | On `--panel` `#101216` | On `--bg` `#07080A` | Result |
| --- | --- | --- | --- |
| `--muted` `#8A9099` | 5.83:1 | 6.23:1 | Passes AA for body text (4.5:1). |
| `--dim` `#5B616B` | 3.01:1 | 3.21:1 | **Fails AA for body text.** Passes 3:1 for large text and non-text UI only. |
| `--text` `#E6E8EB` | 15.27:1 | 16.32:1 | Passes AAA. |
| `--text-2` `#C9CDD3` | 11.75:1 | 12.55:1 | Passes AAA. |
| `--red-bright` `#FF3B3F` | 5.31:1 | 5.68:1 | Passes AA. Used for CVE ids and the focus ring. |
| `--red` `#E5252A` | 4.13:1 | 4.42:1 | Below 4.5:1: use for graphics (bars, sparklines, arcs) only, never small text. |
| `--amber` `#F2A93B` | 9.39:1 | 10.03:1 | Passes. |
| `--blue-text` `#7FC4F0` | 9.87:1 | 10.55:1 | Passes. |
| `--green` `#3FB68B` | 7.39:1 | 7.90:1 | Passes. |

Decision: `--dim` is limited to decorative use (separators, inactive dots, disabled states) and text 18.66px bold or 24px regular and larger. Table headers and placeholders, which mockup-v3 draws in `--dim`, use `--muted` instead. `--dim` on `--panel-2` is 2.88:1, so it is not used on raised controls at all.

## Components

All components live in `web/app/components/`, take typed props, and render on the server. None uses `dangerouslySetInnerHTML` (a unit test scans the sources).

| Component | Purpose | Notes |
| --- | --- | --- |
| `AppShell` | Sidebar with the 12 nav items and count badges, motto card, example data tag; top bar with search, time range toggle, region selector, live indicator, example data banner. | Region options include Australia (AU), the default. Time range is a segmented toggle (1h, 24h, 7d, 30d). |
| `NavItem` | Sidebar link. Active: red left rule, red-tinted fill, `aria-current="page"`. | Count badge in mono on `--red-deep`. |
| `LiveIndicator` | "Live" or "Paused" with the glowing dot. | One of two places glow is allowed. |
| `KpiCard` | Label, icon, value, change, optional note and sparkline. | `accent` puts the value in `--red-bright`. |
| `Sparkline` | Inline SVG path, our own (`sparklinePath`). | Decorative unless given a `label`. |
| `Change` | Arrow and percentage. Up red, down green, with screen reader text. | |
| `Panel` | Card with uppercase title and optional "View all" link. | |
| `AttackMap` | Server-rendered SVG map: dotted land, scatter hits, glowing source clusters, arcs to sensors, sensor callout, zoom, legend. | Map, Globe, Heatmap and AU are a segmented toggle; only Map is built, the others show "coming soon". Props drive all points, so a live-stream client can re-render it (#14). |
| `RankedBarTable` | Top-N rows with a dark-to-red bar. | Counts or percentages; optional tag column (CC). |
| `TrendTable` | Name, count, change and sparkline per row. | Round badge (malware) or square code chip (countries). |
| `ExploitTable` | Recent exploits with a Confidence column. | CVE cell uses `CveRef`; the chip sits in the Confidence column of the same row. |
| `ConfidenceChip` | `ASSESSED nn` amber, `PROBABLE nn` blue, `CONFIRMED nn` green. | Full sentence ("We assess as ...") in the tooltip and for screen readers. API links map with `confidenceFromLink` ([confidence.md](../confidence.md)): analyst-confirmed is Confirmed, unconfirmed `high` band is Probable, `low` and `medium` are Assessed. |
| `CveRef` | The only way to show a CVE id. | `confidence` is a required prop and is also checked at runtime, so no CVE renders without a chip. |
| `SegmentedToggle` | Joined buttons with `aria-pressed`, red-deep active fill. | Options can carry a hint such as "coming soon". |
| `ConfidenceMeter` | Score bar coloured by level, the fixed wording, and the evidence ledger (signal, source, points). | Native `<meter>` for assistive tech. The ledger shows recorded contributions; scoring itself belongs to #27. |
| `AttackHeatmap` | ATT&CK technique ids by column (time windows or sensors), shaded by count. | A real table; every cell has a title with technique, column and count. |
| `AttemptTimeline` | Ordered attempt events with offsets, kind markers, technique tags and CVE refs. | |
| `IocTable` | IOCs with type, value, first and last seen, count and confidence. | Values are text only, control characters escaped, long values shortened in the middle. |
| `RawRequestBlock` | Attacker request text in a scrollable `<pre>`. | Text node only (React escapes markup), control and bidi characters shown as `\xNN` or `\u{NNNN}`, truncated by characters and lines with a visible notice. Keyboard focusable for scrolling. |

### Attack map land data

The land mask is our own: Natural Earth land polygons (public domain) sampled at cell centres on a 1.5 degree grid (240 x 120 cells), stored as run-length rows in `world-land.ts` (about 4 KB). At render time the runs become one clip path, filled with `--map-land` and a 4-unit dot pattern in `--map-dot`. The default view crops to roughly 80N to 58S like the mockup. No large geodata is committed.

## Side-by-side review against mockup-v3.png

Reviewed on 18 Oct 2026 by rendering `/design` at 1600px wide in headless Chromium next to `mockup-v3.png`.

What matches:

- Layout: 232px sidebar, top bar, four KPI cards, map spanning three columns with the 300px right rail (Top attacker IPs, Targeted technologies, Attacker countries), bottom row of Recent exploits and Malware payloads at 1.12 : 1.
- Density: 13px base, 12px table rows, 10px uppercase headers, 14px gaps, 10px card radius, 40px controls.
- Accent use: red only for the active nav rule and fill, badges, KPI headline value, change arrows, bars, sparklines, arcs, CVE ids and the active segment. Amber, blue and green appear only in confidence chips, the example data banner and falling trends.
- Glow: only on the live dot and map hotspots and sensors.
- Map: dotted land, scatter hits, glowing source clusters, curved arcs into Australian sensors, `SYD-EDGE-03 · 88` callout, Map/Globe/Heatmap/AU toggle, zoom stack and legend.
- Region selector shows "Australia (AU)" with the red marker and border.

What differs, and why:

- Table headers and the search placeholder use `--muted`, not `--dim`, to meet 4.5:1 (see Contrast).
- Time range is a segmented toggle (1h, 24h, 7d, 30d) instead of the mockup's "Last 24 hours" dropdown, so the range is one click and keyboard reachable.
- CVE ids in fixtures are `CVE-2099-EXAMPLEn` rather than the mockup's `CVE-2026-EXAMPLEn`, so they can never collide with a real CVE year.
- The land mask is coarser than the mockup's full Natural Earth outline (1.5 degree cells), which shows as slightly blocky coastlines under the dot pattern. It keeps the embedded data small.
- The Recent exploits table wraps long technology names onto two lines at 1600px instead of truncating.
- Malware payloads has an explicit "Change" header; the mockup leaves that column unlabelled.
- KPI icons are stroked line icons in `--red-bright`; the mockup fills the bolt and sandbox icons.
- The page scrolls and continues below the mockup's fold with the detail views (confidence meter, timeline, ATT&CK heatmap, IOCs, raw request) and a primitives section.
- Below 1280px the grid stacks to one column; the mockup is a fixed 1600 x 1060 canvas.

## Accessibility checklist

- Visible `:focus-visible` ring on every interactive element (links, buttons, select, search, scrollable raw block).
- Landmarks: `nav` (Main), `main`, a labelled search form, labelled sections for KPI cards and the map.
- Tables have captions (visually hidden) and scoped headers.
- Charts: sparklines are decorative unless labelled; the map has a text summary and a hidden list of clusters and sensors; the heatmap is a table.
- Colour is never the only signal: chips spell the level, change arrows have text, heatmap cells show counts.

## Related issues

- #14 dashboard and #35 public exploit pages: use this document and these tokens as the UI source of truth.
- #40 front end on Workers ([ADR 0009](../adr/0009-axum-workers-and-front-end.md)).
- #27 confidence scoring, #12 predisclosure, #29 actor associations: wording rules in [voice.md](voice.md).
- #38 licences: fonts and Natural Earth rows in the [licence register](../compliance/licence-register.md).

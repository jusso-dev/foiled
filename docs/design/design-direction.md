# Foiled design direction

> **Chosen direction: v3** (see the [v3 section](#v3-chosen-direction-red-threat-console) and [mockup-v3.png](mockup-v3.png)). The v1 (industrial, matte) and v2 (chamfered, hazard) sections below are kept as earlier explorations. Where v1 or v2 rules conflict with v3 (for example "no glow"), v3 wins.

## v1: industrial cyberpunk, no neon

The feel: a control room in a concrete bunker. Matte steel panels, stencilled labels, hazard tape used once, paper-dry type. Think service manuals, rail signalling boards and ship bridge consoles rather than Tokyo at night. Cyberpunk through grit, density and utility, not light.

## Rules

- No glow, no `box-shadow` blur, no text-shadow, no gradients, no scanlines, no CRT curvature, no saturated cyan or magenta.
- Flat fills, 1px hard borders, square corners (radius 0 or 2px at most).
- Colour carries meaning only. Amber means "watch", red means "act", copper means "ours/brand". Everything else is grey.
- Dense data first. Generous line height in tables, tight elsewhere.
- Texture, if any, is a very faint static noise or a 4px dot grid at 3% opacity on the background. Never animated.
- Motion: instant state changes or 120ms linear slides. No pulsing.

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| `bg/void` | `#0F1113` | App background |
| `bg/gunmetal` | `#181B1E` | Panels |
| `bg/plate` | `#20242A` | Raised panels, table header |
| `line/seam` | `#2E333A` | Borders, grid lines |
| `line/rivet` | `#454B54` | Strong borders, focus outline base |
| `text/concrete` | `#B9B5AC` | Body text (warm grey, like concrete) |
| `text/chalk` | `#E4E0D6` | Headings, key numbers |
| `text/ash` | `#7C7F84` | Labels, metadata |
| `brand/copper` | `#B8733D` | Brand, primary action, selected state |
| `brand/verdigris` | `#4E8C7E` | Oxidised copper. Confirmed, healthy sensor, "foiled" outcome |
| `warn/hazard` | `#D9A520` | Hazard yellow. Assessed, needs review, medium |
| `warn/amber` | `#C7802A` | Major severity |
| `alert/signal` | `#C2402F` | Critical, active exploitation, attacker IP |
| `alert/oxblood` | `#5A211B` | Fill behind critical chips and rows |
| `data/steel` | `#5C6F82` | Neutral chart series |
| `data/slate-2` | `#3C4A57` | Heatmap low end |

Heatmap ramp (ATT&CK, low to high): `#1C2126` → `#2F3A3F` → `#4E5A4B` → `#7A6A3A` → `#A9722E` → `#C2402F`. Concrete to rust, no glow.

Contrast: `text/concrete` on `bg/gunmetal` is about 8.9:1, `text/ash` on `bg/gunmetal` is about 4.5:1. Keep labels at or above 12px.

## Type (all free)

- **Display and headings: Barlow Condensed** (600, 700), uppercase, letter-spacing 0.04em. Stencil-adjacent, reads like signage.
- **UI text: IBM Plex Sans** (400, 500). Neutral, technical, good at small sizes.
- **Data, payloads, IPs, hashes, CVE IDs: JetBrains Mono** (400, 600). Alternative: IBM Plex Mono for a closer family match.
- Optional accent for the wordmark only: **Big Shoulders Stencil Display** (Google Fonts) for a sprayed-stencil feel.

Scale: 11 / 12 / 13 / 15 / 18 / 24 / 32 / 48. Tabular numbers on for every table and counter.

## Layout

- 12-column grid with visible 1px seams between panels, like bolted plates.
- Panel header: small uppercase label left (`text/ash`), panel ID right in mono (for example `PNL-04`), 1px rule under it.
- Corner ticks (two 6px lines) on key panels instead of rounded corners, a HUD cue without glow.
- Left rail navigation grouped like Defused's (Monitor, Deploy, Configure) but labelled CAPTURE, SANDBOXES, INTEL, CONFIG.
- A thin status strip at the top: sensor count, live attempts, feed lag, clock in AEDT and UTC.

## Components

### Attempt timeline
Horizontal stage track per attempt: RECON, FINGERPRINT, EXPLOIT, POST-EXPLOIT, CLEANUP. Each stage is a square cell, filled with severity colour when observed, hatched (diagonal 1px lines) when inferred, empty outline when not seen. Below it a mono event list with relative and absolute time (AEDT), source IP, and the request line. Click a cell to jump to the raw request.

### Confidence meter
Segmented bar of 10 blocks (no smooth fill), with the number in mono beside it and a status word: SPECULATIVE (0 to 39), ASSESSED (40 to 69), PROBABLE (70 to 89), CONFIRMED (90 to 100, or vendor/third party confirmed). Underneath, an evidence ledger: each row is a method (signature match, behaviour sequence, code path hook, public data correlation, LLM correlation, analyst override) with its weight and a tick or dash. Wording always follows the status: "We assess this as CVE-X" until confirmed.

### ATT&CK heatmap
Tactic columns (Recon to Impact), technique cells as small squares with the technique ID in mono on hover and in a side panel. Ramp from concrete to rust as above. Cells with only LLM-suggested mappings get a hatched pattern so analysts can tell inferred from observed.

### Sensor map
Flat dotted world map (dot grid, no satellite imagery), with an inset for Australia that is larger by default. Sensors are small squares: verdigris for healthy, hazard for warming (feed age under 3 days), ash for cold, signal red outline when hit in the last hour. No animated arcs. A list beside it gives sensor ID, product and version, region, age, hits in 24h.

### IOC table
Columns: type (IP, URL, hash, path, UA, JA4, behaviour), value (mono, truncated with copy), first seen, last seen, hits, linked CVE, confidence, TLP. Row stripe every 5th row only, like ledger paper. Bulk select exports STIX 2.1, MISP, CSV, Sigma.

### Severity and status chips
Square chips, 1px border in the colour, fill at about 15% using the dark companion (for example oxblood for critical). Text uppercase mono 11px. Never pills.

### Raw request block
`bg/void`, 1px `line/seam`, mono 12px, line numbers in `text/ash`, header bar with COPY, REDACT, DECODE, EXPORT PCAP as plain bordered buttons.

## Logo ideas for Foiled

1. **The struck F**: a heavy condensed F with a single diagonal cut through it, like a blade mark or a cancelled stamp. Works at 16px.
2. **Foil sheet**: a square with one corner folded back, revealing a hatched underside. Nods to "foil" as metal and to a decoy wrapper hiding what is underneath.
3. **Stencil wordmark**: FOILED in Big Shoulders Stencil with the bridge gaps aligned so the O reads as a target reticle with breaks.
4. **Hazard bracket**: [ FOILED ] with the brackets drawn as short hazard-striped bars, used only in the copper colour.
5. **Tripped wire**: a horizontal line that kinks once under the word, ending in a small square (the sensor).

Recommended: 1 as the mark, 3 as the wordmark. Copper on gunmetal, chalk on void for mono contexts.

## Voice for UI copy

Short, flat, factual. "Attempt captured", "Assessed as CVE-2026-XXXX (not confirmed)", "Sensor warming, 2 days". Australian English. No exclamation marks, no hype.

## v1 mockup

`docs/design/mockup.html` and `docs/design/mockup.png` show the dashboard using this system. All data in it is clearly labelled example data.

---

## v2: chamfered and hazard (exploration)

Files: [mockup-v2.html](mockup-v2.html), [mockup-v2.png](mockup-v2.png).

- Palette: ink `#0A0A0B`, slab `#17191C`, edge `#2C3036`, bone `#ECE6D6`, dust `#A9A396`, blood orange `#E4521B` (primary), acid `#D7E635` (live only), hazard `#F0B323` (assessed), alarm `#D93A2B` (critical), oxidised green `#4F9A86` (confirmed).
- Type: Big Shoulders Stencil Display (wordmark), Big Shoulders Display (titles, big numbers), Chakra Petch (UI), JetBrains Mono (data).
- Motifs: chamfered panel corners, hazard stripe spine on the live alert card, bracketed labels `[ LIKE THIS ]`, registration marks, slanted status chips, system codes (`ATT-0193`, `SBX-0412`), arrow-chevron kill chain, halftone map, redaction bars. No glow.

---

## v3: chosen direction, red threat console

Files: [mockup-v3.html](mockup-v3.html), [mockup-v3.png](mockup-v3.png) (1600 x 1060). README hero art: [../assets/foiled-hero.jpg](../assets/foiled-hero.jpg).

A dark, dense threat intelligence console with a single strong red accent, rounded panels, sparklines and a live world map with glowing hotspots and attack arcs. Glow is allowed on map hotspots and the live indicator only. Everything else stays flat.

### Palette

| Token | Hex | Use |
| --- | --- | --- |
| `bg` | `#07080A` | Page background |
| `side` | `#0B0C0F` | Sidebar |
| `panel` | `#101216` | Cards and panels |
| `panel-2` | `#14171C` | Raised controls, map overlays |
| `line` | `#1F232A` | Card borders |
| `line-2` | `#2A2F37` | Control borders |
| `text` | `#E6E8EB` | Primary text, KPI values |
| `muted` | `#8A9099` | Secondary text |
| `dim` | `#5B616B` | Table headers, placeholders |
| `red` | `#E5252A` | **Primary accent**: active nav, bars, sparklines, arcs |
| `red-bright` | `#FF3B3F` | Hotspots, CVE IDs, rising trends, live dot |
| `red-deep` | `#3A0D0F` | Active segment and badge fills |
| `map-land` | `#1A1D22` + `#3A3F48` dots | Dotted land fill |
| `amber` | `#F2A93B` | Confidence: assessed; example data banner |
| `blue` | `#4C8DF6` (text `#7FC4F0`) | Confidence: probable |
| `green` | `#3FB68B` | Confidence: confirmed; falling trends; healthy sandboxes |

Bar fills use a short dark-to-red ramp (`#7A1114` to `#E5252A`). Hotspot glow is an SVG Gaussian blur on red circles, used on the map only.

### Type

- **Rajdhani 700**: FOILED wordmark (wide tracking).
- **Inter 400 to 700**: UI, headings (uppercase with 0.1em tracking for panel titles), KPI numbers (600, 30px).
- **JetBrains Mono**: IPs, CVE IDs, counts, time offsets, chips.

### Layout

- Left sidebar (232px): hex-framed slashed-F logo, nav (Live Attacks, Exploit Activity, Malware, CVE Intelligence, Attackers, Targeted Tech, Honeypots, Payloads, IOCs, ATT&CK TTPs, Reports, API & MCP), motto card ("Real attackers. Real behaviour. Assessed, not guessed."), example data tag in mockups.
- Top bar: global search (IPs, CVEs, sandboxes, payloads, ATT&CK IDs), time range, **region selector with Australia (AU)**, live indicator.
- KPI row: Exploit attempts, Unique sources, CVEs assessed, Active sandboxes. Each with icon, value, change and sparkline.
- Main map panel with Map, Globe, Heatmap and **AU** toggles, zoom controls and a legend. Arcs run from source clusters to Foiled sensors.
- Right column: Top attacker IPs (bar per IP), Targeted technologies (percentage bars), Attacker countries (sparklines).
- Bottom row: Recent exploits with a **Confidence** column, Malware payloads with trend and sparkline.

### Components

- **KPI card** with sparkline.
- **Live attack map**: Natural Earth land (public domain), dotted fill, red hotspot dots, glowing source clusters, curved arcs, labelled sensor callouts.
- **Ranked bar table** (attacker IPs, technologies).
- **Trend table** with arrow change and sparkline (malware, countries).
- **Confidence chip**: `ASSESSED nn` amber, `PROBABLE nn` blue, `CONFIRMED nn` green. Shown next to every CVE so the "we assess" model stays visible in the v3 look.
- **Segmented toggle** with a red active state.
- **Nav item** with a red left rule, a red-tinted fill and a count badge.

### Carry-overs from v1 and v2

Evidence ledger, attempt timeline, ATT&CK heatmap, raw request block and IOC table still apply as detail views behind the v3 dashboard, restyled with the v3 palette.

### Rules

- Example and mock data is always labelled. Use RFC 5737 IPs and fake CVE IDs (`CVE-YYYY-EXAMPLEn`) in mockups and fixtures.
- Glow only on map hotspots and the live dot. No glowing text and no scanlines.
- Australian English, flat wording, "we assess as" until confirmed.

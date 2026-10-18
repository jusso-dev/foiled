# UI voice and copy rules

Status: draft. Owner: #39. Applies to the operator console (#14), the public exploit pages (#35) and any UI text in examples or fixtures. The design system is in [design-system.md](design-system.md).

## Tone

- Australian English: organise, behaviour, analyse, catalogue, licence (noun), license (verb), colour, defence.
- Flat and plain. State what happened and how sure we are. No hype ("massive", "devastating"), no alarm words, no exclamation marks.
- Short. Labels are one to three words. Sentences in notes and empty states stay under about 20 words.
- No emoji. No em dashes; use a full stop, comma, colon or a spaced hyphen.

## Confidence wording

Every link from an attempt to a CVE, technique or actor carries a level and a score. The wording is fixed so the "assessed, not guessed" model stays visible.

| Level | Chip | Sentence form | Use when |
| --- | --- | --- | --- |
| Assessed | `ASSESSED 64` (amber) | "We assess as an attempt against `CVE-2099-EXAMPLE1`. Score 64 of 100, not confirmed by an analyst." | Signals point to the link but an analyst has not confirmed it. |
| Probable | `PROBABLE 81` (blue) | "Probable attempt against `CVE-2099-EXAMPLE3`. Score 81 of 100, not yet confirmed by an analyst." | Strong signals, still unconfirmed. |
| Confirmed | `CONFIRMED 96` (green) | "Confirmed by an analyst as an attempt against `CVE-2099-EXAMPLE2`. Score 96 of 100." | Only after analyst confirmation (#12, #27). |

Rules:

- Never write "confirmed", "is exploiting" or "exploited" for a link that has not been confirmed by an analyst. Use "we assess as" (see the [glossary](../glossary.md)).
- Never show a CVE id without its chip. In code this is enforced by the `CveRef` component, which requires a confidence prop.
- Actor links use "possible association with" a named public cluster, never a bare actor name as fact (#29).
- Attacker-supplied text (paths, headers, user agents, payloads) is quoted as data, never paraphrased into a claim.
- CVEs a catalogue entry lists describe the software, not an attempt. Label them "catalogue claims" with their sources and show them without a confidence chip (the launch wizard, [console.md](console.md#launch-wizard)).

## Common labels

| Use | Not |
| --- | --- |
| Exploit attempts | Attacks blocked, hacks |
| Unique sources | Hackers, attackers (as a count) |
| CVEs assessed | CVEs detected |
| Active sandboxes, 14 warm | Honeypots online |
| Source cluster | Threat actor (on the map) |
| Egress blocked | Attack stopped |
| Sandbox rotated | Sandbox wiped |
| Coming soon | Under construction, TBD |
| Time since the attempt: `1m 23s` | "just now", "a while ago" |

## Example data

- Any screen, screenshot, fixture or mockup that is not real telemetry shows `EXAMPLE DATA` (amber banner in the top bar and the sidebar tag).
- IPs come from RFC 5737 only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- CVE ids are clearly fake: `CVE-2099-EXAMPLE1`, `CVE-2099-0001` or `FOILED-DEMO-0001`.
- Products, malware and countries are invented: `ExampleVPN`, `Example-Loader`, `Country A`.
- No vendor screenshots and no real customer data.

## Numbers and time

- Thousands separators in counts (`48,317`), formatted for `en-AU`.
- Percentages as whole numbers with an arrow: `↑ 17%`. Rising attack counts are red, falling are green.
- Durations as `1m 23s`, `1h 03m`. Offsets inside an attempt as `+0.412s`.
- Dates in tables as `YYYY-MM-DD HH:MM` (24-hour, UTC unless the column says otherwise).

## Accessibility in copy

- Icons never carry meaning alone: every icon sits next to a text label or has an accessible name.
- Colour never carries meaning alone: chips say the level in words, change arrows have screen reader text ("up 17 per cent").
- Truncation is announced in words: "Truncated: showing 720 of 2,688 characters".

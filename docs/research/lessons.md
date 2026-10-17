# Lessons from commercial honeypot-as-a-service platforms

Researched alongside `landscape.md` (17 Oct 2026, AEDT). This note folds patterns seen on public sites and docs from commercial honeypot-as-a-service platforms (including Defused Cyber as one named reference) into Foiled design principles. It does not reproduce their marketing copy, screenshots or proprietary telemetry.

## Patterns worth adopting

1. **Two halves of the product.** A shared research feed from operators' own sensors, plus dedicated or customer-run sensors. Cross-check hits against the shared fleet so a subscriber can tell "targeting me" from background scanning. Maps to Foiled research sensors (#7), edge sensors (#31) and radar (#35).
2. **Noise score per source IP.** How many hits, how many decoy types touched, and how that compares to the rest of the fleet. Low noise (few decoy types) leans targeted; high fan-out leans mass scanning. Show it next to the IP. Fold it into confidence (#27) and attempts (#25) as one evidence input, not the whole score.
3. **Capability catalogue as the deploy unit.** Product, version, CVE, ports, engine or profile version, one-click (or MCP) deploy. Already the shape of catalogue entries (#5) and `create_sandbox` (#24).
4. **Feed age and recycling.** Label sensors cold / warming / warmed, and rotate decoys that look burnt so they are not permanently fingerprinted. Ties to fingerprint resistance (#18), Honeyscore self-checks and rotation (#8).
5. **Assessment language in the data model.** Status values such as "we assess as", "assessed, not vendor-confirmed", "possibly a variation", "confirmed", with timestamps when the status changed. Not only UI copy. Aligns with #12 and #27.
6. **Behavioural sequence fingerprints** and honest handling of memory-only implants (few file IOCs). Already #12 sequences and #34.
7. **Public exploit pages** with redacted payloads, a timeline (first seen vs advisory) and a clear gate for full IOCs. Good for research reach. Owned by #35.
8. **Severity separate from confidence.** Critical / major / medium / minor for impact of the event; confidence for how sure we are about CVE, technique or actor links.
9. **Posting rhythm.** Short public notes when something lands, longer write-ups when there is a real story, always pointing back at the live feed. Editorial review before publish (#35).

## Patterns to do differently or lighter

- Prefer an **open sensor kit** (signed builds, clear licences) early, with paid analysis and feeds on top, rather than keeping self-host closed.
- **Show the confidence maths.** Evidence trail per attribution (signature, sequence, vuln-path hook, enrichment, LLM, analyst) with weights. This is a main Foiled differentiator (#27, #28).
- Map **ATT&CK** on every attempt and offer heatmaps, not only on rare incident views (#26, #14).
- Export **STIX 2.1, TAXII, MISP and Sigma** from early on (#13).
- Ship an **MCP server** for agents to create and query decoys (#24).
- Skip managed internal deception, custom decoy branding and heavy SLA products at first.
- Avoid flashy AI hero art; use clearly labelled example console views (see `docs/design/`).
- Keep a write-up review step so drafts do not ship with placeholders (#35).

## Australian angle (gap in most commercial references)

- Named Australian sensor locations and onshore data options.
- Mapping to ACSC advisories and Essential Eight where it helps operators.
- AEDT-first digests (European posting windows are overnight here).
- Legal framing already started in #2 (Criminal Code Act 1995 (Cth), Privacy Act 1988). SOCI Act notes for critical infrastructure customers as docs grow.
- Pricing and invoicing in AUD when a commercial feed exists.

## What not to copy

- Do not scrape or republish another vendor's telemetry, screenshots or marketing pages into this repo.
- Do not treat their example CVE calls as verified facts for Foiled's own assessments.
- Do not embed their brand assets.

## Related Foiled docs and issues

- Landscape and reuse plan: `docs/research/landscape.md`
- Design system and mockup: `docs/design/`
- Epic: #23

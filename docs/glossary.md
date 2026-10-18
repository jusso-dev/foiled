# Glossary

Terms used across Foiled issues, docs and code, in alphabetical order. Issue numbers point at where each idea is designed in detail.

**ATT&CK**
MITRE ATT&CK, a public knowledge base of attacker tactics and techniques. Foiled maps attempts to ATT&CK technique ids using a pinned copy of the ATT&CK STIX data (#26).

**Attempt**
One exploit attempt against a decoy: the record that groups related capture events from one source into a single unit with a state, payloads, IOCs and linked CVEs and techniques. Attempts have stable ids so they can be clustered across the fleet (#25).

**Behaviour fingerprint**
A stable id computed over a normalised sequence of attacker steps or vulnerable-path hook hits, plus key arguments. Used as an IOC when there is no file hash to share, for example with memory-only implants (#34), and as a mapping tier signal (#12).

**Campaign**
A cluster of attempts across the decoy fleet that share infrastructure, payloads, behaviour or targeting closely enough to look like one wave of activity. Worded "possible" until an analyst confirms; never attribution ([campaigns.md](campaigns.md), #33).

**Canary**
A planted value, such as a fake credential or token inside a decoy, that has no use except as a tripwire. If it is used outside the sandbox, that is a high-confidence signal that data was stolen. Canaries are never real credentials for anything that matters (#17, [canaries.md](canaries.md)).

**Capture envelope**
The common event shape every capture source emits: event id, timestamp, decoy id, catalogue id, `decoy_kind`, channel, severity, source, `payload_ref` and an optional attempt id. Emulators and sandboxes use the same envelope so attempts look uniform (#9).

**Catalogue entry**
One record in the Foiled catalogue describing a decoy: product, pinned version, `decoy_kind`, the artefact to run, the CVEs it is believed to be affected by with public sources, ports, hints and a status of `draft`, `verified` or `deprecated` (#5). See the catalogue section of [CONTRIBUTING.md](../CONTRIBUTING.md) for how to propose one.

**Confidence**
The score and evidence list attached to every link Foiled asserts, such as attempt to CVE, attempt to technique or attempt to actor. It combines mapping tier weights, enrichment, analyst feedback and capped LLM signals, and decides the wording and whether a link may be published (#27).

**Decoy**
Anything Foiled exposes to attackers on purpose: either a real vulnerable build running in a sandbox or a product emulation. Every decoy comes from a catalogue entry.

**Decoy module**
A third-party honeypot or emulator (for example Cowrie, OpenCanary or Conpot) packaged as an isolated container that emits Foiled capture envelopes. GPL modules run only as separate containers and are never imported into Foiled source (#30).

**`decoy_kind`**
The field that says how a decoy runs: `sandbox` (real software at a pinned vulnerable version) or `emulation` (a lightweight imitation of the product). It appears on catalogue entries, capture envelopes and attempts (#3, #5).

**Durable Object**
A Cloudflare Workers primitive that gives a single instance strong consistency and its own storage. Foiled uses Durable Objects with hibernating WebSockets for the live attempt stream in the dashboard.

**Emulation**
A decoy that imitates a product's network behaviour, banners and key responses without running the real software. Cheaper and broader than a sandbox, but with less fidelity after exploitation (#30).

**Honeypot**
A system that exists only to be attacked, so that any interaction with it is worth recording. In Foiled, each decoy is a honeypot.

**Host agent**
The native Rust service (`crates/hostd`) on each sandbox host. The control plane drives it to create, reset and destroy decoys, and it reports health and capture status back (#41).

**Hyperdrive**
A Cloudflare service that pools and accelerates connections from Workers to an external database. Foiled reaches its Postgres store of attempts and intel through Hyperdrive.

**IOC**
Indicator of compromise: an observable such as an IP address, domain, URL, user agent, payload hash, command line or behaviour fingerprint that can help others detect the same activity (#34). Example IPs in Foiled docs use RFC 5737 ranges such as `192.0.2.10`.

**KEV**
CISA's Known Exploited Vulnerabilities catalogue, a public list of CVEs with confirmed exploitation. Used as an input when proposing catalogue entries (#5).

**Mapping tier**
One rung on the ladder Foiled uses to link an attempt to a CVE: signatures, behavioural sequences, vulnerable-path hooks, pre-disclosure back-matching and vendor description correlation. Each tier produces evidence with a different weight in the confidence layer (#12).

**MISP**
An open source threat intelligence sharing platform and its event format. Foiled exports attempts and IOCs as MISP events (#13, [intel-outputs.md](intel-outputs.md#misp)).

**mTLS**
Mutual TLS: both client and server present certificates. Edge sensors use mTLS with an enrolment identity when they send data to the central ingest (#31).

**Noise score**
An estimate of whether activity is targeted or mass scanning, based on how widely a source hits the fleet and on enrichment such as GreyNoise. It is an input to confidence, not a replacement for it (#25).

**NVD**
The US National Vulnerability Database, which publishes CVE records with scores and affected product data. A source for catalogue entries.

**OSV**
Open Source Vulnerabilities, a public database and schema for vulnerabilities in open source packages. A source for catalogue entries.

**`payload_ref`**
A reference to a payload body stored in R2, used instead of putting large bodies inside capture envelopes or queue messages. Format: `r2://<bucket>/<tenant>/<decoy-id>/<attempt-id>/<channel>/<sha256>` (#9).

**Possible association**
The required wording for a link between activity and a public threat actor or cluster that is not confirmed by an analyst at high confidence. Foiled prefers nexus or named public cluster labels and links to the public reports behind them (#29).

**Predisclosure**
Tracking consistent, non-generic traffic against a decoy that matches no known CVE yet, then back-matching it when an advisory is published. Predisclosure links start capped and are never published automatically (#12).

**R2**
Cloudflare's object storage. Foiled stores packet captures, payload bodies and quarantined files in R2 and refers to them by `payload_ref`.

**Radar**
The trusted-side, fleet-wide intel feed that summarises what is being exploited right now. It feeds the review queue and public research write-ups (#35).

**Review queue**
The analyst queue in the dashboard for items that need a human decision, such as predisclosure candidates, low-confidence but high-impact links and campaign suggestions. Reviews are audited (#14, #35).

**Rotation**
Treating each sandbox as disposable: snapshot the evidence, destroy the guest and boot a clean copy from the catalogue digest. Done when a decoy is compromised or has run for too long (#8).

**Sandbox**
A tightly contained environment that runs real vulnerable software for a decoy, with deny-by-default egress and no path to the control plane (#3, #4). Also used for the `decoy_kind` value `sandbox`.

**Sensor**
A deployment that runs decoys and sends capture data to Foiled.

- A **research sensor** runs on hosts the project or operator controls directly, such as a VPS with KVM. This is the MVP path (#7).
- An **edge sensor** is a lightweight sensor run elsewhere, often by someone else, that buffers offline and forwards to a central backend over mTLS (#31).

**STIX**
Structured Threat Information Expression, the OASIS standard format for threat intelligence. Foiled exports STIX 2.1 bundles (#13) and reads ATT&CK as STIX data (#26).

**TAXII**
Trusted Automated Exchange of Intelligence Information, the protocol for serving and fetching STIX over HTTPS. Foiled will serve its published intel through a read-only TAXII 2.1 collection (#13, [intel-outputs.md](intel-outputs.md#taxii-21)).

**"We assess as"**
The required wording for a link between an attempt and a CVE that an analyst has not confirmed, for example "we assess as an attempt against `CVE-2099-0001`". The word "confirmed" is used only after analyst confirmation (#12, #27).

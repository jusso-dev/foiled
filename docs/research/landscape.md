# Foiled landscape: honeypot, deception and threat intel references

Researched 17 Oct 2026 (AEDT). Facts are taken from the linked pages and the GitHub API on that date. Where something could not be verified it says so. Foiled itself is MIT licensed (checked on `jusso-dev/foiled`).

Key for "Use": **Learn** = study the approach. **Integrate** = call their API or feed for enrichment. **Reuse** = run their code as a Foiled decoy or sensor module. **Contribute** = send our data back.

GitHub "last push" dates are UTC dates from the GitHub API.

---

## Part A. Commercial and community intel

### GreyNoise (greynoise.io)
| | |
| --- | --- |
| Category | Internet noise and edge exploitation intel (commercial, free community tier) |
| What it does | "A global grid of thousands of sensors observes attackers first-hand." Classifies IPs (malicious, benign, unknown), tags them by CVE, tool and campaign, and runs RIOT, a dataset of known business services (their Business Services module lists "156M+ verified business IPs"). Sells dynamic CVE blocklists and C2 detection. |
| API / feeds | Community API `api.greynoise.io/v3/community/{ip}` returns `noise`, `riot`, `classification`, `name`, `last_seen`. Without a key it allows 10 lookups a day, and free accounts get 50 a week, which needs a business email. Paid tiers add the Enterprise API, GNQL, feeds and 80+ integrations. |
| Pricing | Free tier, then Standard, Advanced and Elite platform tiers plus modules (Triage, Investigate, Hunt; add-ons C2 Detection, Vulnerability Prioritization, Business Services). No public dollar prices on the plans page. |
| Learn | Noise versus targeted is the core idea, and it is the same as Defused's noise index. RIOT-style allowlisting of benign infrastructure. CVE-specific blocklists. "~6 days before disclosure" style early warning. |
| Integrate | Yes. Look up every new source IP: `noise=true` lowers the "targeted" score, and `riot=true` marks it benign or business. |
| Reuse | No, it's closed. |
| Licence | Proprietary data. Redistribution terms not checked, so assume we can't republish their data in our feed. |
| Status | Active (product updates dated Oct 2026 on the homepage). |
| Sources | https://www.greynoise.io/ , https://www.greynoise.io/plans , https://docs.greynoise.io/docs/using-the-greynoise-community-api |

### The Shadowserver Foundation (shadowserver.org)
| | |
| --- | --- |
| Category | Non-profit, free remediation reporting |
| What it does | "Every day, Shadowserver sends custom remediation reports to more than 10000 vetted subscribers, including 135 national governments (201 National CSIRTs)." Data comes from "daily Internet-wide scans, sinkholes, honeypot sensors, sandboxes, blocklists and many other sources". Honeypot reports include brute force, HTTP scanner, ICS scanner, RDP, SMB, SNMP, IKEv2, ADB, RocketMQ and DDoS events, plus a Malware URL report "sourced primarily from honeypots". It also publishes one-off special reports on exploitation victims. |
| API / feeds | Reports API, Scan/SSL, ASN and Network, Malware Query and Trusted Programs. You need an API key, requested at sign-up. Supports Splunk, Elasticsearch, CEF and IntelMQ. |
| Pricing | Free ("free and actionable"). |
| Learn | The report taxonomy (one report per protocol and event type), severity labels, and special reports for big exploitation events. |
| Integrate | Subscribe Foiled's own ranges and ASN to get reports on exposure. Use the ASN and Network API for enrichment. Their exploitation victim special reports are a useful outside check on our CVE calls. |
| Reuse | No. |
| Licence | Use is vetted and terms are per subscriber. Not checked for redistribution. |
| Status | Active (lists a 2026 special report). |
| Sources | https://www.shadowserver.org/what-we-do/network-reporting/ |

### SANS Internet Storm Center / DShield (isc.sans.edu)
| | |
| --- | --- |
| Category | Community sensor network and free API |
| What it does | Volunteers run DShield sensors that send firewall logs plus Cowrie and web honeypot data. The DShield sensor install script "install[s] the SSH honeypot Cowrie" and an HTTP honeypot (`isc_agent`). It's built for a Raspberry Pi 3 or later, an N100 mini PC or a VM. |
| API / feeds | REST API at `https://isc.sans.edu/api/` with ip, ipdetails, port, topips, sources, intelfeed, threatfeeds, cloudips, web honeypot search by URL or UA, and OpenIOC. Output in XML, JSON, text or CSV. No auth today, but they ask for a contact email in the User-Agent and send 429s under load. |
| Pricing | Free. |
| Licence | The API page says: "Do not resell the data", data is "CC BY-NC-SA 4.0", commercial use "to protect your own company's network" is OK. The sensor repo `DShield-ISC/dshield` is **GPL-2.0**. |
| Learn | The contribute-to-consume community model. Their web honeypot URL and UA search is a good model for our public search. |
| Integrate | IP lookups (count, attacks, first and last seen, threatfeeds) as an enrichment input. Do **not** put DShield data into a paid Foiled feed, because NC-SA and "do not resell" block that. |
| Contribute | Yes. Cowrie ships a `dshield.py` output plugin, so our Cowrie modules can submit directly. |
| Status | Active (sensor repo last push 2026-10-05). |
| Sources | https://isc.sans.edu/api/ , https://github.com/DShield-ISC/dshield |

### CrowdSec (crowdsec.net)
| | |
| --- | --- |
| Category | Open source IDS/IPS with crowdsourced blocklists, plus commercial CTI |
| What it does | The Security Engine detects attacks locally and sends "signals" to a central consensus engine. Users get blocklists back based on what they contribute. The CTI covers "hundreds of thousands of real CrowdSec deployments" and gives behaviours mapped to MITRE ATT&CK and linked CVEs. |
| API / feeds | CTI API (30+ fields per IP, "Free tier included, no credit card needed"). Live Exploit Tracker (separate key). Community Blocklist tiers: Lite (3,000 IPs), Community (15,000, for active contributors) and Premium (up to 60,000). |
| Pricing | IP Reputation API from US$49/month for 5,000 queries. Platinum Blocklists from US$1,900/month for SMB. Live Exploit Tracker from US$2k/month for SMB. Commercial embedding needs their Partnership Program. |
| Licence | `crowdsecurity/crowdsec` is **MIT**. |
| Learn | Signals only count if they come from unmodified Hub scenarios (checked by content hash). That's a neat anti-poisoning design we could copy for customer-run sensors. |
| Integrate | CTI lookups for reputation and ATT&CK behaviour. Optionally run the Security Engine on sensor hosts. |
| Contribute | Yes. Running the engine with Hub scenarios on a honeypot host shares signals. Note their docs say a honeypot with a modified scenario won't count. |
| Status | Active (repo last push 2026-10-16, about 15.2k stars). |
| Sources | https://www.crowdsec.net/pricing , https://docs.crowdsec.net/docs/next/central_api/community_blocklist/ , https://docs.crowdsec.net/u/cti_api/getting_started/ , https://github.com/crowdsecurity/crowdsec |

### Hunt.io
| | |
| --- | --- |
| Category | Commercial attacker infrastructure and C2 hunting |
| What it does | Finds malicious servers and maps attacker infrastructure: C2 activity, AttackCapture (open directory captures), phishing infrastructure, HuntSQL, IOC Hunter, threat actor intel. |
| API / feeds | "60+ endpoints across C2, IP enrichment, SQL, DNS, AttackCapture", an OpenAPI 3.0 spec, an **MCP server at mcp.hunt.io**, custom feeds and OEM. |
| Pricing | Researcher US$199/licence/month and Starter US$499/licence/month (both billed annually), Professional on quote. No free plan, but a 2-week trial with no card. Full API access and commercial use are on the higher tiers. |
| Learn | They offer an MCP server, which proves the agent-access idea we're planning (Foiled issue #24). |
| Integrate | Paid and optional. Pivot from stage-2 URLs and callback IPs in our captures to known C2 servers. A strong input to actor and campaign links (#29, #33). |
| Reuse | No. |
| Licence | Proprietary. |
| Status | Active. |
| Sources | https://hunt.io/ , https://hunt.io/pricing |

### Thinkst Canary (thinkst.com, canary.tools)
| | |
| --- | --- |
| Category | Commercial internal deception, with open source parts |
| What it does | Hardware, virtual, cloud and container Canaries that copy Windows file servers, routers and Linux servers. They're set up in "under 2 minutes" and talk to a hosted console over DNS. Alerts go out by email, SMS, Slack, webhook or syslog. The FAQ says they detect common fingerprinting methods and alert on them. |
| Pricing | The homepage advertises a package of "5 Beautiful Thinkst Canaries", unlimited Canarytokens and your own AWS-hosted console, with an online quote tool. A search summary quoted US$7,500/year for 5, but I couldn't confirm that on the live page (canary.tools/pricing returns 404), so treat it as unconfirmed. |
| Learn | Low-noise philosophy ("One alert. When it matters!"), setup in minutes, DNS-only phone home, and treating fingerprinting attempts as a signal in themselves. |
| Integrate / Reuse | Use OpenCanary and Canarytokens (below), not the commercial product. |
| Status | Active. |
| Sources | https://canary.tools/ |

### Smokescreen (smokescreen.io)
| | |
| --- | --- |
| Category | Deception, **acquired by Zscaler** |
| Verified | Zscaler announced the deal on 25 May 2021. Zscaler's SEC filing says "In June 2021, we completed the acquisition of Smokescreen Technologies Private Limited ... for approximately $11.5 million in cash", with plans to fold it into the Zero Trust Exchange. |
| Status | Part of Zscaler. smokescreen.io returned an empty page and a WebFetch 500 on 17 Oct 2026. |
| Learn | Placing decoys near identity and zero trust. Not relevant to an internet-facing intel product. |
| Sources | https://ir.zscaler.com/news-releases/news-release-details/zscaler-acquire-smokescreen-enhance-zscaler-zero-trust-exchange , https://www.sec.gov/Archives/edgar/data/1713683/000171368321000096/R21.htm |

### CounterCraft (countercraftsec.com)
| | |
| --- | --- |
| Category | Commercial enterprise deception and threat intel |
| What it does | "AI-powered deception": AI agents (Deception Expert, Threat Hunter Expert, Engager) build "digital twin" decoy environments, engage attackers in real time and pull out their TTPs. Covers IT and OT/ICS, insider threat and external attack surface. Says it deploys "in less than 30 days". |
| Pricing | Not public. |
| Learn | An Engager agent that keeps attackers busy is a good idea for our LLM-driven high-interaction modules. Their 2026 content focuses on zero-day detection on edge devices, the same market as Defused. |
| Integrate / Reuse | No. |
| Status | Active (2026 news on the homepage). |
| Sources | https://www.countercraftsec.com/ |

### TrapX Security (trapx.com)
| | |
| --- | --- |
| Category | Deception, **acquired by Commvault** |
| Verified | Commvault's SEC filing: "We completed the acquisition for TrapX on January 31, 2022", total purchase price US$18.653M. The technology is now Commvault **Threatwise** (decoys that copy IT, OT, network and backup assets). |
| Status | trapx.com didn't respond on 17 Oct 2026. The product lives on as Threatwise. |
| Learn | Decoys placed next to backup systems for ransomware early warning. |
| Sources | https://www.sec.gov/Archives/edgar/data/1169561/000116956122000018/R12.htm , https://www.commvault.com/blogs/welcoming-trapx-to-the-commvault-family , https://www.commvault.com/platform/threatwise |

### Attivo Networks (attivonetworks.com)
| | |
| --- | --- |
| Category | Identity deception, **acquired by SentinelOne** |
| Verified | SentinelOne 8-K: closed 3 May 2022 for about US$351.5M cash plus 6,032,231 shares. attivonetworks.com now redirects to sentinelone.com. |
| Learn | Identity and AD lures for lateral movement. Out of scope for Foiled's external focus. |
| Sources | https://www.sec.gov/Archives/edgar/data/1583708/000119312522140461/d352944d8k.htm , https://www.sentinelone.com/press/sentinelone-completes-acquisition-of-attivo-networks/ |

### Akeyless (akeyless.io)
| | |
| --- | --- |
| Category | **Secrets and machine identity management, not deception** |
| Verified | Akeyless calls itself a "unified Secrets & Machine Identity platform" (vaultless secrets, certificate lifecycle, PAM, KMS). Its October 2024 press release covers a Deutsche Bank investment. Third-party profiles (Tracxn, nhigovernance.com, cybersecdirectory.com) record no acquisitions. I found **no evidence** that it acquired or sells deception technology. akeyless.io returned 403 to curl. |
| Use | Not a reference for honeypots. The only possible link is as a place to store sensor enrolment secrets, which isn't needed. |
| Sources | https://www.prnewswire.com/news-releases/akeyless-secures-strategic-investment-from-deutsche-bank-302289840.html , https://nhigovernance.com/companies/akeyless.html , https://tracxn.com/d/companies/akeyless/__FKVhGoS-ykcHiTzUk50SopD6R_1kQkc37n2sYX2oli0 |

### Binary Defense (binarydefense.com)
| | |
| --- | --- |
| Category | Commercial MDR and AI SOC (not a honeypot vendor) |
| What it does | MDR run by US-based operators on its NightBeacon platform. Claims "116+ connectors" and every finding "mapped to MITRE ATT&CK". NightBeacon CMD includes a "Developer API and MCP server". |
| Learn | An auditable "glass box" AI: "Every verdict shows its reasoning and evidence; every action is logged with its owner and timestamp". That's the pattern our LLM correlation and confidence layer should follow (#27, #28). |
| Integrate / Reuse | No. A possible Foiled customer or channel (MDRs consume feeds). |
| Status | Active. |
| Sources | https://binarydefense.com/ |

### The Honeynet Project (honeynet.org)
| | |
| --- | --- |
| Category | Non-profit research community (founded 1999, 501(c)(3)) |
| What it does | Research, awareness and open source tools ("Cuckoo, Capture-HPC, Glastopf, HoneyC, Honeyd, Honeywall"). Publishes the "Know Your Enemy" papers and mentors projects in Google Summer of Code. Its mission is "to learn the tools, tactics and motives involved in computer and network attacks, and share the lessons learned". |
| Learn | The ethics and legal function (they have a Chief Ethics and Legal Officer), and research write-up formats. |
| Contribute | Possible GSoC or chapter collaboration later. |
| Sources | https://www.honeynet.org/about/ |

### Stratosphere Laboratory (stratosphereips.org)
| | |
| --- | --- |
| Category | Academic lab (Czech Technical University in Prague) |
| What it does | Runs "honeypots on four continents", publishes open datasets (malware, normal and mixed captures, IoT malware via Aposemat, and CTU-13 labelled botnet flows under **CC-BY**), and builds **Slips**, an ML behavioural IDS/IPS. |
| Slips | `stratosphereips/StratosphereLinuxIPS`, **GPL-2.0**, last push 2026-10-17, about 894 stars. |
| Learn | Labelled datasets for testing our behaviour clustering and LLM correlation without live data. |
| Integrate | Use the datasets offline for evaluation (CC-BY means attribution only). Run Slips as an optional separate analyser on sensor PCAP. Don't link it into Foiled code (GPL). |
| Sources | https://www.stratosphereips.org/ , https://www.stratosphereips.org/datasets-overview , https://github.com/stratosphereips/StratosphereLinuxIPS |

### Honeyscore (honeyscore.io as given; the real one is honeyscore.shodan.io)
| | |
| --- | --- |
| Category | Honeypot detector (Shodan Labs) |
| Verified | `honeyscore.io` didn't resolve or respond on 17 Oct 2026. The real tool is **https://honeyscore.shodan.io/**: "The defining characteristics of known honeypots were extracted ... The probability that an IP is a honeypot is captured in a 'Honeyscore' value that can range from 0.0 to 1.0." It's described as a prototype. API: `api.shodan.io/labs/honeyscore/{ip}` (needs a Shodan key, and Labs access according to the Rust client docs). There's also a Metasploit module `auxiliary/gather/shodan_honeyscore`. |
| Use | **Self-check.** Run every Foiled sensor IP through Honeyscore on a schedule. A high score means our decoy has been fingerprinted, so rotate or harden it (fingerprint resistance issue). |
| Sources | https://honeyscore.shodan.io/ , https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/auxiliary/gather/shodan_honeyscore.md , https://docs.rs/shodan-rust/latest/src/shodan_rust/lib.rs.html |

### Canarytokens (canarytokens.org, thinkst/canarytokens)
| | |
| --- | --- |
| Category | Free hosted tripwires plus self-hostable open source server |
| What it does | Tokens such as fake AWS API keys and Word documents that alert when used. Free at canarytokens.org, and the code can be self-hosted. |
| Licence | **GPLv3 "BUT ONLY WITH ALL OF THE CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN"**. Thinkst sells other licences "to embed Canarytokens technology into proprietary software". Last push 2026-10-09, about 2.2k stars. |
| Use | Plant tokens (fake cloud keys, `.env` files, DB credentials) inside Foiled high-interaction sandboxes. If an attacker later uses a stolen token from elsewhere, that links the capture to follow-on activity. Run a separate self-hosted server or use the hosted service, and don't copy their code into Foiled. |
| Sources | https://github.com/thinkst/canarytokens , https://canary.tools/ |

---

## Part B. Open source honeypots

| Project | Protocols / purpose | Licence (verified) | Last push / release | Stars | Status |
| --- | --- | --- | --- | --- | --- |
| telekom-security/tpotce (T-Pot) | Multi-honeypot platform, 20+ honeypots, Elastic Stack, Suricata | GPL-3.0 | push 2026-10-09, release 24.04.1 (2024-12-11) | ~9.6k | Active |
| cowrie/cowrie | SSH/Telnet medium to high interaction | BSD-3-Clause (LICENSE.rst SPDX) | push 2026-10-15, v3.1.2 (2026-10-12) | ~6.6k | Active |
| DinoTools/dionaea | Malware capture (SMB, HTTP, FTP, MSSQL, SIP and more) | GPL-2.0 | push 2024-08-01 | ~817 | Slow / stale |
| mushorg/conpot | ICS/SCADA (Modbus, S7, BACnet and more) | GPL-2.0 | push 2026-10-12 | ~1.5k | Active |
| thinkst/opencanary | Low-interaction, multi-protocol, internal | BSD-3-Clause | push 2026-10-05 | ~3.1k | Active |
| johnnykv/heralding | Credential catching across many protocols | GPL-3.0 | push 2024-05-21 | ~397 | Stale |
| honeytrap/honeytrap (DutchSec) | Go honeypot framework | Apache-2.0 (LICENSE file) | push 2023-10-09 | ~1.3k | Stale |
| armedpot/honeytrap (the one T-Pot ships) | Werner's original honeytrap mirror | GPL-2.0 | push 2021-10-11 | ~44 | Unmaintained mirror |
| mushorg/snare | Web application honeypot front end | GPL-3.0 | push 2024-06-10 | ~485 | Stale |
| mushorg/tanner | SNARE analysis and emulation back end | GPL-3.0 | push 2024-08-19 | ~232 | Stale |
| huuck/ADBHoney | Android Debug Bridge over TCP | GPL-3.0 | push 2025-03-05 | ~183 | Low activity |
| SentryPeer/SentryPeer | SIP honeypot with peer-to-peer bad actor sharing | GPL-2.0-only OR GPL-3.0-only (COPYING) | push 2026-10-16, v5.0.0 (2026-10-15) | ~212 | Active |
| skeeto/endlessh | SSH tarpit (slow banner) | Unlicense (public domain) | push 2024-06-03 | ~8.6k | Finished / stable |

Notes per project:

- **T-Pot.** Docker Compose orchestration of 20+ honeypot images (including adbhoney, beelzebub, ciscoasa, citrixhoneypot, conpot, cowrie, dionaea, galah, heralding, honeytrap, log4pot, redishoneypot, sentrypeer, snare and tanner, wordpot). Also runs Suricata, P0f, Fatt (pcap fingerprints), the Elastic Stack (Elasticsearch, Logstash, Kibana), CyberChef, Elasticvue, Spiderfoot, an attack map and Autoheal. It supports a Hive plus Sensor distributed mode where sensors send to the hive through an NGINX reverse proxy. By default it sends data to Sicherheitstacho via `ewsposter`. It has a section on "LLM-Based Honeypots" (beelzebub, galah). Source: https://github.com/telekom-security/tpotce
- **Cowrie.** Has 40 output plugins, including `dshield`, `greynoise`, `misp`, `virustotal`, `malshare`, `urlhaus`, `abuseipdb`, `hpfeeds3`, `kafka`, `elasticsearch`, `splunk`, `s3` and `jsonlog`. Source: https://github.com/cowrie/cowrie/tree/master/src/cowrie/output
- **OpenCanary.** "OpenCanary is the Open Source version of our commercial Thinkst Canary". Optional SNMP (Scapy) and SMB (Samba) modules, and Docker and PyPI builds. Source: https://github.com/thinkst/opencanary
- **SentryPeer.** Active, with v5.0.0 out two days before this research. Source: https://github.com/SentryPeer/SentryPeer
- **Endlessh.** A tarpit, not a sensor. It wastes attacker time but captures almost nothing.

---

## Reuse plan

Principle: Foiled's own code (control plane, API, MCP, UI, enrichment, confidence engine) stays MIT. Third-party honeypots run as **separate, unmodified or lightly patched container images** that write JSON events to a shared bus. Each one is a "decoy module" with a manifest: protocol, product persona, version string, ports, licence, image digest and event schema mapping.

| Priority | Module | Upstream | Licence | Why | Notes |
| --- | --- | --- | --- | --- | --- |
| MVP | SSH/Telnet | Cowrie | BSD-3 | Best maintained. Rich JSON. Already has DShield, GreyNoise and MISP outputs | Can be embedded and modified freely. Use its JSON log as our reference event schema. |
| MVP | Low-interaction multi-protocol | OpenCanary | BSD-3 | Cheap breadth (FTP, HTTP, MySQL, RDP, VNC, Redis, SNMP and more) for fingerprint and recon signals | Good default "background" persona on every sensor. |
| MVP | Web app | SNARE + TANNER | GPL-3.0 | Clones a real site and emulates web attack classes | Stale since 2024. Run as a separate container and only publish our patches. Our own CVE-specific emulators (#30) will matter more for edge products. |
| v0.2 | Credentials | Heralding | GPL-3.0 | Credential capture across many protocols, which feeds credential IOCs | Stale. Separate container. Could be replaced by Cowrie plus OpenCanary auth logs if it rots. |
| v0.2 | ICS | Conpot | GPL-2.0 | Active. Australian water, energy and council relevance | Separate container. Pair with the Australian critical infrastructure angle (SOCI). |
| v0.2 | SIP/VoIP | SentryPeer | GPL-2.0-only or GPL-3.0-only | Active. Toll fraud and SIP scanning | Separate container. It has its own peer-to-peer sharing we could join. |
| v0.2 | ADB | ADBHoney | GPL-3.0 | IoT and Android botnet droppers (Mirai-style) | Low activity. Separate container. |
| v0.3 | Malware capture | Dionaea | GPL-2.0 | Captures binaries over SMB and others | Stale since Aug 2024 and C-based, so it carries more risk. Run only in a strongly isolated sandbox. Consider later. |
| Optional | Tarpit | Endlessh | Unlicense | Cost-imposing extra on unused SSH ports | No intel value. Not needed for MVP. |
| Skip | honeytrap (DutchSec, Apache-2.0) | | | Last push 2023, so effectively unmaintained | Worth a look for Go framework ideas only. |
| Watch | Beelzebub, Galah (LLM honeypots in T-Pot) | | Licences not checked here | LLM-driven high interaction is the direction our #28 and #32 work points | Check licences before use. |

**How T-Pot's architecture shapes ours:**
- **Copy.** One container per honeypot with a health check and auto-restart (Autoheal). The Hive plus Sensor split with a single authenticated ingest point (T-Pot uses an NGINX proxy, we'd use mTLS per sensor, #31). Run Suricata, P0f and Fatt beside the honeypots so every hit gets JA3/JA4/HASSH and passive OS fingerprints. Share data with the community by default with a clear opt-out.
- **Change.** ELK is heavy for a Raspberry Pi or a A$6 VPS. Use a small event shipper on sensors (Vector or Fluent Bit) and store centrally in Postgres plus ClickHouse or OpenSearch, so sensors stay small. Replace Kibana dashboards with our own UI built around attempts, confidence and ATT&CK instead of raw event counts. T-Pot is all-or-nothing per host. Foiled should let the API or MCP start one persona per sandbox on demand.
- **Licence note.** T-Pot is GPL-3.0. Learn from its compose and config patterns, but write our own orchestration rather than copying T-Pot files into the MIT repo.

---

## Enrichment integrations

Applied in this order for each new source IP or indicator, with every result cached and its timestamp recorded:

1. **GreyNoise Community or paid API.** `noise` and `riot` flags. Noise lowers the targeted score, RIOT marks benign. Inputs to the confidence layer (#27). Free tier is 50 lookups a week, so cache hard or pay for Standard.
2. **CrowdSec CTI.** Reputation, behaviours mapped to ATT&CK, linked CVEs. Free tier first, US$49/month for 5,000 queries if needed. Their ATT&CK labels are an outside check on ours (#26).
3. **DShield `/api/ip`.** Count, attacks, first and last seen, and which threat feeds list the IP. Free, with a contact User-Agent. Internal use only. Never resold.
4. **Shadowserver.** ASN and Network API for routing. Their special reports are an outside check on our CVE calls. Subscribe our own sensor ranges.
5. **Hunt.io (paid, optional).** Pivot stage-2 URLs and callback IPs to known C2 and attacker infrastructure. Raises campaign and actor link confidence (#29, #33). Their MCP server could be called by our own agents.
6. **Honeyscore self-check (Shodan Labs).** A scheduled job scores every Foiled sensor IP. Above a threshold, raise a "decoy burnt" alert and rotate (fingerprint resistance issue, plus feed age as Defused does it).
7. **Canarytokens.** Plant unique fake credentials (AWS keys, `.env`, DB DSNs) in every high-interaction sandbox. A trigger later links the capture to follow-on use and gives near-certain proof the attacker took the bait.
8. **Stratosphere.** CTU-13 and malware captures (CC-BY) as labelled test data for clustering and LLM correlation. Slips as an optional separate analyser on sensor PCAP.
9. Already available through Cowrie output plugins: VirusTotal, MalShare, URLhaus and AbuseIPDB lookups or submissions. Each is opt-in.

---

## Differentiation from the commercial players

- **GreyNoise, CrowdSec, Shadowserver and DShield** tell you *who is scanning*. **Defused and CounterCraft** tell you *what exploit landed*. Foiled's angle is the step after that: **why we think it's this CVE, with a visible confidence score and evidence trail**. Signature, behaviour sequence, code path hook, outside confirmation and LLM correlation are each shown with a weight, the way Binary Defense shows its working.
- **Agent native.** An MCP server to start sandboxes and query attempts (only Hunt.io and Binary Defense mention MCP in this set, and neither runs decoys).
- **Open sensor, paid analysis.** Thinkst's model of an open source OpenCanary next to a commercial Canary, applied to internet-facing exploit intel. Defused's self-hosted Builder is still limited release.
- **Australian first.** No vendor here mentions Australian sensor locations, ACSC or Essential Eight mapping, or onshore data. Shadowserver serves national CSIRTs but isn't tied to one country.
- **Price.** GreyNoise has no public dollar prices, CrowdSec's commercial feeds start at US$1,900 to US$2,000 a month, Hunt.io at US$199 a month, Thinkst's package is quote-based (an unconfirmed US$7,500 a year for 5), and Defused's at US$69 to US$899. Foiled can sit at A$49 to A$99 for a pro feed.
- **Standards exports from day one.** STIX 2.1 and TAXII, MISP and Sigma. Cowrie already has MISP output we can build on.
- **Not competing with** internal deception (Attivo/SentinelOne, Smokescreen/Zscaler, TrapX/Commvault Threatwise, CounterCraft, Thinkst Canary). That market has consolidated into big platforms, and external exploit intel is the open gap.

---

## Contribution back

- **DShield.** Turn on Cowrie's `dshield` output on public research sensors. Note the DShield sensor's own install is opinionated (dedicated device, moves real SSH to 12222), so use the plugin rather than their installer.
- **CrowdSec.** Run the Security Engine with **unmodified** Hub scenarios on sensor hosts so our signals count towards consensus (their docs say modified scenarios on honeypots don't count). That gets us the Community Blocklist (15k IPs) in return.
- **SentryPeer.** Join its peer-to-peer data sharing if the SIP module ships.
- **Upstream patches.** Send fixes back to Cowrie, Conpot, SNARE/TANNER and Heralding. For the GPL modules we have to publish our changes anyway.
- **Public research.** Publish delayed IOCs and write-ups under CC BY 4.0 (our choice, which allows reuse). Give data to Shadowserver if they accept partner honeypot feeds (not verified, so ask them).
- **Datasets.** Publish anonymised, labelled attempt datasets the way Stratosphere does, for researchers.

---

## Licence blockers and implications (summary)

- **No AGPL** in this set. The strongest is GPL-3.0 (T-Pot, Heralding, SNARE, TANNER, ADBHoney) and GPL-2.0 (Dionaea, Conpot, DShield sensor, Slips). SentryPeer is GPL-2.0-only or GPL-3.0-only.
- Running GPL honeypots as **separate programs in their own containers** that talk to Foiled over JSON, a socket or a queue is normally treated as "mere aggregation", so Foiled's MIT code isn't affected. What we must do when we **distribute** those images: ship or offer the source, keep their licence files, and publish any changes under the same GPL.
- **Don't** import GPL Python modules (for example TANNER's emulators or Slips) into Foiled's MIT code, or copy T-Pot compose and config files wholesale. If we want that logic inside Foiled, write it clean-room.
- **Canarytokens** is GPLv3 with Thinkst's own clarifications and a paid embedding licence. Call it as a separate service and never embed it.
- **Data licences matter more than code licences for a paid feed.** DShield data is CC BY-NC-SA and "do not resell", so it's fine for internal enrichment but must stay out of the paid feed. GreyNoise and Hunt.io data are proprietary, and CrowdSec needs its Partnership Program for commercial embedding. Show third-party enrichment to the subscriber who pays for it, but never republish it in Foiled's own feed.
- **Permissive picks** that can be embedded freely: Cowrie (BSD-3), OpenCanary (BSD-3), Endlessh (Unlicense), DutchSec honeytrap (Apache-2.0, but stale), CrowdSec engine (MIT).

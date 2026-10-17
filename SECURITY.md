# Security policy

Foiled deliberately runs vulnerable software. That makes the line between "a decoy is vulnerable" (expected) and "Foiled is vulnerable" (a bug we must fix) important. This page explains how to report the second kind.

## How to report

Report vulnerabilities in Foiled itself privately through a GitHub security advisory:

https://github.com/jusso-dev/foiled/security/advisories/new

Please do not open a public issue, pull request or discussion for a problem that could still be exploited against people running Foiled. If you are unsure whether something is sensitive, report it privately and we will help decide.

## What counts as a Foiled vulnerability

In scope, roughly in order of priority:

1. **Sandbox escape or containment bypass. This is a critical report.** Any way for code or traffic inside a decoy to reach the sandbox host, another decoy, the control plane, the capture store or the internet beyond the allowed egress rules. This includes breaking out of a sandbox or emulator, bypassing the deny-by-default egress policy (#4), tampering with capture from inside a decoy, or reaching the host agent (#41) from a decoy network. Report these even if you only have a partial chain or a theory you could not finish testing.
2. Authentication or authorisation flaws in the control plane API, the operator dashboard, edge sensor enrolment and mTLS (#31) or the host agent protocol.
3. Ways to inject content into exports (STIX, MISP, TAXII, IOC files), the dashboard or public exploit pages from attacker-controlled capture data, for example stored cross-site scripting through a captured payload.
4. Exposure of secrets, operator data or personal information that Foiled stores.
5. Supply chain problems in Foiled's own build, such as an image that is not pinned by digest when it should be.

Out of scope:

- **CVEs in the deliberately vulnerable decoy applications.** The software in a decoy is old and vulnerable on purpose. A working exploit against a decoy, or a chain of third-party CVEs against a honeypot app, is not a Foiled vulnerability. It only becomes one if it lets you get out of the decoy, as described above.
- Fingerprinting a decoy as a honeypot. We track fingerprint resistance as normal work in #18, so a public issue is fine.
- Vulnerabilities in upstream decoy modules (for example Cowrie or Conpot) that do not break Foiled's containment. Please report those to the upstream project.
- Findings that need an already compromised operator account or host, unless they let you go further than that account or host should allow.

## Supported versions

Foiled is in early development and has no stable release yet. Only the `main` branch is supported. Once we tag releases, this section will list which ones receive security fixes.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Anything else | No |

## What we ask of reporters

- Give us enough detail to reproduce: affected component, version or commit, steps, and the impact you observed.
- Test against your own deployment. Do not test against systems you do not own or operate, including other people's Foiled sensors.
- Use example data where you can. Do not include real personal information or real attacker captures in the report unless they are needed to show the problem.
- Do not access, change or delete data beyond what you need to show the issue.
- Give us reasonable time to fix the issue before you publish details. We will agree a disclosure date with you, and we are happy to credit you in the advisory if you would like.

## What you can expect from us

Foiled is maintained by a small team, so these are aims, not guarantees:

- We aim to acknowledge a report within a week.
- We will keep you updated on our assessment and the fix.
- Containment bypass reports are handled first.
- We will publish a GitHub security advisory once a fix is available.

## Safe harbour

If you act in good faith, follow this policy and only test systems you own or are allowed to test, we will not pursue or support legal action against you for your research, and we will treat your report as a helpful contribution. We cannot speak for third parties, such as the vendors of decoy software or the owners of other systems, and this statement is not legal advice. If you are unsure whether something is allowed, ask us first through a private advisory.

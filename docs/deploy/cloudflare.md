# Cloudflare in front: what goes behind the proxy and what never does

Status: Draft for the MVP. Owner: #7. Related: #4 (network isolation and frontend options), #11 (enrichment), #18 (fingerprint resistance), #25 (noise score), #40 (Workers control plane).

Foiled uses Cloudflare in two very different ways, and they must not be confused:

1. The **control plane** runs on Cloudflare Workers ([workers.md](workers.md)). It is on Cloudflare by design, and its hostnames sit behind Cloudflare Access or mTLS.
2. **Decoys** run on sandbox hosts ([vps.md](vps.md)). The question here is whether to put the Cloudflare reverse proxy (an orange-cloud DNS record, or Spectrum for non-HTTP) in front of a decoy.

## MVP recommendation

- **Decoys are never behind the Cloudflare proxy.** Each decoy is reached directly on a dedicated public IP of its sandbox host. If a decoy hostname lives in a Cloudflare DNS zone, its record is DNS-only (grey cloud).
- **Only the control plane is behind Cloudflare:** the console hostname, the API hostname and the ingest hostname.
- Use a **separate registrable domain** for decoy hostnames, with no link to the control-plane domain. Certificate Transparency logs, shared name servers and shared WHOIS details all let an attacker connect a decoy to the console. A separate Cloudflare account for decoy DNS is better still.

This holds whenever intel quality matters, which for Foiled is always. ADR 0009 (#40) records the same rule.

## Trade-offs

| Concern | Decoy behind the Cloudflare proxy | Decoy on a direct dedicated IP (recommended) |
| --- | --- | --- |
| Real client IP | The TCP connection comes from a Cloudflare edge address. For HTTP the client IP arrives in `CF-Connecting-IP`; for non-HTTP you need Spectrum with Proxy Protocol, which is limited by plan for arbitrary TCP and UDP. Every hop that reads the header must trust it only from Cloudflare's published ranges, or an attacker can forge it. | The socket peer is the attacker's address. Nothing to trust or forge. |
| Attribution and enrichment | IP, ASN and geolocation enrichment (#11) and the noise score (#25) work only if every header is handled correctly. Any slip attributes attacks to Cloudflare. | Works as designed. |
| Fingerprints | TLS fingerprints (JA3, JA4), TCP and passive OS fingerprints, and HTTP/2 settings describe Cloudflare's edge, not the attacker's tooling. That evidence is lost for #9 and #12. | The attacker's own TLS, TCP and HTTP fingerprints are captured. |
| "Too clean" | Cloudflare's WAF, managed rules, bot management and DDoS filters drop or challenge a large share of the exploit traffic we want to see. What reaches the decoy is a filtered sample. | The decoy sees the raw traffic, which is the point. |
| Looking like the real thing | Real vulnerable appliances (VPN gateways, NAS boxes, admin panels) rarely sit behind Cloudflare. A `server: cloudflare` header, `cf-ray`, Cloudflare error pages and a Cloudflare IP are honeypot tells (#18). Internet-wide scanners index Cloudflare addresses, not the decoy. | Looks like an exposed server on a hosting provider, which is what most vulnerable software looks like. |
| Non-HTTP decoys | SSH, SMB, databases and ICS protocols need Spectrum, and many do not work at all. | Any TCP or UDP port the catalogue entry publishes (#5). |
| Hiding the origin | Hides the host IP from people who find the hostname, but scanners hit IPs directly, so the origin is found anyway. | Not hidden. It does not need to be: no management port listens on it ([vps.md](vps.md)). |
| DDoS | Absorbed by Cloudflare. | The provider's DDoS protection only. A flooded decoy is a lost decoy, not a breach. Rotate it (#8). |
| Terms and abuse | Proxying deliberately vulnerable content through Cloudflare is a terms question we have not cleared, and abuse reports go to Cloudflare. | Covered by the hosting provider's terms, which the operator checks before bring-up ([vps.md](vps.md)). |

## When the proxy might still be used

There is one case where proxying a decoy can make sense: a lab or a study that specifically measures what gets through Cloudflare. If you do this:

- Treat it as a separate experiment, flagged on the decoy and in its attempts, so its data never mixes with direct decoys in the noise score or the radar (#35).
- Trust `CF-Connecting-IP` only when the TCP peer is in Cloudflare's published ranges, and record both the peer and the header.
- Do not reuse the decoy's hostname, certificate or IP for a direct decoy later.

It is not supported for the MVP.

## The control plane side

Everything the control plane exposes sits on Cloudflare and is never reachable without auth:

| Hostname (placeholder) | Served by | Protection |
| --- | --- | --- |
| `console.example.com` | `foiled-web` Worker | Cloudflare Access application with an identity provider and MFA. |
| `api.example.com` (for MCP #24 and scripts) | `foiled-api` Worker | Cloudflare Access (service tokens for automation) plus scoped API tokens checked in the Worker (#21). |
| `ingest.example.com` | `foiled-api` Worker | mTLS required: a WAF rule blocks requests without a verified client certificate, and the Worker checks the certificate again (#31). |

Details, bindings and deploy steps are in [workers.md](workers.md). Real hostnames and zone names stay out of this repository.

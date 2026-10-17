# Foiled

Foiled runs sandboxed and emulated vulnerable decoys that foil exploit attempts and capture threat intelligence.

It stands up real software at deliberately old, known-vulnerable versions (and lightweight high-fidelity product emulations) inside tightly contained environments. Every request, payload and process an attacker triggers is captured, enriched and exported as threat intelligence (STIX 2.1, MISP, TAXII and plain IOC files).

The idea: if you expose "Product X at version Y, which is affected by CVE Z", the traffic that hits it tells you who is exploiting CVE Z right now, how they do it and what they drop.

## Status

Planning. There is no product code yet. Design and roadmap live in issues and docs:

- Roadmap and tracking: https://github.com/jusso-dev/foiled/issues/23
- MVP scope: https://github.com/jusso-dev/foiled/milestone/1
- All issues: https://github.com/jusso-dev/foiled/issues
- Research landscape: [docs/research/landscape.md](docs/research/landscape.md)
- Lessons from commercial platforms: [docs/research/lessons.md](docs/research/lessons.md)
- Design direction and mockup: [docs/design/design-direction.md](docs/design/design-direction.md), [docs/design/mockup.html](docs/design/mockup.html)

## Safety

This project deliberately runs vulnerable software. The design treats containment, egress control and legal limits as the first requirement, not an add-on. It will never "hack back" or interact with attacker infrastructure beyond passive observation.

## Licence

MIT. See [LICENSE](LICENSE). Third-party honeypot modules shipped as separate container images keep their own licences; see the landscape doc and the compliance register issue.

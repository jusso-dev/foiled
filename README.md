# Foiled

![Foiled hero art: a hooded figure in a burning cyberpunk wasteland facing a wall of red threat intelligence dashboards showing live attacks, exploits and honeypot feeds](docs/assets/foiled-hero.jpg)

Foiled runs sandboxed and emulated vulnerable decoys that foil exploit attempts and capture threat intelligence.

It stands up real software at deliberately old, known-vulnerable versions (and lightweight high-fidelity product emulations) inside tightly contained environments. Every request, payload and process an attacker triggers is captured, enriched and exported as threat intelligence (STIX 2.1, MISP, TAXII and plain IOC files).

The idea: if you expose "Product X at version Y, which is affected by CVE Z", the traffic that hits it tells you who is exploiting CVE Z right now, how they do it and what they drop.

## Status

Planning. There is no code yet. The design and roadmap live in the issues:

- Roadmap and tracking: https://github.com/jusso-dev/foiled/issues/23
- MVP scope: https://github.com/jusso-dev/foiled/milestone/1
- All issues: https://github.com/jusso-dev/foiled/issues

## Safety

This project deliberately runs vulnerable software. The design treats containment, egress control and legal limits as the first requirement, not an add-on. It will never "hack back" or interact with attacker infrastructure beyond passive observation.

## Licence

MIT. See [LICENSE](LICENSE).

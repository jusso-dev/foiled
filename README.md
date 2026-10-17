# version-trap

version-trap is a planned tool that runs real software at deliberately old, known-vulnerable versions inside tightly contained sandboxes, so they can act as honeypots. Every request, payload and process the attacker triggers is captured, enriched and exported as threat intelligence (STIX 2.1, MISP, TAXII and plain IOC files).

The idea: if you expose "Product X at version Y, which is affected by CVE Z", the traffic that hits it tells you who is exploiting CVE Z right now, how they do it and what they drop.

## Status

Planning. There is no code yet. The design and roadmap live in the issues:

- Roadmap and tracking: https://github.com/jusso-dev/version-trap/issues/23
- MVP scope: https://github.com/jusso-dev/version-trap/milestone/1
- All issues: https://github.com/jusso-dev/version-trap/issues

## Safety

This project deliberately runs vulnerable software. The design treats containment, egress control and legal limits as the first requirement, not an add-on. It will never "hack back" or interact with attacker infrastructure beyond passive observation.

## Licence

MIT. See [LICENSE](LICENSE).

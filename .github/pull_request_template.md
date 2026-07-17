## Summary

Describe what changed and why.

## DNSSEC safety

- [ ] The change preserves the invariants in `POLICY.md` and `docs/spec.md`.
- [ ] A defect fix includes a failing reproducer test first, or explains why that was not possible.
- [ ] PowerDNS, registrar, and DNS observations remain behind testable interfaces.
- [ ] No production credential, endpoint, domain, address, identity, state, or deployment file is included.
- [ ] Mutating behavior remains explicit, idempotent, and safe after interruption.

## Repository gates

- [ ] Documentation, comments, examples, and user-facing strings are in English.
- [ ] `make guardrails` passes for the complete first-party project.
- [ ] `vendor/` is synchronized after dependency changes and excluded from lint findings.
- [ ] `make release-guardrails` passes for release-sensitive changes.
- [ ] OpenAPI and configuration documentation match the implementation.

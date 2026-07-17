---
name: dnssec-keyrotation-config-security
description: Keep DNSSEC controller configuration, examples, tests, and repository content secret-safe and publishable. Use when changing configuration loading, SOPS handling, deployment examples, credentials, endpoints, domains, addresses, or ignore rules.
---

# DNSSEC key-rotation configuration safety

## Classify configuration

- Commit only public schemas, defaults, and examples containing RFC-reserved domains, addresses, and obviously fake credentials.
- Keep runtime deployment material under ignored `deploy/` and scratch work under ignored `temp/`.
- Keep `.sops.yaml`, `.sops.yml`, `secrets.sops.env`, `.env`, state databases, and local configuration variants ignored.
- Use file-backed secrets referenced by configuration. Never put secret values in YAML, environment examples, command lines, logs, snapshots, tests, or chat output.

## Change configuration

1. Read `POLICY.md`, `docs/spec.md`, `configs/config.example.yaml`, and `internal/config/`.
2. Preserve strict validation and fail closed for absent or malformed secret files.
3. Use `example.test`, `example.net`, `example.org`, RFC 5737 addresses, and non-routable examples in tests and documentation.
4. Keep defaults, validation, `configs/config.example.yaml`, README guidance, and OpenAPI descriptions aligned.
5. Do not copy live deployment files into public paths, even after redacting selected fields.

## Verify

- Run focused configuration tests, then `make guardrails`.
- Inspect tracked and untracked public files for personal domains, hosts, addresses, email addresses, usernames, tokens, key material, and infrastructure paths.
- Verify ignored sensitive paths with `git check-ignore -v` without printing their contents.

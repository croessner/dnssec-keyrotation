# AGENTS.md

## Mission

This repository operates DNSSEC signing keys and parent delegation material. Treat every mutation as production-critical.

## Mandatory workflow

1. Read `POLICY.md` and `docs/spec.md` before changing behavior.
2. Reproduce with a failing unit, contract, or integration test before fixing a defect.
3. Keep PowerDNS, registrar, and DNS observation behind interfaces. Tests must not need production credentials.
4. Never print, commit, snapshot, or pass secrets on command lines. Secrets are file-backed only.
5. A registrar acknowledgement is not proof. Parent DS observation from every configured resolver is required before local KSK transitions.
6. Never delete the last active key for a role. Never mutate CSK zones through the KSK/ZSK paths.
7. Preserve idempotency. Every state transition must be safe after process interruption and retry.
8. Run `make guardrails` before every commit, pull request, or handoff. Run `make release-guardrails` before publishing `main` or a `v*` tag.

## Repository workflow

- Use `features` for regular development and merge reviewed changes into `main`.
- Create release tags only from validated `main` commits.
- Prefer Makefile targets over ad hoc command variants.
- Lint the complete first-party Go tree with `golangci-lint run ./...`; never limit lint to a diff, HEAD, or new issues. Exclude `vendor/` from lint findings.
- Run `govulncheck ./...` against the complete module before publishing release-sensitive refs.
- Keep `vendor/` synchronized after dependency changes with `go mod tidy` and `go mod vendor`.
- Preserve unrelated working-tree changes. Do not commit, push, merge, tag, or reset unless the user requests that scope.

## Documentation and scratch

- Write code comments, commit messages, and technical documentation in English.
- Keep durable documentation under `docs/` and the normative controller contract in `docs/spec.md`.
- Keep local plans, operational reports, handoffs, and scratch artifacts under ignored `temp/`. Never stage or commit `temp/`.
- Keep examples publication-safe by using reserved example domains, documentation IP ranges, and non-secret placeholder identities.

## Commit format

- Use `Prefix: Concise headline` with one of: `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`, `Docs`, `Build`, `Ci`, `Vendor`, `Security`, `Chore`.
- Use a short bullet-list body for relevant implementation and validation details.
- Split unrelated work into separate commits.

## Scope discipline

- `observe` mode is read-only.
- `enforce` mode may only execute already modelled state-machine transitions.
- Adding a new destructive transition requires a spec and policy update in the same change.
- Generated OpenAPI and configuration documentation must remain aligned with code.

---
name: dnssec-keyrotation-repo-workflow
description: Apply this repository's branch, dependency, test, lint, and release workflow. Use for Go changes, dependency updates, GitHub Actions, release preparation, or any change that must pass the project-wide quality gates.
---

# DNSSEC key-rotation repository workflow

## Establish scope

1. Read `AGENTS.md`, `POLICY.md`, and `docs/spec.md` before changing behavior.
2. Preserve unrelated working-tree changes and ignored operational material.
3. Work on `features` for normal development. Merge reviewed, green changes into `main`; create release tags only from validated `main` commits.

## Implement safely

- Reproduce defects with a failing test before fixing them.
- Keep PowerDNS, registrar, and DNS observations behind interfaces.
- Keep documentation, examples, comments, commit messages, and user-facing strings in English.
- Update vendored dependencies with `go mod tidy` followed by `go mod vendor`; never hand-edit `vendor/`.
- Use `Add:`, `Change:`, `Fix:`, `Remove:`, `Refactor:`, `Test:`, `Docs:`, `Build:`, `CI:`, `Security:`, `Vendor:`, or `Chore:` commit subjects.

## Run gates

1. Run `make guardrails` for every code or CI change.
2. Confirm `golangci-lint run ./...` checks the complete first-party module; do not configure diff-only, HEAD-only, or new-issues-only linting.
3. Keep `vendor/` excluded from lint and security scanning while compiling and testing with `-mod=vendor`.
4. Run `make release-guardrails` before a release tag or a change to release-critical behavior.
5. Run `actionlint` after changing `.github/workflows/`.
6. Confirm validation did not mutate tracked files with `git diff --exit-code` when the tree was clean before validation.

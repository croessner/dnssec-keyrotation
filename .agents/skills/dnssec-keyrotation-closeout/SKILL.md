---
name: dnssec-keyrotation-closeout
description: Verify and hand off completed changes in this production-critical repository. Use before committing, merging, tagging, publishing, or reporting that code, documentation, CI, configuration, or deployment work is complete.
---

# DNSSEC key-rotation change closeout

## Inspect the result

1. Review `git status --short` and the complete diff. Preserve unrelated work and ignored operational files.
2. Confirm the implementation matches `POLICY.md` and `docs/spec.md`; call out any deliberate deviation.
3. Confirm all committed documentation, examples, comments, and user-facing output are English and public-safe.
4. Check that generated OpenAPI and configuration documentation match code.

## Run proportional validation

- Documentation-only: validate links, examples, English wording, ignore behavior, and relevant lightweight checks.
- Code or CI: run `make guardrails`; run `actionlint` for workflow changes.
- Security-sensitive or release-critical: run `make release-guardrails` in addition to focused tests.
- Container changes: build the image and ensure vulnerability scanning, SBOM generation, provenance, and immutable action pins remain configured.

Do not claim a gate passed if it was skipped or blocked. Report the exact command and blocker.

## Hand off

State the outcome first as `healthy`, `blocked`, or `partial`. Then list material changes, validation results, the active branch, and any remaining publication blocker such as a missing license, repository setting, required secret, or branch-protection rule. Never include secret values or private infrastructure details.

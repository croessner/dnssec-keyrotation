---
name: dnssec-keyrotation-openapi-cli
description: Keep the local control HTTP API, OpenAPI document, dnssecctl commands, and contract tests aligned. Use when adding or changing endpoints, request or response types, CLI commands, flags, status output, or error semantics.
---

# DNSSEC key-rotation OpenAPI and CLI

## Map the contract

Read `api/openapi.yaml`, `internal/control/`, `cmd/dnssecctl/`, and the matching controller types before editing. Identify the handler, client call, CLI surface, schema, and contract tests affected by the change.

## Change the contract

1. Add or update tests that demonstrate the expected request, response, status code, idempotency behavior, and error shape.
2. Keep mutating operations explicit: confirmation and idempotency keys remain mandatory where required by policy.
3. Update server routing and typed request or response structures.
4. Update the control client and CLI command, including English help and errors.
5. Update `api/openapi.yaml` in the same change. Do not leave generated or normative API documentation behind the implementation.
6. Preserve the Unix-socket trust boundary; do not add an unauthenticated network listener as a convenience.

## Verify

- Run focused tests for `internal/control` and `cmd/dnssecctl`.
- Run `make openapi-check` and `make guardrails`.
- Exercise read-only CLI commands against test fixtures when possible; never point tests at production sockets or credentials.

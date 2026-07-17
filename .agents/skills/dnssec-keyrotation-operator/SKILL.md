---
name: dnssec-keyrotation-operator
description: Safely inspect, test, deploy, and operate this repository's PowerDNS and InternetX DNSSEC key-rotation controller. Use for DNSSEC rotation changes, deployment rollout or health checks, ZSK/KSK/CSK workflow diagnosis, controller CLI operations, registrar DS drift, or recovery from a blocked phase.
---

# DNSSEC key-rotation operator

## Establish truth

1. Read the repository `AGENTS.md`, `POLICY.md`, `docs/spec.md`, and `api/openapi.yaml`.
2. Treat live PowerDNS API state, public DNSSEC observations, and persisted controller state as independent evidence surfaces.
3. Keep secrets file-backed. Never print SOPS plaintext, API credentials, private DNSKEY material, or broad PowerDNS configuration.

## Choose the workflow

- For review or diagnosis, remain read-only and use `dnssecctl status`, `dnssecctl zones`, logs, and public `dig +dnssec` evidence.
- For code changes, add a failing reproducer first, keep external systems behind interfaces, and run `make check` plus `make security`.
- For deployment, build the static Linux binary and scratch image, verify its digest, deploy in observe/bootstrap mode first, verify every configured DNSSEC zone, then enable enforcement and remove only the superseded cron entries.
- For a manual rotation, run `dnssecctl plan` first. Trigger only with an explicit kind, zone list, `--confirm`, and a unique idempotency key.
- For a blocked phase, do not delete keys or edit state directly. Prove PowerDNS keys, DNSKEY/RRSIG visibility, InternetX public material, and parent DS state; then implement a forward-safe recovery.

## Enforce invariants

- Never delete an active key or the last usable key for a role.
- Never use the KSK/ZSK workflow on a CSK zone. Use only the explicit `split` migration.
- Require new DNSKEY propagation before switching a ZSK.
- Require parallel old/new DNSKEY signatures and full DNSKEY-TTL propagation before replacing parent material with the new-only KSK.
- Require final InternetX job success, authoritative new-only DS evidence, the full persisted parent DS TTL, and AD-validated resolver evidence before deactivating the old KSK.
- Require new-only parent DS observations from every configured resolver before retiring the old KSK.
- Treat InternetX acceptance as asynchronous acknowledgement, not completion.
- Preserve phase intent across ambiguous writes and process restarts.
- Keep LMTP completion events durable until delivered; never include DNSKEY, DS, or credential data in reports.

## Close out

Report the exact controller mode, healthy/blocked zone counts, active workflows, image digest, service health, and whether the legacy cron entries remain. Classify the outcome as `healthy`, `blocked`, or `partial`.

# DNSSEC key rotation controller

This Go controller replaces fixed day-based PowerDNS key scripts with restart-safe RFC 7583 workflows. It discovers DNSSEC-enabled zones through the PowerDNS API, rolls local ZSKs monthly, coordinates double-KSK rollovers with InternetX every 182 days, provides an explicit CSK-to-split migration, and can safely enroll newly discovered clean split zones at the parent.

Private keys never leave PowerDNS. InternetX receives public KSK material only. Parent changes advance solely after authoritative DS-TTL and independent validating-resolver evidence.

Completed rotations are reported through a durable, retrying LMTP outbox. The LMTP endpoint, sender, and recipients are configuration values; reports contain identifiers and timestamps only, never key material or credentials.

## Development

```sh
make guardrails
```

Read `POLICY.md` and `docs/spec.md` before modifying rollover behavior.

Normal development happens on `features`; reviewed, green changes are merged into `main`. The guardrails lint and test the complete first-party Go module with vendored dependency resolution. `vendor/` is compiled but excluded from lint and security findings.

Before publishing `main` or creating a `v*` release tag, run:

```sh
make release-guardrails
```

GitHub Actions repeat the full-project guardrails, govulncheck, gosec, Trivy, CodeQL, container build and scan, multi-architecture image publication, SBOM/provenance generation, and release artifact checks. Actions and tool versions are pinned; no lint workflow is limited to the current diff or HEAD.

## CLI

```sh
dnssecctl status
dnssecctl zones
dnssecctl audit
dnssecctl plan --kind zsk --zone example.test
dnssecctl trigger --kind zsk --zone example.test --confirm \
  --idempotency-key operator-20260717-example-zsk
dnssecctl resume --zone example.test --confirm \
  --idempotency-key operator-20260717-example-resume
dnssecctl enrollment status
dnssecctl enrollment arm --confirm \
  --idempotency-key operator-20260717-enrollment-baseline
```

`status` also reports pending completion notifications. Delivery is at-least-once, so a stable event ID is included for duplicate detection after ambiguous LMTP network failures.

The control plane is Unix-socket-only. `audit` is read-only and compares active local KSK/CSK public material with InternetX without exposing it.

Automatic initial enrollment is disabled by default and remains disarmed even when the config switch is enabled. The one-time `enrollment arm` command baselines all current DNSSEC zones without any external write. Only a clean split zone first seen later can become a candidate. Discovery is minute-level, but the registrar write is intentionally delayed by the 24-hour discovery grace, the full DNSKEY evidence wait, and propagation margin. The enrollment workflow never mutates local PowerDNS keys and is protected by exact parent delegation, no-DS, DNSKEY/signature, one-write, asynchronous-job, parent-TTL, and multi-resolver AD gates.

An explicitly confirmed `split` can also enroll an initially insecure delegation. It accepts only the exact InternetX disabled-empty state (`dnssec=false` with no material, or both documented optional DNSSEC fields omitted together), proves signed parent DS absence before creating replacement keys, uses authoritative-only cryptographic evidence before enrollment, and restores the full recursive AD gates as soon as the DS is published.

During this pre-enrollment transition PowerDNS can report the recorded replacement keys as `csk` until the ZSK becomes active. The controller accepts that label only for the exact persisted IDs when DNSKEY protocol, flags, algorithm, state, and the complete inventory prove the intended KSK/ZSK roles. `dnssecctl resume` is intentionally limited to revalidating and restarting a blocked initial split at `wait_publish`; it performs no PowerDNS or registrar write and restarts the full DNSKEY evidence wait.

## Production layout

Production deployment files are intentionally kept outside the public source tree. A deployment should use host networking only when required to reach loopback PowerDNS, a scratch image, a numeric non-root user, a read-only root filesystem, no capabilities, no-new-privileges, file-backed secrets, bounded resources, and an exclusive persisted-state lock.

Example release images use `registry.example.test/example/dnssec-keyrotation:<tag>`; production deployments should pin the verified digest.

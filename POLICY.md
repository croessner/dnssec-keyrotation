# DNSSEC Key Rotation Policy

## Roles

- ZSKs are generated and stored by PowerDNS and sign zone data.
- KSKs are generated and stored by PowerDNS and sign the apex DNSKEY RRset.
- InternetX receives public KSK material and provisions the corresponding parent/registry DS data. It never receives private key material.
- CSKs are not silently treated as either role. Conversion to split KSK/ZSK is an explicit migration.

## Default cadence

- ZSK: 30 days, RFC 7583 pre-publication rollover.
- KSK: 182 days, RFC 7583 double-KSK rollover coordinated with InternetX.
- Key algorithm: preserve the zone's current algorithm; new split zones default to ECDSAP256SHA256 (algorithm 13).

Cadence makes a rotation eligible. Cache and propagation evidence determines when phases may advance.

## Mandatory guardrails

1. Discover zones from the PowerDNS API and operate only on zones with `dnssec: true`.
2. Require exactly one active key for each expected role before starting.
3. For ZSK, require the candidate DNSKEY to be visible for the authoritatively observed DNSKEY TTL plus propagation margin before activation.
4. For KSK, create the candidate active and published, cryptographically prove parallel DNSKEY signatures, then wait the authoritatively observed DNSKEY TTL plus propagation margin before changing the parent.
5. Activate a new ZSK, prove its zone signature, and only then deactivate the old ZSK. Keep the old DNSKEY published for the persisted pre-switch maximum zone TTL plus margin.
6. Replace InternetX material with the new-only KSK only after DNSKEY prepublication. Treat the asynchronous acknowledgement as pending, not completion.
7. From the first exact new-only authoritative parent DS observation, wait the full authoritative DS TTL (and never less than 48 hours) plus margin. Then require exact new-only, DNSSEC-authenticated DS answers from every configured resolver before deactivating or deleting the old KSK.
8. Compare InternetX's current DNSSEC-enabled flag and public key material with PowerDNS before replacing it. Any unknown or mismatching material blocks the zone. The only empty-state exception is an explicitly confirmed CSK split where InternetX either returns `dnssec=false` plus an empty material list or omits both optional DNSSEC fields together, and cryptographically verified NSEC/NSEC3 proof from every configured resolver plus at least two parent servers shows that no DS exists. One missing field, `null`, a wrong type, non-empty material, or an existing DS always blocks.
9. Limit registrar traffic to at most two requests per second, below the documented three request per second/IP limit.
10. Compare full DNSKEY/DS RDATA and cryptographically verify RRSIGs; a 16-bit key tag alone is never evidence.
11. Never continue a zone after an invariant violation. Other zones may reconcile independently.
12. Before the initial parent DS exists, require exact DNSKEY RRset and CSK/KSK signature evidence from the local and every configured authoritative server; recursive AD evidence is intentionally deferred until the parent DS is published. After publication, all ordinary AD-validating resolver gates apply without exception.
13. During an explicit split migration, PowerDNS may dynamically label the recorded replacement KSK and inactive ZSK as `csk` until both 257 and 256 keys are active. This vendor label is accepted only for those recorded replacement IDs when the parsed DNSKEY protocol is 3, flags are exactly 257/256, algorithms match the old CSK, active/published states match the phase, and no additional active or published key exists. Ordinary KSK/ZSK workflows never accept this exception.
14. An ambiguous key-creation result is reconciled by the same effective-role, algorithm, state, and DNSKEY checks before any new POST. Zero or multiple candidates fail closed.
15. Immediately before activating the split ZSK and before deactivating the old CSK, revalidate three distinct recorded IDs, effective roles, protocol, flags, matching algorithms, exact phase-specific active/published states, and a closed inventory. Only the exact pre-state permits the write; the exact post-state reconciles an ambiguously successful write without repeating it; every other state blocks. An unpublished replacement requires a new full DNSKEY prepublication wait.

## Approval and recovery

- The first controller run bootstraps timestamps and does not rotate immediately.
- Manual triggers require both `--confirm` and an idempotency key and may address only zones inside the configured include/exclude scope.
- Failed phases remain persisted and retry with bounded exponential backoff.
- There is no automatic rollback that deletes newly published public material. Recovery is a forward repair guided by `dnssecctl status` and audit logs.
- The only state-only resume operation is an explicit, confirmed and idempotent `split` recovery from `blocked` to `wait_publish`. It requires three distinct recorded key IDs, `parentMode=initial`, no recorded registrar attempt or transaction, exact live key inventory, InternetX `disabled-empty`, and fresh cryptographic proof that no parent DS exists. It clears prior DNSKEY timing evidence so the complete publication wait restarts. Resume performs no PowerDNS or registrar write.

## Automatic initial enrollment

- Automatic enrollment is disabled by default, requires the explicit `all_selected` enrollment scope, separate enrollment include/exclude filters, bounded pending/daily circuit breakers, and must be armed once with an explicit, confirmed, idempotent baseline. Arming records every current DNSSEC zone as already known (including zones currently outside the enrollment scope, to prevent later scope changes from reclassifying them) and performs no PowerDNS, registrar, or DNS mutation. Missing or lost arm state forbids automatic registrar writes.
- Only a DNSSEC-enabled, selected zone first discovered after that baseline is considered. A zone still being assembled remains in discovery until it first has an exact closed split inventory: one active/published KSK (flags 257, protocol 3) and one distinct active/published ZSK (flags 256, protocol 3), with matching validated algorithms and no other active or published key. A CSK at first classification permanently marks the zone ineligible; CSK labels are never accepted in this workflow.
- Discovery persists intent and starts the grace period only after the first exact split inventory. Enrollment never creates, activates, deactivates, publishes, unpublishes, or deletes a PowerDNS key.
- Before the first parent write, the exact child DNSKEY RRset, KSK DNSKEY signature, ZSK zone signature, and expected parent delegation must be proven from all configured authoritative paths. InternetX must be exactly disabled-empty and signed NSEC/NSEC3 evidence must prove that no DS exists. All evidence and inventory are revalidated immediately before the write.
- Registrar write intent and deterministic CTID are persisted before the one permitted PUT. An ambiguous response is reconciled only by read-back and is never automatically resubmitted.
- Registrar acknowledgement or job success is not completion. Exact authoritative parent DS evidence starts a wait of the full observed DS TTL, never less than 48 hours, plus propagation margin. Completion then requires exact AD-validating DS and DNSKEY evidence from every configured resolver, the recorded KSK and ZSK signatures, exact InternetX read-back, and unchanged parent delegation.
- A previously baselined or completed zone is never automatically enrolled again, including after external DS removal. After a stable keyset was recorded, a zone-ID change, inventory drift, disappearance, DNSSEC disablement, or scope removal permanently blocks the candidate and clears automatic progress. Recovery is forward-only and requires a separately specified guarded enrollment-retry operation; direct state edits and automatic reset are forbidden.

## Secrets

- Credentials are read from dedicated files under `/run/secrets`.
- Secret files are never included in images, state, metrics, API responses, or logs.
- The container runs without Linux capabilities, with a read-only root filesystem and `no-new-privileges`.

## Repository and release gates

- `make guardrails` is mandatory before commits, pull requests, and handoff.
- `golangci-lint` must analyze the complete first-party Go module with `./...`; diff-only or new-issue-only linting is forbidden, and vendored dependencies are excluded.
- `make release-guardrails` is mandatory before publishing `main` or a `v*` tag and includes `govulncheck ./...`, `gosec`, and Trivy configuration checks.
- Vulnerability or security findings block publication unless a maintainer records an explicit, reviewed exception.
- Release-sensitive refs must be published from a clean checkout whose validated `HEAD` is the exact commit being published.
- GitHub Actions and Docker release builds must use immutable action revisions and reproducible, pinned tool versions.

## Completion reports

- Every completed rotation creates a durable notification event in controller state before delivery is attempted.
- LMTP delivery is unauthenticated only to a configured private or loopback address and retries with bounded backoff after failure.
- Reports contain zone, rotation kind, timestamps, local key IDs, registrar transaction ID, and a stable event ID; they never contain DNSKEY, DS, private-key, or credential material.

# Controller specification

## Goals

The controller continuously reconciles every DNSSEC-enabled PowerDNS zone. It replaces the legacy day-1/day-2/day-3 cron workflow with evidence-driven, restart-safe state machines.

## ZSK state machine

`idle -> prepublish -> wait_publish -> activate_new -> wait_new_signature -> deactivate_old -> wait_retire -> delete_old -> idle`

- `prepublish`: create one inactive, published ZSK using the current ZSK algorithm.
- `wait-publish`: record the authoritative DNSKEY TTL at first full visibility, wait it plus margin, then re-verify exact DNSKEY RDATA through all authoritative servers and validating resolvers.
- `activate-new`: activate the new ZSK without deactivating the old ZSK.
- `wait-new-signature`: cryptographically verify a zone RRSIG by the exact new ZSK.
- `deactivate-old`: deactivate the old ZSK and persist the pre-switch maximum zone TTL.
- `wait-retire`: retain the old published DNSKEY for the persisted zone TTL plus margin and re-verify new signatures.
- `delete-old`: delete only the recorded inactive old ZSK.

## KSK state machine

`idle -> prepublish -> wait_publish -> parent_remove -> wait_parent_remove -> deactivate_old -> delete_old -> idle`

- `prepublish-active`: create a published, active KSK so old and new KSKs both sign the DNSKEY RRset.
- `wait-double-signature`: prove the exact new KSK DNSKEY and its cryptographically valid DNSKEY RRSIG, record the authoritative DNSKEY TTL, wait it plus margin, and re-prove.
- `parent-replace`: read-before-write, allow only exact old or already exact new material, persist a deterministic CTID, and submit new-only public KSK material to InternetX.
- `wait-parent-ttl`: treat InternetX `N` as pending. When the authoritative parent first serves exact new-only DS, persist its TTL and wait that TTL (minimum 48h) plus margin. Then require exact new-only AD-validated answers from every resolver.
- `deactivate-old`: re-prove the new KSK signature and parent DS, then deactivate the old KSK.
- `delete-old`: re-prove all invariants and delete only the recorded inactive KSK. A missing old key after an ambiguous DELETE is reconciled as success only after replacement evidence passes.

## CSK conversion

CSK zones are reported as requiring an explicit migration. Automatic conversion is forbidden. The confirmed `split` workflow creates an active KSK and inactive ZSK; proves and waits DNSKEY propagation; replaces parent material and waits the full DS TTL; activates the ZSK; proves overlapping CSK and ZSK zone signatures for a full persisted zone TTL; deactivates the CSK; retains its DNSKEY for another full zone TTL; and only then re-proves KSK, ZSK, and parent evidence and deletes the CSK.

### Initial delegation enrollment

When a confirmed split starts with no parent DS, the controller must classify and persist `parentMode=initial` before creating a key. This classification requires InternetX to report either exactly `dnssec=false` with an empty material list or the documented optional representation in which both DNSSEC fields are omitted together. It also requires cryptographically valid parent NSEC/NSEC3 denial from every configured resolver and at least two authoritative parent servers. Only one omitted field, `null`, a wrong type, `dnssec=true`, non-empty material, an existing DS, or a changed read-back blocks the zone.

Because the child cannot receive recursive AD validation before its trust anchor exists, pre-enrollment propagation uses exact published DNSKEY RRset and cryptographic CSK/KSK signature evidence from the local and all configured authoritative servers. The controller re-proves the disabled-empty registrar state and DS absence immediately before the idempotent InternetX write. After the asynchronous job and exact authoritative DS publication, the normal full DS-TTL wait, exact AD-validating resolver evidence, and recursive DNSKEY/signature gates become mandatory before ZSK activation or any CSK retirement.

PowerDNS derives the reported `keytype` from the active keys of an algorithm. While the replacement ZSK with DNSKEY flags 256 remains inactive, PowerDNS can therefore return `keytype=csk` for both recorded replacement keys. For this split-only transition, the controller derives the effective roles from the three distinct persisted IDs plus exact DNSKEY protocol 3, flags 257/257/256, matching algorithms, expected active/published states, and a closed inventory. Before the first POST, the controller atomically persists a create-attempt marker for the exact replacement slot. A successful response is fully role-validated before its ID is persisted. After an ambiguous result, exactly one candidate is adopted; zero or multiple candidates fail closed and never cause another automatic POST. A malformed key, role mismatch, extra published key, or ambiguous inventory blocks.

The closed inventory is revalidated throughout the long parent transition and immediately before both later PowerDNS mutations. Before ZSK activation it must match either the exact fully prepublished state (old CSK and new KSK active/published; new ZSK inactive/published) or the exact already-committed post-state with all three active/published. Before CSK deactivation it must match either the exact all-active/published pre-state or the exact post-state with only the old CSK inactive but still published. An exact post-state reconciles a lost mutation response and advances without another write; any other drift blocks. In particular, an unpublished replacement ZSK is never activated and must complete a new DNSKEY publication evidence and TTL wait before recovery can continue.

### Forward recovery

`POST /v1/rotations/resume` is limited to a confirmed, idempotent `split` transition from `blocked` to `wait_publish`. Before one atomic state update, every requested zone must still be DNSSEC-enabled and prove `parentMode=initial`, three distinct recorded IDs, no registrar attempt or transaction, the exact transitional key inventory, InternetX disabled-empty state, and current cryptographic parent DS absence. The operation itself performs no PowerDNS or InternetX write. It clears DNSKEY evidence and its persisted TTL so the complete authoritative publication observation and wait run again.

## Automatic initial split-zone enrollment

Automatic enrollment uses its own non-key-mutating workflow:

`enroll_discovered -> enroll_wait_publish -> enroll_parent_add -> enroll_wait_parent -> idle`

The feature is disabled by default and also requires the explicit `all_selected` enrollment scope, separate include/exclude filters, and pending/daily circuit-breaker limits. Before discovery can create candidates, `POST /v1/enrollment/arm` must atomically persist an arm timestamp and an idle `enroll` workflow for every current DNSSEC zone, including currently out-of-scope zones so a later scope expansion cannot reclassify them as new. The confirmed, idempotent arm operation is state-only. A state migrated from an older version remains unarmed, so state loss or upgrade cannot cause mass enrollment.

- `enroll_discovered`: persist the first-seen time and PowerDNS zone ID. A zone still being assembled remains in discovery until an exact stable inventory first appears; a CSK zone is permanently marked ineligible. Once present, persist exact KSK/ZSK IDs and the public-keyset fingerprint, require one active/published KSK and one active/published ZSK with valid protocol, flags, allowed algorithm labels, matching algorithms, and a closed active/published inventory, then wait the configured discovery grace. A changed zone ID or later inventory drift invalidates timing evidence and fails closed.
- `enroll_wait_publish`: prove the exact DNSKEY RRset through the local and every configured authoritative server, a cryptographic DNSKEY RRSIG by the recorded KSK, a zone RRSIG by the recorded ZSK, and the exact expected parent NS delegation. At first success persist the maximum authoritative DNSKEY TTL, then wait `max(TTL, minimum_dnskey_wait) + propagation_margin` and re-prove.
- `enroll_parent_add`: immediately re-prove the closed inventory, authoritative DNSKEY and signature evidence, expected parent delegation, exact InternetX disabled-empty state, and cryptographic no-DS evidence. Persist a deterministic CTID and `registrarAttemptedAt` before the only permitted InternetX PUT containing public KSK material. An ambiguous outcome is read back without resubmission.
- `enroll_wait_parent`: wait for the asynchronous registrar job, then prove exact authoritative DS publication and persist the highest TTL. Wait `max(TTL, minimum_parent_wait) + propagation_margin`; re-prove authoritative DS, exact AD-validating DS and DNSKEY answers through every resolver, KSK and ZSK signatures, exact InternetX material, unchanged delegation, and unchanged local inventory. Completion atomically marks the enrollment idle, leaves both local keys untouched, initializes rotation timestamps, and writes the LMTP completion event.

If InternetX and the parent already contain exact matching material, a candidate can be adopted without a write only after the complete authoritative and AD-validating evidence set passes. Any foreign material, inconsistent state, missing delegation proof, CSK inventory, or invariant violation fails closed. After a stable keyset was recorded, zone disappearance, DNSSEC disablement, zone-ID/keyset drift, or scope removal permanently transitions the candidate to `blocked`; there is no automatic reset or direct-state recovery. A future retry operation requires its own policy, specification, invariant proof, confirmation, and idempotency contract. A completed or baselined `enroll` workflow is permanent managed-state evidence and is never automatically restarted.

## API and CLI

The control API is served only on a Unix socket. `api/openapi.yaml` is normative. The `dnssecctl` command uses that socket and provides health, status, zone, plan, confirmed trigger, guarded resume, and confirmed state-only enrollment arming operations. The controller API never exposes DNSKEY, DS, private material, or credentials.

## Persistence and concurrency

State is stored as an atomically replaced JSON document with mode `0600`. One process-wide lock prevents concurrent writers. Each zone has at most one active workflow. Transitions persist their intent and observed identifiers so retries do not create duplicate keys.

## Failure model

- Read failures retry and do not mutate.
- Ambiguous write results are reconciled by reading PowerDNS/InternetX/public DNS before retrying.
- Invariant violations block only the affected zone and are visible in status and metrics.
- The process is ready only when configuration, state storage, PowerDNS API, and control socket are available.

## Completion notification outbox

The transition to `idle` atomically persists a stable LMTP completion event. Delivery is at-least-once and restart-safe: a failed delivery remains pending with bounded exponential backoff, while a successful delivery timestamp is retained for the configured idempotency period. Ambiguous network failure can cause a duplicate message; its stable event ID allows deduplication. Notification failure never rolls DNSSEC state backward and is visible as `pendingNotifications` in status.

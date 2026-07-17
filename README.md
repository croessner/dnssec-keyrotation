# DNSSEC key rotation controller

[![Guardrails](https://github.com/croessner/dnssec-keyrotation/actions/workflows/guardrails.yaml/badge.svg)](https://github.com/croessner/dnssec-keyrotation/actions/workflows/guardrails.yaml)
[![Govulncheck](https://github.com/croessner/dnssec-keyrotation/actions/workflows/govulncheck.yaml/badge.svg)](https://github.com/croessner/dnssec-keyrotation/actions/workflows/govulncheck.yaml)
[![CodeQL](https://github.com/croessner/dnssec-keyrotation/actions/workflows/codeql.yml/badge.svg)](https://github.com/croessner/dnssec-keyrotation/actions/workflows/codeql.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

`dnssec-keyrotation` is a production-oriented controller and command-line client for evidence-driven DNSSEC key lifecycle management with PowerDNS Authoritative and the InternetX DomainRobot API. It replaces calendar-based key scripts with persisted, restart-safe state machines that advance only after the required DNSSEC evidence is visible.

Private keys never leave PowerDNS. The registrar receives public KSK material only. A successful registrar request is treated as an acknowledgement, not as proof that the parent delegation has changed.

> **Beta status:** `v1.0.0-beta.1` is the first public beta. Validate it in `observe` mode and in a non-critical environment before enabling enforcement for production zones.

## Table of contents

- [Purpose](#purpose)
- [Safety model](#safety-model)
- [Architecture](#architecture)
- [How rotation works](#how-rotation-works)
  - [ZSK rollover](#zsk-rollover)
  - [KSK rollover](#ksk-rollover)
  - [CSK-to-split migration](#csk-to-split-migration)
  - [Automatic initial enrollment](#automatic-initial-enrollment)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Release archive](#release-archive)
  - [Build from source](#build-from-source)
  - [Container image](#container-image)
- [Configuration](#configuration)
  - [Operating modes](#operating-modes)
  - [Secret files](#secret-files)
  - [Zone selection](#zone-selection)
  - [Enrollment controls](#enrollment-controls)
  - [Completion notifications](#completion-notifications)
- [First startup](#first-startup)
- [Using dnssecctl](#using-dnssecctl)
  - [Read-only commands](#read-only-commands)
  - [Plan a rotation](#plan-a-rotation)
  - [Trigger a rotation](#trigger-a-rotation)
  - [Resume a blocked split migration](#resume-a-blocked-split-migration)
  - [Arm automatic enrollment](#arm-automatic-enrollment)
- [Health and operations](#health-and-operations)
- [Persistence and failure handling](#persistence-and-failure-handling)
- [Control API](#control-api)
- [Deployment guidance](#deployment-guidance)
- [Release verification](#release-verification)
- [Development](#development)
- [Project layout](#project-layout)
- [Branch and release model](#branch-and-release-model)
- [License](#license)

## Purpose

Traditional DNSSEC rollover scripts often advance on fixed days and assume that every preceding action succeeded. That is unsafe when API responses are lost, registrar jobs are asynchronous, caches retain old records, or the process stops between mutations.

This controller instead:

- discovers DNSSEC-enabled zones from the local PowerDNS API;
- classifies split KSK/ZSK and CSK key schemes;
- persists every workflow phase and external-write intent;
- performs ZSK pre-publication rollovers;
- coordinates double-KSK rollovers with InternetX;
- supports an explicit, guarded CSK-to-split migration;
- can enroll newly discovered clean split zones at the parent after an explicit baseline;
- verifies DNSKEY, RRSIG, DS, delegation, and registrar state before advancing;
- reports per-zone failures without allowing one blocked zone to stop all others;
- sends durable completion events through an optional LMTP outbox.

It is not a DNSSEC signer and does not handle private key material. PowerDNS remains the source of key generation, storage, activation, signing, and deletion.

## Safety model

The core invariants are defined in [POLICY.md](POLICY.md), while the normative state-machine behavior is defined in [docs/spec.md](docs/spec.md). Important properties include:

- `observe` mode performs no controller mutation.
- `enforce` mode executes only modeled state-machine transitions.
- The last active key for a role is never deleted.
- CSK zones are never passed through ordinary KSK or ZSK workflows.
- Full DNSKEY and DS RDATA is verified; a 16-bit key tag is never sufficient evidence.
- A new ZSK must produce a valid zone signature before the old ZSK is deactivated.
- A new KSK must sign the DNSKEY RRset before parent material is changed.
- Parent DS changes require authoritative observation, a full persisted DS TTL wait of at least 48 hours, and exact AD-validated answers from every configured resolver.
- InternetX job completion alone never authorizes a local key transition.
- External-write intent and deterministic identifiers are persisted before the write.
- Ambiguous write results are reconciled through read-back instead of blind repetition.
- Automatic enrollment cannot run until an operator explicitly records a baseline.
- Secrets are read only from restricted regular files below `/run/secrets`.

## Architecture

```text
                         +---------------------------+
                         | validating DNS resolvers  |
                         +-------------+-------------+
                                       |
 +----------------+     +--------------v--------------+     +------------------+
 | PowerDNS API   |<--->| dnssec-keyrotation          |<--->| InternetX API    |
 | loopback only  |     | controller + state machine  |     | public KSK only  |
 +----------------+     +------+------------+---------+     +------------------+
                              |            |
                 +------------v--+      +--v------------------+
                 | JSON state     |      | authoritative DNS   |
                 | lock + outbox  |      | and parent evidence |
                 +---------------+      +---------------------+
                              |
                    +---------v----------+
                    | Unix control socket |<---- dnssecctl
                    +--------------------+
```

The controller uses five independent evidence surfaces:

1. PowerDNS zone and key inventory.
2. Persisted workflow and write intent.
3. InternetX DNSSEC material and asynchronous job state.
4. Authoritative DNSKEY, RRSIG, delegation, and parent DS observations.
5. Recursive DNSSEC validation through every configured resolver.

The control API is HTTP over a mode-`0600` Unix socket. It is never exposed as an unauthenticated TCP listener.

## How rotation works

Cadence makes a zone eligible; observed TTLs and cryptographic evidence determine when a workflow may advance. The default eligibility intervals are 30 days for ZSKs and 182 days for KSKs.

### ZSK rollover

```text
idle -> prepublish -> wait_publish -> activate_new
     -> wait_new_signature -> deactivate_old -> wait_retire
     -> delete_old -> idle
```

The new ZSK is published inactive. The controller proves DNSKEY visibility, records the authoritative DNSKEY TTL, waits that TTL plus the propagation margin, and verifies visibility again. It then activates the new ZSK, proves a zone signature by that exact key, deactivates the old ZSK, retains its published DNSKEY for the persisted pre-switch zone TTL, and deletes only the recorded inactive old key.

### KSK rollover

```text
idle -> prepublish -> wait_publish -> parent_remove
     -> wait_parent_remove -> deactivate_old -> delete_old -> idle
```

The new KSK is created active and published so the DNSKEY RRset is double-signed. After DNSKEY propagation, InternetX receives new-only public KSK material. The controller waits for exact authoritative parent DS publication, persists the observed parent TTL, waits the full TTL with a minimum of 48 hours plus margin, and then requires exact new-only AD-validated DS evidence from every resolver before retiring the old KSK.

### CSK-to-split migration

CSK conversion is never automatic. An operator must request `--kind split` explicitly. The migration creates a replacement KSK and ZSK, proves their publication, changes parent material, waits the parent TTL, activates the ZSK, proves overlapping CSK/ZSK signatures, retains the old CSK through two guarded zone-TTL windows, and deletes it only after all replacement evidence passes.

An initially insecure delegation may be enrolled by an explicit split only when InternetX is exactly disabled and empty, every configured resolver and at least two parent servers cryptographically prove DS absence, and the complete replacement-key inventory satisfies the specification.

### Automatic initial enrollment

Automatic enrollment handles only clean split zones first discovered after an explicit baseline:

```text
enroll_discovered -> enroll_wait_publish -> enroll_parent_add
                  -> enroll_wait_parent -> idle
```

Enrollment never creates or changes local PowerDNS keys. It observes one active/published KSK and one active/published ZSK, waits the discovery grace and DNSKEY propagation, proves the expected delegation and DS absence, performs at most one persisted registrar write, waits the parent TTL, and completes only after authoritative and recursive DNSSEC evidence agrees.

A baselined, completed, ineligible, drifted, removed, or DNSSEC-disabled zone is never silently re-enrolled.

## Requirements

- A Unix-like host capable of running the static Linux binary or OCI image.
- PowerDNS Authoritative with its HTTP API available on loopback.
- An InternetX DomainRobot account, username, context, and password file.
- At least two independent validating recursive resolvers.
- At least two authoritative DNS endpoints for the managed zones.
- A writable state directory under `/var/lib/dnssec-keyrotation`.
- A writable runtime directory under `/run/dnssec-keyrotation`.
- Two mode-`0600` secret files under `/run/secrets`.
- Go 1.26.5 when building from source.
- Optional: a private or loopback LMTP endpoint for completion reports.

The controller intentionally rejects remote plaintext PowerDNS API URLs, unapproved registrar API hosts, insufficient DNS evidence paths, weak propagation limits, and permissive secret-file modes.

## Installation

### Release archive

Release assets contain the Linux binary, README, policy, specification, example configuration, license, SBOM, and checksums. For example:

```sh
gh release download v1.0.0-beta.1 \
  --repo croessner/dnssec-keyrotation \
  --pattern 'dnssec-keyrotation-linux-amd64.tar.gz' \
  --pattern 'dnssec-keyrotation-linux-amd64.spdx.json' \
  --pattern SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf dnssec-keyrotation-linux-amd64.tar.gz
```

The executable is located at `dnssec-keyrotation-linux-amd64/bin/dnssecctl`. An `arm64` archive is published as well.

### Build from source

Dependencies are vendored and builds use the vendored module graph:

```sh
git clone https://github.com/croessner/dnssec-keyrotation.git
cd dnssec-keyrotation
make guardrails
make build
./bin/dnssecctl version
```

`make build-linux` creates a stripped Linux `amd64` binary and checksum under `dist/`.

### Container image

Multi-architecture images are published to:

```text
ghcr.io/croessner/dnssec-keyrotation:<version>
```

Stable release tags omit the leading `v`, so Git tag `v1.0.0-beta.1` produces image tag `1.0.0-beta.1`. Development pushes to `features` produce `dev` and `features` tags.

The runtime image is `scratch`, runs as numeric user `65532:65532`, and contains only CA certificates and `dnssecctl`. A hardened invocation resembles:

```sh
docker run --rm \
  --name dnssec-keyrotation \
  --network host \
  --read-only \
  --user 65532:65532 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src=/etc/dnssec-keyrotation/config.yaml,dst=/etc/dnssec-keyrotation/config.yaml,readonly \
  --mount type=bind,src=/var/lib/dnssec-keyrotation,dst=/var/lib/dnssec-keyrotation \
  --mount type=bind,src=/run/dnssec-keyrotation,dst=/run/dnssec-keyrotation \
  --mount type=bind,src=/run/secrets,dst=/run/secrets,readonly \
  ghcr.io/croessner/dnssec-keyrotation:1.0.0-beta.1
```

The host state and runtime directories must already exist and be writable by UID/GID `65532`. Use host networking only when required to reach loopback PowerDNS and the local authoritative DNS endpoint.

## Configuration

Start from [configs/config.example.yaml](configs/config.example.yaml):

```sh
install -d -m 0750 /etc/dnssec-keyrotation
install -m 0640 configs/config.example.yaml /etc/dnssec-keyrotation/config.yaml
```

The main sections are:

| Section | Purpose |
| --- | --- |
| `mode` | Select read-only observation or state-machine enforcement. |
| `log` | Set JSON log level: `debug`, `info`, `warn`, or `error`. |
| `controller` | Configure reconciliation, propagation margin, state file, socket, and idempotency retention. |
| `powerdns` | Configure the loopback API, server ID, API key file, and timeout. |
| `autodns` | Configure the approved InternetX endpoint, username, password file, context, timeout, and request rate. |
| `dns` | Configure recursive resolvers, authoritative endpoints, expected nameservers, and the local authoritative endpoint. |
| `rotation` | Configure algorithm, ZSK/KSK cadence, minimum waits, and zone selection. |
| `enrollment` | Configure the separately gated initial-enrollment workflow and circuit breakers. |
| `notifications.lmtp` | Configure optional durable completion delivery. |

Non-secret values may be overridden with `DNSSEC_ROTATION_` environment variables using uppercase underscore-separated paths, for example `DNSSEC_ROTATION_LOG_LEVEL` or `DNSSEC_ROTATION_CONTROLLER_RECONCILE_INTERVAL`. Credentials must remain file-backed.

### Operating modes

`mode: observe`

- Lists and classifies selected DNSSEC zones.
- Serves status, zone, audit, and planning data.
- Performs no controller state-machine mutation.
- Is the mandatory starting point for a new deployment.

`mode: enforce`

- Persists bootstrap timestamps and modeled workflow transitions.
- Executes eligible automatic ZSK and KSK rollovers.
- Delivers pending completion notifications.
- May execute explicitly confirmed split, resume, and enrollment operations.

The first enforcing reconciliation bootstraps existing zones and does not immediately rotate them.

### Secret files

The following configuration values must reference files below `/run/secrets`:

- `powerdns.api_key_file`
- `autodns.password_file`

Provision them through the host secret manager or container runtime. Each path must be a regular, non-symlink file with no group or world permission bits; mode `0600` is appropriate. The file contains only the credential value. Secrets are trimmed in memory and are never included in state, API responses, notifications, or images.

### Zone selection

`rotation.include_zones` and `rotation.exclude_zones` bound ordinary rotation scope. Empty include lists select all DNSSEC-enabled zones except explicit exclusions. Manual commands may address only zones inside this scope.

Enrollment has separate include and exclude lists so enabling enrollment never silently broadens ordinary rotation scope or vice versa.

### Enrollment controls

Automatic enrollment remains unavailable unless all of the following are true:

- `enrollment.enabled: true`
- `enrollment.scope: all_selected`
- the expected nameserver set exactly matches the configured authoritative endpoints;
- pending and daily circuit breakers are valid;
- an operator successfully runs `dnssecctl enrollment arm --confirm` once.

Arming records every currently known DNSSEC zone as baseline state and performs no PowerDNS, registrar, or DNS mutation. Loss of the state file also loses the arm state; the controller does not infer permission to enroll.

### Completion notifications

When LMTP is enabled, completion is written to the state outbox before delivery is attempted. Delivery is at-least-once and retries with bounded backoff. An ambiguous network failure may produce a duplicate, so every message carries a stable event ID.

The LMTP address must be a private or loopback IP. Reports include the zone, workflow kind, timestamps, local key IDs, registrar transaction identifier, and event ID. They never include DNSKEY, DS, private-key, or credential data.

## First startup

1. Create the configuration and restricted secret files.
2. Keep `mode: observe`.
3. Start the controller:

   ```sh
   dnssecctl serve --config /etc/dnssec-keyrotation/config.yaml
   ```

4. Verify liveness and readiness through the Unix socket:

   ```sh
   curl --unix-socket /run/dnssec-keyrotation/control.sock http://unix/healthz
   curl --unix-socket /run/dnssec-keyrotation/control.sock http://unix/readyz
   ```

5. Inspect controller, zone, and registrar state:

   ```sh
   dnssecctl status
   dnssecctl zones
   dnssecctl audit
   ```

6. Confirm that selected zones, split/CSK classification, registrar material, resolvers, authoritative endpoints, and expected delegation match reality.
7. Change to `mode: enforce` only after observation is clean, then restart the process.
8. Verify that the first enforcing run bootstraps timestamps without starting an immediate rollover.
9. Leave automatic enrollment disabled until its scope, circuit breakers, baseline, and evidence paths have been reviewed separately.

## Using dnssecctl

`dnssecctl` is both the controller process and its local client. Client commands communicate with the running controller through the Unix socket and print indented JSON.

```text
dnssecctl [--socket /run/dnssec-keyrotation/control.sock] <command>
```

| Command | Mutation | Purpose |
| --- | --- | --- |
| `serve --config <path>` | Starts controller | Load configuration and run reconciliation plus the control API. |
| `version` | None | Print version, commit, and build date. |
| `status` | None | Print mode, readiness, zone counts, enrollment state, and pending notifications. |
| `zones` | None | Print every selected zone, scheme, enrollment disposition, block reason, and persisted workflow. |
| `audit` | None | Compare active local KSK/CSK public material with InternetX. |
| `plan --kind <kind> --zone <zone>` | None | Describe the modeled mutations for `zsk`, `ksk`, or `split`. |
| `trigger ... --confirm --idempotency-key <key>` | Persists workflow | Start a confirmed manual ZSK, KSK, or split workflow. |
| `resume ... --confirm --idempotency-key <key>` | State only | Revalidate and resume one exact blocked initial split state. |
| `enrollment status` | None | Print aggregate status including enrollment counts and arm state. |
| `enrollment arm --confirm --idempotency-key <key>` | State only | Persist the one-time baseline required for automatic enrollment. |

`--zone` may be repeated or contain comma-separated names. Mutating commands require an idempotency key between 16 and 128 characters. Reusing a key with different input is rejected; retained keys prevent accidental repetition across process restarts.

### Read-only commands

```sh
dnssecctl version
dnssecctl status
dnssecctl zones
dnssecctl audit
```

Example aggregate status:

```json
{
  "mode": "observe",
  "ready": true,
  "zones": 2,
  "blocked": 0,
  "enrollmentArmed": false,
  "enrolling": 0,
  "managed": 0,
  "pendingNotifications": 0
}
```

`audit` is read-only and never returns public key material. It reports only the zone, detected key scheme, whether registrar material matches, and an optional error.

### Plan a rotation

Always plan before triggering:

```sh
dnssecctl plan --kind zsk --zone example.test
dnssecctl plan --kind ksk --zone example.test,example.net
dnssecctl plan --kind split --zone csk-zone.example
```

Planning returns the exact high-level mutations represented by the selected state machine. It does not validate permission to perform every future phase and does not mutate state.

### Trigger a rotation

```sh
dnssecctl trigger \
  --kind zsk \
  --zone example.test \
  --confirm \
  --idempotency-key operator-20260717-example-zsk
```

Valid kinds are `zsk`, `ksk`, and `split`. The request is rejected if the zone is outside configured scope, the key scheme is incompatible, another workflow conflicts, the idempotency key is invalid, or required live invariants do not hold.

`--confirm` authorizes creation of the persisted workflow, not unconditional future mutations. Every later phase still revalidates its evidence and fails closed on drift.

### Resume a blocked split migration

```sh
dnssecctl resume \
  --zone example.test \
  --confirm \
  --idempotency-key operator-20260717-example-resume
```

Resume is intentionally narrow. It can only move a blocked initial `split` workflow back to `wait_publish` after proving the exact recorded three-key inventory, disabled-empty registrar state, absence of a registrar attempt, and fresh cryptographic parent DS absence. The operation itself performs no PowerDNS or InternetX write and restarts the complete DNSKEY publication wait.

Do not edit the state file to recover a zone.

### Arm automatic enrollment

After enabling and reviewing enrollment configuration:

```sh
dnssecctl enrollment status
dnssecctl enrollment arm \
  --confirm \
  --idempotency-key operator-20260717-enrollment-baseline
```

Arming is a one-time, state-only baseline. It marks all current DNSSEC zones as already known so they cannot later be mistaken for newly discovered enrollment candidates. It does not publish DS material.

## Health and operations

The control socket provides:

- `GET /healthz`: the process is alive.
- `GET /readyz`: configuration, state, PowerDNS access, and controller status are ready.
- `GET /v1/status`: aggregate operational state.
- `GET /v1/zones`: per-zone workflow evidence and block reasons.

Operational checks should treat these conditions separately:

| Observation | Meaning | Response |
| --- | --- | --- |
| `ready: false` or `/readyz` returns `503` | A required dependency is unavailable. | Restore the dependency before any mutation. |
| `blocked > 0` | One or more zones violated an invariant. | Inspect `dnssecctl zones`, PowerDNS, registrar state, and DNS evidence. |
| `pendingNotifications > 0` | DNSSEC completion succeeded but LMTP delivery is pending. | Repair LMTP without rolling DNSSEC state backward. |
| CSK `blockedReason` requests explicit migration | The zone is intentionally excluded from ordinary rotation. | Review and plan an explicit `split`; never force KSK/ZSK paths. |
| Registrar job succeeds but workflow still waits | Parent evidence or TTL gates are incomplete. | Wait and inspect authoritative plus recursive DS evidence. |

Logs are structured JSON on standard output. `debug`, `info`, `warn`, and `error` levels are supported. Logs intentionally omit credentials and DNSSEC key material.

## Persistence and failure handling

State is an atomically replaced JSON document under `/var/lib/dnssec-keyrotation` with mode `0600`. A process-wide lock prevents concurrent writers. Each zone has at most one active workflow.

Persisted state includes phase intent, recorded key IDs, observed TTLs, evidence timestamps, registrar transaction state, idempotency records, enrollment disposition, and notification delivery state. It does not include secret values, private keys, DNSKEY RDATA, or DS RDATA.

Failure behavior is forward-only:

- Read failures retry without mutation.
- Failed phases remain persisted with bounded retry state.
- An ambiguous create, update, or delete is reconciled through live read-back.
- Unknown or extra keys block instead of being guessed away.
- One blocked zone does not prevent independent zones from reconciling.
- There is no automatic rollback that deletes newly published material.
- Direct state edits are unsupported and unsafe.

Back up the state file using a mechanism that preserves ownership, mode, atomicity, and confidentiality. Never run two controllers against the same state and PowerDNS instance.

## Control API

The normative OpenAPI 3.1 document is [api/openapi.yaml](api/openapi.yaml). The API is local and Unix-socket-only. Request bodies reject unknown fields and are size-limited. Mutating endpoints require explicit confirmation and an `Idempotency-Key` header.

The API never exposes DNSKEY, DS, private key, or credential material. Prefer `dnssecctl` for operator actions because it provides the supported request shapes and confirmation flags.

## Deployment guidance

Production deployment manifests are intentionally not committed because network topology, secret providers, storage, and service management are environment-specific. A deployment should provide:

- a read-only root filesystem;
- numeric non-root UID/GID `65532:65532`;
- no Linux capabilities;
- `no-new-privileges`;
- read-only configuration and secret mounts;
- writable, persistent state storage;
- a writable runtime directory for the mode-`0600` Unix socket;
- bounded CPU, memory, process, and file-descriptor resources;
- restart-on-failure without concurrent duplicate instances;
- digest-pinned container images;
- host networking only when loopback PowerDNS access requires it;
- log retention appropriate for operational audit without capturing secrets.

Start every new deployment in `observe` mode. Compare controller output with PowerDNS, InternetX, authoritative DNS, and validating resolvers before switching to `enforce`.

## Release verification

Every `v*` tag runs full release gates before publication. Releases provide:

- Linux `amd64` and `arm64` archives;
- SHA-256 checksums;
- SPDX JSON SBOMs;
- GitHub build-provenance attestations;
- multi-architecture GHCR images with SBOM and provenance;
- immutable source, version, revision, creation-time, license, and base-image metadata.

Verify a downloaded artifact attestation with GitHub CLI:

```sh
gh attestation verify \
  dnssec-keyrotation-linux-amd64.tar.gz \
  --repo croessner/dnssec-keyrotation
```

Production deployments should use the verified manifest digest rather than a mutable `latest`, major, or minor tag.

## Development

Read [AGENTS.md](AGENTS.md), [POLICY.md](POLICY.md), and [docs/spec.md](docs/spec.md) before modifying behavior.

```sh
make guardrails
```

The guardrails run formatting checks, `go vet`, full-project `golangci-lint run ./...`, unit tests, race tests, the Linux build, OpenAPI checks, and license checks. First-party code is linted in full; lint is never limited to the current diff or HEAD. Vendored dependencies are used for builds but excluded from lint and security findings.

Release-sensitive work additionally requires:

```sh
make release-guardrails
```

This adds `govulncheck ./...`, gosec, and Trivy configuration checks. GitHub Actions also run CodeQL, container builds and scans, SBOM generation, provenance attestation, and scheduled stable-image base refreshes.

After changing dependencies:

```sh
go mod tidy
go mod vendor
```

Never hand-edit `vendor/`.

## Project layout

```text
api/openapi.yaml          Normative local control API
cmd/dnssecctl/            Controller process and CLI
configs/                  Public example configuration
docs/spec.md              Normative state-machine specification
internal/app/             Runtime assembly and dependency wiring
internal/autodns/         InternetX DomainRobot client
internal/config/          Strict configuration and secret loading
internal/control/         Unix-socket HTTP server and client
internal/controller/      Reconciliation and workflow state machines
internal/dnsprobe/        DNSSEC observation and cryptographic evidence
internal/lmtp/            Durable completion notification transport
internal/model/           Persisted data model
internal/pdns/            PowerDNS API client
internal/state/           Atomic state store and process lock
vendor/                   Vendored Go dependencies
```

Local deployment material belongs in ignored `deploy/`. Plans, reports, and other scratch material belong in ignored `temp/`. Neither directory is part of a public release.

## Branch and release model

- `features` is the regular integration branch.
- Reviewed and fully green changes are merged into `main`.
- `main` is the default and release source branch.
- Release tags are created only from a clean, validated `main` commit.
- Prereleases use semantic tags such as `v1.0.0-beta.1`.
- Stable releases use `vMAJOR.MINOR.PATCH`.

Dependabot targets `features` and maintains the vendored Go dependency graph, GitHub Actions, and the Docker builder image.

## License

The original project code and documentation are licensed under the GNU Affero General Public License version 3 or any later version (`AGPL-3.0-or-later`). See [LICENSE](LICENSE) for the complete license text.

Vendored dependencies retain their respective upstream licenses and copyright notices under `vendor/`.

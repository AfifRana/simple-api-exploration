# Phase 0 Research: Authentication APIs (Go)

**Feature**: `001-authentication` | **Branch**: `feat/001-authentication` | **Date**: 2026-08-03

**Input**: `specs/001-authentication/spec.md`

## Purpose

Resolve the unknowns required to plan a Go implementation of the authentication
feature. Each decision records the chosen option, the reason it satisfies a spec
requirement, and the alternatives rejected.

---

## D-001: Language and Runtime

**Decision**: Go 1.25, built and run in a container (`golang:1.25` build stage,
`gcr.io/distroless/static` runtime stage).

**Rationale**: The user selected Go for this implementation. Go is not installed on
the current development host (`go version` → command not found) while Docker 28.3.0
is available, so a container-first toolchain is the only reproducible option here. It
also satisfies the constitution's requirement that generated artifacts be
reproducible from documented commands, and it gives the environment parity that
`docs/research-method.md` requires for cross-language benchmarking.

**Alternatives rejected**:

- Host-local Go toolchain: not installed, and would make benchmark environment
  parity across language variants harder to guarantee.

**Open item**: pin the exact patch version in `go.mod` and the Dockerfile once the
toolchain image is pulled. If Go 1.25 is unavailable in the registry, fall back to
the latest stable 1.x and record the substitution here.

---

## D-002: HTTP Framework

**Decision**: Standard library `net/http` with `go-chi/chi` v5 for routing and
middleware composition.

**Rationale**: Go 1.22+ `net/http` already supports method-and-wildcard patterns, so
a router is only needed for middleware ergonomics and route grouping. `chi` builds on
the standard `http.Handler` interface, which keeps the implementation compatible with
`httptest`, OpenAPI request-validation middleware, and standard observability
tooling. This directly serves Principle V (Maintainability Through Simplicity) and
keeps the surface area comparable to other language variants.

**Alternatives rejected**:

- **Fiber**: the README lists `go-fiber` as an illustrative directory name. Fiber is
  built on `fasthttp`, which does not implement `net/http` interfaces. That breaks
  compatibility with the standard testing and middleware ecosystem, including the
  OpenAPI validation middleware this plan depends on for contract parity. The
  portability cost outweighs its throughput advantage for a correctness-focused
  security feature. See the note in `plan.md` about the resulting directory name.
- **Gin**: viable and `net/http`-compatible, but its custom context type adds
  indirection over the standard library without a benefit this feature needs.

---

## D-003: Credential Hashing

**Decision**: Argon2id via `golang.org/x/crypto/argon2`, parameters
`memory=64MiB, iterations=1, parallelism=4, saltLen=16, keyLen=32`. Parameters and
the algorithm identifier are stored alongside each hash so they can be rotated.

**Rationale**: Argon2id is the current OWASP first-choice password hash and the
listed parameter set is the OWASP baseline recommendation. Storing parameters inline
lets credentials be rehashed on next successful authentication when the policy
changes, without a mass migration.

**Critical interaction with SC-007**: Argon2id is intentionally expensive. The
baseline parameters cost roughly 50-100ms of CPU per verification, which consumes a
meaningful share of the 500ms p95 budget in SC-007 and does not shrink under
concurrency — it competes for CPU. Two consequences the plan must carry:

1. The p95 budget must be validated with the real hash parameters under the
   benchmark's concurrent load, not with a stubbed hasher.
2. If the budget is missed, tune `memory` down toward 19MiB (the OWASP minimum
   acceptable floor) before weakening `iterations`, and record the change as a
   documented security trade-off.

**Alternatives rejected**:

- **bcrypt**: acceptable and simpler, but weaker against GPU/ASIC attack and capped
  at a 72-byte input. Chosen against because Argon2id is the stronger default and the
  cost is manageable within budget.
- **scrypt**: comparable strength, less clear parameter guidance for this use case.
- **PBKDF2**: only preferred where FIPS compliance is required, which is not a stated
  constraint.

---

## D-004: Session Representation

**Decision**: Opaque server-side session tokens. Generate 256 bits from
`crypto/rand`, return the base64url value to the client once, and persist only a
SHA-256 hash of the token in a `sessions` table with owning account, role snapshot,
issue time, expiry, and revocation state.

**Rationale**: FR-006 requires that a credential change invalidate stale or risky
authenticated access, and FR-010 requires that blocking a user immediately denies
protected access. Server-side sessions make revocation a single indexed `UPDATE`, so
both requirements are satisfied by construction rather than by a compensating
mechanism. Storing only the hash means a database disclosure does not yield usable
tokens. SHA-256 is correct here rather than Argon2id because the token is
high-entropy random material, not a low-entropy human secret, so it is not subject to
guessing attacks.

**Alternatives rejected**:

- **Stateless JWT**: cannot be revoked before expiry without a server-side denylist,
  which reintroduces the same state it was meant to avoid while adding a window where
  FR-006 and FR-010 are violated. Rejected on correctness grounds.
- **Short-lived JWT plus refresh token**: reduces but does not close the revocation
  window, and adds token-rotation complexity that Principle V does not justify at
  this scope.

**Session policy**: 24-hour absolute expiry, revoked on logout, on credential change
(all sessions for the account, including the caller's), and on block or delete.

---

## D-005: Storage

**Decision**: PostgreSQL 17 accessed with `jackc/pgx` v5 (via `database/sql` for
portability of query code), schema managed by `golang-migrate` with versioned
up/down SQL migrations.

**Rationale**: Several requirements need real transactional guarantees, not just
persistence:

- The concurrent-credential-change edge case requires one clear final state and no
  partial update, which needs row-level locking (`SELECT ... FOR UPDATE`).
- FR-013's last-active-admin protection requires a check-then-act sequence that is
  safe under concurrency.
- FR-011 requires deletion that preserves audit evidence, which needs a foreign-key
  and retention model that outlives the account row.

Postgres also matches the multi-language comparison goal: the same schema and
fixtures can back a Python or Node variant, preserving the data parity control in
`docs/research-method.md`.

**Alternatives rejected**:

- **SQLite**: simpler to run, but its single-writer model would mask the concurrency
  behavior this feature is specifically required to get right, and it weakens
  benchmark realism.
- **In-memory store**: unusable for audit retention and concurrency requirements.

---

## D-006: Abuse Protection

**Decision**: Persistent counter-based throttling in Postgres, keyed independently on
the login identifier and on the client IP. Threshold: 5 consecutive failures within a
15-minute window triggers a 15-minute temporary lockout for that key. Locked requests
return `429` with a `Retry-After` header. Counters for an identifier reset on
successful authentication. Every trigger writes an audit event.

**Rationale**: FR-016 and SC-008 require throttling or temporary lockout with a
documented threshold. Keying on both identifier and IP covers the two attack shapes
in the spec — repeated failures against one account, and one source spraying many
accounts. Using the existing Postgres dependency avoids adding Redis for a feature
whose write volume is low, honoring Principle V.

**Alternatives rejected**:

- **Redis counters**: better suited to high volume and gives TTL expiry for free, but
  adds an operational dependency that this scope does not need. Revisit if benchmark
  results show lock contention on the counter table.
- **In-process rate limiter** (`golang.org/x/time/rate`): loses state on restart and
  is incorrect across replicas.

**Note**: A permanent lockout was rejected because it converts a throttling control
into a denial-of-service vector against legitimate accounts.

---

## D-007: Account Enumeration Resistance

**Decision**: Public authentication responses are uniform. Unknown identifier,
invalid credential, blocked, and deleted accounts all return the same
`401` Problem Details body with a single generic code. When the identifier is
unknown, verify the supplied credential against a fixed dummy Argon2id hash so the
response time profile does not distinguish the cases. Specific reasons are recorded
in audit events only.

**Rationale**: FR-002 requires denial for all these cases, while the spec's edge
cases and FR-018 require that responses not expose enumeration signals. Uniform
bodies alone are insufficient — skipping the hash for an unknown user creates a
timing oracle that leaks account existence. The dummy-hash step closes that channel.

**Alternatives rejected**:

- **Distinct error codes per denial reason**: better developer experience, rejected
  because it directly contradicts FR-002 and the stated edge case.
- Uniform body without timing equalization: leaves the timing side channel open.

**Scope boundary**: Admin endpoints under `/v1/admin/users` do distinguish `404` from
other outcomes, because the caller is already an authorized admin and FR-008 grants
them account visibility.

---

## D-008: Account Deletion Semantics

**Decision**: Soft delete. Set `status = 'deleted'` and `deleted_at`, scrub the
credential hash, revoke all sessions, and release the unique login identifier by
moving it to a `deleted_login_identifier` column. Audit events retain the account's
stable UUID.

**Rationale**: FR-011 requires preventing future authentication while preserving
audit evidence, and the edge cases require that security actions stay auditable after
deletion. A hard delete would either destroy audit linkage or require nullable audit
actors. Releasing the login identifier prevents the deleted account from blocking
reuse of that identifier while keeping the stable UUID stable for audit joins, which
also satisfies FR-006's duplicate-identifier concern.

**Alternatives rejected**:

- **Hard delete with denormalized audit copies**: loses referential clarity and
  duplicates identity data across audit rows.
- **Soft delete retaining the login identifier**: blocks legitimate identifier reuse
  with no compliance benefit.

---

## D-009: Error and Validation Contract

**Decision**: RFC 9457 Problem Details (`application/problem+json`) for every error
response, with a stable machine-readable `code`, plus a `errors[]` array of
field-level violations for `422` validation failures. Request-body validation uses
`go-playground/validator` v10 driven by struct tags.

**Rationale**: FR-014, QV-003, and SC-011 require consistent validation and error
semantics across all endpoints. A single standardized envelope is also what makes the
shared conformance suite in `tests/conformance/` reusable across language variants,
which is the contract-parity control in `docs/research-method.md`. Choosing a
published standard over a bespoke shape means other implementations have an
unambiguous target.

**Alternatives rejected**:

- **Bespoke error envelope**: no advantage over the standard, and every additional
  language variant would have to reimplement an undocumented shape.

---

## D-010: Authorization Enforcement

**Decision**: Middleware chain that resolves the session token to an identity, then a
per-route role requirement. Role is re-read from the account record on each request
rather than trusted from the session snapshot. Privilege changes go through a
dedicated endpoint rather than the general edit endpoint.

**Rationale**: FR-003 and FR-012 require role enforcement, and FR-010 requires a
block to take effect on protected access immediately. Re-reading status and role per
request is what makes "immediately" true; a cached role in the session would leave a
stale-privilege window. Separating the role-change endpoint gives FR-013's escalation
guard and its audit event a single unambiguous place to live, instead of hiding a
privileged side effect inside a general `PATCH`.

**Alternatives rejected**:

- **Trusting the session's role snapshot**: faster, but violates FR-010's immediacy
  and creates a privilege-escalation persistence window.
- **Role change folded into `PATCH /v1/admin/users/{id}`**: convenient, rejected
  because it makes the most security-sensitive operation the easiest one to perform
  by accident.

---

## D-011: Testing Strategy

**Decision**:

| Level | Tooling | Covers |
|-------|---------|--------|
| Unit | stdlib `testing` + `stretchr/testify` | credential policy, hashing, token generation, throttle state machine, last-admin guard |
| Contract | `getkin/kin-openapi` validating live responses against `contracts/openapi.yaml` | request/response schema conformance for every endpoint |
| Integration | `testcontainers-go` with real PostgreSQL | concurrency edge cases, session revocation, soft delete, audit writes |
| Conformance | language-agnostic suite in `tests/conformance/` driven by `test-vectors/` | cross-language behavioral parity |

**Rationale**: QV-002 requires fail-before-pass evidence, and QV-005 requires
contract and conformance coverage of authentication, credential change, admin
actions, authorization failures, and security edge cases. Real Postgres via
testcontainers is required rather than a mock because the concurrency and locking
behavior under test is precisely what a mock would fake.

**Alternatives rejected**:

- **Mocked repository layer for integration tests**: would not exercise the
  transactional behavior that FR-013 and the concurrency edge case depend on.
- **Shared long-lived test database**: creates cross-test coupling and flaky runs,
  which Principle II explicitly forbids.

---

## D-012: Observability

**Decision**: `log/slog` with a JSON handler for structured application logs, a
request-scoped correlation ID propagated via `context`, and a separate append-only
`audit_events` table written inside the same transaction as the action it records.
Credential material and session tokens are never logged; a redaction helper wraps
sensitive types.

**Rationale**: FR-015 requires audit events for nine specific action types, FR-017
forbids credential exposure in logs and audit records, and QV-007 requires
observability over security flows. Writing audit rows in the action's transaction is
what makes SC-006's "100% of security-sensitive actions produce an audit event" true
even when a request fails midway — a fire-and-forget writer could drop events under
load.

**Alternatives rejected**:

- **Audit events to logs only**: not queryable for compliance review and subject to
  log retention loss.
- **Asynchronous audit writes**: lower latency, rejected because dropped events would
  break SC-006. Revisit only if benchmarks show audit writes breaching the p95
  budget, and then with a durable queue rather than best-effort.

---

## D-013: Performance Validation

**Decision**: `k6` scenarios in `specs/001-authentication/benchmark-scenarios/`
exercising login, credential change, and admin list operations at a documented
concurrency profile. Report p50, p95, throughput, and error rate. The p95 gate is
500ms per SC-007. Results land in `benchmarks/reports/`.

**Rationale**: SC-007, SC-012, and Principle IV require a measurable budget with
regression detection. k6 is language-agnostic, so the identical scenario files drive
every implementation variant, satisfying the scenario-parity control.

**Alternatives rejected**:

- **Go `testing.B` microbenchmarks as the gate**: useful for tuning the hasher, but
  they measure functions rather than end-to-end API latency under load, so they
  cannot validate SC-007.

---

## Resolved Unknowns Summary

| Spec input | Resolution |
|------------|------------|
| Language/Version | Go 1.25, containerized (D-001) |
| Primary Dependencies | chi v5, pgx v5, x/crypto/argon2, validator v10, kin-openapi (D-002, D-003, D-009) |
| Storage | PostgreSQL 17 + golang-migrate (D-005) |
| Testing | testing, testify, testcontainers-go, kin-openapi, k6 (D-011, D-013) |
| Target Platform | Linux container (D-001) |
| Project Type | Stateless REST API service (D-002) |
| Performance Goals | p95 < 500ms per SC-007, validated with production hash params (D-003, D-013) |
| Credential policy | Argon2id, min 12 chars, breach/reuse checks per FR-005 (D-003) |
| Abuse threshold | 5 failures / 15 min → 15 min lockout (D-006) |

## Follow-Ups Carried Into Design

All resolved 2026-09-01 with verified evidence:

1. Go patch version confirmed: `golang:1.25.14` is the newest 1.25.x registry tag.
2. Breached-credential source confirmed: Pwned Passwords k-anonymity API (verified
   working from the pinned container; only the 5-char SHA-1 prefix is transmitted).
   Local cache plus fail-open policy — network failure must not block login.
3. Argon2id parameters benchmarked in `golang:1.25.14`: 64MiB/1iter/4par averages
   39.0ms (worst 81.9ms), ~8% of the 500ms p95 budget. Planned parameters locked.
   The OWASP 19MiB floor benchmarked slower (43.9ms avg) on this hardware.

# Implementation Plan: Authentication APIs

**Branch**: `feat/001-authentication` | **Date**: 2026-08-03 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-authentication/spec.md`

## Summary

Deliver authentication, credential self-service, and admin account maintenance as a
stateless Go REST API backed by PostgreSQL. Users authenticate with credentials and
change their own password; admins create, view, edit, block, unblock, delete, and
re-role accounts. Every security-sensitive action writes an audit event in the same
transaction as the action itself.

The technical approach centers on three decisions from [research.md](research.md)
that fall out of the requirements rather than preference:

- **Opaque server-side sessions** (D-004) because FR-006 and FR-010 require that a
  credential change or a block invalidate existing access immediately. Stateless JWTs
  cannot satisfy this without reintroducing server state.
- **Argon2id credential hashing** (D-003) as the OWASP default, with the explicit
  caveat that its cost consumes a material share of the 500ms p95 budget in SC-007
  and must be validated under real load rather than stubbed.
- **PostgreSQL with row-level locking** (D-005) because the concurrent-credential-change
  edge case and FR-013's last-active-admin guard are check-then-act sequences that
  need real transactional guarantees.

## Technical Context

**Language/Version**: Go 1.25, containerized (D-001). Go is not installed on the
current host; Docker 28.3.0 is. All build and test commands run in containers.

**Primary Dependencies**: `go-chi/chi` v5 (routing, `net/http`-compatible),
`jackc/pgx` v5 (Postgres driver), `golang.org/x/crypto/argon2` (hashing),
`go-playground/validator` v10 (request validation), `getkin/kin-openapi` (contract
validation), `golang-migrate` (schema migrations)

**Storage**: PostgreSQL 17; versioned up/down SQL migrations

**Testing**: stdlib `testing` + `stretchr/testify` (unit), `testcontainers-go` with
real PostgreSQL (integration), `kin-openapi` against the live service (contract),
`k6` (performance)

**Target Platform**: Linux container; distroless static runtime image

**Project Type**: Stateless REST API service (backend only; no frontend in scope)

**Performance Goals**: p95 < 500ms for authentication and account-management
endpoints under feature-level benchmark load (SC-007), measured with production
Argon2id parameters

**Constraints**: No credential material in responses, logs, or audit records
(FR-017); uniform denial responses on public auth endpoints to prevent enumeration
(FR-002, D-007); audit events written transactionally so SC-006 holds under partial
failure

**Scale/Scope**: 12 endpoints across 3 groups; 6 tables; research-scale workload
(hundreds of accounts, tens of concurrent sessions) sized for cross-language
comparison rather than production volume

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Initial evaluation: PASS** — no violations requiring justification.

**Post-design re-evaluation: PASS** — the design added no complexity beyond what
requirements force. Details below.

### Code Quality Gate (Principle I)

`gofmt` and `go vet` on every build; `golangci-lint` with `errcheck`, `govet`,
`staticcheck`, `gosec`, and `revive` enabled; `govulncheck` for dependency
advisories. CI fails on any new finding (QV-001, SC-009). Each dependency in
Technical Context is justified in [research.md](research.md); the set is deliberately
small and every one is standard-library-compatible.

### Testing Gate (Principle II)

Four levels per D-011: unit, contract, integration against real PostgreSQL, and the
shared cross-language conformance suite. QV-002 fail-before-pass evidence is captured
by committing each test in a failing state before its implementation and linking both
CI runs in the PR. Integration tests use throwaway containers per run, so no shared
mutable fixture state can create flakiness.

### UX Consistency Gate (Principle III)

One error envelope everywhere: RFC 9457 Problem Details with a stable machine-readable
`code`, plus `errors[]` for field-level validation failures (D-009). The envelope is
defined once in [contracts/openapi.yaml](contracts/openapi.yaml) and enforced by
contract tests, which is what makes QV-003 and SC-011 verifiable rather than
aspirational. The one deliberate inconsistency — public auth endpoints return a
uniform `401` while admin endpoints distinguish `404` — is required by FR-002 and
documented in D-007.

### Performance Gate (Principle IV)

Budget is p95 < 500ms (SC-007), validated by k6 scenarios that are shared across
language variants (D-013). The plan explicitly flags Argon2id cost as the dominant
term in that budget and specifies the tuning order if the gate fails: reduce `memory`
toward the OWASP 19MiB floor before touching `iterations`, and record the change as a
security trade-off. Reports land in `benchmarks/reports/` for regression comparison
(SC-012).

### Simplicity Gate (Principle V)

Standard `net/http` handler semantics throughout; no framework-specific context type.
Abuse-protection counters live in the existing PostgreSQL dependency rather than
adding Redis (D-006). No repository/service/controller layering beyond what the
package structure below needs. Two choices are more complex than the minimum and both
are requirement-driven, recorded in Complexity Tracking.

## Project Structure

### Documentation (this feature)

```text
specs/001-authentication/
├── plan.md              # This file (/speckit.plan command output)
├── spec.md              # Feature specification (/speckit.specify output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/
│   └── openapi.yaml     # Phase 1 output (/speckit.plan command)
├── checklists/
│   └── requirements.md  # /speckit.checklist output
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
implementations/001-authentication/go-chi/
├── cmd/
│   └── api/
│       └── main.go                 # composition root, config, graceful shutdown
├── internal/
│   ├── auth/                       # login, logout, session issue/verify/revoke
│   ├── credential/                 # Argon2id hashing, policy validation, history
│   ├── account/                    # admin CRUD, block/unblock, role change, last-admin guard
│   ├── audit/                      # transactional audit writer, action constants
│   ├── throttle/                   # abuse counters, lockout state machine
│   ├── httpapi/
│   │   ├── handlers/               # one file per endpoint group
│   │   ├── middleware/             # session resolution, role check, correlation ID, recovery
│   │   └── problem/                # RFC 9457 envelope + error code registry
│   ├── storage/
│   │   ├── postgres/               # pgx queries, transaction helpers
│   │   └── migrations/             # golang-migrate up/down SQL
│   └── config/                     # env parsing, validation
├── tests/
│   ├── contract/                   # kin-openapi response validation
│   ├── integration/                # testcontainers + real Postgres
│   └── unit/                       # colocated where practical; shared helpers here
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── go.mod

specs/001-authentication/
├── test-vectors/                   # shared fixtures for cross-language conformance
└── benchmark-scenarios/            # k6 scripts (auth-load.js)

tests/conformance/                  # language-agnostic suite driven by test-vectors
benchmarks/reports/                 # k6 output per implementation
```

**Structure Decision**: Single Go service under
`implementations/001-authentication/go-chi/`, matching the
`implementations/<feature-id>/<language-stack>/` convention in the README and
`docs/research-method.md`. Backend only — the spec defines no user interface.

Internal packages are split by domain capability (`auth`, `credential`, `account`,
`audit`, `throttle`) rather than by technical layer, so each requirement group maps to
one package and the last-admin guard, credential policy, and throttle state machine
are independently unit-testable.

Note on naming: the README's illustrative tree shows `go-fiber`. This plan uses
`go-chi` because D-002 rejected Fiber — it is built on `fasthttp` and does not
implement `net/http` interfaces, which would break the `httptest` and OpenAPI
validation middleware this plan depends on for contract parity. The README tree is
illustrative, not prescriptive.

Contract, conformance, and benchmark artifacts are shared at the repository level so a
future Python or Node implementation validates against identical inputs, preserving
the comparison controls in `docs/research-method.md`.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

The Constitution Check passes. The two entries below are recorded because they add
structure beyond the simplest possible design and Principle V requires a decision
record for such choices.

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Separate `role` endpoint instead of folding role into `PATCH /users/{id}` | FR-013 requires blocking unauthorized privilege escalation with audit evidence; a dedicated endpoint gives the guard and its audit event one unambiguous location | Folding it into the general edit endpoint makes the most security-sensitive operation the easiest to trigger accidentally, and scatters the escalation check into generic field-update logic |
| Two extra tables (`credential_history`, `auth_attempts`) beyond the spec's named entities | FR-005 requires rejecting recently reused credentials; FR-016 and SC-008 require durable throttling that survives restart and works across replicas | In-process rate limiting loses state on restart and is incorrect with more than one instance; omitting history makes the reuse rule unenforceable |

## Phase Status

- [x] Phase 0: Research complete → [research.md](research.md)
- [x] Phase 1: Design complete → [data-model.md](data-model.md), [contracts/openapi.yaml](contracts/openapi.yaml), [quickstart.md](quickstart.md)
- [ ] Phase 2: Tasks (run `/speckit.tasks`)

## Open Items Carried Forward

These do not block task generation but must be resolved during implementation:

1. **Go patch version** — confirm availability in the container registry and pin in
   both `go.mod` and the Dockerfile (D-001).
2. **Breached-credential source** — FR-005 requires rejecting compromised credentials.
   A bundled k-anonymity list is the presumed choice; an external lookup inside the
   login path would add a network dependency that puts SC-007 at risk (research.md
   follow-up 2).
3. **Argon2id parameters** — tune against the benchmark before locking, following the
   documented order of adjustment (D-003).

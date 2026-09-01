# Implementation Readiness Checklist: Authentication APIs

**Purpose**: Validate that the requirements and design artifacts are complete, clear, consistent, measurable, and traceable before running `/speckit.implement`
**Created**: 2026-08-03
**Feature**: [spec.md](../spec.md)

**Note**: This checklist evaluates the quality of the written requirements and design artifacts. It does not test the implementation.

## Requirement Completeness

- [ ] CHK001 Are requirements defined for every operation in the OpenAPI contract, including login, logout, password change, account listing, creation, detail, editing, deletion, blocking, unblocking, and role changes? [Completeness, Spec §FR-001–FR-013]
- [ ] CHK002 Does the specification define the expected account status immediately after admin creation, rather than leaving "usable state" open to interpretation? [Ambiguity, Spec §US3 Scenario 1, Spec §FR-007]
- [ ] CHK003 Are requirements documented for explicit logout even though logout is present in the contract but not named in the functional requirements or user scenarios? [Gap, Contract §POST /v1/auth/logout]
- [ ] CHK004 Are requirements documented for changing an account role through the dedicated role operation, including permitted source and target roles? [Gap, Spec §FR-013, Contract §PUT /v1/admin/users/{id}/role]
- [ ] CHK005 Are requirements defined for account reactivation from `inactive` status, or is that transition explicitly excluded from this feature? [Gap, Data Model §UserAccount Status transitions]
- [ ] CHK006 Are credential-history retention and reuse requirements explicitly specified, including whether the current credential plus five prior credentials are prohibited? [Completeness, Spec §FR-005, Data Model §CredentialHistory]
- [ ] CHK007 Are requirements for bootstrap-admin creation, mandatory initial credential change, and bootstrap-secret lifecycle documented in the feature scope? [Gap, Data Model §Bootstrap, Tasks §T018]

## Requirement Clarity

- [ ] CHK008 Is "stale or risky authenticated access" replaced or supplemented with an explicit session-revocation rule for password changes? [Ambiguity, Spec §FR-006]
- [ ] CHK009 Is "bounded, privacy-aware account details" quantified with allowed fields, search fields, page limits, and visibility rules? [Clarity, Spec §FR-008, Contract §GET /v1/admin/users]
- [ ] CHK010 Are "permitted user account attributes" enumerated, with role and credential changes explicitly excluded from general account editing? [Clarity, Spec §FR-009, Contract §PATCH /v1/admin/users/{id}]
- [ ] CHK011 Is "approved recovery path" for actions affecting the last active admin defined, or is rejection the only permitted outcome in this feature? [Ambiguity, Spec §Edge Cases, Spec §FR-013]
- [ ] CHK012 Are "clear recovery outcomes" enumerated for authentication, password-policy, duplicate-account, invalid-state, authorization, and throttling failures? [Clarity, Spec §FR-018]
- [ ] CHK013 Is the client-IP derivation and trusted-proxy policy specified for IP-based abuse protection? [Gap, Research §D-006]
- [ ] CHK014 Is the comparison method for "comparable response times" defined with sample size, tolerance, and acceptable variance so enumeration resistance can be objectively assessed? [Measurability, Research §D-007, Quickstart §Scenario 1]

## Requirement Consistency

- [x] CHK015 Is the Go version stated consistently and pinned to an available patch version across the plan, module, container, and setup requirements? [Assumption, Plan §Open Items 1, Research §D-001] — Resolved 2026-09-01: `golang:1.25.14` confirmed in registry; pin in `go.mod` and Dockerfile.
- [x] CHK016 Is the breached-credential source resolved consistently between FR-005, the presumed bundled list, and task T038, including update and versioning expectations? [Conflict, Spec §FR-005, Plan §Open Items 2, Tasks §T038] — Resolved 2026-09-01: Pwned Passwords k-anonymity API with local cache, fail-open on network failure. T038 must be updated to match.
- [x] CHK017 Are Argon2id parameters presented as provisional everywhere until benchmark tuning is complete, and is the authority for locking them identified? [Consistency, Research §D-003, Plan §Open Items 3] — Resolved 2026-09-01: benchmarked at 39.0ms avg / 81.9ms worst (~8% of p95 budget); planned 64MiB/1iter/4par locked.
- [ ] CHK018 Does the statement that the service is "stateless" align with the documented server-side sessions, throttling counters, audit events, and PostgreSQL dependency? [Ambiguity, Plan §Summary, Research §D-004–D-006]
- [ ] CHK019 Are account deletion requirements consistent about identifier reuse, credential-history scrubbing, audit retention, and the terminal nature of deletion? [Consistency, Spec §FR-011, Research §D-008, Data Model §UserAccount]
- [ ] CHK020 Are session lifetime and revocation rules consistent across the research decision, data model, OpenAPI descriptions, and quickstart scenarios? [Consistency, Research §D-004, Data Model §Session, Contract §Authentication]
- [x] CHK021 Is the count of "12 endpoints" reconciled with the 11 HTTP operations across 8 paths currently defined in the OpenAPI contract? [Conflict, Plan §Scale/Scope, Tasks §Task Completeness Validation, Contract §Paths] — Resolved 2026-09-01: plan and tasks corrected to 11; contract is authoritative.

## Acceptance Criteria Quality

- [ ] CHK022 Is SC-001's 95% first-attempt authentication target reconciled with the deterministic expectation that valid active credentials succeed, including which failures may comprise the remaining 5%? [Ambiguity, Spec §SC-001, Spec §FR-001]
- [ ] CHK023 Are the expected load profile, concurrency, dataset size, warm-up, duration, and execution environment defined for the 500ms p95 budget? [Measurability, Spec §SC-007, Research §D-013]
- [ ] CHK024 Are separate latency criteria defined for Argon2id-bound authentication and non-hashing account-management operations, or is one shared 500ms threshold intentionally required? [Clarity, Spec §SC-007, Research §D-003]
- [ ] CHK025 Are completion-time criteria SC-003 and SC-004 defined for an API-only feature in terms of measurable request sequences rather than human workflow duration? [Measurability, Spec §SC-003–SC-004]
- [ ] CHK026 Does each security-sensitive action have an explicit required audit action name, actor rule, subject rule, outcome rule, and mandatory field set? [Acceptance Criteria, Spec §FR-015, Spec §SC-006, Data Model §AuditEvent]
- [ ] CHK027 Are objective acceptance criteria defined for detecting credential, token, and sensitive-account-data exposure across responses, logs, audit records, and views? [Measurability, Spec §FR-017]
- [ ] CHK028 Is the acceptable performance regression threshold quantified rather than referring only to an "approved regression threshold"? [Ambiguity, Spec §SC-012]

## Scenario Coverage

- [ ] CHK029 Are primary, alternate, and exception requirements complete for login, including malformed input, expired sessions, unknown accounts, blocked accounts, and active accounts with invalid credentials? [Coverage, Spec §US1, Spec §Edge Cases]
- [ ] CHK030 Are recovery requirements defined after a temporary lockout expires, after a blocked account is unblocked, and after an inactive account becomes active? [Recovery Flow, Gap]
- [ ] CHK031 Are requirements defined for logout with an expired, already revoked, malformed, or missing token, including whether the operation is idempotent? [Exception Flow, Gap, Contract §POST /v1/auth/logout]
- [ ] CHK032 Are password-change requirements complete for concurrent requests, policy rejection, current-password rejection, session revocation, and audit failure outcomes? [Coverage, Spec §US2, Spec §Edge Cases]
- [ ] CHK033 Are admin-operation requirements complete for duplicate create, repeated block/unblock, repeated delete, edits to deleted accounts, and self-directed administration? [Coverage, Gap, Spec §US3]
- [ ] CHK034 Are requirements specified for simultaneous attempts to delete, block, or demote different active admins so the last-admin invariant remains unambiguous? [Concurrency, Spec §FR-013]
- [ ] CHK035 Are partial-failure and rollback requirements defined when an account or credential mutation succeeds but session revocation or audit persistence fails? [Recovery Flow, Gap, Research §D-012]

## Edge Case Coverage

- [ ] CHK036 Are login identifier normalization rules defined for case, whitespace, Unicode, and equivalent email forms before uniqueness and throttling keys are evaluated? [Edge Case, Gap, Data Model §UserAccount]
- [ ] CHK037 Are request body size, unknown-field, duplicate-field, invalid-content-type, and malformed-JSON outcomes specified consistently for all endpoints? [Edge Case, Gap, Spec §FR-014]
- [ ] CHK038 Are pagination boundary requirements specified for zero, negative, excessive, and out-of-range limit and offset values? [Edge Case, Gap, Contract §GET /v1/admin/users]
- [ ] CHK039 Are clock-skew and boundary semantics defined for session expiry, throttling windows, Retry-After, and audit timestamps? [Edge Case, Gap]
- [ ] CHK040 Are requirements defined for password inputs at byte-length and Unicode-normalization boundaries, not only character-count boundaries? [Edge Case, Gap, Data Model §Credential]
- [ ] CHK041 Is the behavior defined when a deleted login identifier is reused while historical audit records still reference the prior account UUID? [Edge Case, Research §D-008]

## Non-Functional Requirements

- [ ] CHK042 Are transport-security requirements specified for production, including TLS termination, accepted proxy headers, and prohibition of bearer tokens over plaintext connections? [Security, Gap]
- [ ] CHK043 Are secret-management requirements specified for database credentials, bootstrap credentials, and session-token handling outside source control? [Security, Completeness, Data Model §Bootstrap]
- [ ] CHK044 Are database backup, audit retention duration, audit access control, and deletion/compliance requirements documented? [Security, Operations, Gap]
- [ ] CHK045 Are availability, graceful-shutdown, connection-timeout, query-timeout, and database-unavailable response requirements specified? [Reliability, Gap]
- [ ] CHK046 Are accessibility requirements explicitly marked not applicable because this feature is API-only, rather than silently omitted? [Coverage, Assumption]
- [ ] CHK047 Are observability requirements measurable for authentication failures, lockouts, authorization denials, latency, and audit-write failures without exposing sensitive labels? [Measurability, Spec §QV-007]
- [ ] CHK048 Are dependency-vulnerability acceptance and exception criteria documented for the planned `govulncheck` and security-analysis gates? [Security, Gap, Plan §Code Quality Gate]

## Dependencies & Assumptions

- [ ] CHK049 Is PostgreSQL 17 documented as a required feature dependency, including required extensions such as `citext` and the permissions needed to install them? [Dependency, Research §D-005, Data Model §UserAccount]
- [ ] CHK050 Is Docker-only local development explicitly accepted, with a documented alternative for environments where Docker or Testcontainers is unavailable? [Assumption, Research §D-001]
- [ ] CHK051 Are UUIDv7 generation ownership and compatibility requirements specified for the chosen PostgreSQL and Go versions? [Dependency, Data Model §Entity Overview]
- [ ] CHK052 Are the maintenance-job scheduling and ownership requirements defined for expired sessions and stale abuse counters? [Gap, Tasks §T059]
- [ ] CHK053 Are k6 and the JavaScript conformance runner documented as required tooling, with pinned versions and reproducible execution commands? [Dependency, Tasks §T056–T058]

## Traceability & Conflicts

- [ ] CHK054 Does every FR, QV, SC, edge case, and user-story acceptance scenario map to at least one task and one planned evidence artifact? [Traceability, Gap, Tasks §Task Completeness Validation]
- [ ] CHK055 Is a requirement-to-task-to-test matrix documented instead of relying on the unsubstantiated statement that all 18 functional requirements are covered? [Traceability, Gap, Tasks §Task Completeness Validation]
- [ ] CHK056 Are the deliberate public-auth versus admin error-disclosure differences traced to explicit requirements and represented consistently in acceptance criteria? [Traceability, Spec §FR-002, Research §D-007]
- [ ] CHK057 Is the role-change behavior traced to a functional requirement and acceptance scenario rather than inferred only from the unsafe-privilege-escalation prohibition? [Traceability, Gap, Spec §FR-013]
- [ ] CHK058 Are the three open plan decisions assigned an owner, decision deadline, and blocking task before implementation can depend on them? [Readiness, Plan §Open Items 1–3]

## Notes

- Check items off as the requirement or design artifact is clarified: `[x]`.
- Record findings and links beside each item so decisions remain reviewable.
- Recommended gate: resolve CHK015–CHK017, CHK021–CHK028, CHK035, CHK042–CHK045, and CHK054–CHK058 before running `/speckit.implement`.

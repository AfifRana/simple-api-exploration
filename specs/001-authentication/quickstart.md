# Quickstart: Authentication APIs (Go)

**Feature**: `001-authentication` | **Date**: 2026-08-03

Validation guide for the Go implementation. Run these scenarios to confirm the
feature satisfies its acceptance criteria end to end.

> Implementation lives in `implementations/001-authentication/go-chi/`.
> Details: [contracts/openapi.yaml](contracts/openapi.yaml), [data-model.md](data-model.md), [research.md](research.md)

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Docker | 28.x | Required; the Go toolchain runs in a container (D-001) |
| Docker Compose | v2 | Ships with Docker Desktop |
| `k6` | 0.5x | Performance scenarios only; container image also available |

A local Go install is optional. All commands below work without one.

---

## Setup

From the implementation directory:

```bash
cd implementations/001-authentication/go-chi
cp .env.example .env      # set BOOTSTRAP_ADMIN_PASSWORD before starting
docker compose up -d --build
```

This starts PostgreSQL 17, applies migrations, and seeds a single bootstrap admin
(see Bootstrap in [data-model.md](data-model.md)).

Confirm the service is healthy:

```bash
curl -fsS http://localhost:8080/healthz
```

Set convenience variables:

```bash
export API=http://localhost:8080
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD='<value of BOOTSTRAP_ADMIN_PASSWORD>'
```

---

## Scenario 1 — User authenticates (US1, FR-001, FR-002)

**Login succeeds and returns a session token.**

```bash
curl -sS -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login_identifier\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}"
```

Expected: `200` with `token`, `expires_at`, `account_id`, `role: "admin"`.

**Invalid credentials and unknown accounts are indistinguishable.**

```bash
# wrong password for a real account
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login_identifier\":\"$ADMIN_EMAIL\",\"password\":\"wrong-password-here\"}"

# account that does not exist
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"nobody@example.com","password":"wrong-password-here"}'
```

Expected: both return `401` with identical bodies
(`code: "auth.invalid_credentials"`) and comparable response times (D-007).

---

## Scenario 2 — Admin maintains accounts (US3, FR-007 to FR-011)

Capture an admin token:

```bash
export ADMIN_TOKEN=$(curl -sS -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"login_identifier\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  | jq -r .token)
```

**Create, read, edit:**

```bash
export USER_ID=$(curl -sS -X POST "$API/v1/admin/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","display_name":"Alice",
       "password":"correct-horse-battery","role":"user"}' | jq -r .id)

curl -sS "$API/v1/admin/users/$USER_ID" -H "Authorization: Bearer $ADMIN_TOKEN"

curl -sS -X PATCH "$API/v1/admin/users/$USER_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"display_name":"Alice Smith"}'
```

Expected: `201` then `200` then `200`. No response contains credential material
(FR-017).

**Block revokes access immediately (FR-010):**

```bash
export USER_TOKEN=$(curl -sS -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","password":"correct-horse-battery"}' \
  | jq -r .token)

curl -sS -X POST "$API/v1/admin/users/$USER_ID/block" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# the already-issued token must now be rejected
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$API/v1/auth/logout" \
  -H "Authorization: Bearer $USER_TOKEN"
```

Expected: block returns `204`; the previously valid token then returns `401`.

**Non-admins are denied (FR-012, SC-005):**

```bash
curl -sS -X POST "$API/v1/admin/users/$USER_ID/unblock" -H "Authorization: Bearer $ADMIN_TOKEN"
export USER_TOKEN=$(curl -sS -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","password":"correct-horse-battery"}' \
  | jq -r .token)

curl -sS -o /dev/null -w '%{http_code}\n' "$API/v1/admin/users" \
  -H "Authorization: Bearer $USER_TOKEN"
```

Expected: `403` with `code: "authz.forbidden"`.

**Last active admin is protected (FR-013):**

```bash
export ADMIN_ID=$(curl -sS "$API/v1/admin/users?role=admin&status=active" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.items[0].id')

curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE "$API/v1/admin/users/$ADMIN_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Expected: `409` — the only active admin cannot be removed.

---

## Scenario 3 — User changes credentials (US2, FR-004 to FR-006)

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X PUT "$API/v1/me/password" \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"current_password":"correct-horse-battery","new_password":"a-much-longer-new-secret"}'
```

Expected: `204`.

**All sessions are revoked, including the caller's (FR-006):**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$API/v1/me/password" \
  -H "Authorization: Bearer $USER_TOKEN" -X PUT -H 'Content-Type: application/json' \
  -d '{"current_password":"a-much-longer-new-secret","new_password":"another-new-secret-x"}'
```

Expected: `401` — the pre-change token no longer works.

**Old credential stops working, new one works:**

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","password":"correct-horse-battery"}'   # 401

curl -sS -o /dev/null -w '%{http_code}\n' -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","password":"a-much-longer-new-secret"}' # 200
```

**Weak credentials are rejected (FR-005):**

```bash
# re-authenticate with the new password (all sessions were revoked above)
export NEW_USER_TOKEN=$(curl -sS -X POST "$API/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login_identifier":"alice@example.com","password":"a-much-longer-new-secret"}' \
  | jq -r .token)

curl -sS -X PUT "$API/v1/me/password" \
  -H "Authorization: Bearer $NEW_USER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"current_password":"a-much-longer-new-secret","new_password":"short"}'
```

Expected: `422` with an `errors[]` entry for `new_password` (D-009).

---

## Scenario 4 — Abuse protection (FR-016, SC-008)

```bash
for i in $(seq 1 6); do
  curl -sS -o /dev/null -w "attempt $i: %{http_code}\n" -X POST "$API/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"login_identifier":"alice@example.com","password":"deliberately-wrong"}'
done
```

Expected: attempts 1–5 return `401`; attempt 6 returns `429` with a `Retry-After`
header. A correct password during lockout still returns `429` (D-006).

---

## Scenario 5 — Audit coverage (FR-015, SC-006)

Every action above must have produced an audit row:

```bash
docker compose exec -T postgres psql -U app -d authdb \
  -c "SELECT action, outcome, count(*) FROM audit_events GROUP BY 1,2 ORDER BY 1;"
```

Expected: rows for `auth.login.success`, `auth.login.failure`, `credential.change`,
`account.create`, `account.edit`, `account.block`, `account.unblock`,
`authz.denied`, and `abuse.lockout`.

**No credential material is ever persisted in audit context (FR-017):**

```bash
docker compose exec -T postgres psql -U app -d authdb \
  -c "SELECT count(*) FROM audit_events
      WHERE context::text ILIKE '%password%' OR context::text ILIKE '%token%';"
```

Expected: `0`.

---

## Automated Test Suites

```bash
# unit + integration (starts throwaway Postgres via testcontainers)
docker compose run --rm app go test ./... -race -count=1

# contract tests against the live service
docker compose run --rm app go test ./tests/contract/... -count=1
```

Expected: all pass. Per QV-002, each new test must be demonstrated failing before
its implementation exists.

---

## Performance Validation (SC-007, SC-012)

```bash
k6 run ../../../specs/001-authentication/benchmark-scenarios/auth-load.js
```

Gate: p95 < 500ms across login, credential change, and admin list operations, with
production Argon2id parameters in effect (D-003, D-013). Save output to
`benchmarks/reports/`.

---

## Teardown

```bash
docker compose down -v
```

---

## Acceptance Checklist

| Scenario | Criteria |
|----------|----------|
| 1 | SC-001, SC-002 |
| 2 | SC-004, SC-005 |
| 3 | SC-003 |
| 4 | SC-008 |
| 5 | SC-006 |
| Test suites | SC-010 |
| Performance | SC-007, SC-012 |

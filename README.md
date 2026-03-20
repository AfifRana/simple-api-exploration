# Authentication Service — API Design

## Overview

This document describes the HTTP API design for a standalone Authentication Service that handles user registration, login, token issuance/rotation, password reset, email verification, and session management.

## Base URL

- Production example: `https://auth.example.com/api/v1`

All endpoints are JSON over HTTPS. Use `Authorization: Bearer <access_token>` for protected endpoints.

## Auth Flows (summary)

- Sign up: create account, send verification email (optional).
- Login: issue short-lived JWT access token + long-lived refresh token.
- Refresh: rotate refresh tokens; issue new access + refresh tokens.
- Logout / revoke: invalidate a refresh token/session.
- Password reset: email flow with one-time token.

## Token Strategy

- Access token: JWT signed with RS256 (or HS256 if internal), expires ~15 minutes.
- Refresh token: opaque random token stored hashed in DB, expires ~30 days, rotate on use.
- Token revocation: keep refresh token records per-session; blacklist access tokens briefly on logout if needed.

## Data Model (high-level)

- User: `id`, `email`, `password_hash`, `email_verified`, `created_at`, `updated_at`, `roles`.
- RefreshToken: `id`, `user_id`, `token_hash`, `issued_at`, `expires_at`, `revoked_at`, `device_info`.

## Endpoints

- **POST /signup** — Register a new user
  - Body: `{ "email": "user@example.com", "password": "..." }`
  - Responses: `201` created (user summary), `400` validation, `409` email exists
  - Notes: send verification email if required; do not return tokens until verification if policy requires.

- **POST /login** — Authenticate and receive tokens
  - Body: `{ "email": "user@example.com", "password": "...", "device_info": "..." }`
  - Responses: `200` `{ "access_token": "...", "expires_in": 900, "refresh_token": "..." }`, `401` unauthorized
  - Notes: record a new refresh token row tied to the device/session.

- **POST /token/refresh** — Exchange refresh token for new tokens
  - Body: `{ "refresh_token": "..." }`
  - Responses: `200` new tokens, `401` invalid/expired, `403` revoked
  - Notes: rotate refresh token (issue new refresh token and mark old one revoked); protect against reuse (detect reuse -> revoke all user sessions).

- **POST /logout** — Revoke a refresh token (logout single session)
  - Body: `{ "refresh_token": "..." }` or rely on `Authorization` + session id
  - Responses: `204` no content, `400/401` as applicable

- **POST /password-reset** — Request password reset
  - Body: `{ "email": "..." }`
  - Responses: `204` (always), `429` rate limited
  - Notes: send one-time password-reset token link; do not reveal whether email exists.

- **POST /password-reset/confirm** — Complete password reset
  - Body: `{ "token": "...", "new_password": "..." }`
  - Responses: `200` success, `400` invalid/expired token

- **GET /me** — Get current user profile
  - Auth: `Authorization: Bearer <access_token>`
  - Responses: `200` user object, `401` unauthorized

- **POST /verify-email** — Verify email with token
  - Body: `{ "token": "..." }`
  - Responses: `200` verified, `400` invalid/expired

## Request/Response Examples

- Login example response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1...",
  "expires_in": 900,
  "refresh_token": "e6b1f3..."
}
```

### Errors

- Use a consistent error envelope: `{ "error": { "code": "INVALID_CREDENTIALS", "message": "...", "details": { ... } } }`.
- Common HTTP statuses:
  - `400` Bad Request / validation
  - `401` Unauthorized (invalid/expired token)
  - `403` Forbidden (revoked token/insufficient scope)
  - `404` Not Found
  - `409` Conflict (duplicate resource)
  - `429` Too Many Requests
  - `500` Internal Server Error

## Security Considerations

- Always require HTTPS and HSTS.
- Hash passwords using a strong algorithm (bcrypt/argon2) with appropriate cost.
- Store only hashed refresh tokens; never store raw tokens in plain text.
- Implement refresh token rotation and detect reuse to mitigate theft.
- Limit login attempts and introduce progressive delays / temporary account lockouts.
- Use short-lived access tokens and minimal scopes.
- Protect endpoints with rate limiting and IP/device throttling.
- Avoid using deprecated libraries

## Scalability & Persistence

- Persist users and refresh tokens in a durable DB (Postgres, etc.).
- For distributed deployments, make JWT verification key(s) available via JWKS endpoint (e.g., `/.well-known/jwks.json`).
- Use an in-memory store (Redis) for blacklists or reuse-detection with short expiry when needed.

## Operational

- Logging: audit login, token refresh, password reset, revoke events (no sensitive tokens in logs).
- Monitoring: track failed login rate, refresh reuse incidents, token errors.

## Rate Limits

- Recommended defaults:
  - `POST /login`, `POST /password-reset`: strict per-IP and per-account limits (e.g., 5/minute then exponential backoff).
  - General API: `1000` requests/min per API key or client.

## Idempotency

- `POST /signup` should be idempotent by email: repeated identical requests return `409` if already created.

## Extensions / Next Steps

- Provide an OpenAPI v3 schema for the endpoints.
- Add OAuth2 / SSO support (e.g., OIDC provider integration).

---

For implementation help, sample code, or an OpenAPI spec, ask and I'll generate it.
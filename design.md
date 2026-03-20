# Authentication Service Design Decisions

## Goals

- Minimal memory footprint with reliable production-ready behavior.
- Implement API in `README.md` and extend with static and dynamic JWKS support.
- Default to in-memory DB for easy local setup, while supporting PostgreSQL/MySQL profiles.

## Technology Decisions

- **Framework**: Spring Boot 3.3.x, Java 21.
- **Web stack**: Spring MVC (`spring-boot-starter-web`) for simple and stable request handling.
- **Security**: Spring Security with stateless JWT authentication.
- **Persistence**: Spring Data JPA + Flyway migrations.
- **Database default**: H2 in-memory.
- **Optional databases**: PostgreSQL and MySQL through Spring profiles.
- **JWT/JWKS**: JJWT 0.12.x with RS256 signing.
- **Rate limiting**: Bucket4j with in-memory token buckets.
- **Password hashing**: BCrypt.

## JWT and JWKS Decisions

- Access token is signed with **RS256** using service private key.
- Refresh token is opaque random token, stored as SHA-256 hash in DB.
- Service exposes static JWKS endpoint:
  - `GET /.well-known/jwks.json`
  - returns current public key (`kid`, `kty`, `alg`, `n`, `e`).
- Dynamic JWKS validation is supported for external providers:
  - Provider config includes `jwksUri`, `issuer`, `audience`.
  - Example provider URL: `https://www.googleapis.com/oauth2/v3/certs`.
  - JWKS documents are cached in-memory with TTL.

## Key Management Decisions

- Dev default: generate RSA keypair at startup (`keystore.mode=generate`).
- Optional production mode: load RSA keypair from PKCS12 keystore (`keystore.mode=file`).
- JWT header includes `kid` for key lookup and future rotation.

## Security and Reliability Decisions

- Access tokens short-lived (`~15min`), refresh tokens long-lived (`~30 days`).
- Refresh-token rotation on each refresh request.
- Reuse detection: if revoked refresh token is reused, revoke all sessions for that user.
- Login and password-reset endpoints are rate limited per IP.
- Password reset request always returns `204` to avoid account enumeration.

## API Decisions

- Core endpoints from `README.md` are implemented under `/api/v1`.
- Added endpoint for social login with dynamic JWKS validation:
  - `POST /api/v1/login/social`
- `GET /api/v1/me` requires bearer access token.

## Testing Decisions

- **Unit tests**: service and JWT/JWKS logic with mocked dependencies.
- **Integration tests**: full Spring context + H2 + MockMvc.
- Integration tests include mocked external-token validation path to verify social login behavior without real network calls.

## Out of Scope

- Full OAuth2/OIDC authorization server implementation.
- SMTP/email provider integration (verification and reset token links are logged for now).
- Distributed cache/redis-based revocation list (kept optional for later scale stages).

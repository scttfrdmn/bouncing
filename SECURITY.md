# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Bouncing, please report it responsibly.

**Email:** security@bounc.ing

**Do NOT** file a public GitHub issue for security vulnerabilities.

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Assessment | Within 7 days |
| Fix (critical) | Within 30 days |
| Fix (non-critical) | Next scheduled release |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.7.x | Yes |
| < 0.7 | No |

## Security Architecture

### Authentication

- **JWT signing:** Ed25519 (EdDSA) exclusively — no RSA, no HMAC shared secrets
- **Key rotation:** Keys rotate with millisecond-precision KIDs; old keys remain in JWKS during a grace period for token verification continuity
- **Refresh tokens:** Rotation with replay detection — if a consumed token is replayed, the entire token family is revoked
- **OAuth CSRF:** State parameter is HMAC-SHA256 signed and bound to a secure, HttpOnly cookie

### Cookies

All authentication cookies are:
- `HttpOnly` — not accessible to JavaScript
- `Secure` — only sent over HTTPS (detected via TLS or `X-Forwarded-Proto`)
- `SameSite=Lax` — mitigates CSRF for top-level navigations

The refresh token cookie is path-restricted to `/auth/refresh` to limit exposure.

### Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy` (restrictive default-src 'self')
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security` (when TLS is detected)

### Rate Limiting

Per-IP token-bucket rate limiter on all `/auth/*` endpoints. Management API (behind API key) and JWKS endpoints are exempt.

### Known Considerations

- **Apple Sign-In id_token:** The JWT payload is decoded without cryptographic signature verification. Integrity relies on TLS transport security from Apple's token endpoint. This is a deliberate trade-off to avoid fetching and caching Apple's JWKS for a single-use token delivered over a direct HTTPS connection.

### Static Analysis

- `golangci-lint` (errcheck, staticcheck, unused, gofmt) — runs on every PR
- `gosec` — security-focused static analysis — runs on every PR
- `govulncheck` — dependency vulnerability scanning — runs on every PR and weekly

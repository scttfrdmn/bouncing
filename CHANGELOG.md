# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] — 2026-04-09

### Security
- **[Critical]** WebAuthn registration endpoints now require authentication; users can only register credentials for their own account (#30)
- **[Critical]** SCIM bearer token comparison changed to constant-time via SHA256 hash + hmac.Equal (#31)
- **[High]** Auto-generated API key no longer appears in structured logs; printed to stderr only (#32)
- **[High]** Refresh token rotation serialized with mutex to prevent race condition producing duplicate tokens (#33)
- **[High]** OIDC discovery rejects non-https:// issuer URLs; config rejects webhook URLs without http(s):// scheme (#34)
- **[Medium]** OAuth redirect_url and error_url validated against base_url to prevent open redirects (#35)
- **[Medium]** OIDC discovery and userinfo responses limited to 1MB to prevent OOM (#36)
- **[Medium]** OAuth state HMAC secret derived with domain separator instead of raw API key (#37)
- **[Low]** Dashboard mutation handlers require HX-Request header to prevent cross-site form attacks (#38)

## [0.7.0] — 2026-04-09

### Added
- Security headers middleware: X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, HSTS (TLS-only)
- Max body size middleware (1MB default) to prevent DoS via large payloads
- Input validation: email format, webhook URL scheme, role name format, org slug format
- gosec static analysis in CI and weekly security scan
- SECURITY.md with responsible disclosure policy, response timeline, and security architecture docs

### Changed
- Email validation improved from simple `@` check to require dotted domain
- Middleware chain: SecurityHeaders is now the outermost wrapper

## [0.6.0] — 2026-04-09

### Added
- Custom OAuth/OIDC providers: set `issuer_url` in config to add any OIDC-compliant provider (Okta, Auth0, Keycloak, etc.) without code changes
- OIDC auto-discovery via `.well-known/openid-configuration`
- Generic OIDC userinfo fetcher for standard claims (sub, email, name, picture)
- GitLab and Slack as built-in OIDC providers
- Config-level scope overrides for any OAuth provider
- OAuthProviderConfig gains `issuer_url` and `scopes` fields

### Changed
- NewProvider signature changed to accept OAuthProviderCfg struct (breaking internal API, no external impact)
- Exchange() uses standard OIDC userinfo endpoint for custom and OIDC-native built-in providers

## [0.5.0] — 2026-04-09

### Added
- Test coverage improvements across 6 packages (legal, webauthn, oauth, directory, dashboard, server)
- Dashboard test suite: page renders, HTMX create/delete mutations
- OAuth edge case tests via gock: GitHub no-primary-email, Microsoft UPN fallback
- Directory sync tests: mixed results, nil hooks, bad service account file
- Legal tests: accessor methods, ClearPendingCookie, ShowAgreement HTML rendering

### Fixed
- Dashboard template rendering: per-page template parsing prevents {{define "content"}} collisions

## [0.4.0] — 2026-04-09

### Added
- Management dashboard: embedded HTMX + Go templates web UI at /dashboard/
  - User list with search/filter and inline delete
  - User detail with role assignment/revocation
  - Role list with create/delete
  - Organization list with create
  - Webhook list with create/delete
  - Audit log viewer with actor/action filters
- RequireAdmin middleware (RequireAuth + admin role check)
- Pico CSS for classless styling, HTMX for inline CRUD
- All templates and static assets embedded via go:embed (single binary)

## [0.3.0] — 2026-04-09

### Added
- Rate limiting middleware for /auth/* endpoints (token-bucket per-IP, configurable rate + burst)
- Audit log: immutable audit_entries table, audit.Logger, GET /manage/audit with filters
- Automatic Ed25519 key rotation: KeyRing with multi-key verification, `bouncing keys rotate` + `bouncing keys list` CLI
- Full RBAC management API: PUT /manage/roles/{id}, DELETE /manage/roles/{id}, GET /manage/users/{id}/roles
- Go SDK (sdk/go/): zero-dep client with JWKS verification, Protect/Require middleware, AdminClient
- SCIM 2.0 provisioning: POST/GET/PATCH/DELETE /scim/v2/Users, GET /scim/v2/Groups
- SCIMConfig + RequireSCIMToken middleware (dedicated bearer token)
- pkg/config.RateLimitConfig and pkg/config.SCIMConfig type aliases
- pkg/store.AuditEntry and pkg/store.AuditListOpts type aliases

### Fixed
- .gitignore `bouncing` pattern matched cmd/bouncing/ directory — changed to `/bouncing`
- golangci-lint CI: install from source to match Go 1.26 toolchain
- TOS FK constraint: tos_acceptances no longer has foreign key to users (003 migration), allowing user deletion while preserving legal audit trail

### Changed
- KeySet → KeyRing: Issuer and JWKS handler now work with multiple keys
- JWKS endpoint serves all keys in the ring for graceful rotation

## [0.2.0] — 2026-04-09

### Added
- Organization CRUD (CreateOrg, GetOrg, ListOrgs, AddOrgMember, RemoveOrgMember)
- Management API org endpoints and webhook CRUD endpoints
- Webhook event constants and Dispatch calls at all lifecycle points (user.created, user.login, user.deleted, etc.)
- @bouncing/next TypeScript SDK: auth(), currentUser(), middleware, \<SignIn /\>, \<UserButton /\>, \<BouncingProvider\>
- @bouncing/react SDK: framework-agnostic React components
- Google Workspace directory sync (internal/directory, `bouncing directory sync` CLI)
- GET /auth/providers endpoint (SDK reads configured OAuth providers)
- pkg/ public API layer (pkg/store, pkg/config, pkg/server) for managed offering extensibility
- .goreleaser.yaml release build configuration
- store.ErrNotFound sentinel for consistent error handling across packages

### Changed
- All store single-row lookups now return store.ErrNotFound instead of sql.ErrNoRows
- StoreConfig gains AuthToken and URL fields (for managed Turso support)
- DirectoryConfig gains AdminEmail field (domain-wide delegation)
- Open-core serve rejects non-sqlite drivers with clear error message

## [0.1.0] — 2026-04-07

### Added
- Go binary with OAuth (Google, GitHub, Microsoft, Apple)
- WebAuthn/passkey registration and discoverable login
- Ed25519 JWT issuance and verification with JWKS endpoint
- Refresh token rotation with replay detection
- SQLite storage with embedded migrations
- RBAC engine: roles, permissions, user-role assignments
- Access modes: open, domain-restricted, invite-only
- Management API: user CRUD, invite, bulk import, role assignment
- Legal gate: TOS/NDA agreement with typed-name acceptance
- Webhook dispatch with HMAC-SHA256 signing and exponential retry
- i18n: 7 bundled locales (en, es, fr, de, pt, ja, zh-Hans)
- CLI: serve, init, users add/remove/list/import, version
- HTTP server with request-id, structured logging, CORS middleware
- bouncing.yaml configuration with validation and defaults

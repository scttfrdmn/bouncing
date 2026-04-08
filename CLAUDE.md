# CLAUDE.md — bouncing

## Project Overview

Bouncing is an open-source auth service (Go binary + JS/Go SDKs) with a managed offering at bounc.ing.
Product spec: see `bouncing-spec.md` in this repo root.

## Toolchain

- **Go 1.26** (`go 1.26` in go.mod, `toolchain go1.26.1`)
- **Node 22 LTS** for SDK development
- **pnpm 9** for JS workspace management
- **TypeScript 5.7+** for all JS/TS code
- Formatting: `gofmt` (Go), `prettier` (TS), enforced in CI
- Linting: `golangci-lint` (Go), `eslint` + `@typescript-eslint` (TS)

## Versioning & Release

- **SemVer 2.0.0** strictly. Pre-1.0: 0.MINOR.PATCH. Breaking changes bump MINOR.
- **CHANGELOG.md** follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
- Tags: `v0.1.0`, `v0.1.1`, etc. SDKs versioned independently: `sdk-js/v0.1.0`, `sdk-go/v0.1.0`.
- Releases via GitHub Releases with auto-generated notes from merged PRs.

## Project Tracking

> **IMPORTANT FOR ALL AGENTS**: GitHub is the **sole** source of truth for all project work. Before writing any code, check open issues and the project board. After completing work, file or close issues and update the board. Never track tasks only in memory or task tools — every meaningful unit of work must have a GitHub issue.

All project tracking lives in **GitHub** (`scttfrdmn/bouncing`), not in this file or standalone markdown.

### Required workflow for every session

1. **Start of session**: Run `gh issue list --milestone <current-milestone>` and `gh project item-list` to understand what is open, in-progress, and blocked.
2. **Before coding**: Check whether an issue already exists for the work. If not, create one with appropriate labels and milestone before starting.
3. **During work**: Move the issue to "In Progress" on the project board (`gh project item-edit`).
4. **After coding**: Close the issue via PR or `gh issue close`, referencing the issue number in the commit message (`Closes #N`). Move the card to "Done".
5. **New work discovered**: File a new issue immediately rather than doing it ad-hoc or silently.

### GitHub setup (already configured)

- **Repo**: `scttfrdmn/bouncing` (public) — open-source core
- **Repo**: `scttfrdmn/bouncing-managed` (private) — managed ops
- **GitHub Project**: "Bouncing" board with columns: Backlog → Ready → In Progress → Review → Done
- **Milestones**: one per release version (`v0.1.0`, `v0.2.0`, `v0.3.0`, `v1.0.0`, `v2.0.0+`)
- **Labels**:
  - Area: `area/core`, `area/oauth`, `area/webauthn`, `area/rbac`, `area/session`, `area/store`, `area/cli`, `area/mgmt-api`, `area/sdk-next`, `area/sdk-react`, `area/sdk-go`, `area/dashboard`, `area/docs`, `area/infra`, `area/billing`, `area/legal`, `area/i18n`
  - Type: `type/feature`, `type/bug`, `type/chore`, `type/security`, `type/docs`, `type/test`
  - Priority: `priority/critical`, `priority/high`, `priority/medium`, `priority/low`
  - Size: `size/xs`, `size/s`, `size/m`, `size/l`, `size/xl`
  - Status: `status/blocked`, `status/needs-design`, `status/needs-review`
- **Issue templates**: `bug_report.yml`, `feature_request.yml`, `security_vulnerability.yml` (private)
- **PR template**: checklist for tests, changelog entry, breaking change flag

## Code Conventions (Go)

- **No frameworks for HTTP**. Use `net/http` stdlib mux (Go 1.22+ pattern matching: `GET /auth/oauth/{provider}`).
- **Errors**: return `error`, wrap with `fmt.Errorf("op: %w", err)`. No sentinel errors unless part of public API.
- **Naming**: packages are lowercase single words. Exported types are nouns. Exported functions are verbs.
- **Tests**: `_test.go` in same package for unit, `_integration_test.go` with `//go:build integration` for integration.
- **No globals** except the config loaded at startup. Pass dependencies explicitly.
- **Context**: first parameter, always. `ctx context.Context`.
- **Structured logging**: `log/slog` (stdlib). JSON output in production, text in dev.

## Code Conventions (TypeScript / SDK)

- Strict mode. No `any` except at API boundaries with explicit casts.
- ESM only. No CommonJS.
- Export types separately: `export type { Session }` not mixed with value exports.
- SDK packages use `@bouncing/` npm scope.

## Dependencies — Go

All deps pinned in go.mod. No `latest`. Rationale for each:

```
go 1.26
toolchain go1.26.1

require (
    github.com/go-webauthn/webauthn  v0.12.x    // WebAuthn/FIDO2 — BSD-3-Clause
    github.com/lestrrat-go/jwx/v3    v3.x.x     // JWT/JWK/JWS — MIT — handles Ed25519, JWKS, auto-refresh
    modernc.org/sqlite               v1.x.x     // Pure-Go SQLite — no CGO, cross-compile friendly
    github.com/oklog/ulid/v2         v2.x.x     // ULID generation — Apache-2.0
    gopkg.in/yaml.v3                 v3.x.x     // Config parsing
    golang.org/x/oauth2              v0.x.x     // OAuth2 client flows
    golang.org/x/crypto              v0.x.x     // argon2 (if ever needed), scrypt, etc.
)
```

### Why These Choices

| Dep | Why | Alternatives Rejected |
|-----|-----|----------------------|
| `net/http` stdlib | Go 1.22+ has `{param}` routing. No need for chi/echo/gin. Less deps = smaller binary. | chi (unnecessary), echo (too opinionated), gin (too heavy) |
| `lestrrat-go/jwx/v3` | Full JWx stack: JWT sign/verify, JWK generation/rotation, JWKS endpoint serving, Ed25519 native. One dep instead of three. | `golang-jwt/jwt` (no JWK support), `square/go-jose` (less active) |
| `modernc.org/sqlite` | Pure Go, no CGO. Cross-compiles to ARM (Hetzner CAX) without toolchain gymnastics. | `mattn/go-sqlite3` (requires CGO + gcc) |
| `go-webauthn/webauthn` | Only serious WebAuthn library in Go. FIDO2 conformant. 1200+ stars, active maintenance. | `fxamacker/webauthn` (less maintained) |
| `oklog/ulid/v2` | Sortable, URL-safe, monotonic within millisecond. Better than UUID for primary keys. | `google/uuid` (not sortable), `rs/xid` (smaller but less standard) |

## Module Layout

```
github.com/scttfrdmn/bouncing/
├── cmd/
│   └── bouncing/
│       └── main.go                  // CLI entrypoint: serve, init, users add/remove/import/list, version
├── internal/
│   ├── config/
│   │   ├── config.go                // Parse bouncing.yaml → Config struct
│   │   └── config_test.go
│   ├── authn/
│   │   ├── oauth/
│   │   │   ├── handler.go           // HTTP handlers: begin, callback
│   │   │   ├── providers.go         // Google, GitHub, Microsoft, Apple provider configs
│   │   │   ├── state.go             // CSRF state parameter management
│   │   │   └── oauth_test.go
│   │   └── webauthn/
│   │       ├── handler.go           // HTTP handlers: register/begin, register/finish, login/begin, login/finish
│   │       ├── session.go           // WebAuthn session data storage (short-lived, in-memory or cookie)
│   │       ├── user.go              // Adapter: store.User → webauthn.User interface
│   │       └── webauthn_test.go
│   ├── authz/
│   │   ├── rbac.go                  // Role/permission check: HasRole(), HasPermission()
│   │   ├── policy.go                // Access mode enforcement: open/domain-restricted/invite-only
│   │   └── rbac_test.go
│   ├── session/
│   │   ├── jwt.go                   // Issue access token (Ed25519-signed JWT)
│   │   ├── refresh.go               // Issue/rotate/revoke refresh tokens
│   │   ├── keys.go                  // Ed25519 key generation, loading, rotation
│   │   ├── jwks.go                  // JWKS endpoint handler (/.well-known/jwks.json)
│   │   └── jwt_test.go
│   ├── store/
│   │   ├── store.go                 // Interface: Store (CRUD for users, credentials, roles, orgs, etc.)
│   │   ├── sqlite.go                // SQLite implementation
│   │   ├── turso.go                 // Turso/libSQL implementation (same interface, different driver)
│   │   ├── migrate.go               // Schema migrations (embedded SQL files)
│   │   ├── migrations/
│   │   │   └── 001_initial.sql
│   │   └── store_test.go            // Tests against SQLite (in-memory)
│   ├── tenant/
│   │   ├── tenant.go                // Multi-tenancy namespace (v0.2+)
│   │   └── tenant_test.go
│   ├── mgmt/
│   │   ├── handler.go               // Management API HTTP handlers
│   │   ├── apikey.go                // API key authentication for management endpoints
│   │   └── mgmt_test.go
│   ├── legal/
│   │   ├── handler.go               // GET /auth/agree, POST /auth/agree
│   │   ├── gate.go                  // CheckAccepted(): lookup + pending-cookie logic
│   │   └── legal_test.go
│   ├── i18n/
│   │   ├── i18n.go                  // Lookup(locale, key) + Accept-Language parsing
│   │   ├── locales/                 // go:embed target
│   │   │   ├── en.json
│   │   │   ├── es.json
│   │   │   ├── fr.json
│   │   │   ├── de.json
│   │   │   ├── pt.json
│   │   │   ├── ja.json
│   │   │   └── zh-Hans.json
│   │   └── i18n_test.go
│   ├── hooks/
│   │   ├── dispatch.go              // Webhook event dispatch (async, with retry)
│   │   ├── sign.go                  // HMAC-SHA256 webhook signature
│   │   └── hooks_test.go
│   ├── directory/                    // v0.2+
│   │   ├── sync.go                  // Directory sync orchestrator
│   │   ├── google.go                // Google Workspace provider
│   │   └── directory_test.go
│   └── server/
│       ├── server.go                // HTTP server setup, graceful shutdown
│       ├── routes.go                // Route registration (all endpoints)
│       ├── middleware.go            // Logging, CORS, rate limiting, request ID
│       └── server_test.go
├── migrations/
│   └── embed.go                     // go:embed for SQL migration files
├── CHANGELOG.md
├── CLAUDE.md                        // This file
├── bouncing-spec.md                 // Product spec
├── go.mod
├── go.sum
├── Dockerfile
├── Makefile
└── .github/
    ├── ISSUE_TEMPLATE/
    │   ├── bug_report.yml
    │   └── feature_request.yml
    ├── pull_request_template.md
    └── workflows/
        ├── ci.yml                   // lint + test on PR
        ├── release.yml              // goreleaser on tag push
        └── security.yml             // govulncheck weekly
```

## Open-Core / Managed Boundary

### What `internal/` means in Go

Go's `internal/` convention means **"not a public library API"** — it does NOT mean proprietary or hidden. All code under `internal/` is Apache 2.0 open-source and committed to this public repo. External Go modules simply cannot import from `internal/` (the Go toolchain enforces this).

### What `pkg/` means

`pkg/` is the **stable public API surface** for external consumers. Every type in `pkg/` is a type alias of its `internal/` counterpart — they are completely identical types, requiring no conversions.

| Package | Contents |
|---------|----------|
| `pkg/store/` | `Store` interface + all model types (`User`, `Role`, `Org`, …), `ErrNotFound` |
| `pkg/config/` | `Config` + all sub-types, `Load()` |
| `pkg/server/` | `New(cfg, store.Store, log)` → `*Server` |

### The `bouncing-managed` repo pattern

The private managed offering (`scttfrdmn/bouncing-managed`) imports from `pkg/` to build a binary that adds Turso and billing:

```
bouncing-managed/
├── go.mod                       # module github.com/scttfrdmn/bouncing-managed
│                                # require github.com/scttfrdmn/bouncing vX.Y.Z
├── internal/store/
│   └── turso.go                 # implements pkg/store.Store via go-libsql
└── cmd/bouncing/
    └── main.go                  # imports pkg/server + pkg/config, wires TursoStore
```

The managed `main.go` is the only Go difference from open-core — it passes a `TursoStore` instead of an `SQLiteStore` to `pkg/server.New()`.

### What stays in each repo

| This repo (open-source, Apache 2.0) | bouncing-managed (private) |
|-------------------------------------|---------------------------|
| All auth logic | Turso storage driver |
| SQLite backend | Billing / subscription hooks |
| `@bouncing/next` SDK | Hetzner / Fly.io infra (Terraform, k8s) |
| CLI (`bouncing serve`, etc.) | The bounc.ing website |
| `pkg/` public API | Multi-region deployment configs |

### Local cross-repo development

`managed/` is listed in `.gitignore`. To develop against both repos simultaneously:

```bash
ln -s /path/to/bouncing-managed managed/
```

## Store Interface

This is the central contract. Every storage backend (SQLite, Turso) implements this interface.

```go
package store

type Store interface {
    // Users
    CreateUser(ctx context.Context, u *User) error
    GetUser(ctx context.Context, id string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    ListUsers(ctx context.Context, opts ListOpts) ([]*User, error)
    UpdateUser(ctx context.Context, u *User) error
    DeleteUser(ctx context.Context, id string) error
    CountActiveUsers(ctx context.Context, since time.Time) (int64, error)

    // OAuth
    CreateOAuthConnection(ctx context.Context, c *OAuthConnection) error
    GetOAuthConnection(ctx context.Context, provider, providerID string) (*OAuthConnection, error)
    ListOAuthConnections(ctx context.Context, userID string) ([]*OAuthConnection, error)

    // WebAuthn Credentials
    CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
    GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
    UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
    DeleteWebAuthnCredential(ctx context.Context, id string) error

    // Roles
    CreateRole(ctx context.Context, r *Role) error
    GetRole(ctx context.Context, id string) (*Role, error)
    GetRoleByName(ctx context.Context, name string) (*Role, error)
    ListRoles(ctx context.Context) ([]*Role, error)
    UpdateRole(ctx context.Context, r *Role) error
    DeleteRole(ctx context.Context, id string) error

    // User-Role assignments
    AssignRole(ctx context.Context, userID, roleID string, orgID *string) error
    RevokeRole(ctx context.Context, userID, roleID string, orgID *string) error
    GetUserRoles(ctx context.Context, userID string) ([]*UserRole, error)

    // Organizations (v0.2+)
    CreateOrg(ctx context.Context, o *Org) error
    GetOrg(ctx context.Context, id string) (*Org, error)
    ListOrgs(ctx context.Context) ([]*Org, error)
    AddOrgMember(ctx context.Context, orgID, userID, roleID string) error
    RemoveOrgMember(ctx context.Context, orgID, userID string) error

    // Refresh Tokens
    CreateRefreshToken(ctx context.Context, t *RefreshToken) error
    GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
    DeleteRefreshToken(ctx context.Context, id string) error
    DeleteUserRefreshTokens(ctx context.Context, userID string) error

    // Allowed Domains
    ListAllowedDomains(ctx context.Context) ([]string, error)
    IsAllowedDomain(ctx context.Context, domain string) (bool, error)

    // Webhooks
    ListWebhooks(ctx context.Context) ([]*Webhook, error)
    CreateWebhook(ctx context.Context, w *Webhook) error
    DeleteWebhook(ctx context.Context, id string) error

    // TOS / Legal Acceptances (immutable — never deleted)
    CreateTOSAcceptance(ctx context.Context, a *TOSAcceptance) error
    GetTOSAcceptance(ctx context.Context, userID, version string) (*TOSAcceptance, error)
    ListTOSAcceptances(ctx context.Context, userID string) ([]*TOSAcceptance, error)

    // Migrations
    Migrate(ctx context.Context) error
    Close() error
}
```

## API Request/Response Contracts

All responses are JSON. All error responses follow:

```json
{
    "error": {
        "code": "not_on_the_list",
        "message": "You're not on the list."
    }
}
```

Error codes are stable strings. Messages are human-readable and may change.

### Auth Endpoints

#### `GET /auth/login`
Redirects to the configured auth method selection page (or directly to the sole provider if only one is configured).

#### `GET /auth/oauth/{provider}`
Initiates OAuth flow. Generates CSRF state, stores in secure cookie, redirects to provider.

**Response**: 302 redirect to provider authorization URL.

#### `GET /auth/oauth/{provider}/callback`
Completes OAuth flow. Validates state, exchanges code for token, extracts user info.

**Request** (query params from provider):
```
?code=AUTHORIZATION_CODE&state=CSRF_STATE
```

**On success (existing user)**:
- Issues access token (JWT) + refresh token
- Sets `bouncing_access` and `bouncing_refresh` cookies (httpOnly, secure, sameSite=lax)
- 302 redirect to configured `redirect_url` (or `/`)

**On success (new user, access mode allows)**:
- Creates user record (status=active for open/domain-restricted, links to pending record for invite-only)
- Issues tokens as above
- Fires `user.created` webhook

**On failure (domain restricted / not invited)**:
- 302 redirect to configured `error_url` with `?error=not_on_the_list`

#### `POST /auth/webauthn/register/begin`
Start passkey registration. User must already be authenticated (via OAuth) or pre-provisioned.

**Request**:
```json
{
    "user_id": "01HXYZ..."
}
```

**Response** (200):
```json
{
    "publicKey": {
        "challenge": "base64url...",
        "rp": { "name": "My App", "id": "myapp.com" },
        "user": { "id": "base64url...", "name": "scott@enso.co", "displayName": "Scott" },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -8 },
            { "type": "public-key", "alg": -7 }
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred"
        },
        "attestation": "none"
    }
}
```

Session data is stored server-side (in-memory with short TTL, keyed by user ID).

#### `POST /auth/webauthn/register/finish`
Complete passkey registration.

**Request**: Raw `navigator.credentials.create()` response body.

**Response** (201):
```json
{
    "credential_id": "base64url...",
    "created_at": "2026-04-07T12:00:00Z"
}
```

#### `POST /auth/webauthn/login/begin`
Start passkey authentication. No user ID required (discoverable/resident key flow).

**Request**: `{}` (empty body for discoverable login)

**Response** (200):
```json
{
    "publicKey": {
        "challenge": "base64url...",
        "rpId": "myapp.com",
        "userVerification": "preferred"
    }
}
```

#### `POST /auth/webauthn/login/finish`
Complete passkey authentication.

**Request**: Raw `navigator.credentials.get()` response body.

**Response** (200):
```json
{
    "user": {
        "id": "01HXYZ...",
        "email": "scott@enso.co",
        "name": "Scott",
        "roles": ["admin"],
        "permissions": ["*"]
    },
    "access_token": "eyJ...",
    "refresh_token": "bnc_rt_...",
    "expires_in": 900
}
```

Also sets cookies as with OAuth callback.

#### `POST /auth/refresh`
Rotate refresh token, issue new access token.

**Request**:
```json
{
    "refresh_token": "bnc_rt_..."
}
```
Or reads from `bouncing_refresh` cookie.

**Response** (200):
```json
{
    "access_token": "eyJ...",
    "refresh_token": "bnc_rt_...",
    "expires_in": 900
}
```

Old refresh token is invalidated. This is **refresh token rotation** — if a stolen token is replayed after rotation, the entire family is invalidated.

#### `POST /auth/logout`
Revoke refresh token, clear cookies.

**Response**: 302 redirect to `stop.bounc.ing` (managed) or configured logout URL (self-hosted). 😎

#### `GET /auth/me`
Current user info from access token.

**Response** (200):
```json
{
    "id": "01HXYZ...",
    "email": "scott@enso.co",
    "name": "Scott",
    "avatar_url": "https://...",
    "roles": ["admin"],
    "permissions": ["*"],
    "org_id": null
}
```

#### `GET /.well-known/jwks.json`
JWKS endpoint. Cacheable (Cache-Control: public, max-age=3600).

**Response** (200):
```json
{
    "keys": [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "bouncing-2026-04",
            "use": "sig",
            "x": "base64url..."
        }
    ]
}
```

### Management API

All management endpoints require `Authorization: Bearer bnc_api_...` header.

#### `GET /manage/users`
**Query params**: `page` (int), `per_page` (int, max 100), `status` (pending|active), `role` (string), `q` (search email/name)

**Response** (200):
```json
{
    "users": [
        {
            "id": "01HXYZ...",
            "email": "scott@enso.co",
            "name": "Scott",
            "status": "active",
            "auth_method": "oauth:google",
            "roles": [{ "id": "01ABC...", "name": "admin" }],
            "created_at": "2026-04-07T12:00:00Z",
            "last_login": "2026-04-07T18:30:00Z"
        }
    ],
    "total": 12,
    "page": 1,
    "per_page": 20
}
```

#### `POST /manage/users/invite`
Pre-provision a user (invite-only or any mode).

**Request**:
```json
{
    "email": "newperson@enso.co",
    "role": "editor",
    "name": "New Person"
}
```

**Response** (201):
```json
{
    "id": "01HXYZ...",
    "email": "newperson@enso.co",
    "status": "pending",
    "role": "editor"
}
```

#### `POST /manage/users/import`
Bulk import.

**Request**:
```json
{
    "users": [
        { "email": "a@enso.co", "role": "admin" },
        { "email": "b@enso.co", "role": "editor" },
        { "email": "c@enso.co", "role": "viewer" }
    ]
}
```

**Response** (200):
```json
{
    "created": 3,
    "skipped": 0,
    "errors": []
}
```

#### `DELETE /manage/users/{id}`
Offboard user. Revokes all sessions, deletes record, fires webhook.

**Response** (200):
```json
{
    "deleted": true,
    "sessions_revoked": 3
}
```

#### `POST /manage/users/{id}/roles`
Assign role.

**Request**:
```json
{
    "role": "prompt-editor",
    "org_id": null
}
```

**Response** (200): `{ "ok": true }`

## JWT Claims Structure

```json
{
    "iss": "https://auth.myapp.com",
    "sub": "01HXYZ...",
    "aud": "bnc_client_...",
    "exp": 1712505600,
    "iat": 1712504700,
    "email": "scott@enso.co",
    "name": "Scott",
    "avatar_url": "https://...",
    "roles": ["admin"],
    "permissions": ["*"],
    "org_id": null,
    "kid": "bouncing-2026-04"
}
```

- `exp`: 15 minutes from issuance
- Signed with Ed25519 (alg: `EdDSA`)
- `kid` in header matches JWKS key ID

## WebAuthn Flow Detail

### Registration (adding a passkey to an existing user)

```
Browser                         Bouncing Server               Store
   |                                   |                         |
   |  POST /auth/webauthn/register/begin
   |  { user_id }              ------->|                         |
   |                                   | GetUser(user_id)        |
   |                                   |------------------------>|
   |                                   |<------------------------|
   |                                   |                         |
   |                                   | webauthn.BeginRegistration(user, excludeCredentials)
   |                                   | → CredentialCreation + SessionData
   |                                   |                         |
   |                                   | Store SessionData in memory (TTL 5min, key=userID)
   |                                   |                         |
   |  { publicKey: options }   <-------|                         |
   |                                   |                         |
   |  navigator.credentials.create()   |                         |
   |  (browser prompts user)           |                         |
   |                                   |                         |
   |  POST /auth/webauthn/register/finish
   |  { attestationResponse }  ------->|                         |
   |                                   | Load SessionData from memory
   |                                   | webauthn.FinishRegistration(sessionData, request)
   |                                   | → Credential                |
   |                                   |                         |
   |                                   | CreateWebAuthnCredential()
   |                                   |------------------------>|
   |                                   |<------------------------|
   |                                   |                         |
   |  201 { credential_id }    <-------|                         |
```

### Authentication (logging in with a passkey)

```
Browser                         Bouncing Server               Store
   |                                   |                         |
   |  POST /auth/webauthn/login/begin  |                         |
   |  { }  (discoverable)      ------->|                         |
   |                                   | webauthn.BeginDiscoverableLogin()
   |                                   | → CredentialAssertion + SessionData
   |                                   |                         |
   |                                   | Store SessionData in memory (TTL 5min)
   |                                   |                         |
   |  { publicKey: options }   <-------|                         |
   |                                   |                         |
   |  navigator.credentials.get()      |                         |
   |  (browser prompts user)           |                         |
   |                                   |                         |
   |  POST /auth/webauthn/login/finish |                         |
   |  { assertionResponse }    ------->|                         |
   |                                   | Parse userHandle from response
   |                                   | GetUser(userHandle)     |
   |                                   |------------------------>|
   |                                   | GetWebAuthnCredentials()|
   |                                   |------------------------>|
   |                                   |<------------------------|
   |                                   |                         |
   |                                   | webauthn.FinishPasskeyLogin(
   |                                   |     discoverableUserHandler,
   |                                   |     sessionData, request)
   |                                   | → Credential (verified)
   |                                   |                         |
   |                                   | UpdateWebAuthnCredential() // increment sign_count
   |                                   |------------------------>|
   |                                   |                         |
   |                                   | session.IssueTokens(user)
   |                                   | → access_token (JWT) + refresh_token
   |                                   |                         |
   |  200 { user, tokens }     <-------|                         |
```

### Key Decisions

- **Attestation**: `"none"`. We don't verify hardware attestation. We're not a bank. This simplifies the flow and avoids rejecting legitimate authenticators.
- **Resident keys**: `"preferred"`. Enables usernameless login on supported authenticators but doesn't require it.
- **User verification**: `"preferred"`. Biometric/PIN when available, but don't block if not.
- **Algorithms**: EdDSA (-8) and ES256 (-7). These cover all modern authenticators.
- **Session data**: stored in-memory with 5-minute TTL. NOT in cookies (too large). NOT in the database (unnecessary persistence). Simple `sync.Map` with a cleanup goroutine.

## SDK Architecture (@bouncing/next)

### How the SDK Talks to Bouncing

The SDK operates in TWO modes depending on context:

**Server-side (middleware, server components, API routes)**:
- Reads `bouncing_access` cookie from incoming request
- Verifies JWT locally using cached JWKS public keys (fetched once from `/.well-known/jwks.json`, auto-refreshed hourly)
- No network call to Bouncing on every request
- If access token expired, calls `/auth/refresh` with the refresh token cookie
- `bouncingAdmin` uses API key to call management endpoints directly

**Client-side (React components, useUser hook)**:
- `<BouncingProvider>` wraps the app, provides context
- `useUser()` reads user data from a server-rendered `<script id="__bouncing">` tag (hydration) or calls `/auth/me` on mount
- `<SignIn>` renders OAuth buttons and/or passkey prompt
- `<UserButton>` renders avatar dropdown with sign-out link
- Sign-out calls `/auth/logout` which clears cookies and redirects

### Cookie Strategy

| Cookie | Value | httpOnly | secure | sameSite | path | maxAge |
|--------|-------|----------|--------|----------|------|--------|
| `bouncing_access` | JWT string | true | true | lax | / | 900 (15min) |
| `bouncing_refresh` | opaque token | true | true | lax | /auth/refresh | 604800 (7d) |

The refresh cookie's `path` is restricted to `/auth/refresh` so it's never sent on normal requests — only on explicit refresh calls. This limits exposure.

### Package Exports

```typescript
// @bouncing/next — server
export { createBouncing } from './server/config'
export { auth, currentUser } from './server/auth'
export type { Session, User } from './types'

// @bouncing/next/client — client components
export { useUser } from './client/use-user'
export { UserButton } from './client/user-button'
export { SignIn } from './client/sign-in'
export { BouncingProvider } from './client/provider'

// @bouncing/next/middleware — edge middleware
export { auth as middleware } from './middleware/auth'
```

## Config Parsing

`bouncing.yaml` → `internal/config/config.go`:

```go
type Config struct {
    Listen   string        `yaml:"listen"`
    BaseURL  string        `yaml:"base_url"`
    Store    StoreConfig   `yaml:"store"`
    Signing  SigningConfig `yaml:"signing"`
    Access   AccessConfig  `yaml:"access"`
    Auth     AuthConfig    `yaml:"auth"`
    Session  SessionConfig `yaml:"session"`
    RBAC     RBACConfig    `yaml:"rbac"`
    Legal    *LegalConfig  `yaml:"legal,omitempty"`
    I18n     I18nConfig    `yaml:"i18n"`
    Webhooks []WebhookConfig `yaml:"webhooks"`
    Directory *DirectoryConfig `yaml:"directory,omitempty"`
}

type AccessConfig struct {
    Mode           string   `yaml:"mode"`    // "open" | "domain-restricted" | "invite-only"
    AllowedDomains []string `yaml:"allowed_domains,omitempty"`
}

type AuthConfig struct {
    Methods AuthMethodsConfig `yaml:"methods"`
}

type AuthMethodsConfig struct {
    OAuth    map[string]OAuthProviderConfig `yaml:"oauth"`
    Passkeys PasskeyConfig                  `yaml:"passkeys"`
}

type OAuthProviderConfig struct {
    ClientID     string `yaml:"client_id"`
    ClientSecret string `yaml:"client_secret"`
}

type PasskeyConfig struct {
    Enabled bool     `yaml:"enabled"`
    RPName  string   `yaml:"rp_name"`
    RPID    string   `yaml:"rp_id"`
    Origins []string `yaml:"origins"`
}

type SessionConfig struct {
    AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
    RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
}

type LegalConfig struct {
    Enabled       bool   `yaml:"enabled"`
    Version       string `yaml:"version"`        // e.g. "v1.0" — bump to force re-acceptance
    DocumentURL   string `yaml:"document_url"`   // linked in the agreement page
    DocumentLabel string `yaml:"document_label"` // "Terms of Service", "NDA", etc.
}

type I18nConfig struct {
    DefaultLocale string `yaml:"default_locale"` // BCP 47; defaults to "en"
}
```

## Build & Release

```makefile
# Makefile
.PHONY: build test lint release

build:
	go build -o bin/bouncing ./cmd/bouncing

test:
	go test ./...

test-integration:
	go test -tags integration ./...

lint:
	golangci-lint run
	cd sdk/js && pnpm lint

release:
	goreleaser release --clean
```

**goreleaser.yaml** builds for: linux/amd64, linux/arm64 (Hetzner CAX), darwin/amd64, darwin/arm64.
Docker multi-arch image: `ghcr.io/bouncing-auth/bouncing`.

## CI Workflow (`.github/workflows/ci.yml`)

On PR:
1. `golangci-lint`
2. `go test ./...`
3. `go test -tags integration ./...` (against in-memory SQLite)
4. `cd sdk/js && pnpm install && pnpm lint && pnpm test`
5. `govulncheck ./...`

On tag push (`v*`):
1. All CI checks
2. goreleaser → GitHub Release with binaries
3. Docker build + push to ghcr.io
4. `cd sdk/js && pnpm publish` (to npm)

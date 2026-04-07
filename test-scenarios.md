# test-scenarios.md — Bouncing

This document defines concrete test scenarios for validating Bouncing. Each scenario describes the preconditions, steps, and expected outcomes. These map directly to Go integration tests (`_integration_test.go`) and SDK tests.

All test scenarios are tracked as GitHub issues with label `type/test` and linked to the appropriate milestone.

---

## 1. Server Core

### 1.1 Config Loading

| ID | Scenario | Expected |
|----|----------|----------|
| CFG-01 | Load valid `bouncing.yaml` with all fields | Config struct populated, no error |
| CFG-02 | Load minimal config (only listen + base_url + one OAuth provider) | Defaults applied: access.mode=open, session TTLs default, passkeys disabled |
| CFG-03 | Missing required field (no base_url) | Startup fails with clear error message |
| CFG-04 | Invalid access mode ("closed") | Startup fails: `invalid access mode "closed", must be open|domain-restricted|invite-only` |
| CFG-05 | `bouncing init` interactive command | Generates valid `bouncing.yaml` with prompts for base_url, OAuth provider |

### 1.2 Key Management

| ID | Scenario | Expected |
|----|----------|----------|
| KEY-01 | First startup, no keys directory | Ed25519 keypair generated, saved to `data/keys/`, kid includes date |
| KEY-02 | Startup with existing keys | Keys loaded from disk, no regeneration |
| KEY-03 | JWKS endpoint returns correct public key | `GET /.well-known/jwks.json` returns JWK with `kty=OKP`, `crv=Ed25519`, `use=sig`, correct `kid` |
| KEY-04 | JWKS response is cacheable | `Cache-Control: public, max-age=3600` header present |

### 1.3 Database Migrations

| ID | Scenario | Expected |
|----|----------|----------|
| MIG-01 | Fresh SQLite database | All tables created, schema matches spec |
| MIG-02 | Idempotent migration | Running migrate twice produces no errors, no duplicate tables |
| MIG-03 | Migration version tracking | `schema_version` table tracks applied migrations |

---

## 2. OAuth Flow

### 2.1 Google OAuth — Happy Path (Open Mode)

```
Preconditions:
  - bouncing.yaml: access.mode=open, oauth.google configured
  - No users in database

Steps:
  1. GET /auth/oauth/google
  2. Verify 302 redirect to accounts.google.com with correct client_id, redirect_uri, scope, state
  3. Verify state cookie set (httpOnly, secure)
  4. Simulate callback: GET /auth/oauth/google/callback?code=MOCK_CODE&state=VALID_STATE
  5. Server exchanges code for token, fetches userinfo

Expected:
  - New user created: email from Google, status=active, auth_method=oauth:google
  - OAuth connection record created
  - bouncing_access cookie set (valid JWT, 15min TTL)
  - bouncing_refresh cookie set (path=/auth/refresh, 7d TTL)
  - JWT contains: sub=user_id, email, roles=[], permissions=[]
  - 302 redirect to configured redirect_url
  - user.created webhook fired
```

### 2.2 Google OAuth — Domain Restricted

```
Preconditions:
  - access.mode=domain-restricted
  - allowed_domains: ["@enso.co", "@playgroundlogic.co"]

Steps:
  1. Complete OAuth flow with user email scott@enso.co

Expected:
  - User created, tokens issued, success

Steps:
  2. Complete OAuth flow with user email random@gmail.com

Expected:
  - No user created
  - 302 redirect to error_url with ?error=not_on_the_list
  - user.login.denied webhook fired with reason "domain_mismatch"
```

### 2.3 Google OAuth — Invite Only

```
Preconditions:
  - access.mode=invite-only
  - User pre-provisioned: scott@enso.co (status=pending, role=admin)

Steps:
  1. Complete OAuth flow with email scott@enso.co

Expected:
  - Existing user record updated: status=pending→active, auth_method=oauth:google
  - OAuth connection linked to existing user
  - JWT roles=["admin"], permissions=["*"]
  - user.login webhook fired (not user.created — user already existed)

Steps:
  2. Complete OAuth flow with email unknown@enso.co (not pre-provisioned)

Expected:
  - No user created
  - 302 redirect to error_url with ?error=not_on_the_list
  - user.login.denied webhook fired with reason "not_invited"
```

### 2.4 OAuth — Returning User

```
Preconditions:
  - User scott@enso.co already exists (status=active)
  - Has OAuth connection for Google

Steps:
  1. Complete OAuth flow with email scott@enso.co

Expected:
  - No new user created
  - last_login updated
  - Fresh tokens issued
  - user.login webhook fired
```

### 2.5 OAuth — CSRF Validation

```
Steps:
  1. GET /auth/oauth/google/callback?code=VALID&state=TAMPERED_STATE

Expected:
  - 403 error
  - No user created, no tokens issued
```

---

## 3. WebAuthn (Passkey) Flow

### 3.1 Passkey Registration

```
Preconditions:
  - User scott@enso.co exists (authenticated via OAuth)
  - No passkey credentials yet

Steps:
  1. POST /auth/webauthn/register/begin { user_id: "01HXYZ" }

Expected:
  - 200 with CredentialCreation options
  - options.publicKey.rp.id matches config
  - options.publicKey.user.id matches user ID
  - options.publicKey.pubKeyCredParams includes EdDSA (-8) and ES256 (-7)
  - options.publicKey.attestation = "none"
  - options.publicKey.authenticatorSelection.residentKey = "preferred"

Steps:
  2. POST /auth/webauthn/register/finish { attestationResponse }
     (simulated using go-webauthn test helpers or virtual authenticator)

Expected:
  - 201 with credential_id
  - WebAuthn credential record created in store
  - public_key stored, sign_count=0
```

### 3.2 Passkey Login (Discoverable)

```
Preconditions:
  - User exists with registered passkey

Steps:
  1. POST /auth/webauthn/login/begin { }

Expected:
  - 200 with CredentialAssertion options
  - No allowCredentials (discoverable mode)
  - Challenge is cryptographically random

Steps:
  2. POST /auth/webauthn/login/finish { assertionResponse }
     (simulated with matching credential)

Expected:
  - 200 with user info + tokens
  - JWT contains correct sub, email, roles, permissions
  - sign_count incremented in store
  - bouncing_access and bouncing_refresh cookies set
  - user.login webhook fired
```

### 3.3 Passkey — Cloned Authenticator Detection

```
Preconditions:
  - User has passkey with sign_count=10

Steps:
  1. Login with assertion where sign_count=5 (lower than stored)

Expected:
  - Authentication rejected (potential cloned authenticator)
  - Error response, no tokens issued
```

### 3.4 Passkey — Session Data Expiry

```
Steps:
  1. POST /auth/webauthn/login/begin → get challenge
  2. Wait >5 minutes
  3. POST /auth/webauthn/login/finish with valid assertion

Expected:
  - Error: session expired
  - Must restart the ceremony
```

---

## 4. Session Management

### 4.1 Access Token Verification

```
Steps:
  1. Issue JWT for user with roles=["editor"], permissions=["content:read", "content:write"]
  2. Verify JWT with public key from JWKS

Expected:
  - Token verifies successfully
  - Claims extracted correctly
  - Token expires after 15 minutes
```

### 4.2 Refresh Token Rotation

```
Steps:
  1. Login → receive access_token_1 + refresh_token_1
  2. POST /auth/refresh { refresh_token: refresh_token_1 }

Expected:
  - 200 with access_token_2 + refresh_token_2
  - refresh_token_1 is invalidated in store
  - Using refresh_token_1 again returns 401
```

### 4.3 Refresh Token Replay Detection

```
Steps:
  1. Login → refresh_token_1
  2. Refresh → refresh_token_2 (refresh_token_1 invalidated)
  3. Attempt refresh with refresh_token_1 (replayed)

Expected:
  - 401 error
  - ALL refresh tokens for this user are invalidated (token family revocation)
  - User must re-authenticate
```

### 4.4 Logout

```
Steps:
  1. POST /auth/logout (with valid refresh token cookie)

Expected:
  - Refresh token deleted from store
  - bouncing_access cookie cleared
  - bouncing_refresh cookie cleared
  - 302 redirect to configured logout URL
```

---

## 5. RBAC

### 5.1 Role-Based Access

```
Preconditions:
  - Role "prompt-editor" with permissions: ["prompts:read", "prompts:write"]
  - User scott@enso.co has role "prompt-editor"

Steps:
  1. Authenticate user
  2. Check JWT claims

Expected:
  - roles: ["prompt-editor"]
  - permissions: ["prompts:read", "prompts:write"]
```

### 5.2 Permission Check

```
Steps:
  1. HasPermission(session, "prompts:write") → true
  2. HasPermission(session, "admin:delete") → false
  3. User with role "admin" (permissions: ["*"]) → HasPermission(session, "anything") → true
```

### 5.3 Multiple Roles

```
Preconditions:
  - User has roles: ["editor", "reviewer"]
  - editor permissions: ["content:read", "content:write"]
  - reviewer permissions: ["content:read", "content:review"]

Expected JWT:
  - roles: ["editor", "reviewer"]
  - permissions: ["content:read", "content:write", "content:review"] (deduplicated, sorted)
```

---

## 6. Access Control

### 6.1 Open Mode

```
Config: access.mode=open

Expected:
  - Any email can sign up via OAuth
  - Any email can register a passkey (after initial OAuth)
```

### 6.2 Domain-Restricted Mode

```
Config: access.mode=domain-restricted, allowed_domains=["@enso.co"]

Expected:
  - scott@enso.co → allowed
  - scott@gmail.com → rejected with "not_on_the_list"
  - SCOTT@ENSO.CO → allowed (case-insensitive)
  - scott@sub.enso.co → rejected (exact domain match only)
```

### 6.3 Invite-Only Mode

```
Config: access.mode=invite-only

Steps:
  1. No users pre-provisioned → OAuth login with any email → rejected
  2. Admin runs: bouncing users add scott@enso.co --role admin
  3. OAuth login with scott@enso.co → success, user activated
  4. OAuth login with maya@enso.co (not invited) → rejected
```

---

## 7. Management API

### 7.1 Authentication

```
Steps:
  1. GET /manage/users without Authorization header → 401
  2. GET /manage/users with Authorization: Bearer invalid_key → 401
  3. GET /manage/users with Authorization: Bearer bnc_api_VALID → 200
```

### 7.2 User CRUD

```
Steps:
  1. POST /manage/users/invite { email: "test@enso.co", role: "viewer" }
     → 201, user created with status=pending
  2. GET /manage/users → list includes new user
  3. GET /manage/users/01HXYZ → user detail
  4. POST /manage/users/01HXYZ/roles { role: "editor" }
     → role assigned, user.role.assigned webhook fired
  5. DELETE /manage/users/01HXYZ
     → user deleted, refresh tokens revoked, user.deleted webhook fired
  6. GET /manage/users/01HXYZ → 404
```

### 7.3 Bulk Import

```
Steps:
  1. POST /manage/users/import with 3 users
     → 200, created=3
  2. POST /manage/users/import with 2 new + 1 duplicate email
     → 200, created=2, skipped=1
  3. POST /manage/users/import with invalid email format
     → 200, created=0, errors=[{ email: "bad", reason: "invalid email format" }]
```

---

## 8. CLI

### 8.1 User Management

```
$ bouncing users add scott@enso.co --role admin
✓ User scott@enso.co created (pending, role: admin)

$ bouncing users list
ID          EMAIL              STATUS   ROLES    LAST LOGIN
01HXYZ...   scott@enso.co     pending  admin    -

$ bouncing users remove scott@enso.co
✓ User scott@enso.co removed (0 sessions revoked)
```

### 8.2 Bulk Import

```
$ cat team.csv
email,role
scott@enso.co,admin
maya@enso.co,editor

$ bouncing users import team.csv
✓ Imported 2 users (0 skipped, 0 errors)
```

### 8.3 Server

```
$ bouncing serve
INFO bouncing listening addr=:3117 access_mode=invite-only
INFO keys loaded kid=bouncing-2026-04
INFO oauth providers google github
INFO passkeys enabled rp_id=myapp.com
INFO store connected driver=sqlite path=./data/bouncing.db
```

### 8.4 Version

```
$ bouncing version
bouncing v0.1.0 (abc1234) built 2026-04-07T12:00:00Z go1.26.1
```

---

## 9. Webhooks

### 9.1 Delivery

```
Preconditions:
  - Webhook configured: url=https://myapp.com/webhooks, events=["user.created"], secret=SECRET

Steps:
  1. New user registers

Expected:
  - POST to https://myapp.com/webhooks
  - Headers: X-Bouncing-Event: user.created, X-Bouncing-Signature: sha256=HMAC
  - Body:
    {
      "event": "user.created",
      "timestamp": "2026-04-07T12:00:00Z",
      "data": {
        "user_id": "01HXYZ...",
        "email": "scott@enso.co",
        "auth_method": "oauth:google"
      }
    }
  - Signature verifiable: HMAC-SHA256(body, SECRET)
```

### 9.2 Retry

```
Steps:
  1. Webhook endpoint returns 500
  2. Bouncing retries: 1s, 5s, 30s (3 retries total)
  3. All retries fail → event logged, no further retries
```

---

## 10. SDK (@bouncing/next)

### 10.1 Middleware Protection

```typescript
// middleware.ts
export { auth as middleware } from '@/bouncing.config'

Test:
  1. Request to /dashboard without cookies → 302 redirect to /auth/login
  2. Request to /dashboard with valid bouncing_access cookie → request passes through
  3. Request to /dashboard with expired access token but valid refresh → auto-refresh, request succeeds
  4. Request to /dashboard with expired access + expired refresh → 302 redirect to /auth/login
```

### 10.2 Server Component: auth()

```typescript
// In server component
const session = await auth()

Test:
  1. Valid cookie → session = { userId, email, roles, permissions }
  2. No cookie → session = null
  3. Expired + refreshable → session returned after transparent refresh
```

### 10.3 Server Component: currentUser()

```typescript
const user = await currentUser()

Test:
  1. Valid session → user = { id, email, name, avatarUrl, roles }
  2. No session → user = null
```

### 10.4 Client Component: useUser()

```typescript
const { user, isLoaded, isSignedIn } = useUser()

Test:
  1. Before hydration → isLoaded=false
  2. After hydration, signed in → isLoaded=true, isSignedIn=true, user populated
  3. After hydration, not signed in → isLoaded=true, isSignedIn=false, user=null
```

### 10.5 Management API Client

```typescript
const users = await bouncingAdmin.users.list()
await bouncingAdmin.users.assignRole(userId, 'editor')

Test:
  1. List users → returns array of User objects
  2. Assign role → role appears in user's JWT on next refresh
  3. Invalid API key → throws BouncingError with code "unauthorized"
```

---

## 11. Integration / End-to-End

### 11.1 Full Lifecycle: Invite → OAuth → Passkey → RBAC → Offboard

```
1. Admin: bouncing users add scott@enso.co --role admin
2. Scott: OAuth login with Google → user activated, JWT has roles=["admin"]
3. Scott: Register passkey via /auth/webauthn/register/*
4. Scott: Logout
5. Scott: Login with passkey via /auth/webauthn/login/* → JWT has roles=["admin"]
6. Admin: POST /manage/users/{id}/roles { role: "viewer" } (change role)
7. Scott: Refresh token → new JWT has roles=["viewer"] (not admin)
8. Admin: DELETE /manage/users/{id}
9. Scott: Next request fails with expired token, refresh fails → signed out
10. Verify: user.deleted webhook fired, all refresh tokens gone from store
```

### 11.2 Multi-Provider Auth

```
1. Scott registers via Google OAuth
2. Scott adds a passkey
3. Scott logs out
4. Scott logs in via passkey → same user, same roles
5. Verify: single user record, one OAuth connection, one WebAuthn credential
```

### 11.3 Concurrent Sessions

```
1. Scott logs in on Desktop Chrome → access_token_1 + refresh_token_1
2. Scott logs in on Mobile Safari → access_token_2 + refresh_token_2
3. Both sessions valid simultaneously
4. Admin removes Scott → both refresh tokens revoked
5. Both sessions expire within 15 minutes (access token TTL)
```

---

## 12. Legal Gate (TOS / NDA)

### 12.1 First Login — Agreement Required

```
Preconditions:
  - legal.enabled=true, legal.version="v1.0"
  - legal.document_url="https://myapp.com/terms"
  - User has no tos_acceptances record

Steps:
  1. Complete OAuth flow with scott@enso.co

Expected:
  - bouncing_pending cookie set (signed, 10min TTL)
  - 302 redirect to /auth/agree (NOT to redirect_url)
  - No access/refresh tokens issued yet

Steps:
  2. GET /auth/agree

Expected:
  - 200 page rendered
  - Contains link to document_url
  - Contains name input field, read-only date field, checkbox

Steps:
  3. POST /auth/agree { name: "Scott Freeman", agreed: true }

Expected:
  - tos_acceptances record created: user_id, version="v1.0", name_typed="Scott Freeman", accepted_at, ip_address
  - bouncing_pending cookie cleared
  - bouncing_access + bouncing_refresh cookies set
  - 302 redirect to configured redirect_url
  - user.tos.accepted webhook fired
```

### 12.2 Returning User — Already Accepted

```
Preconditions:
  - legal.enabled=true, legal.version="v1.0"
  - User scott@enso.co has tos_acceptances record for version="v1.0"

Steps:
  1. Complete OAuth flow with scott@enso.co

Expected:
  - No redirect to /auth/agree
  - Tokens issued normally
  - 302 redirect to redirect_url
```

### 12.3 Version Bump — Re-acceptance Required

```
Preconditions:
  - User has accepted version="v1.0"
  - Config updated to legal.version="v2.0"

Steps:
  1. User logs in

Expected:
  - Redirected to /auth/agree (no v2.0 acceptance record)
  - After acceptance: new tos_acceptances record for version="v2.0"
  - Original v1.0 record untouched (immutable)
```

### 12.4 Tampered Pending Cookie

```
Steps:
  1. POST /auth/agree with forged/expired bouncing_pending cookie

Expected:
  - 400/403 error
  - No acceptance record created, no tokens issued
```

### 12.5 Acceptance Records Survive Offboard

```
Steps:
  1. User accepts TOS → tos_acceptances record created
  2. Admin: DELETE /manage/users/{id}
  3. Inspect tos_acceptances table

Expected:
  - tos_acceptances record is retained (legal audit trail)
  - User record deleted, but acceptance records preserved
```

### 12.6 Management API — List Agreements

```
Steps:
  1. GET /manage/users/{id}/agreements

Expected:
  - 200 with array of acceptance records
  - Each record: id, version, name_typed, accepted_at, ip_address
```

### 12.7 Legal Gate Disabled

```
Preconditions:
  - legal config absent (default)

Steps:
  1. Complete OAuth flow

Expected:
  - No redirect to /auth/agree
  - Tokens issued normally (same behavior as before)
```

---

## 13. Internationalization (i18n)

### 13.1 Default Locale (English)

```
Steps:
  1. GET /auth/agree (no Accept-Language header)

Expected:
  - Page rendered in English
  - Error messages from /auth/agree POST in English
```

### 13.2 Accept-Language Header

| ID | Accept-Language | Expected locale |
|----|-----------------|-----------------|
| I18N-01 | `fr` | French |
| I18N-02 | `de-AT` | German (`de` matched) |
| I18N-03 | `ja` | Japanese |
| I18N-04 | `zh-Hans-CN` | Simplified Chinese (`zh-Hans` matched) |
| I18N-05 | `pt-BR` | Portuguese (`pt` matched) |
| I18N-06 | `ar` (unsupported) | Falls back to `en` |
| I18N-07 | `fr;q=0.9,de;q=0.8` | French (highest q-value wins) |

### 13.3 Error Response Messages Are Localized

```
Steps:
  1. GET /auth/oauth/google/callback with invalid state
     Accept-Language: fr

Expected:
  - Response JSON: { "error": { "code": "invalid_state", "message": "..." } }
  - "code" is always "invalid_state" (stable, English, unchanged)
  - "message" is in French
```

### 13.4 Config Default Locale

```
Preconditions:
  - bouncing.yaml: i18n.default_locale: "es"

Steps:
  1. GET /auth/agree (no Accept-Language header)

Expected:
  - Page rendered in Spanish
```

### 13.5 SDK Locale Prop

```typescript
// Test: explicit locale prop overrides Accept-Language
<SignIn locale="de" />

Expected:
  - All UI strings rendered in German
  - No Accept-Language header needed
```

### 13.6 Custom String Overrides

```typescript
const bouncing = createBouncing({
  domain: '...',
  clientId: '...',
  localization: {
    signIn: { title: "Welcome to Acme Corp" },
  },
})

Expected:
  - <SignIn /> renders "Welcome to Acme Corp" as title
  - All other strings use default locale
```

### 13.7 Locale Fallback Chain

```
Steps:
  1. Accept-Language: zh-TW (Traditional Chinese, not bundled)

Expected:
  - Falls back to default_locale (e.g. "en"), not a 500 error
```

---

## Running Tests

```bash
# Unit tests (fast, no external deps)
go test ./...

# Integration tests (against in-memory SQLite)
go test -tags integration ./...

# SDK tests
cd sdk/js && pnpm test

# Full end-to-end (requires running Bouncing server)
go test -tags e2e ./test/e2e/...
```

Tests use Go's built-in testing package. No testify, no gomega. Table-driven tests preferred. `t.Helper()` in all test helpers. `t.Parallel()` where safe.

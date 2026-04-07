# Bouncing — Auth that scales down

**Domain:** bounc.ing
**Tagline:** "No guest list, no entry."
**License:** Apache 2.0 (core binary + SDKs)

---

## Problem

Every auth solution is either:
- Beautiful DX but expensive and tier-gated (Clerk, Auth0)
- Open-source but needs a separate always-on backend + database (SuperTokens)
- Enterprise-grade and overbuilt (Keycloak, Ory)

Nobody's built auth for the 1–50 user app. The internal tool. The side project that might grow. The indie SaaS that shouldn't pay $225/mo for basic RBAC.

## Product Principles

1. **Everything, for everyone.** No feature tiers. Self-hosted and managed get identical capabilities.
2. **Zero infrastructure by default.** OAuth + passkeys mean no password storage, no email sending, no TOTP secrets. Ever. It's 2026. Bouncing doesn't do passwords — and neither should you.
3. **One number pricing.** Free under 100 MAU. $1/mo per 100 MAU after that. Done.
4. **SDK-first.** The DX is the product. If `npm install @bouncing/next` + 3 lines of code doesn't get you to "protected app," we failed.

---

## Authentication Methods

### 1. OAuth Social Login
- Google, GitHub, Microsoft, Apple
- Covers 95%+ of real-world use cases
- We proxy the OAuth flow — providers do the heavy lifting
- **Domain-restricted signup**: e.g., only `@enso.co` and `@playgroundlogic.co` (extremely common pattern for internal tools)

### 2. Passkeys (WebAuthn/FIDO2)
- Browser-native, phishing-resistant, no shared secrets
- We store public keys only — no password hashing, no breach liability
- Registration: browser creates keypair → we store public key + credential ID
- Authentication: we send a challenge → browser signs it → we verify
- Resident keys supported (usernameless login)
- Platform authenticators (Touch ID, Face ID, Windows Hello) + roaming (YubiKey)
- **This is the passwordless future and we ship it day one, not as a premium add-on**

**That's it. Two auth methods. Both passwordless. Both delegate credential storage to someone else (the browser or the identity provider). Bouncing never stores a password, never sends an email, never manages SMTP. There is nothing to breach.**

---

## Architecture

### Core: Single Go Binary

```
bouncing
├── cmd/bouncing/         # CLI entrypoint
├── internal/
│   ├── authn/            # Authentication flows
│   │   ├── oauth/        # OAuth 2.0 / OIDC proxy
│   │   └── webauthn/     # Passkey registration + assertion
│   ├── authz/            # Authorization / RBAC engine
│   │   ├── roles.go      # Role definitions + assignment
│   │   ├── permissions.go # Permission checks
│   │   └── policy.go     # Domain restriction, org scoping
│   ├── session/          # JWT issuance + verification
│   │   ├── jwt.go        # Ed25519-signed JWTs
│   │   ├── refresh.go    # Refresh token rotation
│   │   └── keys.go       # Key management (rotation, JWKS endpoint)
│   ├── store/            # Storage abstraction
│   │   ├── sqlite.go     # Local SQLite (self-hosted default)
│   │   ├── turso.go      # Turso/libSQL (managed tier)
│   │   └── schema.go     # Migrations
│   ├── tenant/           # Multi-tenancy namespace layer
│   ├── mgmt/             # Management API
│   │   ├── users.go      # List, invite, remove users
│   │   ├── roles.go      # Create, assign, revoke roles
│   │   └── orgs.go       # Organization CRUD
│   ├── hooks/            # Webhook event dispatch
│   ├── billing/          # Stripe integration (managed tier only)
│   └── server/           # HTTP server, middleware, routing
├── sdk/
│   ├── js/               # Core JS/TS client
│   ├── next/             # Next.js App Router SDK (@bouncing/next)
│   ├── react/            # React components (@bouncing/react)
│   └── go/               # Go client SDK
└── ui/
    ├── signin/           # Pre-built <SignIn /> component
    ├── userbutton/       # Pre-built <UserButton /> component
    └── manage/           # Embeddable user management panel
```

### Stateless Edge Design

- **Sessions are JWTs** signed with Ed25519. No server-side session store.
- JWT contains: `sub` (user ID), `email`, `roles[]`, `permissions[]`, `org_id` (if applicable), `exp`, `iat`.
- Short-lived access tokens (15 min) + longer refresh tokens (7 days, rotated on use).
- JWKS endpoint at `/.well-known/jwks.json` for external verification.
- **Consequence:** Auth verification is a local operation in the SDK. No network call to Bouncing on every request.

### Storage

| Deployment     | Backend         | Cost           |
|---------------|-----------------|----------------|
| Self-hosted   | SQLite file      | $0             |
| Managed       | Turso (per-tenant DB) | ~$0 at low scale |

Schema (simplified):

```sql
-- users
CREATE TABLE users (
    id          TEXT PRIMARY KEY,  -- ULID
    email       TEXT UNIQUE NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',  -- 'pending' (pre-provisioned) | 'active' (has authenticated)
    auth_method TEXT,              -- 'oauth:google', 'oauth:github', 'passkey' (NULL until first login)
    created_at  INTEGER NOT NULL,
    last_login  INTEGER
);

-- passkey credentials
CREATE TABLE webauthn_credentials (
    id              TEXT PRIMARY KEY,  -- credential ID (base64url)
    user_id         TEXT NOT NULL REFERENCES users(id),
    public_key      BLOB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT,              -- JSON array: ["internal", "usb", "ble", "nfc"]
    created_at      INTEGER NOT NULL,
    last_used       INTEGER
);

-- oauth connections
CREATE TABLE oauth_connections (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    provider    TEXT NOT NULL,         -- 'google', 'github', 'microsoft', 'apple'
    provider_id TEXT NOT NULL,
    email       TEXT NOT NULL,
    UNIQUE(provider, provider_id)
);

-- roles
CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,  -- 'admin', 'prompt-editor', 'viewer'
    permissions TEXT NOT NULL           -- JSON array: ["prompts:write", "prompts:read"]
);

-- user ↔ role mapping
CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    org_id  TEXT,                       -- NULL = global, else scoped to org
    PRIMARY KEY (user_id, role_id, org_id)
);

-- organizations (optional multi-tenancy)
CREATE TABLE orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    created_at  INTEGER NOT NULL
);

-- org membership
CREATE TABLE org_members (
    org_id  TEXT NOT NULL REFERENCES orgs(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    PRIMARY KEY (org_id, user_id)
);

-- refresh tokens
CREATE TABLE refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

-- domain restrictions (domain-restricted mode)
CREATE TABLE allowed_domains (
    domain TEXT PRIMARY KEY           -- '@enso.co', '@playgroundlogic.co'
);

-- directory sync state (v0.2+)
CREATE TABLE directory_sync (
    id              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,    -- 'google-workspace', 'okta', 'azure-ad'
    domain          TEXT NOT NULL,
    last_sync       INTEGER,
    last_sync_hash  TEXT,             -- hash of directory state for diffing
    status          TEXT NOT NULL DEFAULT 'idle'  -- 'idle', 'syncing', 'error'
);

-- webhook subscriptions
CREATE TABLE webhooks (
    id      TEXT PRIMARY KEY,
    url     TEXT NOT NULL,
    events  TEXT NOT NULL,             -- JSON array: ["user.created", "user.deleted"]
    secret  TEXT NOT NULL              -- HMAC signing secret
);

-- TOS / NDA acceptances (optional legal gate)
CREATE TABLE tos_acceptances (
    id          TEXT PRIMARY KEY,      -- ULID
    user_id     TEXT NOT NULL REFERENCES users(id),
    version     TEXT NOT NULL,         -- matches legal.version in config (e.g. "v1.0")
    name_typed  TEXT NOT NULL,         -- full name as typed by user
    accepted_at INTEGER NOT NULL,      -- unix timestamp
    ip_address  TEXT                   -- for audit purposes
);
```

### API Surface

All endpoints under `/api/v1/` (public) and `/api/v1/manage/` (management, API-key authenticated).

**Auth Flows:**
```
GET   /auth/login                    # Redirect to configured auth method(s)
GET   /auth/oauth/:provider          # Initiate OAuth flow
GET   /auth/oauth/:provider/callback # OAuth callback
POST  /auth/webauthn/register/begin  # Start passkey registration
POST  /auth/webauthn/register/finish # Complete passkey registration
POST  /auth/webauthn/login/begin     # Start passkey authentication
POST  /auth/webauthn/login/finish    # Complete passkey authentication
POST  /auth/refresh                  # Rotate refresh token, get new access token
POST  /auth/logout                   # Revoke refresh token → stop.bounc.ing 😎
GET   /auth/agree                    # Show TOS/NDA agreement page (if legal gate enabled)
POST  /auth/agree                    # Record acceptance, complete login flow
```

**Session / Identity:**
```
GET   /auth/me                       # Current user + roles + permissions
GET   /auth/jwks                     # JWKS public keys (also at /.well-known/jwks.json)
```

**Management API (API-key required):**
```
GET    /manage/users                 # List users (paginated, filterable)
GET    /manage/users/:id             # Get user detail
DELETE /manage/users/:id             # Remove user
PATCH  /manage/users/:id             # Update user metadata
POST   /manage/users/:id/roles       # Assign role
DELETE /manage/users/:id/roles/:rid  # Revoke role
GET    /manage/roles                 # List roles
POST   /manage/roles                 # Create role
PATCH  /manage/roles/:id             # Update role permissions
DELETE /manage/roles/:id             # Delete role
GET    /manage/orgs                  # List organizations
POST   /manage/orgs                  # Create organization
POST   /manage/orgs/:id/members      # Add member to org
DELETE /manage/orgs/:id/members/:uid # Remove member from org
POST   /manage/users/invite          # Pre-provision a user by email + role
POST   /manage/users/import          # Bulk import from JSON array
POST   /manage/directory/sync        # Trigger directory sync manually
GET    /manage/users/:id/agreements  # List TOS acceptance records for a user
```

**SCIM Endpoints (v0.3+):**
```
POST   /scim/v2/Users               # Create user (from IdP)
GET    /scim/v2/Users/:id            # Get user
PATCH  /scim/v2/Users/:id            # Update user
DELETE /scim/v2/Users/:id            # Deprovision user
GET    /scim/v2/Groups               # List groups/roles
```

**Webhook Events:**
```
user.created        # New user registered or pre-provisioned
user.deleted        # User removed / offboarded
user.invited        # User pre-provisioned, awaiting first login
user.login          # Successful authentication
user.login.denied   # Rejected — not on the list (invite-only / domain mismatch)
user.role.assigned  # Role granted
user.role.revoked   # Role removed
user.tos.accepted   # User accepted TOS/NDA (includes version, name_typed)
org.created         # New organization
org.member.added    # User added to org
org.member.removed  # User removed from org
directory.synced    # Directory sync completed
```

---

## Access Control & User Provisioning

### Access Modes

Three modes, one config line. This determines who can authenticate:

**Open** — anyone can sign up via OAuth or passkey. Consumer SaaS default.

**Domain-restricted** — only emails matching `allowed_domains` can sign up. Self-registration is allowed but filtered. The most common pattern for company tools that don't want to manually manage every user.

**Invite-only** — no self-registration. An admin explicitly pre-provisions users via CLI, management API, or directory sync. Anyone not on the list gets "You're not on the list" — very on brand. This is the killer feature for small teams. Clerk doesn't make this easy. Bouncing makes it a one-line config.

```yaml
access:
  mode: invite-only  # open | domain-restricted | invite-only
```

### CLI Provisioning

```bash
# Add a single user (pre-provisioned, awaiting first login)
bouncing users add scott@enso.co --role admin

# Bulk seed from a CSV
bouncing users import team.csv

# team.csv format:
# email,role
# scott@enso.co,admin
# maya@enso.co,editor
# newperson@enso.co,viewer

# Offboard — revokes all sessions immediately, removes user, fires webhook
bouncing users remove former-employee@enso.co

# List all users
bouncing users list

# Sync directory manually
bouncing directory sync
```

Pre-provisioned users don't create a password or do anything. The admin adds them, and the user record is created in a `pending` state. First time they hit the login page, they authenticate via OAuth or register a passkey, and the existing record links to their identity. Zero friction onboarding.

Offboarding via `bouncing users remove` does three things atomically:
1. Invalidates all refresh tokens (existing sessions expire within 15 min)
2. Removes the user record and all associated credentials
3. Fires `user.deleted` webhook so the app can clean up app-side data

### Directory Sync

For teams that manage users in Google Workspace, Okta, or Azure AD — Bouncing can sync users automatically so onboarding/offboarding happens in one place.

**Level 1 — Manual + CLI (v0.1):**
Export your directory, run `bouncing users import`. Good enough for teams under 50 who change rarely.

**Level 2 — Google Workspace Sync (v0.2):**
A scheduled job calls the Google Admin SDK Directory API, diffs against the Bouncing user list, and provisions/deprovisions accordingly. Run it hourly or daily.

```yaml
directory:
  provider: google-workspace
  domain: enso.co
  service_account: ./credentials.json
  sync_interval: 1h
  auto_deprovision: true    # remove users no longer in directory
  default_role: viewer
  role_mapping:
    "Admin": admin
    "Engineering": editor
```

When someone gets removed from your Google Workspace, they get removed from Bouncing on the next sync. Offboarding handled. When someone joins, they're pre-provisioned with the appropriate role. Onboarding handled.

**Level 3 — SCIM (v0.3+):**
The enterprise standard. Okta, Azure AD, and Google Workspace all push user changes to a SCIM endpoint in real time. No polling, no sync interval — changes propagate immediately.

This is the feature that unlocks selling to companies with 100+ people who run Okta or Azure AD. Clerk and Auth0 charge enterprise pricing for this. Bouncing includes it for everyone.

### Legal Agreements (TOS / NDA Gate)

Optional. Disabled by default. When enabled, first-time users must read and explicitly accept a terms of service or NDA before tokens are issued. Returning users re-accept only when the configured version changes.

```yaml
legal:
  enabled: true
  version: "v1.0"                      # bump to force re-acceptance by all users
  document_url: "https://myapp.com/terms"  # linked in the agreement UI
  document_label: "Terms of Service"   # what to call it ("NDA", "Terms of Service", etc.)
```

**Flow:**

After a successful OAuth callback or passkey login finish, Bouncing checks whether the authenticated user has accepted the current `legal.version`. If not:

1. A short-lived `bouncing_pending` cookie is set (signed, 10-minute TTL) containing the pending user ID and post-auth redirect destination.
2. The user is redirected to `GET /auth/agree` instead of receiving tokens.
3. The agreement page renders: a link to `document_url`, a typed-name field, a read-only date field, and an "I agree" checkbox.
4. On submit, `POST /auth/agree` validates the form, records the acceptance, clears the `bouncing_pending` cookie, issues tokens normally, and fires `user.tos.accepted`.

Returning users who have already accepted the current version see no agreement page — the check is a single indexed DB lookup and adds no perceptible latency.

**Acceptance record** — stored in `tos_acceptances`:

| Field | Value |
|-------|-------|
| `user_id` | ULID of the user |
| `version` | value of `legal.version` at time of acceptance |
| `name_typed` | full name as entered by the user |
| `accepted_at` | unix timestamp |
| `ip_address` | request IP (for audit trail) |

Retrievable via `GET /manage/users/:id/agreements`. Immutable — records are never deleted, even if the user is offboarded (for legal defensibility).

**Version bumping** — change `legal.version` in config (e.g. `"v1.0"` → `"v2.0"`) and restart. On next login, every user who lacks an acceptance record for `"v2.0"` is gated. No migration or backfill needed.

---

## SDK Design

### @bouncing/next (Next.js App Router — primary target)

**Setup:**
```ts
// bouncing.config.ts
import { createBouncing } from '@bouncing/next'

export const bouncing = createBouncing({
  domain: 'your-app.bounc.ing',  // or self-hosted URL
  clientId: 'bnc_...',
})
```

**Middleware (route protection):**
```ts
// middleware.ts
export { auth as middleware } from '@/bouncing.config'

export const config = {
  matcher: ['/((?!_next|favicon.ico|public).*)'],
}
```

**Server Components:**
```tsx
// app/dashboard/page.tsx
import { auth, currentUser } from '@/bouncing.config'

export default async function Dashboard() {
  const session = await auth()          // { userId, roles, permissions }
  const user = await currentUser()      // { id, email, name, avatarUrl, roles }

  return <h1>Hello {user.name}</h1>
}
```

**RBAC in Server Components:**
```tsx
import { auth } from '@/bouncing.config'

export default async function PromptsPage() {
  const session = await auth()

  if (!session.permissions.includes('prompts:write')) {
    redirect('/unauthorized')
  }

  return <PromptEditor />
}
```

**Client Components:**
```tsx
'use client'
import { useUser, UserButton, SignIn } from '@bouncing/next/client'

function Header() {
  const { user, isLoaded } = useUser()

  return (
    <header>
      <span>{user?.name}</span>
      <UserButton />
    </header>
  )
}
```

**Management API (server-side):**
```ts
// app/api/team/route.ts
import { bouncingAdmin } from '@/bouncing.config'

export async function GET() {
  const users = await bouncingAdmin.users.list()
  return Response.json(users)
}

export async function POST(req: Request) {
  const { userId, role } = await req.json()
  await bouncingAdmin.users.assignRole(userId, role)
  return Response.json({ ok: true })
}
```

### @bouncing/react (generic React SPA)

```tsx
import { BouncingProvider, useUser, UserButton, SignIn } from '@bouncing/react'

function App() {
  return (
    <BouncingProvider domain="your-app.bounc.ing" clientId="bnc_...">
      <Router />
    </BouncingProvider>
  )
}
```

### Go SDK

```go
import "bounc.ing/sdk/go/bouncing"

func main() {
    b := bouncing.New(bouncing.Config{
        Domain:   "your-app.bounc.ing",
        ClientID: "bnc_...",
    })

    // Middleware
    http.Handle("/", b.Protect(myHandler))

    // RBAC
    http.Handle("/admin", b.Require("admin")(adminHandler))

    // Management
    users, _ := b.Admin.ListUsers(ctx)
}
```

### Internationalization (i18n)

All user-visible strings in pre-built components and server-rendered error pages are fully localized from v0.1. Locale selection priority (highest wins):

1. Explicit `locale` prop on component / `createBouncing` config
2. `Accept-Language` request header (server-side components and middleware)
3. `navigator.language` (client-side components)
4. `i18n.default_locale` in `bouncing.yaml`
5. `"en"` hardcoded fallback

**Config:**
```yaml
i18n:
  default_locale: "en"              # BCP 47 language tag
```

**SDK — explicit locale:**
```ts
// bouncing.config.ts
export const bouncing = createBouncing({
  domain: 'your-app.bounc.ing',
  clientId: 'bnc_...',
  locale: 'fr',                     // optional override
})
```

```tsx
// or per-component
<SignIn locale="de" />
<UserButton locale="ja" />
```

**Custom string overrides** — replace any message without forking:
```ts
export const bouncing = createBouncing({
  domain: 'your-app.bounc.ing',
  clientId: 'bnc_...',
  localization: {
    signIn: {
      title: "Welcome to Acme",
      continueWithGoogle: "Sign in with Google",
    },
    legal: {
      agreementTitle: "Contractor NDA",
      agreementCheckbox: "I have read and agree to the NDA",
    },
  },
})
```

**Server-side error messages** — the `message` field in error responses is localized based on `Accept-Language`. The `code` field is always the stable English identifier and is never localized.

**Bundled locales (v0.1):** `en`, `es`, `fr`, `de`, `pt`, `ja`, `zh-Hans`. Additional locales accepted via community PRs. Translation files live at `sdk/js/packages/next/src/locales/*.json` (flat key-value JSON, no nested objects).

**Go binary** — server-rendered pages (the TOS/NDA agreement page, error pages) embed locale files via `//go:embed`. Strings live in `internal/i18n/`.

---

## Deployment

### Self-Hosted
```bash
# Install
curl -sSf https://get.bounc.ing | sh

# Configure
bouncing init                          # Interactive setup → bouncing.yaml
bouncing serve                         # Starts on :3117

# Or Docker
docker run -v ./data:/data -p 3117:3117 ghcr.io/bouncing/bouncing
```

**bouncing.yaml:**
```yaml
# bounc.ing configuration
listen: ":3117"
base_url: "https://auth.myapp.com"

store:
  driver: sqlite                       # sqlite | turso
  path: ./data/bouncing.db

signing:
  algorithm: ed25519
  # Auto-generates keys on first run, stores in ./data/keys/

access:
  mode: invite-only                    # open | domain-restricted | invite-only
  allowed_domains:                     # only used in domain-restricted mode
    - "@mycompany.com"

auth:
  methods:
    oauth:
      google:
        client_id: "..."
        client_secret: "..."
      github:
        client_id: "..."
        client_secret: "..."
    passkeys:
      enabled: true
      rp_name: "My App"
      rp_id: "myapp.com"
      origins:
        - "https://myapp.com"

session:
  access_token_ttl: 15m
  refresh_token_ttl: 168h             # 7 days

rbac:
  roles:
    admin:
      permissions: ["*"]
    editor:
      permissions: ["content:read", "content:write"]
    viewer:
      permissions: ["content:read"]

# Optional: TOS / NDA legal gate
# legal:
#   enabled: true
#   version: "v1.0"                    # bump to force re-acceptance
#   document_url: "https://myapp.com/terms"
#   document_label: "Terms of Service" # or "NDA", "Acceptable Use Policy", etc.

# Optional: i18n (default: "en")
# i18n:
#   default_locale: "en"

# Optional: Google Workspace directory sync (v0.2+)
# directory:
#   provider: google-workspace
#   domain: mycompany.com
#   service_account: ./credentials.json
#   sync_interval: 1h
#   auto_deprovision: true
#   default_role: viewer
#   role_mapping:
#     "Admin": admin
#     "Engineering": editor

webhooks: []
```

### Managed (bounc.ing)
1. Sign up at `start.bounc.ing`
2. Create app → get `clientId`
3. Configure OAuth providers in dashboard (`who.bounc.ing`)
4. `npm install @bouncing/next`
5. Done

---

## Infrastructure — The $50/mo "Never Goes Down" Architecture

Auth cannot go down. If Bouncing hiccups, every customer's login page breaks and credibility is gone forever. But the architecture has a built-in safety net: **SDKs cache JWKS public keys and verify JWTs locally.** If Bouncing disappears for 5 minutes, every already-logged-in user keeps working. Only new logins fail. That said — new logins can't fail either.

### Production Setup (Day One)

| Component | Provider | Monthly Cost |
|-----------|----------|-------------|
| 2× Hetzner CAX21 (4 ARM vCPU, 8GB) | Hetzner (Falkenstein + Ashburn) | **$16** |
| Database with edge replicas + backups | Turso Scaler | **$29** |
| TLS, DDoS, failover, JWKS edge cache | Cloudflare Tunnel (free tier) | **$0** |
| Uptime monitoring + status page | Betterstack / Openstatus (free tier) | **$0** |
| Domain | bounc.ing | **$13** ($160/yr) |
| **Total** | | **~$58/mo** |

Why Hetzner: German hosting company, around since 1997. ARM instances (CAX line) are dedicated vCPU — no noisy neighbors, no shared CPU throttling. Equivalent specs on DigitalOcean/Linode/Vultr: $48/server. Hetzner: $8/server. Same reliability, 6× cheaper.

### What This Gets You

- **Two-region automatic failover.** One server dies completely → Cloudflare Tunnel routes all traffic to the survivor. Zero intervention required.
- **Replicated database.** Turso replicates across edge locations. Daily backups. Point-in-time recovery.
- **JWKS cached at Cloudflare's edge.** The most-hit endpoint (`/.well-known/jwks.json`) is fully cacheable. Key fetches almost never reach origin.
- **Public status page from day one.** Trust signal for customers evaluating Bouncing.
- **DDoS protection.** Cloudflare handles it. Free.

### Deploy Pipeline

```bash
scp bouncing hetzner-1:/usr/local/bin/bouncing
scp bouncing hetzner-2:/usr/local/bin/bouncing
ssh hetzner-1 'systemctl restart bouncing'
ssh hetzner-2 'systemctl restart bouncing'
```

Four commands. That's production deployment until hundreds of customers. When it's time to get fancy, a GitHub Action does those four commands on a tagged release.

### Why This Is Enough For a Long Time

Auth traffic is bursty (login events), not sustained (every API call). A single Go binary on a CAX21 handles thousands of req/sec. Two servers is not about capacity — it's about redundancy. You won't need to scale compute until you're well past the point where revenue makes scaling trivial.

### Scaling Curve

| Phase | Customers | Monthly Infra | Revenue | Margin |
|-------|-----------|--------------|---------|--------|
| Launch | 0–30 | $58 | $0–150 | – |
| Traction | 30–100 | $58 (same) | $150–800 | 92% |
| Growth | 100–500 | $100 (add region) | $800–4,000 | 97% |
| Scale | 500+ | $200+ | $4,000+ | 95% |

Infrastructure stays flat at $58/mo until you need a third region. The margin never erodes because the workload (sign JWTs, verify WebAuthn assertions) is computationally trivial. No email sending, no password hashing, no session store — just cryptographic operations that a single core handles at wire speed.

### What You Don't Need

- Kubernetes
- Docker orchestration
- CI/CD pipeline beyond scp + systemctl
- Load balancer (Cloudflare Tunnel handles it)
- Managed database beyond Turso
- Email/SMTP infrastructure (ever)
- Redis/Memcached (JWTs are stateless)

---

## Pricing

### Self-Hosted
**Free. Forever. All features. Apache 2.0.**

### Managed (bounc.ing)

| Active Users | Monthly | Yearly (2 months free) |
|-------------|---------|----------------------|
| 1–5 | Free | Free |
| 6–10 | $2 | $20/yr |
| 11–25 | $5 | $50/yr |
| 26–100 | $10 | $100/yr |
| 101–500 | $25 | $250/yr |
| 501–1,000 | $50 | $500/yr |
| 1,001–5,000 | $100 | $1,000/yr |
| 5,001+ | $100 + $15/1K | yearly on request |

All features at every tier. No "contact sales." No per-seat. No feature gating. Credit card, go.

**Active user** = distinct user with at least one authenticated session in the billing period. Not registered users, not logins. One SQL query, no ambiguity, the customer can predict their bill by looking at their own analytics.

**Why this works:** $2 is below the threshold of financial consciousness. Nobody evaluates alternatives over $2/mo. Nobody cancels a $2/mo service. It's a lock-in mechanism disguised as generosity — the Tailscale playbook.

**What you get with managed:**
- Hosted Bouncing instance (multi-region, automatic failover)
- Turso-backed storage (replicated, backed up, point-in-time recovery)
- Dashboard at `who.bounc.ing`
- Automatic key rotation
- Public status page
- 99.9% uptime SLA on all paid tiers

---

## Billing — Stripe, Just Stripe

No enterprise billing platform. No homegrown payment system. Stripe handles everything: cards, subscriptions, invoicing, tax, dunning, receipts, customer portal. We never touch a card number.

### Customer Lifecycle

1. Sign up at `start.bounc.ing` → create app. **Free, no card required.**
2. App hits 100 MAU → dashboard nudge: "You've got users, nice — add a card to keep going."
3. Click → Stripe Checkout → subscription created. Done.
4. Self-serve plan changes / cancellation via Stripe's hosted customer portal. Zero billing UI for us to build.
5. Usage above 1K MAU → metered billing via Stripe's usage API. Stripe calculates the invoice.

### What We Build (~200 lines of Go)

**A `billing` table per tenant:**
```sql
CREATE TABLE billing (
    tenant_id              TEXT PRIMARY KEY,
    stripe_customer_id     TEXT NOT NULL,
    stripe_subscription_id TEXT,
    plan                   TEXT NOT NULL DEFAULT 'free',  -- 'free', 'starter', 'usage'
    status                 TEXT NOT NULL DEFAULT 'active', -- 'active', 'past_due', 'cancelled'
    current_period_start   INTEGER,
    current_period_end     INTEGER
);
```

**A webhook handler for:**
- `invoice.paid` → mark tenant active
- `invoice.payment_failed` → mark tenant past_due, grace period
- `customer.subscription.updated` → sync plan/status
- `customer.subscription.deleted` → mark cancelled, begin 7-day grace then suspend

**A MAU counter (one SQL query):**
```sql
SELECT COUNT(DISTINCT id) FROM users WHERE last_login >= ?
```

**A monthly cron** that reports each tenant's MAU to Stripe's metered billing API. Stripe handles proration and invoicing from there.

**A "Manage billing" link** in the dashboard that opens Stripe's hosted customer portal. That's our entire billing UI.

### What We Don't Build

- Payment form (Stripe Checkout)
- Invoice generation (Stripe Billing)
- Tax calculation (Stripe Tax — 0.5% per transaction, handles global compliance)
- Dunning / retry logic (Stripe Smart Retries)
- Receipts and email notifications (Stripe)
- Customer billing portal (Stripe Customer Portal)
- PCI compliance (Stripe — card data never touches our servers)

### Stripe Fee Impact

Stripe's cut is 2.9% + $0.30 per transaction. At $2/mo that's ~18% — painful but unavoidable at the entry tier. It improves fast as customers move up tiers.

| Customers (avg tier) | Monthly Revenue | Stripe Fees | Net Revenue | Infra Cost | Profit |
|---------------------|----------------|-------------|-------------|------------|--------|
| 20 × $2 | $40 | $10 | $30 | $58 | -$28 |
| 20 × $5 | $100 | $12 | $88 | $58 | $30 |
| 30 × $10 | $300 | $18 | $282 | $58 | $224 |
| 50 mixed | $500 | $30 | $470 | $58 | $412 |
| 100 mixed | $1,500 | $74 | $1,426 | $58 | $1,368 |
| 200 mixed | $4,000 | $174 | $3,826 | $100 | $3,726 |

At volume, Stripe's rate is negotiable. But even at list pricing, margins stay above 85% once past break-even.

### Grace Period Policy

Auth can't just stop working because a credit card expired. Policy:
- `invoice.payment_failed` → tenant marked `past_due`. Auth continues working. Dashboard shows banner.
- Stripe retries automatically (Smart Retries, up to 4 attempts over ~3 weeks).
- After all retries exhausted → 7-day final grace period with email warning.
- After grace → tenant suspended. Auth returns 503 with a clear message pointing to billing portal.
- **Never delete user data on suspension.** Tenant can reactivate by paying. Data retained 90 days after suspension.

---

## Migration Path from Clerk

For the specific Clerk → Bouncing migration pattern (the one that started this):

| Clerk Concept              | Bouncing Equivalent                    |
|---------------------------|----------------------------------------|
| `auth()`                  | `auth()` (identical API surface)       |
| `currentUser()`           | `currentUser()` (identical)            |
| `useUser()`               | `useUser()` (identical)                |
| `<UserButton />`          | `<UserButton />` (identical)           |
| `<SignIn />`              | `<SignIn />` (identical)               |
| `clerkClient()`           | `bouncingAdmin`                        |
| `clerkMiddleware()`       | `export { auth as middleware }`        |
| `publicMetadata.role`     | `session.roles` / `session.permissions`|
| Google OAuth domain filter| `access.mode: domain-restricted`       |
| Clerk Dashboard           | `who.bounc.ing` or self-hosted UI      |
| Manual user management    | `bouncing users add/remove` CLI        |

**Goal: The migration guide is a find-and-replace document.** Change the import, keep the function names.

---

## Roadmap

### v0.1 — "Let me in" (MVP)
- [ ] Go binary with OAuth (Google + GitHub)
- [ ] Passkey registration + authentication
- [ ] JWT session issuance (Ed25519)
- [ ] SQLite storage
- [ ] RBAC (roles + permissions)
- [ ] Access modes: open, domain-restricted, invite-only
- [ ] User pre-provisioning (CLI: add, remove, import, list)
- [ ] Basic management API (including invite + bulk import endpoints)
- [ ] `@bouncing/next` SDK (auth, currentUser, useUser, middleware)
- [ ] `<SignIn />` and `<UserButton />` components
- [ ] `bouncing.yaml` configuration
- [ ] Legal gate: optional TOS/NDA agreement page with typed-name acceptance
- [ ] i18n: bundled locales (en, es, fr, de, pt, ja, zh-Hans), `Accept-Language` detection, custom string overrides
- [ ] Security page at `docs.bounc.ing/security`
- [ ] Docker image + `curl get.bounc.ing | sh`

### v0.2 — "Who's on the list"
- [ ] Organization / multi-tenancy
- [ ] Webhook events
- [ ] Google Workspace directory sync (scheduled, with auto-deprovision)
- [ ] Management dashboard UI (who.bounc.ing)
- [ ] `@bouncing/react` SDK
- [ ] Turso storage driver

### v0.3 — "VIP section"
- [ ] Managed service launch on Hetzner + Cloudflare
- [ ] Automatic key rotation
- [ ] Go SDK
- [ ] SCIM endpoint (Okta, Azure AD, Google Workspace real-time sync)
- [ ] SAML SSO (enterprise orgs that need it)
- [ ] Audit log
- [ ] Rate limiting

### v1.0 — "Doors open"
- [ ] Production-hardened
- [ ] Independent security audit (code + cryptography review)
- [ ] Additional OAuth providers (GitLab, Bitbucket, Slack)
- [ ] Custom OAuth/OIDC provider support
- [ ] i18n for pre-built components

### v2.0+ — "Enterprise" (when revenue justifies it)
- [ ] SOC 2 Type I ($30-100K audit — only when chasing 500+ user enterprise accounts)
- [ ] SSO enforcement policies
- [ ] Advanced audit log with export

---

## Competitive Position

| Feature                    | Clerk   | Auth0    | SuperTokens | Keycloak | Bouncing |
|---------------------------|---------|----------|-------------|----------|----------|
| Free self-host             | ✗       | ✗        | ✓ (needs backend) | ✓ (Java, heavy) | ✓ (single binary) |
| No passwords/email infra   | ✗       | ✗        | ✗           | ✗        | ✓ (by design) |
| Passkeys                  | ✓       | ✓        | ✗           | Plugin   | ✓        |
| Pre-built React components| ✓       | ✗        | ✓           | ✗        | ✓        |
| Next.js App Router native | ✓       | Partial  | Partial     | ✗        | ✓        |
| Invite-only mode          | Hacky   | ✓        | ✗           | ✓        | ✓ (one-line config) |
| RBAC included free        | ✗ (Pro) | ✗ (paid) | ✓           | ✓        | ✓        |
| Orgs included free        | ✗ (Pro) | ✗ (paid) | ✓           | ✓        | ✓        |
| Directory sync included   | ✗ (Ent) | ✗ (Ent)  | ✗           | ✓        | ✓        |
| Domain restriction        | ✓       | ✓        | ✓           | ✓        | ✓        |
| No separate backend needed| ✓       | ✓        | ✗           | ✗        | ✓        |
| Managed < $10/mo at 1K MAU| ✗ ($25+)| ✗ ($23+) | ✗ (~$25)    | N/A      | ✓ ($2 entry) |
| Clerk-compatible API shape| ✓       | ✗        | ✗           | ✗        | ✓        |

---

## Key Technical Decisions

1. **Ed25519 for JWT signing** — faster than RSA, smaller keys, no padding oracle attacks.
2. **ULID for IDs** — sortable, URL-safe, no coordination needed.
3. **SQLite as default store** — zero-config, single-file, embedded. Turso for managed gives us the same SQL with edge replication.
4. **WebAuthn via go-webauthn/webauthn** — mature, well-tested Go library.
5. **No passwords. No email. Period.** — OAuth + passkeys mean Bouncing never stores credentials, never sends email, never needs SMTP/SES/Resend. This eliminates entire categories of cost, complexity, and liability. It's 2026.
6. **Clerk-shaped SDK API** — deliberate. Migration should be import swaps, not rewrites.

---

## Security Posture — What We Store and Don't Store

SOC 2 costs $30-100K, takes 6-12 months, and requires ongoing compliance overhead. For a product that doesn't store anything sensitive, that's spending more on the audit than on the infrastructure. SOC 2 is a v2.0 problem — when enterprise procurement teams start asking and revenue justifies the cost.

What matters from day one is a clear, honest, verifiable security posture.

### What Bouncing Stores

- Email addresses (from OAuth profile)
- Display names (from OAuth profile)
- Avatar URLs (from OAuth profile)
- Passkey public keys (literally public — not secrets)
- OAuth provider IDs (not tokens — we don't retain OAuth refresh tokens)
- Roles and organization membership
- Refresh token hashes (not the tokens themselves)

### What Bouncing Does NOT Store

- **Passwords** — we don't support them
- **OAuth tokens** — we use them to complete the flow and discard them
- **Payment info** — Stripe holds that, card data never touches our servers
- **Private keys from passkeys** — those never leave the user's device
- **Session state** — JWTs are verified locally by the SDK, we never see user requests
- **PII beyond email and name** — no addresses, no phone numbers, no government IDs
- **Health, financial, or regulated data** — not our problem, by design

### The Security Page (`docs.bounc.ing/security`)

Ships with v0.1. Covers:

- Exactly what data we store (the list above)
- Encryption: Ed25519 JWT signing, HTTPS-only, Turso encryption at rest
- Architecture: stateless edge, no session store to breach, JWKS cached at Cloudflare
- Open source: the code is the audit — anyone can verify every claim
- Data residency: Hetzner EU (Falkenstein) + US (Ashburn), Turso edge locations documented
- Incident response: how we handle and disclose security issues
- Responsible disclosure policy with `security@bounc.ing`

### Why This Is Better Than a SOC 2 Badge at This Stage

SOC 2 tells you a company followed a process. Open source tells you exactly what the code does. For a product whose entire security story is "we don't store anything worth stealing," transparency beats certification. The security page is verifiable against the source code. A SOC 2 report is a PDF you have to take on faith.

When enterprise customers with procurement checklists show up, we'll get SOC 2. Until then, the open code and the security page do more for trust than any badge.

---

## Open Source Strategy

### The Tailscale Model, Not the MongoDB Model

Auth is a trust product. You're asking people to put Bouncing between their users and their app. Nobody trusts a closed-source auth service from a company they've never heard of. The source code IS the sales pitch. Open source lets customers read the code, verify the cryptography, audit the JWT signing, confirm nothing sketchy happens with their OAuth tokens.

**License: Apache 2.0.** Not AGPL. Not BSL. Not "source available." Real open source. No license games. No "commons clause." Apache 2.0 sails through university and enterprise procurement without friction — important for the academic market.

### What's Open (Apache 2.0)

Everything a self-hosted user needs to run Bouncing with full feature parity:

- Core Go binary (auth flows, RBAC, session management, storage, management API)
- `@bouncing/next` SDK
- `@bouncing/react` SDK
- Go client SDK
- `<SignIn />` and `<UserButton />` components
- `bouncing.yaml` configuration schema
- Docker image + install script
- Documentation

### What's Not Open (Managed Service Ops)

The operational layer that makes `bounc.ing` the managed service. This is the moat — not the product, the ops:

- Multi-tenant routing and isolation
- Stripe billing integration
- Dashboard UI at `who.bounc.ing`
- Cloudflare Tunnel orchestration and failover
- Automated key rotation infrastructure
- Status page and monitoring
- Turso provisioning and backup automation

Nobody wants to replicate ops. They want to not think about ops. That's what they pay for.

### The Fork Risk

Someone forks Bouncing and offers a competing managed service. The defense:

- **Brand and domain.** `bounc.ing` is the canonical home. A fork has to explain why it exists.
- **Pace of development.** We ship faster than a fork can follow.
- **Trust.** Auth is a trust product. The original is the trusted one.
- **Network effects.** Docs, blog posts, Stack Overflow answers, SDK downloads all point to us.

This is the same defense Tailscale has. Their client is BSD-licensed. Nobody has out-competed them with a fork. The coordination layer and brand are the moat.

### Why Self-Hosted Users Are Marketing

Self-hosted users cost us nothing to serve and they:

- Tell friends and colleagues about Bouncing
- Write blog posts and tutorials
- File issues and contribute fixes
- Star the repo (social proof)
- Convert to managed when they get tired of running it themselves

A percentage of every self-hosted user eventually decides $2/mo is cheaper than maintaining their own uptime. That conversion is free customer acquisition.

---

## Repo Structure

```
github.com/bouncing-auth/bouncing     # Core Go binary (Apache 2.0)
github.com/bouncing-auth/sdk-js       # @bouncing/next, @bouncing/react (Apache 2.0)
github.com/bouncing-auth/sdk-go       # Go client SDK (Apache 2.0)
github.com/bouncing-auth/docs         # docs.bounc.ing (Apache 2.0)
```

Private repos (managed service ops):
```
github.com/bouncing-auth/cloud        # Multi-tenant orchestration, billing, monitoring
github.com/bouncing-auth/dashboard    # who.bounc.ing management UI
```

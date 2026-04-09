# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

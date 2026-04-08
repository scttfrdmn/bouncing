-- 001_initial.sql
-- Note: schema_version table and version tracking are managed by the migration runner.

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    auth_method TEXT,
    created_at  INTEGER NOT NULL,
    last_login  INTEGER
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    public_key  BLOB NOT NULL,
    sign_count  INTEGER NOT NULL DEFAULT 0,
    transports  TEXT,
    created_at  INTEGER NOT NULL,
    last_used   INTEGER
);

CREATE TABLE IF NOT EXISTS oauth_connections (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    provider    TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    email       TEXT NOT NULL,
    UNIQUE(provider, provider_id)
);

CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    permissions TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    org_id  TEXT NOT NULL DEFAULT '',  -- '' = global scope, non-empty = org-scoped
    PRIMARY KEY (user_id, role_id, org_id)
);

CREATE TABLE IF NOT EXISTS orgs (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    slug       TEXT UNIQUE NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS org_members (
    org_id  TEXT NOT NULL REFERENCES orgs(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS allowed_domains (
    domain TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS directory_sync (
    id             TEXT PRIMARY KEY,
    provider       TEXT NOT NULL,
    domain         TEXT NOT NULL,
    last_sync      INTEGER,
    last_sync_hash TEXT,
    status         TEXT NOT NULL DEFAULT 'idle'
);

CREATE TABLE IF NOT EXISTS webhooks (
    id     TEXT PRIMARY KEY,
    url    TEXT NOT NULL,
    events TEXT NOT NULL,
    secret TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tos_acceptances (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    version     TEXT NOT NULL,
    name_typed  TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    ip_address  TEXT,
    UNIQUE(user_id, version)
);


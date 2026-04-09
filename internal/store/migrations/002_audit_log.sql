-- 002_audit_log.sql
-- Immutable audit trail for auth and management actions.

CREATE TABLE IF NOT EXISTS audit_entries (
    id          TEXT PRIMARY KEY,
    timestamp   INTEGER NOT NULL,
    actor_id    TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    metadata    TEXT,
    ip_address  TEXT,
    request_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_entries(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action);

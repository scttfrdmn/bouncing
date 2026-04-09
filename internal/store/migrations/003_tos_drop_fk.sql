-- 003_tos_drop_fk.sql
-- Remove the foreign key constraint from tos_acceptances so that
-- user deletion preserves the immutable audit trail (legal requirement).

CREATE TABLE IF NOT EXISTS tos_acceptances_new (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    version     TEXT NOT NULL,
    name_typed  TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    ip_address  TEXT,
    UNIQUE(user_id, version)
);

INSERT OR IGNORE INTO tos_acceptances_new
    SELECT id, user_id, version, name_typed, accepted_at, ip_address
    FROM tos_acceptances;

DROP TABLE IF EXISTS tos_acceptances;

ALTER TABLE tos_acceptances_new RENAME TO tos_acceptances;

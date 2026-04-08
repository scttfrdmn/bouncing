-- 002_tos_fk.sql
-- Drop the FK constraint on tos_acceptances.user_id so that offboarding a user
-- does not delete their legal acceptance records (audit trail must survive offboarding).
-- SQLite cannot DROP CONSTRAINT; we recreate the table without the FK.

CREATE TABLE IF NOT EXISTS tos_acceptances_new (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,              -- intentionally no FK: records must survive user deletion
    version     TEXT NOT NULL,
    name_typed  TEXT NOT NULL,
    accepted_at INTEGER NOT NULL,
    ip_address  TEXT,
    UNIQUE(user_id, version)
);

INSERT INTO tos_acceptances_new SELECT id, user_id, version, name_typed, accepted_at, ip_address
FROM tos_acceptances;

DROP TABLE tos_acceptances;

ALTER TABLE tos_acceptances_new RENAME TO tos_acceptances;


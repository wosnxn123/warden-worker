-- Emergency access: allow a grantor to designate a grantee who can view or
-- take over their vault after a configurable wait time.
CREATE TABLE IF NOT EXISTS emergency_access (
    id TEXT PRIMARY KEY NOT NULL,
    grantor_id TEXT NOT NULL,
    grantee_id TEXT,                 -- NULL until the invitee accepts
    grantee_email TEXT,              -- email used to locate the invitee
    key_encrypted TEXT,              -- grantor's encrypted key, set at confirm time
    atype INTEGER NOT NULL,          -- 0 = View, 1 = Takeover
    status INTEGER NOT NULL,         -- 0 = Invited, 1 = Accepted, 2 = Confirmed, -1 = RecoveryInitiated
    wait_time_days INTEGER NOT NULL DEFAULT 7,
    recovery_initiated_at TEXT,      -- ISO timestamp when grantee initiated recovery
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (grantor_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_emergency_access_grantor ON emergency_access(grantor_id);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantee ON emergency_access(grantee_id);

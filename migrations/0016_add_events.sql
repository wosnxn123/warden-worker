-- Event log for auditing user and organization actions.
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY NOT NULL,
    type INTEGER NOT NULL,            -- Bitwarden EventType
    user_id TEXT,
    organization_id TEXT,
    cipher_id TEXT,
    collection_id TEXT,
    device_type INTEGER,
    ip TEXT,
    data TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(organization_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, created_at);

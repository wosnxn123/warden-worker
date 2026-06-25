-- Organization API keys for SCIM and org-level API access.
CREATE TABLE IF NOT EXISTS organization_api_keys (
    org_id TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,       -- SHA-256 hash of the plaintext key
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (org_id, api_key_hash),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

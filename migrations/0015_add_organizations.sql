-- Organizations & sharing
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    private_key TEXT,
    public_key TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users_organizations (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    invited_by_email TEXT,
    access_all INTEGER NOT NULL DEFAULT 0,
    akey TEXT NOT NULL,
    status INTEGER NOT NULL,    -- 0=Invited,1=Accepted,2=Confirmed
    atype INTEGER NOT NULL,     -- 0=Owner,1=Admin,2=User,3=Manager
    reset_password_key TEXT,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_users_organizations_user ON users_organizations(user_id);
CREATE INDEX IF NOT EXISTS idx_users_organizations_org ON users_organizations(org_id);

CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(org_id);

CREATE TABLE IF NOT EXISTS users_collections (
    user_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, collection_id)
);

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    PRIMARY KEY (cipher_id, collection_id)
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    access_all INTEGER NOT NULL DEFAULT 0,
    external_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS groups_users (
    group_id TEXT NOT NULL,
    users_organizations_id TEXT NOT NULL,
    PRIMARY KEY (group_id, users_organizations_id)
);

CREATE TABLE IF NOT EXISTS collections_groups (
    collection_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    read_only INTEGER NOT NULL DEFAULT 0,
    hide_passwords INTEGER NOT NULL DEFAULT 0,
    manage INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection_id, group_id)
);

CREATE TABLE IF NOT EXISTS org_policies (
    id TEXT PRIMARY KEY NOT NULL,
    org_id TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    UNIQUE (org_id, atype)
);

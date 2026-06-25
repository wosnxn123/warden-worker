-- Users table to store user accounts and their master keys/hashes
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT,
    avatar_color TEXT,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    master_password_hash TEXT NOT NULL,
    master_password_hint TEXT,
    password_salt TEXT, -- Salt for server-side PBKDF2 hashing (NULL for legacy users pending migration)
    password_iterations INTEGER NOT NULL DEFAULT 600000, -- Per-user server-side PBKDF2 iteration count (migrated on login)
    key TEXT NOT NULL, -- The encrypted symmetric key
    private_key TEXT NOT NULL, -- encrypted asymmetric private_key
    public_key TEXT NOT NULL, -- asymmetric public_key
    kdf_type INTEGER NOT NULL DEFAULT 0, -- 0 for PBKDF2, 1 for Argon2id
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    kdf_memory INTEGER, -- Argon2 memory parameter in MB (15-1024), NULL for PBKDF2
    kdf_parallelism INTEGER, -- Argon2 parallelism parameter (1-16), NULL for PBKDF2
    security_stamp TEXT,
    equivalent_domains TEXT NOT NULL DEFAULT '[]', -- JSON: Vec<Vec<String>>
    excluded_globals TEXT NOT NULL DEFAULT '[]', -- JSON: Vec<i32> (reserved for future global groups)
    totp_recover TEXT, -- Recovery code for 2FA
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Ciphers table for storing encrypted vault items
CREATE TABLE IF NOT EXISTS ciphers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT,
    organization_id TEXT,
    type INTEGER NOT NULL,
    data TEXT NOT NULL, -- JSON blob of all encrypted fields (name, notes, login, etc.)
    favorite BOOLEAN NOT NULL DEFAULT 0,
    folder_id TEXT,
    deleted_at TEXT,
    archived_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- Index to speed up common per-user cipher queries (sync/list/attachments joins)
CREATE INDEX IF NOT EXISTS idx_ciphers_user_id ON ciphers(user_id);

-- Attachments table for cipher file metadata
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);

-- Pending attachments table for in-flight uploads
CREATE TABLE IF NOT EXISTS attachments_pending (
    id TEXT PRIMARY KEY NOT NULL,
    cipher_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    akey TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    organization_id TEXT,
    FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_attachments_pending_cipher ON attachments_pending(cipher_id);
CREATE INDEX IF NOT EXISTS idx_attachments_pending_created_at ON attachments_pending(created_at);

-- TwoFactor table for two-factor authentication
-- Types: 0=Authenticator(TOTP), 1=Email, 5=Remember, 8=RecoveryCode
CREATE TABLE IF NOT EXISTS twofactor (
    uuid TEXT PRIMARY KEY NOT NULL,
    user_uuid TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    data TEXT NOT NULL, -- JSON data specific to the 2FA type (e.g., TOTP secret)
    last_used INTEGER NOT NULL DEFAULT 0, -- Unix timestamp or TOTP time step
    FOREIGN KEY (user_uuid) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_uuid, atype)
);

-- Devices table for device-bound auth, refresh tokens, and push registration.
CREATE TABLE IF NOT EXISTS devices (
    identifier TEXT NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type INTEGER NOT NULL,
    push_uuid TEXT,
    push_token TEXT,
    refresh_token TEXT NOT NULL,
    twofactor_remember TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (identifier, user_id),
    UNIQUE(refresh_token)
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_push_token ON devices(push_token);

-- Auth requests table for device approval login.
CREATE TABLE IF NOT EXISTS auth_requests (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    request_device_identifier TEXT NOT NULL,
    device_type INTEGER NOT NULL,
    request_ip TEXT NOT NULL,
    response_device_id TEXT,
    access_code TEXT NOT NULL,
    public_key TEXT NOT NULL,
    enc_key TEXT,
    master_password_hash TEXT,
    approved INTEGER,
    creation_date TEXT NOT NULL,
    response_date TEXT,
    authentication_date TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_requests_user_id ON auth_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_requests_creation_date
    ON auth_requests(creation_date);

-- Folders table for organizing ciphers
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL, -- Encrypted folder name
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_folders_user_id ON folders(user_id);

-- Global equivalent domains dataset (seeded separately, not bundled into the Worker)
CREATE TABLE IF NOT EXISTS global_equivalent_domains (
    type INTEGER PRIMARY KEY NOT NULL,
    sort_order INTEGER NOT NULL,
    domains_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_global_equivalent_domains_sort_order
    ON global_equivalent_domains(sort_order);

-- Send support: main sends table
CREATE TABLE IF NOT EXISTS sends (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  type INTEGER NOT NULL,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sends_user_id ON sends(user_id);
CREATE INDEX IF NOT EXISTS idx_sends_deletion_date ON sends(deletion_date);

-- Emergency access: designate a trusted contact who can view or take over
-- your vault after a configurable wait time.
CREATE TABLE IF NOT EXISTS emergency_access (
    id TEXT PRIMARY KEY NOT NULL,
    grantor_id TEXT NOT NULL,
    grantee_id TEXT,
    grantee_email TEXT,
    key_encrypted TEXT,
    atype INTEGER NOT NULL,          -- 0 = View, 1 = Takeover
    status INTEGER NOT NULL,         -- 0=Invited,1=Accepted,2=Confirmed,-1=RecoveryInitiated,3=Approved
    wait_time_days INTEGER NOT NULL DEFAULT 7,
    recovery_initiated_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (grantor_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantor ON emergency_access(grantor_id);
CREATE INDEX IF NOT EXISTS idx_emergency_access_grantee ON emergency_access(grantee_id);

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
    status INTEGER NOT NULL,
    atype INTEGER NOT NULL,
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

-- Event log (audit trail)
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY NOT NULL,
    type INTEGER NOT NULL,
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

-- SSO auth: temporary state for the OIDC authorization-code login flow.
CREATE TABLE IF NOT EXISTS sso_auth (
    state TEXT PRIMARY KEY NOT NULL,
    code_verifier TEXT,
    redirect_uri TEXT NOT NULL,
    user_email TEXT,
    code TEXT,
    code_response_error TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_auth_created_at ON sso_auth(created_at);

-- Email verification tokens (registration + resend flows).
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user ON email_verification_tokens(user_id);

-- Organization API keys for SCIM and org-level API access.
CREATE TABLE IF NOT EXISTS organization_api_keys (
    org_id TEXT NOT NULL,
    api_key_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (org_id, api_key_hash),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
);

-- Staging table for file Sends whose upload has not yet completed.
CREATE TABLE IF NOT EXISTS sends_pending (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  type INTEGER NOT NULL,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash TEXT,
  password_salt TEXT,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  hide_email INTEGER NOT NULL DEFAULT 0
);

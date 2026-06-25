-- SSO auth: temporary state for the OIDC authorization-code login flow.
-- Maps the warden<->client `state` to the IdP authorization code so the
-- final /connect/token exchange can complete.
CREATE TABLE IF NOT EXISTS sso_auth (
    state TEXT PRIMARY KEY NOT NULL,
    code_verifier TEXT,                 -- PKCE verifier used with the IdP
    redirect_uri TEXT NOT NULL,         -- where to send the client after callback
    user_email TEXT,                    -- resolved from the IdP id_token
    code TEXT,                          -- IdP authorization code (set on callback)
    code_response_error TEXT,           -- error payload if the IdP callback failed
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sso_auth_created_at ON sso_auth(created_at);

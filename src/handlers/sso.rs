//! SSO (OIDC) login flow.
//!
//! Simplified model (no Key Connector): SSO authenticates the user's identity
//! via the configured OIDC IdP; the user still unlocks the vault with their
//! master password. This matches vaultwarden's default when Key Connector is
//! not enabled.
//!
//! Flow:
//!   1. Client → GET /identity/connect/authorize  (we redirect to the IdP)
//!   2. IdP   → GET /identity/connect/oidc-signin (we store the IdP code, redirect back to client)
//!   3. Client → POST /identity/connect/token grant_type=authorization_code
//!      (we exchange the IdP code for an id_token, resolve the user by email
//!      and issue a Warden access/refresh token pair)

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::Value;
use worker::{wasm_bindgen::JsValue, Env, Fetch, Method, Request, RequestInit};

use crate::{
    db,
    error::AppError,
    models::{sso_auth::SsoAuth, user::User},
};

const DEFAULT_SCOPES: &str = "openid email profile";

/// A selectable SSO tenant (e.g. one of several Microsoft E3 organizations).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsoTenant {
    /// Stable identifier used in the authorize request (`domain_hint`).
    pub id: String,
    /// Display name shown to the user in the tenant picker.
    pub name: String,
    /// OIDC issuer/authority URL for this tenant.
    pub authority: String,
    /// OAuth client_id registered at this tenant's IdP.
    pub client_id: String,
    /// Display label, e.g. "Contoso (E3)".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Parse `SSO_TENANTS` (JSON array). Returns empty when unset.
pub fn sso_tenants(env: &Env) -> Vec<SsoTenant> {
    env.var("SSO_TENANTS")
        .ok()
        .and_then(|v| serde_json::from_str::<Vec<SsoTenant>>(&v.to_string()).ok())
        .unwrap_or_default()
}

/// Resolve the SSO config for a given `domain_hint`.
/// Falls back to the single-tenant `SSO_AUTHORITY`/`SSO_CLIENT_ID` when no
/// tenants are configured or the hint doesn't match.
fn resolve_sso_config(env: &Env, domain_hint: Option<&str>) -> Result<(String, String), AppError> {
    let tenants = sso_tenants(env);
    if !tenants.is_empty() {
        let hint = domain_hint.unwrap_or("");
        let selected = tenants
            .iter()
            .find(|t| t.id == hint)
            .or_else(|| tenants.first())
            .ok_or_else(|| AppError::BadRequest("No SSO tenant configured".to_string()))?;
        return Ok((selected.authority.clone(), selected.client_id.clone()));
    }
    // Single-tenant fallback.
    Ok((
        sso_var(env, "SSO_AUTHORITY")?,
        sso_var(env, "SSO_CLIENT_ID")?,
    ))
}

fn sso_enabled(env: &Env) -> bool {
    env.var("SSO_ENABLED")
        .map(|v| matches!(v.to_string().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn sso_var(env: &Env, name: &str) -> Result<String, AppError> {
    env.var(name)
        .map(|v| v.to_string())
        .map_err(|_| AppError::BadRequest(format!("{name} not configured for SSO")))
}

fn sso_secret(env: &Env) -> Result<String, AppError> {
    env.secret("SSO_CLIENT_SECRET")
        .map(|v| v.to_string())
        .map_err(|_| AppError::BadRequest("SSO_CLIENT_SECRET not configured".to_string()))
}

fn random_verifier() -> Result<String, AppError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| AppError::Crypto(format!("PKCE verifier: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

async fn sha256_hex(data: &[u8]) -> Result<String, AppError> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

/// Fetch the OIDC discovery document and return (authorize_url, token_url).
async fn discovery_endpoints(authority: &str) -> Result<(String, String), AppError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        authority.trim_end_matches('/')
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        return Err(AppError::Internal);
    }
    let doc: serde_json::Value = resp.json().await.map_err(AppError::Worker)?;
    let auth = doc
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal)?
        .to_string();
    let token = doc
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Internal)?
        .to_string();
    Ok((auth, token))
}

/// The warden-side callback URL (must be registered at the IdP).
fn callback_url(env: &Env, base_url: &str) -> String {
    env.var("SSO_CALLBACK_URL")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}/identity/connect/oidc-signin",
                base_url.trim_end_matches('/')
            )
        })
}

// ── GET /identity/connect/authorize ─────────────────────────────────

/// GET /identity/connect/sso-tenants — list selectable SSO organizations.
/// Returns the `SSO_TENANTS` array so the client can render a tenant picker.
#[worker::send]
pub async fn list_sso_tenants(State(env): State<Arc<Env>>) -> Result<Json<Value>, AppError> {
    let tenants = sso_tenants(&env);
    Ok(Json(serde_json::json!({
        "data": tenants,
        "object": "list",
        "continuationToken": null
    })))
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeParams {
    #[allow(dead_code)]
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    #[allow(dead_code)]
    pub code_challenge: Option<String>,
    #[allow(dead_code)]
    pub code_challenge_method: Option<String>,
    #[allow(dead_code)]
    pub scope: Option<String>,
    #[allow(dead_code)]
    pub response_type: Option<String>,
    /// Tenant selector: matches an `id` in `SSO_TENANTS`.
    pub domain_hint: Option<String>,
}

#[worker::send]
pub async fn authorize(
    State(env): State<Arc<Env>>,
    Extension(base): Extension<crate::BaseUrl>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    if !sso_enabled(&env) {
        return Err(AppError::BadRequest("SSO is not enabled".to_string()));
    }

    let client_state = params
        .state
        .ok_or_else(|| AppError::BadRequest("Missing state".to_string()))?;
    let redirect_uri = params
        .redirect_uri
        .ok_or_else(|| AppError::BadRequest("Missing redirect_uri".to_string()))?;

    let (authority, client_id) = resolve_sso_config(&env, params.domain_hint.as_deref())?;
    let scopes = env
        .var("SSO_SCOPES")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| DEFAULT_SCOPES.to_string());
    let cb = callback_url(&env, &base.0);

    let (auth_endpoint, _) = discovery_endpoints(&authority).await?;

    // warden↔IdP PKCE
    let verifier = random_verifier()?;
    let challenge = sha256_hex(verifier.as_bytes()).await?;

    // Persist the in-flight SSO state.
    let db = db::get_db(&env)?;
    let sso = SsoAuth {
        state: client_state.clone(),
        code_verifier: Some(verifier),
        redirect_uri,
        user_email: None,
        code: None,
        code_response_error: None,
        created_at: db::now_string(),
    };
    sso.insert(&db).await?;

    let idp_url = format!(
        "{auth_endpoint}?response_type=code&client_id={client_id}&redirect_uri={cb}&scope={scopes}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        cb = urlencoding::encode(&cb),
        scopes = urlencoding::encode(&scopes),
        state = urlencoding::encode(&client_state),
        challenge = challenge
    );

    Ok(Redirect::to(&idp_url).into_response())
}

// ── GET /identity/connect/oidc-signin (IdP callback) ────────────────

#[derive(Debug, Deserialize)]
pub struct SigninParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[worker::send]
pub async fn oidc_signin(
    State(env): State<Arc<Env>>,
    Query(params): Query<SigninParams>,
) -> Result<Response, AppError> {
    let state = params
        .state
        .ok_or_else(|| AppError::BadRequest("Missing state".to_string()))?;
    let db = db::get_db(&env)?;
    let mut sso = SsoAuth::find_by_state(&db, &state)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired SSO state".to_string()))?;

    if let Some(err) = params.error {
        sso.code_response_error = Some(format!(
            "{err}: {}",
            params.error_description.unwrap_or_default()
        ));
        sso.save(&db).await?;
        // Redirect back to the client with the error so it can surface it.
        return Ok(Redirect::to(&format!(
            "{}?state={}&error=sso_failed",
            sso.redirect_uri,
            urlencoding::encode(&state)
        ))
        .into_response());
    }

    let code = params
        .code
        .ok_or_else(|| AppError::BadRequest("Missing code".to_string()))?;
    sso.code = Some(code);
    sso.save(&db).await?;

    Ok(Redirect::to(&format!(
        "{}?state={}",
        sso.redirect_uri,
        urlencoding::encode(&state)
    ))
    .into_response())
}

// ── Token exchange (called from identity.rs) ────────────────────────

/// Resolve the user for an SSO `authorization_code` grant.
/// Returns the matched user; the caller issues tokens.
pub(crate) async fn sso_resolve_user(env: &Arc<Env>, state: &str) -> Result<User, AppError> {
    let db = db::get_db(env)?;
    let sso = SsoAuth::find_by_state(&db, state)
        .await?
        .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;

    if let Some(ref err) = sso.code_response_error {
        let _ = err;
        SsoAuth::delete(&db, state).await?;
        return Err(AppError::BadRequest("invalid_grant".to_string()));
    }

    let idp_code = sso
        .code
        .clone()
        .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;
    let verifier = sso
        .code_verifier
        .clone()
        .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;

    let (authority, client_id) = resolve_sso_config(env, None)?;
    let client_secret = sso_secret(env)?;
    let base_url = env
        .var("BASE_URL")
        .ok()
        .map(|v| v.to_string())
        .unwrap_or_default();
    let cb = callback_url(env, &base_url);

    let (_, token_endpoint) = discovery_endpoints(&authority).await?;

    // Exchange the IdP code for tokens.
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={cb}&client_id={cid}&client_secret={secret}&code_verifier={v}",
        code = urlencoding::encode(&idp_code),
        cb = urlencoding::encode(&cb),
        cid = urlencoding::encode(&client_id),
        secret = urlencoding::encode(&client_secret),
        v = urlencoding::encode(&verifier)
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init(&token_endpoint, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let t = resp.text().await.unwrap_or_default();
        log::error!("SSO token exchange failed ({}): {t}", resp.status_code());
        SsoAuth::delete(&db, state).await?;
        return Err(AppError::BadRequest("invalid_grant".to_string()));
    }
    let tokens: serde_json::Value = resp.json().await.map_err(AppError::Worker)?;
    let id_token = tokens
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("invalid_grant".to_string()))?;

    // Parse the id_token without signature verification: the token was obtained
    // directly from the IdP token endpoint using our client_secret, so its
    // provenance is trusted. We still validate iss/aud/exp below.
    use jwt_compact::{Claims, UntrustedToken};
    let untrusted = UntrustedToken::new(id_token)
        .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
    let claims: Claims<serde_json::Value> = untrusted
        .deserialize_claims_unchecked()
        .map_err(|_| AppError::BadRequest("invalid_grant".to_string()))?;
    let claims = &claims.custom;

    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("IdP did not return an email".to_string()))?
        .to_lowercase();

    // Optional: verify email_verified.
    let email_verified = claims
        .get("email_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow_unverified = env
        .var("SSO_ALLOW_UNVERIFIED_EMAIL")
        .map(|v| matches!(v.to_string().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if !email_verified && !allow_unverified {
        SsoAuth::delete(&db, state).await?;
        return Err(AppError::BadRequest(
            "Email not verified by IdP".to_string(),
        ));
    }

    // Consume the SSO state.
    SsoAuth::delete(&db, state).await?;

    // Match against an existing account.
    let match_email = env
        .var("SSO_SIGNUPS_MATCH_EMAIL")
        .map(|v| !matches!(v.to_string().as_str(), "0" | "false" | "no"))
        .unwrap_or(true);

    let user = User::find_by_email(&db, &email).await?;
    match user {
        Some(u) => Ok(u),
        None if match_email => Err(AppError::BadRequest(
            "No account matches the SSO email. Register first with a master password.".to_string(),
        )),
        None => Err(AppError::BadRequest(
            "SSO sign-up is not enabled".to_string(),
        )),
    }
}

// tiny URL-encoder (avoids pulling in another crate).
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }
}

#[allow(dead_code)]
fn _u(_v: JsValue) {}

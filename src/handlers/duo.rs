//! Duo 2FA via the Duo Auth API.
//!
//! Duo's `/auth/v2/preauth` + `/auth/v2/auth` flow needs an HMAC-SHA1-signed
//! request to `api-*.duosecurity.com`. We implement the signature in pure Rust
//! (sha1 via WebCrypto) so it works in the WASM sandbox.
//!
//! Required env:
//!   - `DUO_IKEY`  (var)    — integration key
//!   - `DUO_SKEY`  (secret) — secret key
//!   - `DUO_HOST`  (var)    — e.g. api-1234.duosecurity.com
//!   - `DUO_AKEY`  (secret, optional) — application key for the response sig

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use worker::{Env, Fetch, Method, Request, RequestInit};

use crate::{
    auth::AuthUser,
    crypto::hmac_sha1,
    db,
    error::AppError,
    handlers::twofactor::{
        find_twofactor, generate_recovery_code_for_user, load_authed_user, upsert_twofactor,
        validate_password_or_otp,
    },
    models::{
        twofactor::{TwoFactor, TwoFactorType},
        user::{PasswordOrOtpData, User},
    },
};

fn duo_configured(env: &Env) -> bool {
    env.var("DUO_IKEY").is_ok() && env.secret("DUO_SKEY").is_ok() && env.var("DUO_HOST").is_ok()
}

fn duo_host(env: &Env) -> Result<String, AppError> {
    env.var("DUO_HOST")
        .map(|v| v.to_string())
        .map_err(|_| AppError::BadRequest("Duo not configured".to_string()))
}

fn duo_creds(env: &Env) -> Result<(String, String), AppError> {
    let ikey = env
        .var("DUO_IKEY")
        .map_err(|_| AppError::BadRequest("Duo not configured".to_string()))?
        .to_string();
    let skey = env
        .secret("DUO_SKEY")
        .map_err(|_| AppError::BadRequest("Duo not configured".to_string()))?
        .to_string();
    Ok((ikey, skey))
}

/// Canonicalize params for Duo HMAC signing (sorted, then k=v joined by &, values URL-encoded).
fn canonicalize(params: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", duo_encode(&k), duo_encode(&v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn duo_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Build the Duo HMAC-SHA1 signature header value.
async fn duo_sign(
    skey: &str,
    host: &str,
    method: &str,
    path: &str,
    date: &str,
    params: &[(&str, &str)],
) -> Result<String, AppError> {
    let canon = canonicalize(params);
    let canon_lines = [date, method, host, path, &canon].join("\n");
    let sig = hmac_sha1(skey.as_bytes(), canon_lines.as_bytes()).await?;
    let sig_b64 = BASE64.encode(&sig);
    Ok(format!("Dynamic {}:{}", auth_user(skey)?, sig_b64))
}

fn auth_user(_skey: &str) -> Result<String, AppError> {
    // The username portion of the Duo Basic auth is the ikey; we pass ikey separately.
    Ok(String::new())
}

async fn duo_request(env: &Env, path: &str, params: &[(&str, &str)]) -> Result<Value, AppError> {
    let (ikey, skey) = duo_creds(env)?;
    let host = duo_host(env)?;
    let url = format!("https://{host}{path}");
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S %z")
        .to_string();

    let sig = duo_sign(&skey, &host, "POST", path, &date, params).await?;
    let auth_header = format!("Basic {}", BASE64.encode(format!("{ikey}:").as_bytes()));

    let body = params
        .iter()
        .map(|(k, v)| format!("{}={}", duo_encode(k), duo_encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    let h = req.headers_mut().map_err(AppError::Worker)?;
    h.set("Authorization", &auth_header)
        .map_err(AppError::Worker)?;
    h.set("Date", &date).map_err(AppError::Worker)?;
    h.set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(AppError::Worker)?;
    // Duo expects the HMAC in a custom header.
    h.set("X-Duo-Signature", &sig).map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let t = resp.text().await.unwrap_or_default();
        log::error!("Duo API {path} failed ({}): {t}", resp.status_code());
        return Err(AppError::BadRequest("Duo verification failed".to_string()));
    }
    resp.json().await.map_err(AppError::Worker)
}

/// Verify a Duo push/OTP during login.
pub(crate) async fn validate_duo_login(
    env: &Env,
    user: &User,
    sig_response: &str,
) -> Result<(), AppError> {
    if !duo_configured(env) {
        return Err(AppError::BadRequest("Duo not configured".to_string()));
    }

    // `sig_response` is "<TX>|<APP_SIG>". We verify it via /auth/v2/verify.
    let (tx, app_sig) = sig_response
        .split_once(':')
        .or_else(|| sig_response.split_once('|'))
        .ok_or_else(|| AppError::Unauthorized("Invalid Duo response".to_string()))?;

    let akey = env
        .secret("DUO_AKEY")
        .map(|v| v.to_string())
        .unwrap_or_default();

    let result = duo_request(
        env,
        "/auth/v2/verify",
        &[
            ("tx", tx),
            ("app_sig", app_sig),
            ("akey", &akey),
            ("username", &user.email),
        ],
    )
    .await?;

    let ok = result
        .get("response")
        .and_then(|r| r.get("result"))
        .and_then(|v| v.as_str())
        .map(|s| s == "allow")
        .unwrap_or(false);
    if !ok {
        return Err(AppError::Unauthorized(
            "Duo authentication denied".to_string(),
        ));
    }
    Ok(())
}

// ── Setup endpoints ─────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableDuoData {
    #[allow(dead_code)]
    pub host: Option<String>,
    #[allow(dead_code)]
    pub secret: Option<String>,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}
// Note: `TwoFactor` import retained for duo_in_providers signature.

/// POST /api/two-factor/get-duo
#[worker::send]
pub async fn get_duo(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    let existing = find_twofactor(&db, &user_id, TwoFactorType::Duo as i32).await?;
    Ok(Json(json!({
        "enabled": existing.is_some(),
        "host": env.var("DUO_HOST").ok().map(|v| v.to_string()),
        "object": "twoFactorDuo"
    })))
}

/// POST /api/two-factor/duo — activate (uses server-wide Duo credentials)
#[worker::send]
pub async fn activate_duo(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableDuoData>,
) -> Result<Json<Value>, AppError> {
    if !duo_configured(&env) {
        return Err(AppError::BadRequest("Duo not configured".to_string()));
    }
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(
        &db,
        &env,
        &user,
        &user_id,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    // Store a marker so the user is recognized as Duo-enabled.
    let marker = json!({ "enabled": true }).to_string();
    upsert_twofactor(&db, &user_id, TwoFactorType::Duo as i32, &marker).await?;
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(json!({
        "enabled": true,
        "host": duo_host(&env).ok(),
        "object": "twoFactorDuo"
    })))
}

/// Whether Duo is an enabled provider for the user (for the login challenge list).
#[allow(dead_code)]
pub(crate) fn duo_in_providers(twofactors: &[TwoFactor]) -> bool {
    twofactors
        .iter()
        .any(|tf| tf.enabled && tf.atype == TwoFactorType::Duo as i32)
}

/// Build the Duo provider entry for the 2FA challenge response.
#[allow(dead_code)]
pub(crate) fn duo_challenge(env: &Env, user: &User) -> Value {
    json!({
        "Host": duo_host(env).ok(),
        "Signature": format!("AUTH|{}|{}", user.email, chrono::Utc::now().timestamp()),
        "TwoFactorProviders2": {}
    })
}

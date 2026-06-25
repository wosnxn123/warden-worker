use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::{Env, Fetch, Method, Request, RequestInit};

use crate::d1_query;
use crate::{
    auth::AuthUser,
    crypto::{
        base32_decode, ct_eq, generate_recovery_code, generate_totp_secret, hmac_sha1,
        validate_totp,
    },
    db,
    error::AppError,
    handlers::allow_totp_drift,
    mail,
    models::twofactor::{
        DisableAuthenticatorData, DisableTwoFactorData, EmailTokenData, EnableAuthenticatorData,
        EnableEmailData, EnableYubikeyData, TwoFactor, TwoFactorType, YubikeyMetadata,
    },
    models::user::{PasswordOrOtpData, User},
};

/// List all 2FA records for a user (excludes atype >= 1000).
pub(crate) async fn list_user_twofactors(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<Vec<TwoFactor>, AppError> {
    db.prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000")
        .bind(&[user_id.to_string().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<TwoFactor>()
        .map_err(|_| AppError::Database)
}

/// Whether the user has 2FA enabled.
///
/// Real 2FA providers are Authenticator (TOTP), Email, and Yubikey.
/// Remember-device tokens and recovery codes are never a 2FA method by themselves.
pub(crate) fn is_twofactor_enabled(twofactors: &[TwoFactor]) -> bool {
    twofactors.iter().any(|tf| {
        tf.enabled
            && matches!(
                tf.atype,
                x if x == TwoFactorType::Authenticator as i32
                    || x == TwoFactorType::Email as i32
                    || x == TwoFactorType::YubiKey as i32
                    || x == TwoFactorType::Duo as i32
                    || x == TwoFactorType::Webauthn as i32
            )
    })
}

/// IDs of all enabled real 2FA providers for the user (for the login challenge).
pub(crate) fn enabled_twofactor_provider_ids(twofactors: &[TwoFactor]) -> Vec<i32> {
    let mut ids: Vec<i32> = twofactors
        .iter()
        .filter(|tf| {
            tf.enabled
                && matches!(
                    tf.atype,
                    x if x == TwoFactorType::Authenticator as i32
                        || x == TwoFactorType::Email as i32
                        || x == TwoFactorType::YubiKey as i32
                        || x == TwoFactorType::Duo as i32
                        || x == TwoFactorType::Webauthn as i32
                )
        })
        .map(|tf| tf.atype)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// GET /api/two-factor - Get all enabled 2FA providers for current user
#[worker::send]
pub async fn get_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    let twofactors = list_user_twofactors(&db, &user_id).await?;
    let twofactors: Vec<Value> = twofactors.iter().map(|tf| tf.to_json_provider()).collect();

    Ok(Json(serde_json::json!({
        "data": twofactors,
        "object": "list",
        "continuationToken": null,
    })))
}

/// POST /api/two-factor/get-authenticator - Get or generate TOTP secret
#[worker::send]
pub async fn get_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    // Check if TOTP is already configured
    let existing: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let (enabled, key) = match existing {
        Some(tf_value) => {
            let tf: TwoFactor = serde_json::from_value(tf_value).map_err(|_| AppError::Internal)?;
            (true, tf.data)
        }
        None => (false, generate_totp_secret()?),
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// POST /api/two-factor/authenticator - Activate TOTP
#[worker::send]
pub async fn activate_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

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

    let key = data.key.to_uppercase();

    // Validate key format (Base32, 20 bytes = 32 characters without padding)
    let decoded_key = base32_decode(&key)?;
    if decoded_key.len() != 20 {
        return Err(AppError::BadRequest("Invalid key length".to_string()));
    }

    // Check if TOTP is already configured - reuse existing record for replay protection
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.clone().into(),
            (TwoFactorType::Authenticator as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    // Get last_used from existing record to prevent replay during reconfiguration
    let previous_last_used = existing.as_ref().map(|tf| tf.last_used).unwrap_or(0);

    // Validate TOTP code and capture time step for replay protection
    let allow_drift = allow_totp_drift(&env);
    let last_used_step = validate_totp(&data.token, &key, previous_last_used, allow_drift).await?;

    // Delete existing TOTP and any remember-device tokens bound to it to avoid stale bypass
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype IN (?2, ?3)",
        &user_id,
        TwoFactorType::Authenticator as i32,
        TwoFactorType::Remember as i32
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Create new TOTP entry
    let mut twofactor = TwoFactor::new(user_id.clone(), TwoFactorType::Authenticator, key.clone());
    twofactor.last_used = last_used_step;

    d1_query!(
        &db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &twofactor.uuid,
        &twofactor.user_uuid,
        twofactor.atype,
        twofactor.enabled as i32,
        &twofactor.data,
        twofactor.last_used
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Generate recovery code if not exists
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

/// PUT /api/two-factor/authenticator - Same as POST
#[worker::send]
pub async fn activate_authenticator_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<EnableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    activate_authenticator(state, auth_user, json).await
}

/// POST /api/two-factor/disable - Disable a 2FA method
#[worker::send]
pub async fn disable_twofactor(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

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

    let type_ = data.r#type;

    // Delete the specified 2FA type
    d1_query!(
        &db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        &user_id,
        type_
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    log::info!("User {} disabled 2FA type {}", user_id, type_);

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": type_,
        "object": "twoFactorProvider"
    })))
}

/// DELETE /api/two-factor/authenticator - Disable TOTP with key verification
#[worker::send]
pub async fn disable_authenticator(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DisableAuthenticatorData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    if data.r#type != TwoFactorType::Authenticator as i32 {
        return Err(AppError::BadRequest("Invalid two factor type".to_string()));
    }

    // Verify master password (OTP not supported in this minimal implementation)
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

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

    // Fetch existing TOTP and verify key matches before deleting
    let existing: Option<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.clone().into(), data.r#type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .map(|value| serde_json::from_value(value).map_err(|_| AppError::Internal))
        .transpose()?;

    let Some(tf) = existing else {
        return Err(AppError::BadRequest("TOTP not configured".to_string()));
    };

    // Compare keys case-insensitively (key is stored uppercased during activation)
    if !ct_eq(&tf.data, &data.key.to_uppercase()) {
        return Err(AppError::BadRequest(
            "TOTP key does not match recorded value".to_string(),
        ));
    }

    d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

    log::info!(
        "User {} disabled authenticator (2FA type {})",
        user_id,
        data.r#type
    );

    clear_recovery_if_no_twofactor(&db, &user_id).await?;

    Ok(Json(serde_json::json!({
        "enabled": false,
        "type": data.r#type,
        "object": "twoFactorProvider"
    })))
}

/// PUT /api/two-factor/disable - Same as POST
#[worker::send]
pub async fn disable_twofactor_put(
    state: State<Arc<Env>>,
    auth_user: AuthUser,
    json: Json<DisableTwoFactorData>,
) -> Result<Json<Value>, AppError> {
    disable_twofactor(state, auth_user, json).await
}

/// POST /api/two-factor/get-recover - Get recovery code
#[worker::send]
pub async fn get_recover(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Verify master password
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    Ok(Json(serde_json::json!({
        "code": user.totp_recover,
        "object": "twoFactorRecover"
    })))
}

// Helper functions

pub async fn validate_password_or_otp(
    db: &crate::db::Db,
    env: &Arc<Env>,
    user: &User,
    user_id: &str,
    data: &PasswordOrOtpData,
) -> Result<(), AppError> {
    // 1. Master password
    if let Some(ref password_hash) = data.master_password_hash {
        let verification = user.verify_master_password(password_hash).await?;
        if verification.is_valid() {
            return Ok(());
        }
    }

    // 2. Email OTP (protected-action token)
    if let Some(ref otp) = data.otp {
        if validate_protected_action_otp(db, env, user_id, otp).await? {
            return Ok(());
        }
    }

    Err(AppError::Unauthorized(
        "Invalid password or OTP".to_string(),
    ))
}

/// Validate an Email OTP used for protected actions (e.g. delete account, purge).
/// Looks up the `EmailVerificationChallenge` (type 1002) record, checks the token,
/// expiry and attempt count, then consumes it (one-time use).
pub(crate) async fn validate_protected_action_otp(
    db: &crate::db::Db,
    env: &Arc<Env>,
    user_id: &str,
    otp: &str,
) -> Result<bool, AppError> {
    let _ = env;
    let row: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[
            user_id.to_string().into(),
            (TwoFactorType::EmailVerificationChallenge as i32).into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let Some(row) = row else {
        return Ok(false);
    };
    let tf: TwoFactor = serde_json::from_value(row).map_err(|_| AppError::Internal)?;

    let mut data: EmailTokenData =
        serde_json::from_str(&tf.data).map_err(|_| AppError::Internal)?;

    // Too many attempts
    if data.attempts >= 5 {
        return Ok(false);
    }

    // Token expired (15 min window)
    let now = chrono::Utc::now().timestamp();
    if now - data.token_sent > 900 {
        return Ok(false);
    }

    let valid = data.last_token.as_deref().is_some_and(|t| ct_eq(t, otp));

    if !valid {
        data.attempts += 1;
        let updated = serde_json::to_string(&data).map_err(|_| AppError::Internal)?;
        d1_query!(
            db,
            "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
            &updated,
            &tf.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        return Ok(false);
    }

    // Consume the challenge.
    d1_query!(db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(true)
}

pub async fn generate_recovery_code_for_user(
    db: &crate::db::Db,
    user_id: &str,
) -> Result<(), AppError> {
    // Check if recovery code already exists
    let user_value: Value = db
        .prepare("SELECT totp_recover FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;

    let totp_recover: Option<String> = user_value
        .get("totp_recover")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if totp_recover.is_none() {
        let recovery_code = generate_recovery_code()?;
        d1_query!(
            db,
            "UPDATE users SET totp_recover = ?1 WHERE id = ?2",
            &recovery_code,
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

/// Clear recovery code when no real 2FA providers remain.
async fn clear_recovery_if_no_twofactor(db: &crate::db::Db, user_id: &str) -> Result<(), AppError> {
    let remaining: Vec<TwoFactor> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype < 1000 AND atype != ?2")
        .bind(&[
            user_id.to_string().into(),
            (TwoFactorType::Remember as i32).into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;

    if remaining.is_empty() {
        d1_query!(
            db,
            "UPDATE users SET totp_recover = NULL WHERE id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }

    Ok(())
}

// ============================================================================
// Shared 2FA helpers
// ============================================================================

pub async fn upsert_twofactor(
    db: &crate::db::Db,
    user_id: &str,
    atype: i32,
    data: &str,
) -> Result<(), AppError> {
    d1_query!(
        db,
        "DELETE FROM twofactor WHERE user_uuid = ?1 AND atype = ?2",
        user_id,
        atype
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let uuid = uuid::Uuid::new_v4().to_string();
    d1_query!(
        db,
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES (?1, ?2, ?3, 1, ?4, 0)",
        &uuid,
        user_id,
        atype,
        data
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn find_twofactor(
    db: &crate::db::Db,
    user_id: &str,
    atype: i32,
) -> Result<Option<TwoFactor>, AppError> {
    let row: Option<Value> = db
        .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
        .bind(&[user_id.to_string().into(), atype.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
        .transpose()
}

pub async fn load_authed_user(db: &crate::db::Db, user_id: &str) -> Result<User, AppError> {
    let user_value: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::Unauthorized("User not found".to_string()))?;
    serde_json::from_value(user_value).map_err(|_| AppError::Internal)
}

// ============================================================================
// Yubikey 2FA
// ============================================================================

fn yubico_configured(env: &Env) -> bool {
    env.var("YUBICO_CLIENT_ID").is_ok() && env.secret("YUBICO_SECRET_KEY").is_ok()
}

fn generate_nonce() -> Result<String, AppError> {
    let mut buf = [0u8; 20];
    getrandom::fill(&mut buf)
        .map_err(|e| AppError::Crypto(format!("nonce generation failed: {e}")))?;
    Ok(hex::encode(buf))
}

/// Verify a full 44-char Yubikey OTP against the Yubico validation server.
async fn yubico_verify_otp(env: &Env, otp: &str) -> Result<(), AppError> {
    let client_id = env
        .var("YUBICO_CLIENT_ID")
        .map_err(|_| AppError::BadRequest("Yubico not configured".to_string()))?
        .to_string();
    let secret_b64 = env
        .secret("YUBICO_SECRET_KEY")
        .map_err(|_| AppError::BadRequest("Yubico not configured".to_string()))?
        .to_string();
    let key = BASE64
        .decode(secret_b64.as_bytes())
        .map_err(|_| AppError::Crypto("Invalid Yubico secret".to_string()))?;
    let nonce = generate_nonce()?;

    // Signed parameter string (alphabetical, no trailing &): id, nonce, otp, timestamp
    let signed = format!("id={client_id}&nonce={nonce}&otp={otp}&timestamp=1");
    let sig = hmac_sha1(&key, signed.as_bytes()).await?;
    let h = BASE64.encode(&sig);

    let body = format!("id={client_id}&otp={otp}&nonce={nonce}&timestamp=1&h={h}");

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init("https://api.yubico.com/wsapi/2.0/verify", &init)
        .map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        return Err(AppError::BadRequest(
            "Yubico verification failed".to_string(),
        ));
    }
    let text = resp.text().await.unwrap_or_default();

    let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let status = map.get("status").cloned().unwrap_or_default();
    if status != "OK" {
        return Err(AppError::Unauthorized(format!("Yubico: {status}")));
    }
    if map.get("nonce").map(String::as_str) != Some(nonce.as_str())
        || map.get("otp").map(String::as_str) != Some(otp)
    {
        return Err(AppError::Unauthorized(
            "Yubico response mismatch".to_string(),
        ));
    }

    if let Some(resp_h) = map.get("h") {
        let mut keys: Vec<&String> = map.keys().filter(|k| k.as_str() != "h").collect();
        keys.sort();
        let resp_signed = keys
            .iter()
            .map(|k| format!("{}={}", k, map.get(*k).unwrap()))
            .collect::<Vec<_>>()
            .join("&");
        let expected = hmac_sha1(&key, resp_signed.as_bytes()).await?;
        let expected_b64 = BASE64.encode(&expected);
        if !ct_eq(&expected_b64, resp_h) {
            return Err(AppError::Unauthorized(
                "Yubico signature mismatch".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate a Yubikey OTP during login.
pub(crate) async fn validate_yubikey_login(
    env: &Env,
    response: &str,
    tf_data: &str,
) -> Result<(), AppError> {
    if response.len() != 44 {
        return Err(AppError::Unauthorized("Invalid Yubikey OTP".to_string()));
    }
    let metadata: YubikeyMetadata =
        serde_json::from_str(tf_data).map_err(|_| AppError::Internal)?;
    let response_id = &response[..12];
    if !metadata.keys.iter().any(|k| k == response_id) {
        return Err(AppError::Unauthorized("Yubikey not registered".to_string()));
    }
    yubico_verify_otp(env, response).await
}

/// POST /api/two-factor/get-yubikey
#[worker::send]
pub async fn get_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    if !yubico_configured(&env) {
        return Err(AppError::BadRequest("Yubikey not configured".to_string()));
    }
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    let existing = find_twofactor(&db, &user_id, TwoFactorType::YubiKey as i32).await?;
    let (enabled, keys): (bool, Vec<String>) = match existing {
        Some(tf) => {
            let m: YubikeyMetadata =
                serde_json::from_str(&tf.data).map_err(|_| AppError::Internal)?;
            (true, m.keys)
        }
        None => (false, Vec::new()),
    };

    let mut obj = serde_json::Map::new();
    obj.insert("enabled".into(), json!(enabled));
    obj.insert("nfc".into(), json!(false));
    obj.insert("object".into(), json!("twoFactorYubikey"));
    for (i, k) in keys.iter().enumerate() {
        obj.insert(format!("key{}", i + 1), json!(k));
    }
    Ok(Json(Value::Object(obj)))
}

/// POST /api/two-factor/yubikey — activate
#[worker::send]
pub async fn activate_yubikey(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    if !yubico_configured(&env) {
        return Err(AppError::BadRequest("Yubikey not configured".to_string()));
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

    let raw_keys = [data.key1, data.key2, data.key3, data.key4, data.key5];
    let mut public_ids: Vec<String> = Vec::new();
    for k in raw_keys.into_iter().flatten() {
        let k = k.trim();
        if k.is_empty() || k.len() == 12 {
            continue;
        }
        if k.len() != 44 {
            return Err(AppError::BadRequest(
                "Invalid Yubikey OTP length".to_string(),
            ));
        }
        yubico_verify_otp(&env, k).await?;
        public_ids.push(k[..12].to_string());
    }
    if public_ids.is_empty() {
        return Err(AppError::BadRequest("No Yubikey provided".to_string()));
    }

    let metadata = YubikeyMetadata {
        keys: public_ids.clone(),
        nfc: data.nfc,
    };
    let data_str = serde_json::to_string(&metadata).map_err(|_| AppError::Internal)?;
    upsert_twofactor(&db, &user_id, TwoFactorType::YubiKey as i32, &data_str).await?;
    generate_recovery_code_for_user(&db, &user_id).await?;

    let mut obj = serde_json::Map::new();
    obj.insert("enabled".into(), json!(true));
    obj.insert("nfc".into(), json!(data.nfc));
    obj.insert("object".into(), json!("twoFactorYubikey"));
    for (i, k) in public_ids.iter().enumerate() {
        obj.insert(format!("key{}", i + 1), json!(k));
    }
    Ok(Json(Value::Object(obj)))
}

// ============================================================================
// Email 2FA
// ============================================================================

fn generate_email_token() -> Result<String, AppError> {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf)
        .map_err(|e| AppError::Crypto(format!("token generation failed: {e}")))?;
    let n = u32::from_le_bytes(buf) % 1_000_000;
    Ok(format!("{n:06}"))
}

/// Generate a fresh email token, store it as a challenge, and email it.
pub(crate) async fn send_email_otp(
    db: &crate::db::Db,
    env: &Arc<Env>,
    user_id: &str,
    email: &str,
) -> Result<(), AppError> {
    let token = generate_email_token()?;
    let now = chrono::Utc::now().timestamp();
    let data = EmailTokenData {
        email: email.to_string(),
        last_token: Some(token.clone()),
        token_sent: now,
        attempts: 0,
    };
    let data_str = serde_json::to_string(&data).map_err(|_| AppError::Internal)?;
    upsert_twofactor(
        db,
        user_id,
        TwoFactorType::EmailVerificationChallenge as i32,
        &data_str,
    )
    .await?;

    let subject = "Your Warden verification code";
    let body = format!("Your verification code is: {token}\n\n— Warden");
    mail::send(env, email, subject, &body).await?;
    Ok(())
}

/// Validate an email 2FA token during login.
pub(crate) async fn validate_email_login(
    db: &crate::db::Db,
    token: &str,
    tf: &TwoFactor,
) -> Result<(), AppError> {
    let mut data: EmailTokenData =
        serde_json::from_str(&tf.data).map_err(|_| AppError::Internal)?;
    let now = chrono::Utc::now().timestamp();
    if now - data.token_sent > 900 {
        return Err(AppError::Unauthorized("Email token expired".to_string()));
    }
    if data.attempts >= 5 {
        return Err(AppError::Unauthorized("Too many attempts".to_string()));
    }
    let valid = data.last_token.as_deref().is_some_and(|t| ct_eq(t, token));
    if !valid {
        data.attempts += 1;
        let updated = serde_json::to_string(&data).map_err(|_| AppError::Internal)?;
        d1_query!(
            db,
            "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
            &updated,
            &tf.uuid
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        return Err(AppError::Unauthorized("Invalid email token".to_string()));
    }
    data.last_token = None;
    data.attempts = 0;
    let updated = serde_json::to_string(&data).map_err(|_| AppError::Internal)?;
    d1_query!(
        db,
        "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
        &updated,
        &tf.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

/// POST /api/two-factor/get-email
#[worker::send]
pub async fn get_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    let existing = find_twofactor(&db, &user_id, TwoFactorType::Email as i32).await?;
    Ok(Json(json!({
        "email": user.email,
        "enabled": existing.is_some(),
        "object": "twoFactorEmail"
    })))
}

/// POST /api/two-factor/send-email — send a verification token (setup flow)
#[worker::send]
pub async fn send_email_2fa(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(&db, &env, &user, &user_id, &data).await?;

    send_email_otp(&db, &env, &user_id, &user.email).await?;
    Ok(Json(json!({})))
}

/// POST /api/two-factor/email — activate email 2FA by verifying the token
#[worker::send]
pub async fn activate_email(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<EnableEmailData>,
) -> Result<Json<Value>, AppError> {
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

    let challenge = find_twofactor(
        &db,
        &user_id,
        TwoFactorType::EmailVerificationChallenge as i32,
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("No email token requested".to_string()))?;

    validate_email_login(&db, &data.token, &challenge).await?;

    let data_str = serde_json::to_string(&EmailTokenData {
        email: user.email.clone(),
        last_token: None,
        token_sent: 0,
        attempts: 0,
    })
    .map_err(|_| AppError::Internal)?;
    upsert_twofactor(&db, &user_id, TwoFactorType::Email as i32, &data_str).await?;
    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(json!({
        "email": user.email,
        "enabled": true,
        "object": "twoFactorEmail"
    })))
}

// ============================================================================
// Recovery (unauthenticated — used when locked out)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryData {
    pub recovery_code: String,
    pub email: String,
}

/// POST /api/two-factor/recover — disable all 2FA using the recovery code.
#[worker::send]
pub async fn recover(
    State(env): State<Arc<Env>>,
    Json(data): Json<RecoveryData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = User::find_by_email(&db, &data.email.to_lowercase())
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid recovery code".to_string()))?;

    let valid = user
        .totp_recover
        .as_deref()
        .is_some_and(|c| ct_eq(&c.to_uppercase(), &data.recovery_code.to_uppercase()));
    if !valid {
        return Err(AppError::BadRequest("Invalid recovery code".to_string()));
    }

    d1_query!(&db, "DELETE FROM twofactor WHERE user_uuid = ?1", &user.id)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    d1_query!(
        &db,
        "UPDATE users SET totp_recover = NULL WHERE id = ?1",
        &user.id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    d1_query!(
        &db,
        "UPDATE devices SET twofactor_remember = NULL WHERE user_id = ?1",
        &user.id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(Json(json!({})))
}

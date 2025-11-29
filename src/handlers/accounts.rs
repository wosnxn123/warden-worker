use axum::{extract::State, Json};
use chrono::Utc;
use constant_time_eq::constant_time_eq;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, Env};

use crate::{
    auth::Claims,
    crypto::{generate_salt, hash_password_for_storage, verify_password},
    db,
    error::AppError,
    models::user::{DeleteAccountRequest, PreloginResponse, RegisterRequest, User},
};

#[worker::send]
pub async fn prelogin(
    State(env): State<Arc<Env>>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PreloginResponse>, AppError> {
    let email = payload["email"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("Missing email".to_string()))?;
    let db = db::get_db(&env)?;

    let stmt = db.prepare("SELECT kdf_iterations FROM users WHERE email = ?1");
    let query = stmt.bind(&[email.into()])?;
    let kdf_iterations: Option<i32> = query
        .first(Some("kdf_iterations"))
        .await
        .map_err(|_| AppError::Database)?;

    Ok(Json(PreloginResponse {
        kdf: 0, // PBKDF2
        kdf_iterations: kdf_iterations.unwrap_or(600_000),
    }))
}

#[worker::send]
pub async fn register(
    State(env): State<Arc<Env>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let allowed_emails = env
        .secret("ALLOWED_EMAILS")
        .map_err(|_| AppError::Internal)?;
    let allowed_emails = allowed_emails
        .as_ref()
        .as_string()
        .ok_or_else(|| AppError::Internal)?;
    if allowed_emails
        .split(",")
        .all(|email| email.trim() != payload.email)
    {
        return Err(AppError::Unauthorized("Not allowed to signup".to_string()));
    }

    // Generate salt and hash the password with server-side PBKDF2
    let password_salt = generate_salt()?;
    let hashed_password =
        hash_password_for_storage(&payload.master_password_hash, &password_salt).await?;

    let db = db::get_db(&env)?;
    let now = Utc::now().to_rfc3339();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: payload.name,
        email: payload.email.to_lowercase(),
        email_verified: false,
        master_password_hash: hashed_password,
        master_password_hint: payload.master_password_hint,
        password_salt: Some(password_salt),
        key: payload.user_symmetric_key,
        private_key: payload.user_asymmetric_keys.encrypted_private_key,
        public_key: payload.user_asymmetric_keys.public_key,
        kdf_type: payload.kdf,
        kdf_iterations: payload.kdf_iterations,
        security_stamp: Uuid::new_v4().to_string(),
        created_at: now.clone(),
        updated_at: now,
    };

    query!(
        &db,
        "INSERT INTO users (id, name, email, master_password_hash, password_salt, key, private_key, public_key, kdf_iterations, security_stamp, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
         user.id,
         user.name,
         user.email,
         user.master_password_hash,
         user.password_salt,
         user.key,
         user.private_key,
         user.public_key,
         user.kdf_iterations,
         user.security_stamp,
         user.created_at,
         user.updated_at
    ).map_err(|_|{
        AppError::Database
    })?
    .run()
    .await
    .map_err(|_|{
        AppError::Database
    })?;

    Ok(Json(json!({})))
}

#[worker::send]
pub async fn send_verification_email() -> Result<Json<String>, AppError> {
    Ok(Json("fixed-token-to-mock".to_string()))
}

#[worker::send]
pub async fn revision_date(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<Json<i64>, AppError> {
    let db = db::get_db(&env)? ;
    
    // get the user's updated_at timestamp
    let updated_at: Option<String> = db
        .prepare("SELECT updated_at FROM users WHERE id = ?1")
        .bind(&[claims.sub. into()])?
        .first(Some("updated_at"))
        .await
        .map_err(|_| AppError::Database)?;
        
    // convert the timestamp to a millisecond-level Unix timestamp
    let revision_date = updated_at
        .and_then(|ts| chrono::DateTime::parse_from_rfc3339(&ts). ok())
        . map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
    
    Ok(Json(revision_date))
}

#[worker::send]
pub async fn delete_account(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<DeleteAccountRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user_id = &claims.sub;

    // Get the user from the database
    let user: Value = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

    // Verify the master password hash
    let provided_hash = payload
        .master_password_hash
        .ok_or_else(|| AppError::BadRequest("Missing master password hash".to_string()))?;

    let is_valid = if let Some(ref salt) = user.password_salt {
        // New user with PBKDF2 hashed password
        verify_password(&provided_hash, &user.master_password_hash, salt).await?
    } else {
        // Legacy user: direct comparison (migration happens at login, not delete)
        constant_time_eq(
            user.master_password_hash.as_bytes(),
            provided_hash.as_bytes(),
        )
    };

    if !is_valid {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Delete all user's ciphers
    query!(&db, "DELETE FROM ciphers WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete all user's folders
    query!(&db, "DELETE FROM folders WHERE user_id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    // Delete the user
    query!(&db, "DELETE FROM users WHERE id = ?1", user_id)
        .map_err(|_| AppError::Database)?
        .run()
        .await?;

    Ok(Json(json!({})))
}

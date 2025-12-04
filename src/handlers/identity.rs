use axum::{extract::State, Form, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use worker::{query, Env};

use crate::{
    auth::Claims,
    crypto::{generate_salt, hash_password_for_storage},
    db,
    error::AppError,
    models::user::User,
};

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    username: Option<String>,
    password: Option<String>, // This is the masterPasswordHash
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Kdf")]
    kdf: i32,
    #[serde(rename = "KdfIterations")]
    kdf_iterations: i32,
    #[serde(rename = "KdfMemory", skip_serializing_if = "Option::is_none")]
    kdf_memory: Option<i32>,
    #[serde(rename = "KdfParallelism", skip_serializing_if = "Option::is_none")]
    kdf_parallelism: Option<i32>,
    #[serde(rename = "ResetMasterPassword")]
    reset_master_password: bool,
    #[serde(rename = "ForcePasswordReset")]
    force_password_reset: bool,
    #[serde(rename = "UserDecryptionOptions")]
    user_decryption_options: UserDecryptionOptions,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserDecryptionOptions {
    pub has_master_password: bool,
    pub object: String,
}

fn generate_tokens_and_response(
    user: User,
    env: &Arc<Env>,
) -> Result<Json<TokenResponse>, AppError> {
    let now = Utc::now();
    let expires_in = Duration::hours(1);
    let exp = (now + expires_in).timestamp() as usize;

    let access_claims = Claims {
        sub: user.id.clone(),
        exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.clone().unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };

    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let access_token = encode(
        &Header::default(),
        &access_claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )?;

    let refresh_expires_in = Duration::days(30);
    let refresh_exp = (now + refresh_expires_in).timestamp() as usize;
    let refresh_claims = Claims {
        sub: user.id.clone(),
        exp: refresh_exp,
        nbf: now.timestamp() as usize,
        premium: true,
        name: user.name.unwrap_or_else(|| "User".to_string()),
        email: user.email.clone(),
        email_verified: true,
        amr: vec!["Application".into()],
    };
    let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(jwt_refresh_secret.as_ref()),
    )?;

    Ok(Json(TokenResponse {
        access_token,
        expires_in: expires_in.num_seconds(),
        token_type: "Bearer".to_string(),
        refresh_token,
        key: user.key,
        private_key: user.private_key,
        kdf: user.kdf_type,
        kdf_iterations: user.kdf_iterations,
        kdf_memory: user.kdf_memory,
        kdf_parallelism: user.kdf_parallelism,
        force_password_reset: false,
        reset_master_password: false,
        user_decryption_options: UserDecryptionOptions {
            has_master_password: true,
            object: "userDecryptionOptions".to_string(),
        },
    }))
}

#[worker::send]
pub async fn token(
    State(env): State<Arc<Env>>,
    Form(payload): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let db = db::get_db(&env)?;
    match payload.grant_type.as_str() {
        "password" => {
            let username = payload
                .username
                .ok_or_else(|| AppError::BadRequest("Missing username".to_string()))?;
            let password_hash = payload
                .password
                .ok_or_else(|| AppError::BadRequest("Missing password".to_string()))?;

            // Check rate limit using email as key to prevent brute force attacks
            // This limits login attempts per email address, not per IP
            if let Ok(rate_limiter) = env.rate_limiter("LOGIN_RATE_LIMITER") {
                let rate_limit_key = format!("login:{}", username.to_lowercase());
                if let Ok(outcome) = rate_limiter.limit(rate_limit_key).await {
                    if !outcome.success {
                        return Err(AppError::TooManyRequests(
                            "Too many login attempts. Please try again later.".to_string(),
                        ));
                    }
                }
            }

            let user_value: Value = db
                .prepare("SELECT * FROM users WHERE email = ?1")
                .bind(&[username.to_lowercase().into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid credentials".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid credentials".to_string()))?;
            let user: User = serde_json::from_value(user_value).map_err(|_| AppError::Internal)?;

            let verification = user.verify_master_password(&password_hash).await?;

            if !verification.is_valid() {
                return Err(AppError::Unauthorized("Invalid credentials".to_string()));
            }

            // Migrate legacy user to PBKDF2 if password matches and no salt exists
            let user = if verification.needs_migration() {
                // Generate new salt and hash the password
                let new_salt = generate_salt()?;
                let new_hash = hash_password_for_storage(&password_hash, &new_salt).await?;
                let now = Utc::now().to_rfc3339();

                // Update user in database
                query!(
                    &db,
                    "UPDATE users SET master_password_hash = ?1, password_salt = ?2, updated_at = ?3 WHERE id = ?4",
                    &new_hash,
                    &new_salt,
                    &now,
                    &user.id
                )
                .map_err(|_| AppError::Database)?
                .run()
                .await
                .map_err(|_| AppError::Database)?;

                // Return updated user
                User {
                    master_password_hash: new_hash,
                    password_salt: Some(new_salt),
                    updated_at: now,
                    ..user
                }
            } else {
                user
            };

            generate_tokens_and_response(user, &env)
        }
        "refresh_token" => {
            let refresh_token = payload
                .refresh_token
                .ok_or_else(|| AppError::BadRequest("Missing refresh_token".to_string()))?;

            let jwt_refresh_secret = env.secret("JWT_REFRESH_SECRET")?.to_string();
            let token_data = decode::<Claims>(
                &refresh_token,
                &DecodingKey::from_secret(jwt_refresh_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| AppError::Unauthorized("Invalid refresh token".to_string()))?;

            let user_id = token_data.claims.sub;
            let user: Value = db
                .prepare("SELECT * FROM users WHERE id = ?1")
                .bind(&[user_id.into()])?
                .first(None)
                .await
                .map_err(|_| AppError::Unauthorized("Invalid user".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Invalid user".to_string()))?;
            let user: User = serde_json::from_value(user).map_err(|_| AppError::Internal)?;

            generate_tokens_and_response(user, &env)
        }
        _ => Err(AppError::BadRequest("Unsupported grant_type".to_string())),
    }
}

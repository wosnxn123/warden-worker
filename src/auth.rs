use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use constant_time_eq::constant_time_eq;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use worker::Env;

use crate::db;
use crate::error::AppError;

pub(crate) const JWT_VALIDATION_LEEWAY_SECS: u64 = 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,    // User ID
    pub exp: usize,     // Expiration time
    pub nbf: usize,     // Not before time
    pub sstamp: String, // Security stamp

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub amr: Vec<String>,
}

pub(crate) fn jwt_validation() -> Validation {
    let mut required_spec_claims = HashSet::new();
    required_spec_claims.insert("exp".to_string());

    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = required_spec_claims;
    validation.leeway = JWT_VALIDATION_LEEWAY_SECS;
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.algorithms = vec![Algorithm::HS256];
    validation
}

/// AuthUser extractor - provides (user_id, email) tuple
pub struct AuthUser(
    pub String, // user_id
    #[allow(dead_code)] // email is not used in this simplified version
    pub  String, // email
);

impl FromRequestParts<Arc<Env>> for Claims {
    type Rejection = AppError;
    #[worker::send]
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| {
                auth_value
                    .strip_prefix("Bearer ")
                    .map(|value| value.to_owned())
            })
            .ok_or_else(|| AppError::Unauthorized("Missing or invalid token".to_string()))?;

        let secret = state.secret("JWT_SECRET")?;

        // Decode and validate the token
        let decoding_key = DecodingKey::from_secret(secret.to_string().as_ref());
        let token_data = decode::<Claims>(&token, &decoding_key, &jwt_validation())
            .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

        let claims = token_data.claims;

        let db = db::get_db(state)?;
        let current_sstamp = db
            .prepare("SELECT security_stamp FROM users WHERE id = ?1")
            .bind(&[claims.sub.clone().into()])?
            .first::<String>(Some("security_stamp"))
            .await
            .map_err(|_| AppError::Database)?
            .ok_or_else(|| AppError::Unauthorized("Invalid token".to_string()))?;

        if !constant_time_eq(claims.sstamp.as_bytes(), current_sstamp.as_bytes()) {
            return Err(AppError::Unauthorized("Invalid token".to_string()));
        }

        Ok(claims)
    }
}

impl FromRequestParts<Arc<Env>> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<Env>,
    ) -> Result<Self, Self::Rejection> {
        let claims = Claims::from_request_parts(parts, state).await?;
        Ok(AuthUser(claims.sub, claims.email))
    }
}

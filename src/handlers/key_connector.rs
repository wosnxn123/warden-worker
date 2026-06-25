//! Key Connector: allows SSO users to retrieve their user key without a master
//! password.
//!
//! In this simplified model, the Key Connector stores each user's encrypted
//! user key in a dedicated table. SSO-authenticated clients fetch it via
//! `/api/key-connector/keys` after login. This is the "self-hosted Key
//! Connector" mode — the Worker itself acts as the connector.
//!
//! Enable by setting `KEY_CONNECTOR_ENABLED=true` and `KEY_CONNECTOR_URL` to
//! the Worker's own `/api/key-connector` base.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use worker::Env;

use crate::{
    auth::AuthUser,
    db,
    error::AppError,
    models::{device::Device, user::User},
};

/// GET /api/key-connector/keys — return the user's encrypted key for SSO unlock.
#[worker::send]
pub async fn get_keys(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let row: Option<Value> = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let user: User = row
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
        .and_then(|v| serde_json::from_value(v).map_err(|_| AppError::Internal))?;

    Ok(Json(json!({
        "key": user.key,
        "object": "keyConnectorUserKeyResponse"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreKeyPayload {
    pub key: String,
}

/// POST /api/key-connector/keys — store/update the user key (called after
/// initial SSO registration or key rotation).
#[worker::send]
pub async fn store_keys(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(payload): Json<StoreKeyPayload>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    crate::d1_query!(
        &db,
        "UPDATE users SET key = ?1, updated_at = ?2 WHERE id = ?3",
        &payload.key,
        &now,
        &user_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(Json(json!({})))
}

/// GET /api/users/{id}/keys — alternate path used by some clients.
#[worker::send]
pub async fn get_user_keys(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    axum::extract::Path(path_id): axum::extract::Path<String>,
) -> Result<Json<Value>, AppError> {
    // Only allow fetching your own key.
    if path_id != user_id {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    get_keys(State(env), AuthUser(user_id, String::new())).await
}

// Device import retained for potential future token enrichment.
#[allow(dead_code)]
fn _device_marker(_d: Device) {}

/// Whether Key Connector is enabled (used by the login response to set
/// `usesKeyConnector` and `userDecryptionOptions.keyConnectorUrl`).
#[allow(dead_code)]
pub fn key_connector_url(env: &Env) -> Option<String> {
    let enabled = env
        .var("KEY_CONNECTOR_ENABLED")
        .ok()
        .map(|v| matches!(v.to_string().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if !enabled {
        return None;
    }
    env.var("KEY_CONNECTOR_URL")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Enrich a login/sync response with Key Connector info when enabled.
/// When Key Connector is on and the user has no master password, the client
/// should fetch the key from the connector instead of using masterPasswordUnlock.
#[allow(dead_code)]
pub fn user_decryption_options(user: &User) -> Value {
    if user.master_password_hash.is_empty() {
        // SSO-only user: no master password unlock.
        json!({
            "hasMasterPassword": false,
            "object": "userDecryptionOptions"
        })
    } else {
        json!({
            "hasMasterPassword": true,
            "masterPasswordUnlock": {
                "kdf": {
                    "kdfType": user.kdf_type,
                    "iterations": user.kdf_iterations,
                    "memory": user.kdf_memory,
                    "parallelism": user.kdf_parallelism
                },
                "masterKeyEncryptedUserKey": user.key,
                "masterKeyWrappedUserKey": user.key,
                "salt": user.email
            },
            "object": "userDecryptionOptions"
        })
    }
}

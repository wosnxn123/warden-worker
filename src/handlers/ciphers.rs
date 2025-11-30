use super::get_batch_size;
use axum::{extract::State, Json};
use chrono::Utc;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use worker::{query, D1PreparedStatement, Env};

use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::models::cipher::{Cipher, CipherData, CipherRequestData, CreateCipherRequest};
use axum::extract::Path;

/// Execute D1 statements in batches, allowing batch_size 0 to run everything at once.
async fn execute_in_batches(
    db: &worker::D1Database,
    statements: Vec<D1PreparedStatement>,
    batch_size: usize,
) -> Result<(), AppError> {
    if statements.is_empty() {
        return Ok(());
    }

    if batch_size == 0 {
        db.batch(statements).await?;
    } else {
        for chunk in statements.chunks(batch_size) {
            db.batch(chunk.to_vec()).await?;
        }
    }

    Ok(())
}

#[worker::send]
pub async fn create_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CreateCipherRequest>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let cipher_data_req = payload.cipher;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: if payload.collection_ids.is_empty() {
            None
        } else {
            Some(payload.collection_ids)
        },
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,

         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    Ok(Json(cipher))
}

#[worker::send]
pub async fn update_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let existing_cipher: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    let cipher_data_req = payload;

    let cipher_data = CipherData {
        name: cipher_data_req.name,
        notes: cipher_data_req.notes,
        login: cipher_data_req.login,
        card: cipher_data_req.card,
        identity: cipher_data_req.identity,
        secure_note: cipher_data_req.secure_note,
        fields: cipher_data_req.fields,
        password_history: cipher_data_req.password_history,
        reprompt: cipher_data_req.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: id.clone(),
        user_id: Some(claims.sub.clone()),
        organization_id: cipher_data_req.organization_id.clone(),
        r#type: cipher_data_req.r#type,
        data: data_value,
        favorite: cipher_data_req.favorite,
        folder_id: cipher_data_req.folder_id.clone(),
        deleted_at: None,
        created_at: existing_cipher.created_at,
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "UPDATE ciphers SET organization_id = ?1, type = ?2, data = ?3, favorite = ?4, folder_id = ?5, updated_at = ?6 WHERE id = ?7 AND user_id = ?8",
        cipher.organization_id,
        cipher.r#type,
        data,
        cipher.favorite,
        cipher.folder_id,
        cipher.updated_at,
        id,
        claims.sub,
    ).map_err(|_|AppError::Database)?
    .run()
    .await?;

    Ok(Json(cipher))
}

/// Request body for bulk cipher operations
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdsData {
    pub ids: Vec<String>,
}

/// Soft delete a single cipher (PUT /api/ciphers/{id}/delete)
/// Sets deleted_at to current timestamp
#[worker::send]
pub async fn soft_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    query!(
        &db,
        "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(()))
}

/// Soft delete multiple ciphers (PUT /api/ciphers/delete)
#[worker::send]
pub async fn soft_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = get_batch_size(&env);
    let mut statements = Vec::with_capacity(payload.ids.len());

    for id in payload.ids {
        let stmt = query!(
            &db,
            "UPDATE ciphers SET deleted_at = ?1, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        statements.push(stmt);
    }

    execute_in_batches(&db, statements, batch_size).await?;

    Ok(Json(()))
}

/// Hard delete a single cipher (DELETE /api/ciphers/{id} or POST /api/ciphers/{id}/delete)
/// Permanently removes the cipher from database
#[worker::send]
pub async fn hard_delete_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;

    query!(
        &db,
        "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(()))
}

/// Hard delete multiple ciphers (DELETE /api/ciphers or POST /api/ciphers/delete)
#[worker::send]
pub async fn hard_delete_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<()>, AppError> {
    let db = db::get_db(&env)?;
    let batch_size = get_batch_size(&env);
    let mut statements = Vec::with_capacity(payload.ids.len());

    for id in payload.ids {
        let stmt = query!(
            &db,
            "DELETE FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        statements.push(stmt);
    }

    execute_in_batches(&db, statements, batch_size).await?;

    Ok(Json(()))
}

/// Restore a single cipher (PUT /api/ciphers/{id}/restore)
/// Clears the deleted_at timestamp
#[worker::send]
pub async fn restore_cipher(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Path(id): Path<String>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    // Update the cipher to clear deleted_at
    query!(
        &db,
        "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
        now,
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    // Fetch and return the restored cipher
    let cipher_db: crate::models::cipher::CipherDBModel = query!(
        &db,
        "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
        id,
        claims.sub
    )
    .map_err(|_| AppError::Database)?
    .first(None)
    .await?
    .ok_or(AppError::NotFound("Cipher not found".to_string()))?;

    Ok(Json(cipher_db.into()))
}

/// Response for bulk restore operation
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkRestoreResponse {
    pub data: Vec<Cipher>,
    pub object: String,
    pub continuation_token: Option<String>,
}

/// Restore multiple ciphers (PUT /api/ciphers/restore)
#[worker::send]
pub async fn restore_ciphers_bulk(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherIdsData>,
) -> Result<Json<BulkRestoreResponse>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let batch_size = get_batch_size(&env);
    let ids = payload.ids;
    let mut update_statements = Vec::with_capacity(ids.len());

    for id in ids.iter() {
        let stmt = query!(
            &db,
            "UPDATE ciphers SET deleted_at = NULL, updated_at = ?1 WHERE id = ?2 AND user_id = ?3",
            now,
            id.clone(),
            claims.sub
        )
        .map_err(|_| AppError::Database)?;

        update_statements.push(stmt);
    }

    execute_in_batches(&db, update_statements, batch_size).await?;

    let mut restored_ciphers = Vec::with_capacity(ids.len());

    for id in ids {
        let cipher_db: Option<crate::models::cipher::CipherDBModel> = query!(
            &db,
            "SELECT * FROM ciphers WHERE id = ?1 AND user_id = ?2",
            id,
            claims.sub
        )
        .map_err(|_| AppError::Database)?
        .first(None)
        .await?;

        if let Some(cipher) = cipher_db {
            restored_ciphers.push(cipher.into());
        }
    }

    Ok(Json(BulkRestoreResponse {
        data: restored_ciphers,
        object: "list".to_string(),
        continuation_token: None,
    }))
}

/// Handler for POST /api/ciphers
/// Accepts flat JSON structure (camelCase) as sent by Bitwarden clients
/// when creating a cipher without collection assignments.
#[worker::send]
pub async fn create_cipher_simple(
    claims: Claims,
    State(env): State<Arc<Env>>,
    Json(payload): Json<CipherRequestData>,
) -> Result<Json<Cipher>, AppError> {
    let db = db::get_db(&env)?;
    let now = Utc::now();
    let now = now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    let cipher_data = CipherData {
        name: payload.name,
        notes: payload.notes,
        login: payload.login,
        card: payload.card,
        identity: payload.identity,
        secure_note: payload.secure_note,
        fields: payload.fields,
        password_history: payload.password_history,
        reprompt: payload.reprompt,
    };

    let data_value = serde_json::to_value(&cipher_data).map_err(|_| AppError::Internal)?;

    let cipher = Cipher {
        id: Uuid::new_v4().to_string(),
        user_id: Some(claims.sub.clone()),
        organization_id: payload.organization_id.clone(),
        r#type: payload.r#type,
        data: data_value,
        favorite: payload.favorite,
        folder_id: payload.folder_id.clone(),
        deleted_at: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        object: "cipher".to_string(),
        organization_use_totp: false,
        edit: true,
        view_password: true,
        collection_ids: None,
    };

    let data = serde_json::to_string(&cipher.data).map_err(|_| AppError::Internal)?;

    query!(
        &db,
        "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
         cipher.id,
         cipher.user_id,
         cipher.organization_id,
         cipher.r#type,
         data,
         cipher.favorite,
         cipher.folder_id,
         cipher.created_at,
         cipher.updated_at,
    ).map_err(|_| AppError::Database)?
    .run()
    .await?;

    Ok(Json(cipher))
}

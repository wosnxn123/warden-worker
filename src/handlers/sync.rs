use axum::extract::State;
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::Claims,
    db,
    error::AppError,
    handlers::{attachments, ciphers},
    models::{
        folder::{Folder, FolderResponse},
        sync::Profile,
        user::User,
    },
};

use ciphers::RawJson;

#[worker::send]
pub async fn get_sync_data(
    claims: Claims,
    State(env): State<Arc<Env>>,
) -> Result<RawJson, AppError> {
    let user_id = claims.sub;
    let db = db::get_db(&env)?;

    // Fetch profile
    let user: User = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.clone().into()])?
        .first(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Fetch folders
    let folders_db: Vec<Folder> = db
        .prepare("SELECT * FROM folders WHERE user_id = ?1")
        .bind(&[user_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let folders: Vec<FolderResponse> = folders_db.into_iter().map(|f| f.into()).collect();

    // Fetch ciphers as raw JSON array string (no parsing in Rust!)
    let include_attachments = attachments::attachments_enabled(env.as_ref());
    let ciphers_json = ciphers::fetch_cipher_json_array_raw(
        &db,
        include_attachments,
        "WHERE c.user_id = ?1",
        &[user_id.clone().into()],
        "",
    )
    .await?;

    // Serialize profile and folders (small data, acceptable CPU cost)
    let profile = Profile::from_user(user)?;
    let profile_json = serde_json::to_string(&profile).map_err(|_| AppError::Internal)?;
    let folders_json = serde_json::to_string(&folders).map_err(|_| AppError::Internal)?;

    // Build response JSON via string concatenation (ciphers already raw JSON)
    let response = format!(
        r#"{{"profile":{},"folders":{},"collections":[],"policies":[],"ciphers":{},"domains":null,"sends":[],"object":"sync"}}"#,
        profile_json, folders_json, ciphers_json
    );

    Ok(RawJson(response))
}

//! Emergency access: designate a trusted contact who can view or take over
//! your vault after a configurable waiting period.
//!
//! Flow: invite → accept → confirm (key exchange) → initiate (grantee) →
//! approve/reject (grantor) → view / takeover (+ password reset).

use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use worker::Env;

use crate::{
    auth::AuthUser,
    db,
    error::AppError,
    mail,
    models::{
        emergency_access::{
            EmergencyAccess, EmergencyAccessType, STATUS_ACCEPTED, STATUS_APPROVED,
            STATUS_CONFIRMED, STATUS_INVITED, STATUS_RECOVERY_INITIATED,
        },
        user::User,
    },
};

// ── Request payloads ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteData {
    pub email: String,
    #[serde(rename = "type")]
    pub atype: i32,
    pub wait_time_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateData {
    #[serde(rename = "type")]
    pub atype: Option<i32>,
    pub wait_time_days: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmData {
    pub key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordResetData {
    pub new_master_password_hash: String,
    pub key: String,
}

// ── Helpers ─────────────────────────────────────────────────────────

async fn load_ea(db: &db::Db, id: &str) -> Result<EmergencyAccess, AppError> {
    EmergencyAccess::find_by_id(db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Emergency access not found".to_string()))
}

async fn load_user(db: &db::Db, id: &str) -> Result<User, AppError> {
    let row: Option<Value> = db
        .prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
        .transpose()?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

/// Resolve grantee email for a record: stored grantee_email, or the email of the
/// linked grantee user.
async fn resolve_grantee_email(db: &db::Db, ea: &EmergencyAccess) -> Option<String> {
    if let Some(uid) = &ea.grantee_id {
        let row: Option<Value> = db
            .prepare("SELECT email FROM users WHERE id = ?1")
            .bind(&[uid.clone().into()])
            .ok()?
            .first(None)
            .await
            .ok()?;
        if let Some(email) =
            row.and_then(|v| v.get("email").and_then(|x| x.as_str()).map(str::to_owned))
        {
            return Some(email);
        }
    }
    ea.grantee_email.clone()
}

fn recovery_wait_elapsed(ea: &EmergencyAccess) -> Result<bool, AppError> {
    let initiated = ea
        .recovery_initiated_at
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Recovery not initiated".to_string()))?;
    let initiated_ts = chrono::DateTime::parse_from_rfc3339(initiated)
        .map_err(|_| AppError::Internal)?
        .timestamp();
    let now = chrono::Utc::now().timestamp();
    Ok(now - initiated_ts >= i64::from(ea.wait_time_days) * 86_400)
}

// ── Endpoints ───────────────────────────────────────────────────────

/// GET /emergency-access/trusted — grantor's designated contacts.
#[worker::send]
pub async fn get_trusted_contacts(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let records = EmergencyAccess::list_by_grantor(&db, &user_id).await?;
    let mut data = Vec::with_capacity(records.len());
    for ea in records {
        let email = resolve_grantee_email(&db, &ea).await;
        data.push(ea.to_json(email.as_deref()));
    }
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// GET /emergency-access/granted — access granted to the current user (grantee).
#[worker::send]
pub async fn get_granted_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let records = EmergencyAccess::list_by_grantee(&db, &user_id).await?;
    let mut data = Vec::with_capacity(records.len());
    for ea in records {
        let email = resolve_grantee_email(&db, &ea).await;
        data.push(ea.to_json(email.as_deref()));
    }
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// GET /emergency-access/{id}
#[worker::send]
pub async fn get_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id && ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// PUT/POST /emergency-access/{id} — update type / wait time.
#[worker::send]
pub async fn post_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<UpdateData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_INVITED {
        return Err(AppError::BadRequest(
            "Cannot modify an accepted emergency access".to_string(),
        ));
    }
    if let Some(t) = data.atype {
        EmergencyAccessType::from_i32(t)
            .ok_or_else(|| AppError::BadRequest("Invalid type".to_string()))?;
        ea.atype = t;
    }
    if let Some(d) = data.wait_time_days {
        ea.wait_time_days = d;
    }
    ea.save(&db).await?;
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

#[worker::send]
pub async fn put_emergency_access(
    state: State<Arc<Env>>,
    auth: AuthUser,
    path: Path<String>,
    json: Json<UpdateData>,
) -> Result<Json<Value>, AppError> {
    post_emergency_access(state, auth, path, json).await
}

/// DELETE /emergency-access/{id} and POST /{id}/delete
#[worker::send]
pub async fn delete_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    // Grantor or grantee may remove the relationship.
    if ea.grantor_id != user_id && ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    EmergencyAccess::delete(&db, &id).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn post_delete_emergency_access(
    state: State<Arc<Env>>,
    auth: AuthUser,
    path: Path<String>,
) -> Result<Json<Value>, AppError> {
    delete_emergency_access(state, auth, path).await
}

/// POST /emergency-access/invite
#[worker::send]
pub async fn send_invite(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<InviteData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let email = data.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(AppError::BadRequest("Email is required".to_string()));
    }
    EmergencyAccessType::from_i32(data.atype)
        .ok_or_else(|| AppError::BadRequest("Invalid type".to_string()))?;

    // Prevent duplicates.
    let existing: Vec<EmergencyAccess> = EmergencyAccess::list_by_grantor(&db, &user_id).await?;
    if existing
        .iter()
        .any(|e| e.grantee_email.as_deref() == Some(email.as_str()))
    {
        return Err(AppError::BadRequest("Already invited".to_string()));
    }

    // If the invitee already has an account, link immediately as Accepted.
    let grantee = User::find_by_email(&db, &email).await?;
    let (grantee_id, status) = match &grantee {
        Some(u) => (Some(u.id.clone()), STATUS_ACCEPTED),
        None => (None, STATUS_INVITED),
    };

    let now = db::now_string();
    let ea = EmergencyAccess {
        id: uuid::Uuid::new_v4().to_string(),
        grantor_id: user_id.clone(),
        grantee_id,
        grantee_email: Some(email.clone()),
        key_encrypted: None,
        atype: data.atype,
        status,
        wait_time_days: data.wait_time_days.unwrap_or(7),
        recovery_initiated_at: None,
        created_at: now.clone(),
        updated_at: now,
    };
    ea.insert(&db).await?;

    let grantor = load_user(&db, &user_id).await?;
    let subject = "You've been invited as an emergency contact";
    let body = format!(
        "Hello,\n\n{} ({}) has invited you as an emergency access contact on Warden.\n\
         If you already have an account, log in and accept the invitation.\n\n\
         — Warden",
        grantor.name.clone().unwrap_or_default(),
        grantor.email
    );
    mail::send(&env, &email, subject, &body).await?;

    Ok(Json(ea.to_json(Some(&email))))
}

/// POST /emergency-access/{id}/reinvite
#[worker::send]
pub async fn resend_invite(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_INVITED && ea.status != STATUS_ACCEPTED {
        return Err(AppError::BadRequest(
            "Invite already accepted/confirmed".to_string(),
        ));
    }
    let email = ea
        .grantee_email
        .clone()
        .ok_or_else(|| AppError::BadRequest("No email on record".to_string()))?;
    let grantor = load_user(&db, &user_id).await?;
    let subject = "Reminder: emergency access invitation";
    let body = format!(
        "Hello,\n\nThis is a reminder that {} ({}) invited you as an emergency access contact.\n\n— Warden",
        grantor.name.clone().unwrap_or_default(),
        grantor.email
    );
    mail::send(&env, &email, subject, &body).await?;
    Ok(Json(json!({})))
}

/// POST /emergency-access/{id}/accept — grantee accepts the invite.
#[worker::send]
pub async fn accept_invite(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    // The invite is addressed to this user's email.
    let target_email = ea
        .grantee_email
        .clone()
        .ok_or_else(|| AppError::BadRequest("Invalid invitation".to_string()))?;
    let me = load_user(&db, &user_id).await?;
    if me.email.to_lowercase() != target_email.to_lowercase() {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_INVITED && ea.status != STATUS_ACCEPTED {
        return Err(AppError::BadRequest("Invalid status".to_string()));
    }
    ea.grantee_id = Some(user_id.clone());
    ea.status = STATUS_ACCEPTED;
    ea.save(&db).await?;
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// POST /emergency-access/{id}/confirm — grantor confirms (key exchange).
#[worker::send]
pub async fn confirm_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<ConfirmData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_ACCEPTED {
        return Err(AppError::BadRequest(
            "Invite must be accepted first".to_string(),
        ));
    }
    ea.key_encrypted = Some(data.key);
    ea.status = STATUS_CONFIRMED;
    ea.save(&db).await?;
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// POST /emergency-access/{id}/initiate — grantee starts recovery.
#[worker::send]
pub async fn initiate_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    if ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_CONFIRMED {
        return Err(AppError::BadRequest(
            "Emergency access must be confirmed first".to_string(),
        ));
    }
    ea.status = STATUS_RECOVERY_INITIATED;
    ea.recovery_initiated_at = Some(db::now_string());
    ea.save(&db).await?;

    // Notify the grantor.
    if let Ok(grantor) = load_user(&db, &ea.grantor_id).await {
        let subject = "Emergency access request initiated";
        let body = format!(
            "Hello {},\n\nAn emergency access request was just initiated for your account. \
             You have {} day(s) to approve or reject it.\n\n— Warden",
            grantor.name.clone().unwrap_or_default(),
            ea.wait_time_days
        );
        let _ = mail::send(&env, &grantor.email, subject, &body).await;
    }
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// POST /emergency-access/{id}/approve — grantor approves (immediate access).
#[worker::send]
pub async fn approve_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_RECOVERY_INITIATED {
        return Err(AppError::BadRequest(
            "No pending recovery request".to_string(),
        ));
    }
    ea.status = STATUS_APPROVED;
    ea.save(&db).await?;
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// POST /emergency-access/{id}/reject — grantor rejects; back to confirmed.
#[worker::send]
pub async fn reject_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut ea = load_ea(&db, &id).await?;
    if ea.grantor_id != user_id {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.status != STATUS_RECOVERY_INITIATED && ea.status != STATUS_APPROVED {
        return Err(AppError::BadRequest(
            "No pending recovery request".to_string(),
        ));
    }
    ea.status = STATUS_CONFIRMED;
    ea.recovery_initiated_at = None;
    ea.save(&db).await?;
    let email = resolve_grantee_email(&db, &ea).await;
    Ok(Json(ea.to_json(email.as_deref())))
}

/// Ensure the grantee is allowed to view/takeover: approved, or recovery
/// initiated past the waiting period.
fn ensure_access_granted(ea: &EmergencyAccess) -> Result<(), AppError> {
    match ea.status {
        STATUS_APPROVED => Ok(()),
        STATUS_RECOVERY_INITIATED => {
            if recovery_wait_elapsed(ea)? {
                Ok(())
            } else {
                Err(AppError::BadRequest(
                    "Waiting period has not elapsed".to_string(),
                ))
            }
        }
        _ => Err(AppError::BadRequest(
            "Recovery has not been initiated or approved".to_string(),
        )),
    }
}

/// POST /emergency-access/{id}/view — get the encrypted key (View type).
#[worker::send]
pub async fn view_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.atype != EmergencyAccessType::View as i32 {
        return Err(AppError::BadRequest("Not a view-type access".to_string()));
    }
    ensure_access_granted(&ea)?;

    let key = ea.key_encrypted.clone().ok_or_else(|| AppError::Internal)?;
    Ok(Json(json!({ "key": key, "object": "emergencyAccessView" })))
}

/// POST /emergency-access/{id}/takeover — get grantor key/private key (Takeover type).
#[worker::send]
pub async fn takeover_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.atype != EmergencyAccessType::Takeover as i32 {
        return Err(AppError::BadRequest(
            "Not a takeover-type access".to_string(),
        ));
    }
    ensure_access_granted(&ea)?;

    let grantor = load_user(&db, &ea.grantor_id).await?;
    let key = ea.key_encrypted.clone().ok_or_else(|| AppError::Internal)?;
    Ok(Json(json!({
        "key": key,
        "privateKey": grantor.private_key,
        "masterPasswordHash": grantor.master_password_hash,
        "object": "emergencyAccessTakeover"
    })))
}

/// POST /emergency-access/{id}/password — finalize takeover: reset grantor's
/// master password and keys.
#[worker::send]
pub async fn password_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<PasswordResetData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    if ea.atype != EmergencyAccessType::Takeover as i32 {
        return Err(AppError::BadRequest(
            "Not a takeover-type access".to_string(),
        ));
    }
    ensure_access_granted(&ea)?;

    // Rotate security stamp to invalidate all existing sessions of the grantor.
    let new_stamp = uuid::Uuid::new_v4().to_string();
    let now = db::now_string();
    crate::d1_query!(
        &db,
        "UPDATE users SET master_password_hash = ?1, key = ?2, security_stamp = ?3, updated_at = ?4 WHERE id = ?5",
        &data.new_master_password_hash,
        &data.key,
        &new_stamp,
        &now,
        &ea.grantor_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Revoke all of the grantor's devices.
    crate::models::device::Device::delete_all_by_user(&db, &ea.grantor_id).await?;

    Ok(Json(json!({})))
}

/// GET /emergency-access/{id}/policies — org policies of the grantor (Takeover).
/// We don't yet support organizations, so return an empty list.
#[worker::send]
pub async fn policies_emergency_access(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let ea = load_ea(&db, &id).await?;
    if ea.grantee_id.as_deref() != Some(&user_id) {
        return Err(AppError::NotFound("Emergency access not found".to_string()));
    }
    Ok(Json(
        json!({ "data": [], "object": "list", "continuationToken": null }),
    ))
}

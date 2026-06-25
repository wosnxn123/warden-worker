//! SCIM 2.0 (RFC 7643/7644) endpoints for directory sync.
//!
//! Bitwarden uses SCIM to let identity providers (Entra ID, Okta, etc.)
//! provision users and groups into an organization. Each org gets an API key;
//! SCIM requests authenticate with `Bearer {org_id}:{api_key}`.
//!
//! Mappings:
//!   SCIM User  → users_organizations membership (invite/activate/deactivate)
//!   SCIM Group → groups + groups_users (collection-less org groups)
//!
//! Content-Type is `application/scim+json`; we parse bodies manually to avoid
//! axum's `application/json`-only Json extractor.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::Env;

use crate::{
    db,
    error::AppError,
    models::organization::{Membership, MembershipType, STATUS_CONFIRMED, STATUS_INVITED},
};

const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_LIST_RESPONSE: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

// ── Auth ────────────────────────────────────────────────────────────

/// Verify SCIM auth: `Bearer {org_id}:{api_key}`.
/// Returns the validated org_id.
async fn verify_scim_auth(
    db: &db::Db,
    headers: &HeaderMap,
    path_org_id: &str,
) -> Result<String, AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(scim_unauthorized)?;

    // Format: "{org_id}:{api_key}" OR just "{api_key}" with org from path.
    let (org_id, api_key) = if let Some((o, k)) = auth.split_once(':') {
        (o.to_string(), k.to_string())
    } else {
        (path_org_id.to_string(), auth.to_string())
    };

    if org_id != path_org_id {
        return Err(scim_unauthorized());
    }

    // Hash the provided key and look it up.
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let row: Option<Value> = db
        .prepare("SELECT 1 FROM organization_api_keys WHERE org_id = ?1 AND api_key_hash = ?2")
        .bind(&[org_id.clone().into(), key_hash.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    if row.is_none() {
        return Err(scim_unauthorized());
    }
    Ok(org_id)
}

fn scim_unauthorized() -> AppError {
    let resp = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": "Invalid credentials",
        "status": "401"
    });
    // Reuse BadRequest but we'll override status in the response.
    AppError::ScimError(StatusCode::UNAUTHORIZED, resp)
}

fn scim_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/scim+json")],
        axum::Json(body),
    )
        .into_response()
}

// ── List query params ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ScimListQuery {
    #[serde(default = "default_start")]
    pub start_index: u64,
    #[serde(default = "default_count")]
    pub count: u64,
    pub filter: Option<String>,
}

fn default_start() -> u64 {
    1
}
fn default_count() -> u64 {
    100
}

/// Parse a simple SCIM filter like `userName eq "user@example.com"` or
/// `emails.value eq "..."`. Returns an optional SQL WHERE fragment + bind value.
fn parse_scim_filter(filter: &str) -> Option<(String, String)> {
    // Very simplified: "attr eq \"value\"" or "attr eq value"
    let filter = filter.trim();
    let eq_idx = filter.find(" eq ")?;
    let attr = filter[..eq_idx].trim();
    let mut val = filter[eq_idx + 4..].trim().to_string();
    if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
        val = val[1..val.len() - 1].to_string();
    }
    match attr {
        "userName" | "emails.value" => {
            Some(("LOWER(u.email) = ?1".to_string(), val.to_lowercase()))
        }
        "displayName" => Some(("LOWER(u.name) = ?1".to_string(), val.to_lowercase())),
        _ => None,
    }
}

// ── Users ───────────────────────────────────────────────────────────

/// GET /scim/v2/{org_id}/Users
#[worker::send]
pub async fn list_users(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ScimListQuery>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let (where_clause, bind_val) = match query.filter.as_deref() {
        Some(f) if !f.is_empty() => match parse_scim_filter(f) {
            Some((wc, v)) => (format!("AND {wc}"), Some(v)),
            None => (String::new(), None),
        },
        _ => (String::new(), None),
    };

    let sql = format!(
        "SELECT uo.id, uo.user_id, uo.status, uo.atype, u.email, u.name
         FROM users_organizations uo
         JOIN users u ON u.id = uo.user_id
         WHERE uo.org_id = ?1 {where_clause}
         ORDER BY uo.created_at ASC"
    );

    let rows: Vec<Value> = if let Some(v) = bind_val {
        db.prepare(&sql)
            .bind(&[org_id.clone().into(), v.into()])?
            .all()
            .await?
            .results()?
    } else {
        db.prepare(&sql)
            .bind(&[org_id.clone().into()])?
            .all()
            .await?
            .results()?
    };

    let total = rows.len() as u64;
    let resources: Vec<Value> = rows.iter().map(|r| user_to_scim(r, &org_id)).collect();

    Ok(scim_response(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": total,
            "itemsPerPage": query.count,
            "startIndex": query.start_index,
            "Resources": resources
        }),
    ))
}

fn user_to_scim(row: &Value, org_id: &str) -> Value {
    let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let email = row.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let status = row.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    let active = status == STATUS_CONFIRMED as i64;
    json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": id,
        "externalId": row.get("user_id").and_then(|v| v.as_str()).unwrap_or(""),
        "userName": email,
        "displayName": name,
        "active": active,
        "emails": [{ "value": email, "primary": true, "type": "work" }],
        "groups": [],
        "meta": {
            "resourceType": "User",
            "location": format!("/scim/v2/{org_id}/Users/{id}")
        }
    })
}

/// POST /scim/v2/{org_id}/Users — provision (invite) a user.
#[worker::send]
pub async fn create_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| scim_bad_request("Invalid SCIM User payload"))?;

    let email = payload
        .get("userName")
        .and_then(|v| v.as_str())
        .or_else(|| {
            payload
                .get("emails")
                .and_then(|e| e.get(0))
                .and_then(|e| e.get("value"))
                .and_then(|v| v.as_str())
        })
        .ok_or_else(|| scim_bad_request("userName or emails[0].value required"))?
        .to_lowercase();

    let display_name = payload
        .get("displayName")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    // Find or create the user account (SCIM provisioned users may not have registered yet).
    let mut user = crate::models::user::User::find_by_email(&db, &email).await?;
    if user.is_none() {
        // Create a placeholder account (no master password yet).
        let now = db::now_string();
        let uid = uuid::Uuid::new_v4().to_string();
        crate::d1_query!(
            &db,
            "INSERT INTO users (id, name, email, email_verified, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, security_stamp, created_at, updated_at)
             VALUES (?1, ?2, ?3, 1, '', '', '', '', 0, 600000, ?4, ?5, ?6)",
            &uid,
            display_name.as_deref(),
            &email,
            &uuid::Uuid::new_v4().to_string(),
            &now,
            &now
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await?;
        user = crate::models::user::User::find_by_email(&db, &email).await?;
    }

    let user = user.ok_or_else(|| AppError::Internal)?;
    let now = db::now_string();

    // Invite into the org (or reuse existing membership).
    let existing = Membership::find_by_user_and_org(&db, &user.id, &org_id).await?;
    let member_id = if let Some(m) = existing {
        m.id
    } else {
        let m = Membership {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            org_id: org_id.clone(),
            invited_by_email: None,
            access_all: true,
            akey: String::new(),
            status: STATUS_CONFIRMED,
            atype: MembershipType::User as i32,
            reset_password_key: None,
            external_id: Some(email.clone()),
            created_at: now.clone(),
            updated_at: now,
        };
        m.insert(&db).await?;
        m.id
    };

    let row = json!({
        "id": member_id,
        "user_id": user.id,
        "status": STATUS_CONFIRMED,
        "email": email,
        "name": display_name.unwrap_or_default()
    });
    Ok(scim_response(
        StatusCode::CREATED,
        user_to_scim(&row, &org_id),
    ))
}

/// GET /scim/v2/{org_id}/Users/{id}
#[worker::send]
pub async fn get_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let row: Option<Value> = db
        .prepare(
            "SELECT uo.id, uo.user_id, uo.status, uo.atype, u.email, u.name
             FROM users_organizations uo
             JOIN users u ON u.id = uo.user_id
             WHERE uo.org_id = ?1 AND uo.id = ?2",
        )
        .bind(&[org_id.clone().into(), member_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let row = row.ok_or_else(|| scim_not_found("User"))?;
    Ok(scim_response(StatusCode::OK, user_to_scim(&row, &org_id)))
}

/// PUT /scim/v2/{org_id}/Users/{id} — replace user (update active status).
#[worker::send]
pub async fn replace_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| scim_bad_request("Invalid payload"))?;
    let active = payload
        .get("active")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let mut m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| scim_not_found("User"))?;
    if m.org_id != org_id {
        return Err(scim_not_found("User"));
    }
    m.status = if active {
        STATUS_CONFIRMED
    } else {
        STATUS_INVITED
    };
    m.save(&db).await?;

    let row = json!({
        "id": m.id, "user_id": m.user_id, "status": m.status,
        "email": "", "name": ""
    });
    Ok(scim_response(StatusCode::OK, user_to_scim(&row, &org_id)))
}

/// PATCH /scim/v2/{org_id}/Users/{id} — patch (typically activate/deactivate).
#[worker::send]
pub async fn patch_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| scim_bad_request("Invalid patch payload"))?;

    let mut m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| scim_not_found("User"))?;
    if m.org_id != org_id {
        return Err(scim_not_found("User"));
    }

    // SCIM PATCH Operations: [{ "op": "replace", "path": "active", "value": false }]
    if let Some(ops) = payload.get("Operations").and_then(|v| v.as_array()) {
        for op in ops {
            let op_type = op.get("op").and_then(|v| v.as_str()).unwrap_or("");
            let path = op.get("path").and_then(|v| v.as_str()).unwrap_or("");
            if op_type == "replace" && path == "active" {
                let active = op.get("value").and_then(|v| v.as_bool()).unwrap_or(true);
                m.status = if active {
                    STATUS_CONFIRMED
                } else {
                    STATUS_INVITED
                };
            }
        }
    }
    m.save(&db).await?;

    Ok(scim_response(StatusCode::OK, json!({})))
}

/// DELETE /scim/v2/{org_id}/Users/{id} — deprovision (remove from org).
#[worker::send]
pub async fn delete_user(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| scim_not_found("User"))?;
    if m.org_id != org_id {
        return Err(scim_not_found("User"));
    }
    Membership::delete(&db, &member_id).await?;
    Ok(scim_response(StatusCode::NO_CONTENT, json!({})))
}

// ── Groups ──────────────────────────────────────────────────────────

fn group_to_scim(row: &Value, org_id: &str) -> Value {
    let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("");
    json!({
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": id,
        "displayName": row.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        "members": [],
        "meta": {
            "resourceType": "Group",
            "location": format!("/scim/v2/{org_id}/Groups/{id}")
        }
    })
}

/// GET /scim/v2/{org_id}/Groups
#[worker::send]
pub async fn list_groups(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(query): Query<ScimListQuery>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let rows: Vec<Value> = db
        .prepare("SELECT id, name FROM groups WHERE org_id = ?1 ORDER BY created_at ASC")
        .bind(&[org_id.clone().into()])?
        .all()
        .await?
        .results()?;

    let resources: Vec<Value> = rows.iter().map(|r| group_to_scim(r, &org_id)).collect();
    Ok(scim_response(
        StatusCode::OK,
        json!({
            "schemas": [SCIM_LIST_RESPONSE],
            "totalResults": resources.len(),
            "itemsPerPage": query.count,
            "startIndex": query.start_index,
            "Resources": resources
        }),
    ))
}

/// POST /scim/v2/{org_id}/Groups
#[worker::send]
pub async fn create_group(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    body: Bytes,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    let payload: Value =
        serde_json::from_slice(&body).map_err(|_| scim_bad_request("Invalid Group payload"))?;
    let name = payload
        .get("displayName")
        .and_then(|v| v.as_str())
        .ok_or_else(|| scim_bad_request("displayName required"))?;

    let now = db::now_string();
    let gid = uuid::Uuid::new_v4().to_string();
    crate::d1_query!(
        &db,
        "INSERT INTO groups (id, org_id, name, access_all, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5)",
        &gid, &org_id, name, &now, &now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;

    let row = json!({ "id": gid, "name": name });
    Ok(scim_response(
        StatusCode::CREATED,
        group_to_scim(&row, &org_id),
    ))
}

/// DELETE /scim/v2/{org_id}/Groups/{id}
#[worker::send]
pub async fn delete_group(
    State(env): State<Arc<Env>>,
    headers: HeaderMap,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Response, AppError> {
    let db = db::get_db(&env)?;
    let _ = verify_scim_auth(&db, &headers, &org_id).await?;

    crate::d1_query!(
        &db,
        "DELETE FROM groups WHERE id = ?1 AND org_id = ?2",
        &group_id,
        &org_id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await?;
    Ok(scim_response(StatusCode::NO_CONTENT, json!({})))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn scim_bad_request(msg: &str) -> AppError {
    AppError::ScimError(
        StatusCode::BAD_REQUEST,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": msg,
            "status": "400"
        }),
    )
}

fn scim_not_found(resource: &str) -> AppError {
    AppError::ScimError(
        StatusCode::NOT_FOUND,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": format!("{resource} not found"),
            "status": "404"
        }),
    )
}

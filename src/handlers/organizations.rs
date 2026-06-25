//! Organizations & sharing: create orgs, manage members, collections, policies,
//! and bulk-import into an organization.

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
        collection::{Collection, CollectionCipher, CollectionUser},
        org_policy::OrgPolicy,
        organization::{
            Membership, MembershipType, Organization, STATUS_ACCEPTED, STATUS_CONFIRMED,
            STATUS_INVITED,
        },
        user::User,
    },
};

// ── Request payloads ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrgData {
    pub name: String,
    pub key: String, // org key, encrypted for the creating user
    pub keys: OrgKeyData,
    pub billing_email: Option<String>,
    pub collection_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyData {
    pub public_key: String,
    pub encrypted_private_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteUserData {
    pub emails: Vec<String>,
    #[serde(rename = "type")]
    pub atype: i32,
    pub access_all: Option<bool>,
    pub collections: Option<Vec<CollectionAccess>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionAccess {
    pub id: String,
    pub read_only: Option<bool>,
    pub hide_passwords: Option<bool>,
    pub manage: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmUserData {
    pub key: String, // org key, encrypted for the grantee's public key
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserData {
    #[serde(rename = "type")]
    pub atype: Option<i32>,
    pub access_all: Option<bool>,
    pub collections: Option<Vec<CollectionAccess>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCollectionData {
    pub name: String,
    pub external_id: Option<String>,
    // Optional initial user assignments
    #[allow(dead_code)]
    pub groups: Option<Vec<Value>>,
    pub users: Option<Vec<CollectionUserAccess>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionUserAccess {
    pub id: String,
    pub read_only: Option<bool>,
    pub hide_passwords: Option<bool>,
    pub manage: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCollectionData {
    pub name: String,
    pub external_id: Option<String>,
    #[allow(dead_code)]
    pub groups: Option<Vec<Value>>,
    pub users: Option<Vec<CollectionUserAccess>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePolicyData {
    pub enabled: bool,
    pub data: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportData {
    pub collections: Vec<OrgImportCollection>,
    pub ciphers: Vec<OrgImportCipher>,
    pub collection_relationships: Vec<OrgImportRelationship>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportCollection {
    pub id: Option<String>,
    pub name: String,
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportCipher {
    #[serde(flatten)]
    pub cipher: crate::models::cipher::CipherRequestData,
    #[allow(dead_code)]
    pub collection_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportRelationship {
    pub cipher_index: usize,
    pub collection_index: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupData {
    pub name: String,
    pub access_all: Option<bool>,
    pub external_id: Option<String>,
    #[allow(dead_code)]
    pub users: Option<Vec<GroupUserAccess>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupUserAccess {
    pub id: String,
}

// ── Helpers ─────────────────────────────────────────────────────────

async fn get_confirmed_membership(
    db: &db::Db,
    user_id: &str,
    org_id: &str,
) -> Result<Membership, AppError> {
    Membership::find_by_user_and_org(db, user_id, org_id)
        .await?
        .filter(|m| m.status == STATUS_CONFIRMED)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))
}

async fn require_admin(db: &db::Db, user_id: &str, org_id: &str) -> Result<Membership, AppError> {
    let m = get_confirmed_membership(db, user_id, org_id).await?;
    if !MembershipType::from_i32(m.atype)
        .map(|t| t.has_admin_rights())
        .unwrap_or(false)
    {
        return Err(AppError::Unauthorized("Admin access required".to_string()));
    }
    Ok(m)
}

async fn load_user_email(db: &db::Db, user_id: &str) -> Result<String, AppError> {
    let row: Option<Value> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[user_id.to_string().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    row.and_then(|v| v.get("email").and_then(|x| x.as_str()).map(str::to_owned))
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

// ── Organization CRUD ───────────────────────────────────────────────

/// POST /api/organizations
#[worker::send]
pub async fn create_organization(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, email): AuthUser,
    Json(data): Json<CreateOrgData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let now = db::now_string();
    let org_id = uuid::Uuid::new_v4().to_string();

    let org = Organization {
        id: org_id.clone(),
        name: data.name.clone(),
        billing_email: data.billing_email.unwrap_or_else(|| email.clone()),
        private_key: Some(data.keys.encrypted_private_key.clone()),
        public_key: Some(data.keys.public_key.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    org.insert(&db).await?;

    // Owner membership with access to all collections.
    let membership = Membership {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.clone(),
        org_id: org_id.clone(),
        invited_by_email: Some(email),
        access_all: true,
        akey: data.key.clone(),
        status: STATUS_CONFIRMED,
        atype: MembershipType::Owner as i32,
        reset_password_key: None,
        external_id: None,
        created_at: now.clone(),
        updated_at: now,
    };
    membership.insert(&db).await?;

    // Optional default collection.
    if let Some(coll_name) = data.collection_name {
        let coll = Collection {
            id: uuid::Uuid::new_v4().to_string(),
            org_id: org_id.clone(),
            name: coll_name,
            external_id: None,
            created_at: db::now_string(),
            updated_at: db::now_string(),
        };
        coll.insert(&db).await?;
    }

    crate::db::touch_user_updated_at(&db, &user_id, &db::now_string()).await?;
    Ok(Json(org.to_json()))
}

/// GET /api/organizations/{id}
#[worker::send]
pub async fn get_organization(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    get_confirmed_membership(&db, &user_id, &id).await?;
    let org = Organization::find_by_id(&db, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    Ok(Json(org.to_json()))
}

/// DELETE /api/organizations/{id} (owner only)
#[worker::send]
pub async fn delete_organization(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = require_admin(&db, &user_id, &id).await?;
    if m.atype != MembershipType::Owner as i32 {
        return Err(AppError::Unauthorized("Only owners can delete".to_string()));
    }
    Organization::delete(&db, &id).await?;
    Ok(Json(json!({})))
}

/// POST /api/organizations/{id}/leave
#[worker::send]
pub async fn leave_organization(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = get_confirmed_membership(&db, &user_id, &id).await?;
    Membership::delete(&db, &m.id).await?;
    Ok(Json(json!({})))
}

// ── Members ─────────────────────────────────────────────────────────

/// GET /api/organizations/{id}/users
#[worker::send]
pub async fn list_users(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &id).await?;
    let members = Membership::list_by_org(&db, &id).await?;
    let mut data = Vec::with_capacity(members.len());
    for m in members {
        let (email, name) = if m.status == STATUS_INVITED {
            (m.invited_by_email.clone().unwrap_or_default(), None)
        } else {
            let email = load_user_email(&db, &m.user_id).await.unwrap_or_default();
            let name: Option<String> = match db
                .prepare("SELECT name FROM users WHERE id = ?1")
                .bind(&[m.user_id.clone().into()])
            {
                Ok(stmt) => stmt.first::<String>(Some("name")).await.ok().flatten(),
                Err(_) => None,
            };
            (email, name)
        };
        data.push(m.to_user_json(&email, name.as_deref()));
    }
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// POST /api/organizations/{id}/users/invite
#[worker::send]
pub async fn invite_users(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, inviter_email): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<InviteUserData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &id).await?;
    MembershipType::from_i32(data.atype)
        .ok_or_else(|| AppError::BadRequest("Invalid member type".to_string()))?;
    let org = Organization::find_by_id(&db, &id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    for raw_email in &data.emails {
        let email = raw_email.trim().to_lowercase();
        if email.is_empty() {
            continue;
        }
        // Skip if already a member.
        let existing = User::find_by_email(&db, &email).await?;
        if let Some(ref u) = existing {
            if Membership::find_by_user_and_org(&db, &u.id, &id)
                .await?
                .is_some()
            {
                continue;
            }
        }

        let now = db::now_string();
        let (uid, status) = match &existing {
            Some(u) => (Some(u.id.clone()), STATUS_INVITED),
            None => (None, STATUS_INVITED),
        };
        let membership = Membership {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: uid.unwrap_or_default(),
            org_id: id.clone(),
            invited_by_email: Some(inviter_email.clone()),
            access_all: data.access_all.unwrap_or(false),
            akey: String::new(), // set at confirm time
            status,
            atype: data.atype,
            reset_password_key: None,
            external_id: None,
            created_at: now.clone(),
            updated_at: now,
        };
        membership.insert(&db).await?;

        // Optional initial collection access.
        if let Some(colls) = &data.collections {
            if let Some(u) = &existing {
                for c in colls {
                    let cu = CollectionUser {
                        user_id: u.id.clone(),
                        collection_id: c.id.clone(),
                        read_only: c.read_only.unwrap_or(false),
                        hide_passwords: c.hide_passwords.unwrap_or(false),
                        manage: c.manage.unwrap_or(false),
                    };
                    cu.upsert(&db).await?;
                }
            }
        }

        let subject = format!("You've been invited to {}", org.name);
        let body = format!(
            "Hello,\n\nYou've been invited to join the organization \"{}\" on Warden.\n\
             Log in and accept the invitation.\n\n— Warden",
            org.name
        );
        let _ = mail::send(&env, &email, &subject, &body).await;
    }
    Ok(Json(json!({})))
}

/// POST /api/organizations/{org_id}/users/{id}/accept
#[worker::send]
pub async fn accept_user(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let mut m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Invitation not found".to_string()))?;
    if m.org_id != org_id {
        return Err(AppError::NotFound("Invitation not found".to_string()));
    }
    if m.user_id.is_empty() {
        m.user_id = user_id.clone();
    } else if m.user_id != user_id {
        return Err(AppError::NotFound("Invitation not found".to_string()));
    }
    m.status = STATUS_ACCEPTED;
    m.save(&db).await?;
    Ok(Json(json!({})))
}

/// POST /api/organizations/{org_id}/users/{id}/confirm
#[worker::send]
pub async fn confirm_user(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<ConfirmUserData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let mut m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Member not found".to_string()))?;
    if m.org_id != org_id || m.status != STATUS_ACCEPTED {
        return Err(AppError::BadRequest("Member must accept first".to_string()));
    }
    m.akey = data.key;
    m.status = STATUS_CONFIRMED;
    m.save(&db).await?;
    Ok(Json(json!({})))
}

/// PUT /api/organizations/{org_id}/users/{id}
#[worker::send]
pub async fn update_user(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<UpdateUserData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let mut m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Member not found".to_string()))?;
    if let Some(t) = data.atype {
        MembershipType::from_i32(t)
            .ok_or_else(|| AppError::BadRequest("Invalid member type".to_string()))?;
        m.atype = t;
    }
    if let Some(a) = data.access_all {
        m.access_all = a;
    }
    m.save(&db).await?;

    // Reassign collection access.
    if let Some(colls) = data.collections {
        crate::d1_query!(
            &db,
            "DELETE FROM users_collections WHERE user_id = ?1 AND collection_id IN (SELECT id FROM collections WHERE org_id = ?2)",
            &m.user_id,
            &org_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        for c in colls {
            let cu = CollectionUser {
                user_id: m.user_id.clone(),
                collection_id: c.id.clone(),
                read_only: c.read_only.unwrap_or(false),
                hide_passwords: c.hide_passwords.unwrap_or(false),
                manage: c.manage.unwrap_or(false),
            };
            cu.upsert(&db).await?;
        }
    }
    Ok(Json(json!({})))
}

/// DELETE /api/organizations/{org_id}/users/{id}
#[worker::send]
pub async fn remove_user(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let m = Membership::find_by_id(&db, &member_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Member not found".to_string()))?;
    if m.org_id != org_id {
        return Err(AppError::NotFound("Member not found".to_string()));
    }
    if m.atype == MembershipType::Owner as i32 {
        return Err(AppError::BadRequest("Cannot remove owner".to_string()));
    }
    Membership::delete(&db, &member_id).await?;
    Ok(Json(json!({})))
}

// ── Collections ─────────────────────────────────────────────────────

/// GET /api/organizations/{id}/collections
#[worker::send]
pub async fn list_collections(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    get_confirmed_membership(&db, &user_id, &id).await?;
    let cols = Collection::list_by_org(&db, &id).await?;
    let data: Vec<Value> = cols.iter().map(|c| c.to_json(&c.name)).collect();
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// POST /api/organizations/{id}/collections
#[worker::send]
pub async fn create_collection(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<CreateCollectionData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &id).await?;
    let now = db::now_string();
    let coll = Collection {
        id: uuid::Uuid::new_v4().to_string(),
        org_id: id,
        name: data.name,
        external_id: data.external_id,
        created_at: now.clone(),
        updated_at: now,
    };
    coll.insert(&db).await?;

    if let Some(users) = data.users {
        for u in users {
            let cu = CollectionUser {
                user_id: u.id,
                collection_id: coll.id.clone(),
                read_only: u.read_only.unwrap_or(false),
                hide_passwords: u.hide_passwords.unwrap_or(false),
                manage: u.manage.unwrap_or(false),
            };
            cu.upsert(&db).await?;
        }
    }
    Ok(Json(coll.to_json(&coll.name)))
}

/// PUT /api/organizations/{org_id}/collections/{id}
#[worker::send]
pub async fn update_collection(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, coll_id)): Path<(String, String)>,
    Json(data): Json<UpdateCollectionData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let mut coll = Collection::find_by_id(&db, &coll_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Collection not found".to_string()))?;
    if coll.org_id != org_id {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    coll.name = data.name;
    coll.external_id = data.external_id;
    coll.save(&db).await?;

    if let Some(users) = data.users {
        crate::d1_query!(
            &db,
            "DELETE FROM users_collections WHERE collection_id = ?1",
            &coll_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        for u in users {
            let cu = CollectionUser {
                user_id: u.id,
                collection_id: coll_id.clone(),
                read_only: u.read_only.unwrap_or(false),
                hide_passwords: u.hide_passwords.unwrap_or(false),
                manage: u.manage.unwrap_or(false),
            };
            cu.upsert(&db).await?;
        }
    }
    Ok(Json(coll.to_json(&coll.name)))
}

/// DELETE /api/organizations/{org_id}/collections/{id}
#[worker::send]
pub async fn delete_collection(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, coll_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    Collection::delete(&db, &coll_id).await?;
    Ok(Json(json!({})))
}

/// GET /api/organizations/{org_id}/collections/{id}/users
#[worker::send]
pub async fn list_collection_users(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, coll_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let cus = CollectionUser::list_for_collection(&db, &coll_id).await?;
    let mut data = Vec::with_capacity(cus.len());
    for cu in cus {
        let email = load_user_email(&db, &cu.user_id).await.unwrap_or_default();
        data.push(json!({
            "id": cu.user_id,
            "readOnly": cu.read_only,
            "hidePasswords": cu.hide_passwords,
            "manage": cu.manage,
            "userId": cu.user_id,
            "organizationUserId": cu.user_id,
            "email": email,
            "object": "collectionUser"
        }));
    }
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

// ── Policies ────────────────────────────────────────────────────────

/// GET /api/organizations/{id}/policies
#[worker::send]
pub async fn list_policies(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    get_confirmed_membership(&db, &user_id, &id).await?;
    let policies = OrgPolicy::list_by_org(&db, &id).await?;
    let data: Vec<Value> = policies.iter().map(|p| p.to_json()).collect();
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// GET /api/organizations/{org_id}/policies/{type}
#[worker::send]
pub async fn get_policy(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, ptype)): Path<(String, i32)>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    get_confirmed_membership(&db, &user_id, &org_id).await?;
    let policies = OrgPolicy::list_by_org(&db, &org_id).await?;
    let p = policies
        .into_iter()
        .find(|p| p.atype == ptype)
        .map(|p| p.to_json())
        .unwrap_or_else(|| {
            json!({
                "id": null,
                "organizationId": org_id,
                "type": ptype,
                "data": null,
                "enabled": false,
                "object": "policy"
            })
        });
    Ok(Json(p))
}

/// PUT /api/organizations/{org_id}/policies/{type}
#[worker::send]
pub async fn update_policy(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path((org_id, ptype)): Path<(String, i32)>,
    Json(data): Json<UpdatePolicyData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &org_id).await?;
    let data_str = data.data.unwrap_or(Value::Null).to_string();
    OrgPolicy::upsert(&db, &org_id, ptype, data.enabled, &data_str).await?;
    Ok(Json(json!({
        "organizationId": org_id,
        "type": ptype,
        "data": serde_json::from_str::<Value>(&data_str).unwrap_or(Value::Null),
        "enabled": data.enabled,
        "object": "policy"
    })))
}

// ── Groups ─────────────────────────────────────────────────────────

/// GET /api/organizations/{id}/groups
#[worker::send]
pub async fn list_groups(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &id).await?;
    let rows: Vec<Value> = crate::d1_query!(
        db,
        "SELECT * FROM groups WHERE org_id = ?1 ORDER BY created_at ASC",
        id
    )
    .map_err(|_| AppError::Database)?
    .all()
    .await
    .map_err(|_| AppError::Database)?
    .results()
    .map_err(|_| AppError::Database)?;
    let data: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                "organizationId": r.get("org_id").and_then(|v| v.as_str()).unwrap_or(""),
                "name": r.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                "accessAll": r.get("access_all")
                    .and_then(|v| v.as_i64())
                    .map(|x| x != 0)
                    .unwrap_or(false),
                "object": "group"
            })
        })
        .collect();
    Ok(Json(
        json!({ "data": data, "object": "list", "continuationToken": null }),
    ))
}

/// POST /api/organizations/{id}/groups
#[worker::send]
pub async fn create_group(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<CreateGroupData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    require_admin(&db, &user_id, &id).await?;
    let now = db::now_string();
    let gid = uuid::Uuid::new_v4().to_string();
    crate::d1_query!(
        db,
        "INSERT INTO groups (id, org_id, name, access_all, external_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &gid,
        &id,
        &data.name,
        data.access_all.unwrap_or(false) as i32,
        data.external_id.as_deref(),
        &now,
        &now
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    // Assign users to group if provided.
    if let Some(users) = &data.users {
        for u in users {
            if let Ok(Some(m)) = Membership::find_by_user_and_org(&db, &u.id, &id).await {
                crate::d1_query!(
                    db,
                    "INSERT OR IGNORE INTO groups_users (group_id, users_organizations_id) VALUES (?1, ?2)",
                    &gid, &m.id
                )
                .map_err(|_| AppError::Database)?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
            }
        }
    }

    Ok(Json(json!({
        "id": gid,
        "organizationId": id,
        "name": data.name,
        "accessAll": data.access_all.unwrap_or(false),
        "object": "group"
    })))
}

/// POST /api/organizations/{id}/delete (Bitwarden uses POST, not DELETE)
#[worker::send]
pub async fn post_delete_organization(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(_data): Json<Value>,
) -> Result<Json<Value>, AppError> {
    delete_organization(State(env), AuthUser(user_id, String::new()), Path(id)).await
}

// ── Import ──────────────────────────────────────────────────────────

/// POST /api/organizations/{id}/import
#[worker::send]
pub async fn import(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Json(data): Json<OrgImportData>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let m = get_confirmed_membership(&db, &user_id, &id).await?;
    let now = db::now_string();

    // Insert collections (resolve temp ids -> real ids).
    let mut coll_id_map: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for c in &data.collections {
        let real_id = uuid::Uuid::new_v4().to_string();
        let coll = Collection {
            id: real_id.clone(),
            org_id: id.clone(),
            name: c.name.clone(),
            external_id: c.external_id.clone(),
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        coll.insert(&db).await?;
        if let Some(temp) = &c.id {
            coll_id_map.insert(temp.clone(), real_id);
        }
    }

    // Insert ciphers as org ciphers owned by the importing user.
    for (idx, c) in data.ciphers.iter().enumerate() {
        let cipher_id = uuid::Uuid::new_v4().to_string();
        let data_json = serde_json::to_string(&c.cipher).map_err(|_| AppError::Internal)?;
        crate::d1_query!(
            &db,
            "INSERT INTO ciphers (id, user_id, organization_id, type, data, favorite, folder_id, deleted_at, archived_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, NULL, NULL, ?6, ?7)",
            &cipher_id,
            &m.user_id,
            &id,
            c.cipher.r#type,
            &data_json,
            &now,
            &now
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        // Assign to collections referenced via relationships (by index).
        let mut ids: Vec<String> = Vec::new();
        for rel in &data.collection_relationships {
            if rel.cipher_index == idx && rel.collection_index < data.collections.len() {
                if let Some(temp) = &data.collections[rel.collection_index].id {
                    if let Some(real) = coll_id_map.get(temp) {
                        ids.push(real.clone());
                    }
                }
            }
        }
        CollectionCipher::set_for_cipher(&db, &cipher_id, &ids).await?;
    }

    crate::db::touch_user_updated_at(&db, &user_id, &now).await?;
    Ok(Json(json!({})))
}

//! Event log endpoints (organization audit trail).

use axum::{
    extract::{Path, Query, State},
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
    models::{event::Event, organization::MembershipType},
};

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    250
}

/// GET /api/organizations/{id}/events — admin-only audit log.
#[worker::send]
pub async fn list_org_events(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Path(id): Path<String>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;

    // Require admin rights in the org.
    let m = crate::models::organization::Membership::find_by_user_and_org(&db, &user_id, &id)
        .await?
        .filter(|m| {
            m.status == crate::models::organization::STATUS_CONFIRMED
                && MembershipType::from_i32(m.atype)
                    .map(|t| t.has_admin_rights())
                    .unwrap_or(false)
        })
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let _ = m;

    let limit = query.limit.clamp(1, 1000);
    let events = Event::list_by_org(&db, &id, limit).await?;
    let data: Vec<Value> = events.iter().map(|e| e.to_json()).collect();
    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

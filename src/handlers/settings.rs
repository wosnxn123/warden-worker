use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{auth::Claims, error::AppError};

/// GET /api/settings/domains
///
/// Equivalent domains (eq_domains) are used by clients to treat some domains as interchangeable
/// for URI matching (e.g. `google.com` vs `youtube.com` in predefined "global" groups).
///
/// Vaultwarden persists per-user:
/// - `equivalentDomains`: custom groups set by the user
/// - `excludedGlobalEquivalentDomains`: which predefined groups are disabled
///
/// This minimal server currently does not persist these settings. We return empty data to
/// prevent 404s. In the future, we can implement storage by adding two `users` columns:
/// - `equivalent_domains` (TEXT JSON, default "[]")
/// - `excluded_globals` (TEXT JSON, default "[]")
/// and (optionally) embedding/updating the global domains dataset.
#[worker::send]
pub async fn get_domains(_claims: Claims) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({
        "equivalentDomains": [],
        "globalEquivalentDomains": [],
        "object": "domains"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivDomainData {
    #[allow(dead_code)] // stub endpoint doesn't persist these yet
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    #[allow(dead_code)] // stub endpoint doesn't persist these yet
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

/// POST /api/settings/domains
///
/// Stub: accept payload but do not persist yet.
#[worker::send]
pub async fn post_domains(
    _claims: Claims,
    _payload: Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    Ok(Json(json!({})))
}

/// PUT /api/settings/domains
///
/// Stub: behaves like POST.
#[worker::send]
pub async fn put_domains(
    claims: Claims,
    payload: Json<EquivDomainData>,
) -> Result<Json<Value>, AppError> {
    post_domains(claims, payload).await
}



//! Microsoft Graph API integration for Cloudflare Workers.
//!
//! Enables two E3/M365-backed capabilities:
//!   1. **Email** — `MAIL_PROVIDER=msgraph` uses Exchange Online `sendMail`.
//!   2. **Attachment / Send file storage** — OneDrive for Business as a storage
//!      backend alongside KV/R2, leveraging the E3 subscription's 1–5 TB quota.
//!
//! Authentication is app-only (client credentials flow). As a Global Admin you
//! grant the Azure AD App Registration the required application permissions:
//!   - `Mail.Send` (for email)
//!   - `Files.ReadWrite.All` (for OneDrive storage)
//!
//! Required env vars / secrets:
//!   - `MSGRAPH_TENANT_ID`     (var)   — tenant GUID
//!   - `MSGRAPH_CLIENT_ID`     (var)   — app client id
//!   - `MSGRAPH_CLIENT_SECRET` (secret)— app secret
//!   - `MSGRAPH_USER`          (var)   — UPN of the service account owning the
//!     OneDrive used for attachment storage
//!   - `MSGRAPH_MAIL_USER`     (var, optional) — sender UPN; defaults to MSGRAPH_USER
//!   - `MSGRAPH_BASE_PATH`     (var, optional) — OneDrive folder, default `/warden-attachments`
//!
//! Token caching uses the Cloudflare Cache API (same pattern as push.rs).

use std::sync::Arc;

use serde::Deserialize;
use web_sys::ReadableStream;
use worker::{
    wasm_bindgen::JsValue, Cache, Env, Fetch, Headers, Method, Request, RequestInit, Response,
};

use crate::error::AppError;

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";
const LOGIN_BASE: &str = "https://login.microsoftonline.com";
const TOKEN_CACHE_KEY: &str = "https://msgraph-token.internal/app-token";

#[derive(Debug, Clone)]
pub struct GraphConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub storage_user: String,
    pub base_path: String,
}

pub fn graph_config(env: &Env) -> Option<GraphConfig> {
    let tenant_id = env.var("MSGRAPH_TENANT_ID").ok()?.to_string();
    let client_id = env.var("MSGRAPH_CLIENT_ID").ok()?.to_string();
    let client_secret = env.secret("MSGRAPH_CLIENT_SECRET").ok()?.to_string();
    let storage_user = env.var("MSGRAPH_USER").ok()?.to_string();
    let base_path = env
        .var("MSGRAPH_BASE_PATH")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/warden-attachments".to_string());

    if tenant_id.is_empty() || client_id.is_empty() || client_secret.is_empty() {
        return None;
    }
    Some(GraphConfig {
        tenant_id,
        client_id,
        client_secret,
        storage_user,
        base_path,
    })
}

pub fn mail_sender(env: &Env) -> Option<String> {
    env.var("MSGRAPH_MAIL_USER")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.is_empty())
        .or_else(|| env.var("MSGRAPH_USER").ok().map(|v| v.to_string()))
        .filter(|v| !v.is_empty())
}

// ── Token management ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: i64,
}

pub(crate) async fn app_token(env: &Arc<Env>) -> Result<String, AppError> {
    let cache = Cache::default();
    if let Some(mut cached) = cache.get(TOKEN_CACHE_KEY, false).await.ok().flatten() {
        if let Ok(text) = cached.text().await {
            if !text.is_empty() {
                return Ok(text);
            }
        }
    }

    let cfg = graph_config(env).ok_or_else(|| AppError::Internal)?;
    let url = format!("{LOGIN_BASE}/{}/oauth2/v2.0/token", cfg.tenant_id);
    let body = format!(
        "client_id={cid}&client_secret={secret}&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default",
        cid = cfg.client_id,
        secret = cfg.client_secret
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let t = resp.text().await.unwrap_or_default();
        log::error!("Graph token request failed ({}): {t}", resp.status_code());
        return Err(AppError::Internal);
    }
    let token: TokenResponse = resp.json().await.map_err(AppError::Worker)?;

    // Cache the token (Cache-Control max-age ~50min; token lives 60min).
    let headers = Headers::new();
    let _ = headers
        .set("Cache-Control", "max-age=3000")
        .map_err(AppError::Worker);
    let _ = headers
        .set("Content-Type", "text/plain")
        .map_err(AppError::Worker);
    let put_resp = Response::ok(&token.access_token)
        .map_err(AppError::Worker)?
        .with_headers(headers);
    let _ = cache.put(TOKEN_CACHE_KEY, put_resp).await;

    Ok(token.access_token)
}

// ── Email ───────────────────────────────────────────────────────────

pub async fn send_mail(env: &Env, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
    let env = Arc::new(env.clone());
    let token = app_token(&env).await?;
    let sender = mail_sender(&env).ok_or_else(|| AppError::Internal)?;
    let url = format!("{GRAPH_BASE}/users/{}/sendMail", sender);

    let payload = serde_json::json!({
        "message": {
            "subject": subject,
            "body": { "contentType": "Text", "content": body },
            "toRecipients": [{ "emailAddress": { "address": to } }]
        },
        "saveToSentItems": false
    })
    .to_string();

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(payload.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    let h = req.headers_mut().map_err(AppError::Worker)?;
    h.set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;
    h.set("Content-Type", "application/json")
        .map_err(AppError::Worker)?;

    let resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        log::warn!("Graph sendMail returned {} for {to}", resp.status_code());
    }
    Ok(())
}

// ── OneDrive storage ────────────────────────────────────────────────

fn prefix_slash(s: &str) -> String {
    if s.starts_with('/') {
        s.to_string()
    } else {
        format!("/{s}")
    }
}

/// Upload a file to OneDrive via PUT content (Graph supports up to 250 MB).
pub async fn upload_file(
    env: &Env,
    storage_key: &str,
    body: ReadableStream,
    content_type: Option<&str>,
    _declared_size: i64,
) -> Result<(), AppError> {
    let env = Arc::new(env.clone());
    let token = app_token(&env).await?;
    let cfg = graph_config(&env).ok_or_else(|| AppError::Internal)?;
    let item_path = format!("{}{}", cfg.base_path, prefix_slash(storage_key));
    let url = format!(
        "{GRAPH_BASE}/users/{}/drive/root:{}:/content",
        cfg.storage_user, item_path
    );
    let ct = content_type.unwrap_or("application/octet-stream");

    let mut init = RequestInit::new();
    init.with_method(Method::Put)
        .with_body(Some(JsValue::from(body)));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    let h = req.headers_mut().map_err(AppError::Worker)?;
    h.set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;
    h.set("Content-Type", ct).map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let t = resp.text().await.unwrap_or_default();
        log::error!("Graph OneDrive upload failed ({}): {t}", resp.status_code());
        return Err(AppError::Internal);
    }
    Ok(())
}

/// Upload raw bytes to OneDrive (used by the legacy v1 attachment endpoint).
pub async fn upload_file_bytes(
    env: &Env,
    storage_key: &str,
    data: &[u8],
    content_type: Option<&str>,
) -> Result<(), AppError> {
    let env = Arc::new(env.clone());
    let token = app_token(&env).await?;
    let cfg = graph_config(&env).ok_or_else(|| AppError::Internal)?;
    let item_path = format!("{}{}", cfg.base_path, prefix_slash(storage_key));
    let url = format!(
        "{GRAPH_BASE}/users/{}/drive/root:{}:/content",
        cfg.storage_user, item_path
    );
    let ct = content_type.unwrap_or("application/octet-stream");

    let bytes = js_sys::Uint8Array::new_with_length(data.len() as u32);
    bytes.copy_from(data);

    let mut init = RequestInit::new();
    init.with_method(Method::Put).with_body(Some(bytes.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    let h = req.headers_mut().map_err(AppError::Worker)?;
    h.set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;
    h.set("Content-Type", ct).map_err(AppError::Worker)?;

    let mut resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        let t = resp.text().await.unwrap_or_default();
        log::error!(
            "Graph OneDrive upload_bytes failed ({}): {t}",
            resp.status_code()
        );
        return Err(AppError::Internal);
    }
    Ok(())
}

/// Download a file from OneDrive, returning a streaming Response.
pub async fn download_file(env: &Env, storage_key: &str) -> Result<Response, AppError> {
    let env = Arc::new(env.clone());
    let token = app_token(&env).await?;
    let cfg = graph_config(&env).ok_or_else(|| AppError::Internal)?;
    let item_path = format!("{}{}", cfg.base_path, prefix_slash(storage_key));
    let url = format!(
        "{GRAPH_BASE}/users/{}/drive/root:{}:/content",
        cfg.storage_user, item_path
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;

    let resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) {
        if resp.status_code() == 404 {
            return Err(AppError::NotFound("Not found in storage".to_string()));
        }
        return Err(AppError::Internal);
    }
    Ok(resp)
}

/// Delete a file from OneDrive (used on attachment removal).
pub async fn delete_file(env: &Env, storage_key: &str) -> Result<(), AppError> {
    let env = Arc::new(env.clone());
    let token = app_token(&env).await?;
    let cfg = graph_config(&env).ok_or_else(|| AppError::Internal)?;
    let item_path = format!("{}{}", cfg.base_path, prefix_slash(storage_key));
    let url = format!(
        "{GRAPH_BASE}/users/{}/drive/root:{}",
        cfg.storage_user, item_path
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Delete);
    let mut req = Request::new_with_init(&url, &init).map_err(AppError::Worker)?;
    req.headers_mut()
        .map_err(AppError::Worker)?
        .set("Authorization", &format!("Bearer {token}"))
        .map_err(AppError::Worker)?;

    let resp = Fetch::Request(req).send().await.map_err(AppError::Worker)?;
    if !(200..300).contains(&resp.status_code()) && resp.status_code() != 404 {
        log::warn!("Graph OneDrive delete returned {}", resp.status_code());
    }
    Ok(())
}

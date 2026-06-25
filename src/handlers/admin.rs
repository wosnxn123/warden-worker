//! Admin panel: server-side-rendered HTML + JSON API for managing the instance.
//!
//! Access is gated by the `ADMIN_TOKEN` secret. The token is sent as a
//! bearer header or cookie. When `ADMIN_TOKEN` is unset, the panel is
//! disabled (returns 404).
//!
//! Endpoints:
//!   GET  /admin             — login page + dashboard (HTML)
//!   POST /admin/api/login   — verify token, set cookie
//!   GET  /admin/api/users   — list all users
//!   POST /admin/api/users/{id}/delete — delete a user
//!   POST /admin/api/users/{id}/verify-email — mark email verified
//!   GET  /admin/api/stats   — user/cipher/attachment counts
//!   GET  /admin/api/config  — current server config (safe subset)

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use worker::{Env, Headers};

use crate::{db, error::AppError};

/// Check the admin token from either the Authorization header or the `admin_token` cookie.
fn check_admin(env: &Env, auth_header: Option<&str>, cookie_header: Option<&str>) -> bool {
    let Ok(token) = env.secret("ADMIN_TOKEN") else {
        return false;
    };
    let token = token.to_string();
    if token.is_empty() {
        return false;
    }

    // Bearer token
    if let Some(header) = auth_header {
        if let Some(bearer) = header.strip_prefix("Bearer ") {
            if constant_time_eq::constant_time_eq(bearer.as_bytes(), token.as_bytes()) {
                return true;
            }
        }
    }
    // Cookie
    if let Some(cookie) = cookie_header {
        for c in cookie.split(';') {
            let c = c.trim();
            if let Some(val) = c.strip_prefix("admin_token=") {
                if constant_time_eq::constant_time_eq(val.as_bytes(), token.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}

fn admin_enabled(env: &Env) -> bool {
    env.secret("ADMIN_TOKEN")
        .map(|t| !t.to_string().is_empty())
        .unwrap_or(false)
}

fn extract_headers(headers: &axum::http::HeaderMap) -> (Option<String>, Option<String>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    (auth, cookie)
}

/// GET /admin — serve the admin dashboard HTML.
#[worker::send]
pub async fn admin_page(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    if !admin_enabled(&env) {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    let (auth, cookie) = extract_headers(&headers);
    let authed = check_admin(&env, auth.as_deref(), cookie.as_deref());

    let html = render_admin_html(authed);
    Ok(Html(html).into_response())
}

/// POST /admin/api/login — verify the token and set a cookie.
#[derive(Debug, serde::Deserialize)]
pub struct LoginPayload {
    pub token: String,
}

#[worker::send]
pub async fn admin_login(
    State(env): State<Arc<Env>>,
    Json(payload): Json<LoginPayload>,
) -> Result<Response, AppError> {
    if !admin_enabled(&env) {
        return Err(AppError::NotFound("Not found".to_string()));
    }
    let Ok(stored) = env.secret("ADMIN_TOKEN") else {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    };
    let stored = stored.to_string();
    if !constant_time_eq::constant_time_eq(payload.token.as_bytes(), stored.as_bytes()) {
        return Err(AppError::Unauthorized("Invalid token".to_string()));
    }

    let h = Headers::new();
    let _ = h.set(
        "Set-Cookie",
        &format!(
            "admin_token={}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=86400",
            payload.token
        ),
    );
    let _ = h.set("Content-Type", "application/json");
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Json(json!({ "success": true })),
    )
        .into_response())
}

/// GET /admin/api/stats
#[worker::send]
pub async fn admin_stats(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, AppError> {
    let (auth, cookie) = extract_headers(&headers);
    if !check_admin(&env, auth.as_deref(), cookie.as_deref()) {
        return Err(AppError::Unauthorized("Unauthorized".to_string()));
    }
    let db = db::get_db(&env)?;

    let users: i64 = db
        .prepare("SELECT COUNT(*) as c FROM users")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);
    let ciphers: i64 = db
        .prepare("SELECT COUNT(*) as c FROM ciphers")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);
    let folders: i64 = db
        .prepare("SELECT COUNT(*) as c FROM folders")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);
    let sends: i64 = db
        .prepare("SELECT COUNT(*) as c FROM sends")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);
    let orgs: i64 = db
        .prepare("SELECT COUNT(*) as c FROM organizations")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);
    let attachments: i64 = db
        .prepare("SELECT COUNT(*) as c FROM attachments")
        .bind(&[])?
        .first::<i64>(Some("c"))
        .await?
        .unwrap_or(0);

    Ok(Json(json!({
        "users": users,
        "ciphers": ciphers,
        "folders": folders,
        "sends": sends,
        "organizations": orgs,
        "attachments": attachments
    })))
}

/// GET /admin/api/users — list all users (admin view).
#[worker::send]
pub async fn admin_list_users(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, AppError> {
    let (auth, cookie) = extract_headers(&headers);
    if !check_admin(&env, auth.as_deref(), cookie.as_deref()) {
        return Err(AppError::Unauthorized("Unauthorized".to_string()));
    }
    let db = db::get_db(&env)?;

    let rows: Vec<Value> = db
        .prepare(
            "SELECT id, email, name, email_verified, created_at, updated_at, kdf_type, kdf_iterations FROM users ORDER BY created_at DESC",
        )
        .bind(&[])?
        .all()
        .await?
        .results()?;

    Ok(Json(json!({ "data": rows, "object": "list" })))
}

/// POST /admin/api/users/{id}/delete — delete a user and all their data.
#[worker::send]
pub async fn admin_delete_user(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let (auth, cookie) = extract_headers(&headers);
    if !check_admin(&env, auth.as_deref(), cookie.as_deref()) {
        return Err(AppError::Unauthorized("Unauthorized".to_string()));
    }
    let db = db::get_db(&env)?;
    crate::d1_query!(&db, "DELETE FROM users WHERE id = ?1", &id)
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(Json(json!({ "success": true })))
}

/// POST /admin/api/users/{id}/verify-email — mark email as verified.
#[worker::send]
pub async fn admin_verify_email(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let (auth, cookie) = extract_headers(&headers);
    if !check_admin(&env, auth.as_deref(), cookie.as_deref()) {
        return Err(AppError::Unauthorized("Unauthorized".to_string()));
    }
    let db = db::get_db(&env)?;
    crate::d1_query!(
        &db,
        "UPDATE users SET email_verified = 1, updated_at = ?1 WHERE id = ?2",
        db::now_string(),
        &id
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(Json(json!({ "success": true })))
}

/// GET /admin/api/config — safe config subset.
#[worker::send]
pub async fn admin_config(
    State(env): State<Arc<Env>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, AppError> {
    let (auth, cookie) = extract_headers(&headers);
    if !check_admin(&env, auth.as_deref(), cookie.as_deref()) {
        return Err(AppError::Unauthorized("Unauthorized".to_string()));
    }

    let has = |name: &str| env.var(name).is_ok() || env.secret(name).is_ok();
    Ok(Json(json!({
        "sso_enabled": env.var("SSO_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false),
        "sso_tenants": crate::handlers::sso::sso_tenants(&env).len(),
        "push_enabled": env.var("PUSH_ENABLED").map(|v| v.to_string() == "true").unwrap_or(false),
        "mail_provider": env.var("MAIL_PROVIDER").ok().map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
        "msgraph_storage": has("MSGRAPH_TENANT_ID") && has("MSGRAPH_CLIENT_ID") && has("MSGRAPH_CLIENT_SECRET"),
        "duo_configured": has("DUO_IKEY") && has("DUO_SKEY"),
        "yubico_configured": has("YUBICO_CLIENT_ID") && has("YUBICO_SECRET_KEY"),
        "r2_storage": env.bucket("ATTACHMENTS_BUCKET").is_ok(),
        "kv_storage": env.kv("ATTACHMENTS_KV").is_ok(),
    })))
}

// ── HTML ────────────────────────────────────────────────────────────

fn render_admin_html(authed: bool) -> String {
    if !authed {
        return LOGIN_HTML.to_string();
    }
    DASHBOARD_HTML.to_string()
}

const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#16213e;padding:2.5rem;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,.4);width:360px}
h1{font-size:1.5rem;margin-bottom:1.5rem;color:#0d6efd;text-align:center}
input{width:100%;padding:.75rem;margin:.5rem 0;border:1px solid #333;border-radius:6px;background:#0f0f23;color:#fff;font-size:.95rem}
button{width:100%;padding:.75rem;margin-top:1rem;border:none;border-radius:6px;background:#0d6efd;color:#fff;font-size:1rem;cursor:pointer}
button:hover{background:#0b5ed7}
.err{color:#e74c3c;font-size:.85rem;margin-top:.5rem;display:none}
</style></head>
<body><div class="card">
<h1>Warden Admin</h1>
<input type="password" id="token" placeholder="Admin Token" autofocus>
<button onclick="login()">Login</button>
<div class="err" id="err">Invalid token</div>
</div><script>
async function login(){
  const t=document.getElementById('token').value;
  const r=await fetch('/admin/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});
  if(r.ok){location.reload();}else{document.getElementById('err').style.display='block';}
}
document.getElementById('token').addEventListener('keydown',e=>{if(e.key==='Enter')login();});
</script></body></html>"#;

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden Admin — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:1.5rem}
h1{color:#0d6efd;margin-bottom:1rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}
.stat{background:#16213e;padding:1.25rem;border-radius:8px;text-align:center}
.stat .n{font-size:2rem;font-weight:700;color:#0d6efd}
.stat .l{font-size:.8rem;color:#888;margin-top:.25rem}
table{width:100%;border-collapse:collapse;background:#16213e;border-radius:8px;overflow:hidden}
th,td{padding:.75rem 1rem;text-align:left;border-bottom:1px solid #0f0f23}
th{background:#0d6efd;color:#fff;font-size:.85rem}
td{font-size:.9rem}
.btn{padding:.4rem .8rem;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;margin-right:.3rem}
.btn-del{background:#dc3545;color:#fff}.btn-ver{background:#198754;color:#fff}
</style></head>
<body>
<h1>Warden Admin Dashboard</h1>
<div class="grid" id="stats"></div>
<h2>Users</h2>
<table><thead><tr><th>Email</th><th>Name</th><th>Verified</th><th>Created</th><th>Actions</th></tr></thead>
<tbody id="users"></tbody></table>
<script>
const H={'Content-Type':'application/json'};
async function api(p,o={}){const r=await fetch(p,o);return r.json();}
async function init(){
  const s=await api('/admin/api/stats');
  const labels={users:'Users',ciphers:'Ciphers',folders:'Folders',sends:'Sends',organizations:'Orgs',attachments:'Attachments'};
  document.getElementById('stats').innerHTML=Object.entries(s).map(([k,v])=>`<div class="stat"><div class="n">${v}</div><div class="l">${labels[k]||k}</div></div>`).join('');
  const u=await api('/admin/api/users');
  document.getElementById('users').innerHTML=u.data.map(x=>`<tr>
    <td>${x.email}</td><td>${x.name||''}</td><td>${x.email_verified?'✓':'✗'}</td><td>${x.created_at}</td>
    <td>${x.email_verified?'':`<button class="btn btn-ver" onclick="ver('${x.id}')">Verify</button>`}<button class="btn btn-del" onclick="del('${x.id}')">Delete</button></td>
  </tr>`).join('');
}
async function del(id){if(!confirm('Delete this user and all data?'))return;await api('/admin/api/users/'+id+'/delete',{method:'POST',headers:H});init();}
async function ver(id){await api('/admin/api/users/'+id+'/verify-email',{method:'POST',headers:H});init();}
init();
</script></body></html>"#;

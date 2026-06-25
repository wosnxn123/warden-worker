//! Email sending abstraction for Cloudflare Workers.
//!
//! Workers cannot speak SMTP directly, so email is delivered via an HTTP API.
//! Supported providers (selected via `MAIL_PROVIDER`):
//!   - `resend`  (https://resend.com) — needs `RESEND_API_KEY` + `MAIL_FROM`
//!   - `webhook` — POSTs JSON to `MAIL_WEBHOOK_URL` (+ optional `MAIL_FROM`)
//!
//! When unconfigured, `send()` logs a warning and returns `Ok(())`
//! (graceful degradation). This lets the server run without email, while
//! email-dependent features (email 2FA, invite notifications) simply no-op.

use crate::error::AppError;
use serde_json::json;
use worker::{Env, Fetch, Method, Request, RequestInit, Response};

/// Send a plain-text email. Returns `Ok(())` when mail is disabled.
pub async fn send(env: &Env, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
    let provider = env
        .var("MAIL_PROVIDER")
        .ok()
        .map(|v| v.to_string().to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());

    match provider.as_str() {
        "none" | "" => {
            log::warn!("MAIL_PROVIDER not configured; dropping email to {to} ({subject})");
            Ok(())
        }
        "resend" => send_via_resend(env, to, subject, body).await,
        "webhook" => send_via_webhook(env, to, subject, body).await,
        "msgraph" => crate::msgraph::send_mail(env, to, subject, body).await,
        other => {
            log::warn!("Unknown MAIL_PROVIDER '{other}'; dropping email to {to}");
            Ok(())
        }
    }
}

fn mail_from(env: &Env) -> String {
    env.var("MAIL_FROM")
        .ok()
        .map(|v| v.to_string())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "warden@localhost".to_string())
}

async fn post_json(
    url: &str,
    headers: &[(&str, &str)],
    payload: String,
) -> Result<Response, AppError> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(payload.into()));
    let mut req = Request::new_with_init(url, &init).map_err(AppError::Worker)?;
    for (k, v) in headers {
        req.headers_mut()
            .map_err(AppError::Worker)?
            .set(k, v)
            .map_err(AppError::Worker)?;
    }
    Fetch::Request(req).send().await.map_err(AppError::Worker)
}

async fn send_via_resend(env: &Env, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
    let api_key = env
        .secret("RESEND_API_KEY")
        .map_err(|_| AppError::Internal)?
        .to_string();
    let from = mail_from(env);

    let payload = json!({ "from": from, "to": [to], "subject": subject, "text": body }).to_string();

    let auth = format!("Bearer {api_key}");
    let resp = post_json(
        "https://api.resend.com/emails",
        &[
            ("Authorization", auth.as_str()),
            ("Content-Type", "application/json"),
        ],
        payload,
    )
    .await?;

    if !(200..300).contains(&resp.status_code()) {
        log::warn!("Resend returned {} for email to {to}", resp.status_code());
    }
    Ok(())
}

async fn send_via_webhook(env: &Env, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
    let url = env
        .var("MAIL_WEBHOOK_URL")
        .map_err(|_| AppError::Internal)?
        .to_string();
    let from = mail_from(env);

    let payload = json!({ "from": from, "to": to, "subject": subject, "text": body }).to_string();
    let resp = post_json(&url, &[("Content-Type", "application/json")], payload).await?;

    if !(200..300).contains(&resp.status_code()) {
        log::warn!(
            "Mail webhook {url} returned {} for {to}",
            resp.status_code()
        );
    }
    Ok(())
}

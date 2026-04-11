use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, Extension};
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::*;

mod auth;
mod crypto;
mod db;
mod durable;
mod error;
mod handlers;
mod models;
mod notifications;
mod push;
mod router;

/// Base URL extracted from the incoming request, used for config endpoint.
#[derive(Clone)]
pub struct BaseUrl(pub String);

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    Router::new()
        .put_async(
            "/api/ciphers/:cipher_id/attachment/:attachment_id/azure-upload",
            handlers::streaming::attachment_upload,
        )
        .get_async(
            "/api/ciphers/:cipher_id/attachment/:attachment_id/download",
            handlers::streaming::attachment_download,
        )
        .put_async(
            "/api/sends/:send_id/file/:file_id/azure-upload",
            handlers::streaming::send_upload,
        )
        // Send file download is GET-only streaming, but this 4-segment pattern
        // also matches POST /api/sends/file/v2.
        // Registering via get_async would put it in the GET trie, causing the
        // Router's 405 check (which runs BEFORE or_else_any_method) to reject
        // valid non-GET requests. So we also register a POST route handled by axum_fallback.
        .get_async(
            "/api/sends/:send_id/:file_id",
            handlers::streaming::send_download,
        )
        .post_async("/api/sends/:send_id/:file_id", axum_fallback)
        .or_else_any_method_async("/*catchall", axum_fallback)
        .run(req, env)
        .await
}

async fn axum_fallback(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let http_req: HttpRequest = req.try_into()?;

    let uri = http_req.uri().clone();
    let base_url = format!(
        "{}://{}",
        uri.scheme_str().unwrap_or("https"),
        uri.authority().map(|a| a.as_str()).unwrap_or("localhost")
    );

    let env = Arc::new(ctx.env);

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    const BODY_LIMIT: usize = 5 * 1024 * 1024;

    let mut app = router::api_router((*env).clone())
        .layer(Extension(BaseUrl(base_url)))
        .layer(cors)
        .layer(DefaultBodyLimit::max(BODY_LIMIT));

    let http_resp = app.call(http_req).await?;
    http_resp.try_into()
}

/// Scheduled event handler for cron-triggered tasks.
///
/// This handler is triggered by Cloudflare's cron triggers configured in wrangler.toml.
/// It performs automatic cleanup of soft-deleted ciphers that have exceeded the
/// retention period (default: 30 days, configurable via TRASH_AUTO_DELETE_DAYS env var).
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // Set up logging
    console_error_panic_hook::set_once();
    let _ = console_log::init_with_level(log::Level::Debug);

    log::info!("Scheduled task triggered: purging stale pending attachments");
    match handlers::purge::purge_stale_pending_attachments(&env).await {
        Ok(count) => {
            log::info!(
                "Pending attachment purge completed: {} record(s) removed",
                count
            );
        }
        Err(e) => {
            log::error!("Pending attachment purge failed: {:?}", e);
        }
    }

    log::info!("Scheduled task triggered: purging soft-deleted ciphers");

    match handlers::purge::purge_deleted_ciphers(&env).await {
        Ok(count) => {
            log::info!("Scheduled purge completed: {} cipher(s) removed", count);
        }
        Err(e) => {
            log::error!("Scheduled purge failed: {:?}", e);
        }
    }

    log::info!("Scheduled task triggered: purging stale pending sends");
    match handlers::purge::purge_stale_pending_sends(&env).await {
        Ok(count) => {
            log::info!("Pending send purge completed: {} record(s) removed", count);
        }
        Err(e) => {
            log::error!("Pending send purge failed: {:?}", e);
        }
    }

    log::info!("Scheduled task triggered: purging expired sends");
    match handlers::purge::purge_expired_sends(&env).await {
        Ok(count) => {
            log::info!("Expired send purge completed: {} record(s) removed", count);
        }
        Err(e) => {
            log::error!("Expired send purge failed: {:?}", e);
        }
    }
}

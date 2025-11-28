use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use worker::Env;

use crate::handlers::{accounts, ciphers, config, folders, identity, import, sync};

pub fn api_router(env: Env) -> Router {
    let app_state = Arc::new(env);

    Router::new()
        // Identity/Auth routes
        .route("/identity/accounts/prelogin", post(accounts::prelogin))
        .route(
            "/identity/accounts/register/finish",
            post(accounts::register),
        )
        .route("/identity/connect/token", post(identity::token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(accounts::send_verification_email),
        )
        // Main data sync route
        .route("/api/sync", get(sync::get_sync_data))
        // For on-demand sync checks
        .route("/api/accounts/revision-date", get(accounts::revision_date))
        // Delete account
        .route("/api/accounts", delete(accounts::delete_account))
        .route("/api/accounts/delete", post(accounts::delete_account))
        // Ciphers CRUD
        .route("/api/ciphers", post(ciphers::create_cipher_simple))
        .route("/api/ciphers/create", post(ciphers::create_cipher))
        .route("/api/ciphers/import", post(import::import_data))
        .route("/api/ciphers/{id}", put(ciphers::update_cipher))
        // Cipher soft delete (PUT sets deleted_at timestamp)
        .route("/api/ciphers/{id}/delete", put(ciphers::soft_delete_cipher))
        // Cipher hard delete (DELETE/POST permanently removes cipher)
        .route("/api/ciphers/{id}", delete(ciphers::hard_delete_cipher))
        .route("/api/ciphers/{id}/delete", post(ciphers::hard_delete_cipher))
        // Cipher bulk soft delete
        .route("/api/ciphers/delete", put(ciphers::soft_delete_ciphers_bulk))
        // Cipher bulk hard delete
        .route("/api/ciphers/delete", post(ciphers::hard_delete_ciphers_bulk))
        .route("/api/ciphers", delete(ciphers::hard_delete_ciphers_bulk))
        // Cipher restore (clears deleted_at)
        .route("/api/ciphers/{id}/restore", put(ciphers::restore_cipher))
        // Cipher bulk restore
        .route("/api/ciphers/restore", put(ciphers::restore_ciphers_bulk))
        // Folders CRUD
        .route("/api/folders", post(folders::create_folder))
        .route("/api/folders/{id}", put(folders::update_folder))
        .route("/api/folders/{id}", delete(folders::delete_folder))
        .route("/api/config", get(config::config))
        .with_state(app_state)
}

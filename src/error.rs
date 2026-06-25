use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use thiserror::Error;

/// Bitwarden-compatible application errors.
///
/// Most endpoints return the `ApiErrorResponse` shape (with `message`,
/// `validationErrors`, `errorModel`, `object`), which the official clients
/// parse to display user-friendly messages.
///
/// The OAuth2 `/identity/connect/token` endpoint instead needs the compact
/// `{"error":"invalid_grant","error_description":"..."}` shape — use
/// [`AppError::IdentityError`] for that.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Worker error: {0}")]
    Worker(#[from] worker::Error),

    #[error("Database query failed")]
    Database,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Internal server error")]
    Internal,

    #[error("Two factor authentication required")]
    TwoFactorRequired(Value),

    /// OAuth2-style error for `/identity/connect/token`.
    /// Returns `{"error":"<error>","error_description":"<description>"}` with 400.
    #[error("Identity error: {error}")]
    IdentityError { error: String, description: String },

    /// SCIM 2.0 error response (application/scim+json).
    #[error("SCIM error")]
    ScimError(StatusCode, Value),
}

impl AppError {
    /// The HTTP status code for this error.
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Worker(_) | AppError::Database | AppError::Crypto(_) | AppError::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::TwoFactorRequired(_) => StatusCode::BAD_REQUEST,
            AppError::IdentityError { .. } => StatusCode::BAD_REQUEST,
            AppError::ScimError(code, _) => *code,
        }
    }

    /// The human-readable message shown to the client.
    fn message(&self) -> String {
        match self {
            AppError::Worker(e) => format!("Worker error: {e}"),
            AppError::Database => "A database error occurred. Please try again.".to_string(),
            AppError::NotFound(msg) => msg.clone(),
            AppError::BadRequest(msg) => msg.clone(),
            AppError::Unauthorized(msg) => msg.clone(),
            AppError::TooManyRequests(msg) => msg.clone(),
            AppError::Crypto(msg) => format!("Cryptography error: {msg}"),
            AppError::Internal => "Internal server error".to_string(),
            AppError::TwoFactorRequired(_) => "Two factor required.".to_string(),
            AppError::IdentityError { description, .. } => description.clone(),
            AppError::ScimError(_, _) => "SCIM error".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::TwoFactorRequired(json_body) => {
                (StatusCode::BAD_REQUEST, Json(json_body)).into_response()
            }
            AppError::IdentityError { error, description } => {
                // OAuth2 compact error shape expected by /identity/connect/token
                Json(json!({
                    "error": error,
                    "error_description": description
                }))
                .into_response()
            }
            AppError::ScimError(code, body) => (
                code,
                [(axum::http::header::CONTENT_TYPE, "application/scim+json")],
                Json(body),
            )
                .into_response(),
            other => {
                let status = other.status_code();
                let message = other.message();

                // Bitwarden ApiErrorResponse shape — the official clients read
                // `message` and `validationErrors[""]` to surface errors in the UI.
                let body = Json(json!({
                    "message": message,
                    "validationErrors": { "": [message] },
                    "errorModel": {
                        "message": message,
                        "object": "error"
                    },
                    "error": "",
                    "error_description": "",
                    "exceptionMessage": null,
                    "exceptionStackTrace": null,
                    "innerExceptionMessage": null,
                    "object": "error"
                }));
                (status, body).into_response()
            }
        }
    }
}

use axum::Json;
use serde_json::{json, Value};

/// GET /devices
///
/// Returns an empty list of devices.
/// Device tracking is not implemented in this minimal Bitwarden-compatible server.
/// This does not affect authentication since we use stateless JWT tokens.
/// Clients will show "No devices currently logged in" in the device management settings.
#[worker::send]
pub async fn get_devices() -> Json<Value> {
    Json(json!({
        "data": [],
        "continuationToken": null,
        "object": "list"
    }))
}


//! WebAuthn (passkey) 2FA.
//!
//! Implemented with pure-Rust crypto so it runs in the WASM sandbox:
//!   - `ciborium` to decode the CBOR attestation/assertion objects
//!   - `p256` to verify ECDSA-P256 (ES256) assertion signatures
//!   - `sha2` for rpId / clientData hashing
//!
//! Registration trusts the authenticated user's submitted credential (we verify
//! the attestation object is well-formed and extract the public key, but do not
//! verify the attestation statement signature — the user is already logged in
//! and authenticating their own device).

use std::sync::Arc;

use axum::{extract::State, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::Env;

use crate::{
    auth::AuthUser,
    crypto::generate_recovery_code,
    db,
    error::AppError,
    handlers::twofactor::{
        find_twofactor, generate_recovery_code_for_user, load_authed_user, upsert_twofactor,
        validate_password_or_otp,
    },
    models::{
        twofactor::TwoFactorType,
        user::{PasswordOrOtpData, User},
    },
};

/// Stored credential (one per registered passkey).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    /// Base64url(credential id)
    pub credential_id: String,
    /// Base64url(uncompressed EC P-256 public key: 0x04 || x || y)
    pub public_key: String,
    /// Last seen signature counter (replay protection)
    pub counter: u32,
    /// User-chosen label
    pub name: String,
}

fn now_challenge() -> Result<String, AppError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| AppError::Crypto(format!("challenge: {e}")))?;
    Ok(B64URL.encode(buf))
}

/// GET /api/webauthn — list registered passkeys.
#[worker::send]
pub async fn get_webauthn_credentials(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let existing = find_twofactor(&db, &user_id, TwoFactorType::Webauthn as i32).await?;
    let creds: Vec<WebauthnCredential> = match existing {
        Some(tf) => serde_json::from_str(&tf.data).unwrap_or_default(),
        None => Vec::new(),
    };
    let data: Vec<Value> = creds
        .iter()
        .map(|c| {
            json!({
                "id": c.credential_id,
                "name": c.name,
                "object": "webauthnCredential"
            })
        })
        .collect();
    Ok(Json(json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterChallengeRequest {
    #[allow(dead_code)]
    pub device: Option<Value>,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

/// POST /api/webauthn (step 1: request a registration challenge)
#[worker::send]
pub async fn post_webauthn_challenge(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<RegisterChallengeRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(
        &db,
        &env,
        &user,
        &user_id,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let challenge = now_challenge()?;
    // Store the challenge as a transient record (type 1003).
    let marker =
        json!({ "challenge": challenge, "created_at": chrono::Utc::now().timestamp() }).to_string();
    upsert_twofactor(
        &db,
        &user_id,
        TwoFactorType::WebauthnRegisterChallenge as i32,
        &marker,
    )
    .await?;

    Ok(Json(json!({
        "rp": { "name": "Warden", "id": null },
        "user": {
            "id": B64URL.encode(user.id.as_bytes()),
            "name": user.email,
            "displayName": user.name.clone().unwrap_or_else(|| user.email.clone())
        },
        "challenge": challenge,
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 }
        ],
        "timeout": 60000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "userVerification": "preferred",
            "residentKey": "preferred"
        },
        "attestation": "none",
        "object": "webauthnCredentialCreationOptions"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRegisterRequest {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub raw_id: String,
    pub response: AttestationResponse,
    #[allow(dead_code)]
    pub r#type: String,
    #[allow(dead_code)]
    pub device: Option<Value>,
    pub name: Option<String>,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    pub attestation_object: String,
    pub client_data_json: String,
}

/// POST /api/webauthn/complete — finish registration by storing the credential.
#[worker::send]
pub async fn complete_webauthn_register(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<CompleteRegisterRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(
        &db,
        &env,
        &user,
        &user_id,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    // Look up + consume the challenge.
    let challenge_tf = find_twofactor(
        &db,
        &user_id,
        TwoFactorType::WebauthnRegisterChallenge as i32,
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("No pending WebAuthn challenge".to_string()))?;

    let att_obj_bytes = B64URL
        .decode(&data.response.attestation_object)
        .map_err(|_| AppError::BadRequest("Invalid attestationObject".to_string()))?;

    let (credential_id, public_key) = parse_attestation(&att_obj_bytes)?;

    // Verify clientDataJSON references our challenge.
    let client_data = B64URL
        .decode(&data.response.client_data_json)
        .map_err(|_| AppError::BadRequest("Invalid clientDataJSON".to_string()))?;
    let client_data_json: Value = serde_json::from_slice(&client_data)
        .map_err(|_| AppError::BadRequest("Invalid clientDataJSON".to_string()))?;
    let cd_challenge = client_data_json
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let challenge_val: Value = serde_json::from_str(&challenge_tf.data).unwrap_or(Value::Null);
    let expected = challenge_val
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cd_challenge != expected {
        return Err(AppError::BadRequest(
            "WebAuthn challenge mismatch".to_string(),
        ));
    }

    let cred = WebauthnCredential {
        credential_id: B64URL.encode(&credential_id),
        public_key: B64URL.encode(&public_key),
        counter: 0,
        name: data.name.unwrap_or_else(|| "Passkey".to_string()),
    };

    // Append to existing credentials.
    let mut creds: Vec<WebauthnCredential> =
        match find_twofactor(&db, &user_id, TwoFactorType::Webauthn as i32).await? {
            Some(tf) => serde_json::from_str(&tf.data).unwrap_or_default(),
            None => Vec::new(),
        };
    creds.push(cred.clone());
    let data_str = serde_json::to_string(&creds).map_err(|_| AppError::Internal)?;
    upsert_twofactor(&db, &user_id, TwoFactorType::Webauthn as i32, &data_str).await?;

    // Consume the challenge.
    crate::d1_query!(
        &db,
        "DELETE FROM twofactor WHERE uuid = ?1",
        &challenge_tf.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    generate_recovery_code_for_user(&db, &user_id).await?;

    Ok(Json(json!({
        "id": cred.credential_id,
        "name": cred.name,
        "object": "webauthnCredential"
    })))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWebauthnRequest {
    pub id: String,
    pub master_password_hash: Option<String>,
    pub otp: Option<String>,
}

/// DELETE /api/webauthn — remove a registered passkey.
#[worker::send]
pub async fn delete_webauthn_credential(
    State(env): State<Arc<Env>>,
    AuthUser(user_id, _): AuthUser,
    Json(data): Json<DeleteWebauthnRequest>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&env)?;
    let user = load_authed_user(&db, &user_id).await?;
    validate_password_or_otp(
        &db,
        &env,
        &user,
        &user_id,
        &PasswordOrOtpData {
            master_password_hash: data.master_password_hash,
            otp: data.otp,
        },
    )
    .await?;

    let tf = find_twofactor(&db, &user_id, TwoFactorType::Webauthn as i32)
        .await?
        .ok_or_else(|| AppError::BadRequest("No WebAuthn credentials".to_string()))?;
    let mut creds: Vec<WebauthnCredential> = serde_json::from_str(&tf.data).unwrap_or_default();
    let before = creds.len();
    creds.retain(|c| c.credential_id != data.id);
    if creds.len() == before {
        return Err(AppError::NotFound("Credential not found".to_string()));
    }
    if creds.is_empty() {
        crate::d1_query!(&db, "DELETE FROM twofactor WHERE uuid = ?1", &tf.uuid)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
    } else {
        let data_str = serde_json::to_string(&creds).map_err(|_| AppError::Internal)?;
        upsert_twofactor(&db, &user_id, TwoFactorType::Webauthn as i32, &data_str).await?;
    }
    Ok(Json(json!({})))
}

// ── Assertion verification (login) ──────────────────────────────────

/// Verify a WebAuthn assertion during 2FA login.
///
/// `assertion_response` fields (base64url): authenticatorData, clientDataJSON, signature, id
pub(crate) async fn validate_webauthn_login(
    db: &crate::db::Db,
    user: &User,
    provider_data: &str, // twofactor.data: JSON array of credentials
    assertion: &Value,
) -> Result<(), AppError> {
    let creds: Vec<WebauthnCredential> =
        serde_json::from_str(provider_data).map_err(|_| AppError::Internal)?;

    let cred_id = assertion
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("Invalid WebAuthn response".to_string()))?;
    let cred = creds
        .iter()
        .find(|c| c.credential_id == cred_id)
        .ok_or_else(|| AppError::Unauthorized("WebAuthn credential not registered".to_string()))?;

    let auth_data = B64URL
        .decode(
            assertion
                .get("authenticatorData")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .map_err(|_| AppError::Unauthorized("Invalid authenticatorData".to_string()))?;
    let client_data = B64URL
        .decode(
            assertion
                .get("clientDataJSON")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .map_err(|_| AppError::Unauthorized("Invalid clientDataJSON".to_string()))?;
    let signature = B64URL
        .decode(
            assertion
                .get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .map_err(|_| AppError::Unauthorized("Invalid signature".to_string()))?;

    if auth_data.len() < 37 {
        return Err(AppError::Unauthorized(
            "Malformed authenticatorData".to_string(),
        ));
    }
    // flags byte at offset 32: require User Present (bit 0).
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(AppError::Unauthorized("User presence required".to_string()));
    }
    let counter = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    if counter != 0 && counter <= cred.counter {
        return Err(AppError::Unauthorized(
            "Possible cloned authenticator".to_string(),
        ));
    }

    // clientDataHash = SHA256(clientDataJSON)
    let mut hasher = Sha256::new();
    hasher.update(&client_data);
    let client_data_hash = hasher.finalize();

    // Signed message = authenticatorData || clientDataHash
    let mut message = Vec::with_capacity(auth_data.len() + 32);
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_data_hash);

    // Decode the uncompressed public key.
    let pub_key_bytes = B64URL
        .decode(&cred.public_key)
        .map_err(|_| AppError::Internal)?;
    if pub_key_bytes.len() != 65 || pub_key_bytes[0] != 0x04 {
        return Err(AppError::Internal);
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&pub_key_bytes[1..33]);
    y.copy_from_slice(&pub_key_bytes[33..65]);
    let sec1 = p256::EncodedPoint::from_affine_coordinates(
        &p256::FieldBytes::from(x),
        &p256::FieldBytes::from(y),
        false,
    );
    let vk = VerifyingKey::from_sec1_bytes(sec1.as_bytes()).map_err(|_| AppError::Internal)?;

    let sig = p256::ecdsa::Signature::from_der(&signature)
        .or_else(|_| {
            // Some authenticators return raw r||s (64 bytes) instead of DER.
            if signature.len() == 64 {
                p256::ecdsa::Signature::from_slice(&signature)
            } else {
                Err(p256::ecdsa::Error::new())
            }
        })
        .map_err(|_| AppError::Unauthorized("Invalid signature encoding".to_string()))?;

    vk.verify(&message, &sig)
        .map_err(|_| AppError::Unauthorized("WebAuthn signature invalid".to_string()))?;

    // Update the counter (replay protection).
    let mut updated = creds.clone();
    if let Some(c) = updated.iter_mut().find(|c| c.credential_id == cred_id) {
        c.counter = counter;
    }
    let new_data = serde_json::to_string(&updated).map_err(|_| AppError::Internal)?;
    let tf = find_twofactor(db, &user.id, TwoFactorType::Webauthn as i32)
        .await?
        .ok_or_else(|| AppError::Internal)?;
    crate::d1_query!(
        db,
        "UPDATE twofactor SET data = ?1 WHERE uuid = ?2",
        &new_data,
        &tf.uuid
    )
    .map_err(|_| AppError::Database)?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    Ok(())
}

// ── CBOR attestation parsing ────────────────────────────────────────

/// Parse the attestationObject CBOR and extract (credentialId, uncompressed public key bytes).
fn parse_attestation(att_obj: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    use ciborium::value::Value as Cbor;
    let val: Cbor = ciborium::from_reader(att_obj)
        .map_err(|_| AppError::BadRequest("Invalid attestation CBOR".to_string()))?;
    let map = val
        .as_map()
        .ok_or_else(|| AppError::BadRequest("attestationObject is not a map".to_string()))?;

    let mut auth_data: Vec<u8> = Vec::new();
    for (k, v) in map.iter() {
        if let Some(k) = k.as_text() {
            if k == "authData" {
                if let Some(b) = v.as_bytes() {
                    auth_data = b.clone();
                }
            }
        }
    }
    if auth_data.is_empty() {
        return Err(AppError::BadRequest("Missing authData".to_string()));
    }

    // authData: rpIdHash(32) + flags(1) + signCount(4) + [attestedCredentialData]
    if auth_data.len() < 37 {
        return Err(AppError::BadRequest("authData too short".to_string()));
    }
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err(AppError::BadRequest(
            "authData missing attested credential data".to_string(),
        ));
    }
    // attestedCredentialData: aaguid(16) + credIdLen(2 BE) + credId + COSE_Key
    let mut off = 37;
    off += 16; // aaguid
    if off + 2 > auth_data.len() {
        return Err(AppError::BadRequest(
            "Truncated attested credential data".to_string(),
        ));
    }
    let cred_len = u16::from_be_bytes([auth_data[off], auth_data[off + 1]]) as usize;
    off += 2;
    if off + cred_len > auth_data.len() {
        return Err(AppError::BadRequest("Truncated credential id".to_string()));
    }
    let credential_id = auth_data[off..off + cred_len].to_vec();
    off += cred_len;

    // The rest is the COSE_Key (CBOR).
    let cose_bytes = &auth_data[off..];
    let cose: Cbor = ciborium::from_reader(cose_bytes)
        .map_err(|_| AppError::BadRequest("Invalid COSE_Key CBOR".to_string()))?;
    let cose_map = cose
        .as_map()
        .ok_or_else(|| AppError::BadRequest("COSE_Key is not a map".to_string()))?;

    let mut kty = None;
    let mut crv = None;
    let mut x: Vec<u8> = Vec::new();
    let mut y: Vec<u8> = Vec::new();
    for (k, v) in cose_map.iter() {
        // Keys are COSE labels (integers). ciborium::Integer converts to i128.
        let label: Option<i128> = k.as_integer().map(i128::from);
        let val_u64 = || {
            v.as_integer()
                .and_then(|i| u64::try_from(i128::from(i)).ok())
        };
        match label {
            Some(1) => kty = val_u64(),
            Some(-1) => crv = val_u64(),
            Some(-2) => {
                if let Some(b) = v.as_bytes() {
                    x = b.clone();
                }
            }
            Some(-3) => {
                if let Some(b) = v.as_bytes() {
                    y = b.clone();
                }
            }
            _ => {}
        }
    }

    if kty != Some(2) || crv != Some(1) {
        return Err(AppError::BadRequest(
            "Only EC2 P-256 passkeys are supported".to_string(),
        ));
    }
    if x.len() != 32 || y.len() != 32 {
        return Err(AppError::BadRequest(
            "Invalid P-256 coordinates".to_string(),
        ));
    }
    let mut public_key = vec![0x04];
    public_key.extend_from_slice(&x);
    public_key.extend_from_slice(&y);

    Ok((credential_id, public_key))
}

// generate_recovery_code is re-exported for completeness; unused here.
#[allow(dead_code)]
fn _grc() -> Result<String, AppError> {
    generate_recovery_code()
}

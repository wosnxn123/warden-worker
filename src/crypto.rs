use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use constant_time_eq::constant_time_eq;
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey, SubtleCrypto};
use worker::js_sys;

use crate::error::AppError;

/// Number of PBKDF2 iterations for server-side password hashing
const SERVER_PBKDF2_ITERATIONS: u32 = 100_000;
/// Salt length in bytes
const SALT_LENGTH: usize = 16;
/// Derived key length in bits
const KEY_LENGTH_BITS: u32 = 256;

/// Gets the Crypto interface from the global scope.
/// Works in Cloudflare Workers by using js_sys::Reflect instead of WorkerGlobalScope.
fn get_crypto() -> Result<Crypto, AppError> {
    let global = js_sys::global();
    let crypto_value = js_sys::Reflect::get(&global, &JsValue::from_str("crypto"))
        .map_err(|e| AppError::Crypto(format!("Failed to get crypto property: {:?}", e)))?;

    crypto_value
        .dyn_into::<Crypto>()
        .map_err(|_| AppError::Crypto("Failed to cast to Crypto".to_string()))
}

/// Gets the SubtleCrypto interface from the global scope.
fn subtle_crypto() -> Result<SubtleCrypto, AppError> {
    Ok(get_crypto()?.subtle())
}

/// Derives a key using PBKDF2-SHA256.
pub async fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length_bits: u32,
) -> Result<Vec<u8>, AppError> {
    let subtle = subtle_crypto()?;

    // Import the password as a raw key material
    let password_array = Uint8Array::new_from_slice(password);
    let password_obj = password_array.as_ref();
    let key_material = JsFuture::from(
        subtle
            .import_key_with_str(
                "raw",
                password_obj,
                "PBKDF2",
                false,
                &js_sys::Array::of1(&JsValue::from_str("deriveBits")),
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 import_key await failed: {:?}", e)))?;

    let salt_array = Uint8Array::new_from_slice(salt);
    // Define PBKDF2 parameters
    let params = web_sys::Pbkdf2Params::new(
        "PBKDF2",
        JsValue::from_str("SHA-256").as_ref(),
        iterations,
        salt_array.as_ref(),
    );

    // Derive the bits
    let derived_bits = JsFuture::from(
        subtle
            .derive_bits_with_object(
                params.as_ref(),
                &CryptoKey::from(key_material),
                key_length_bits,
            )
            .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits failed: {:?}", e)))?,
    )
    .await
    .map_err(|e| AppError::Crypto(format!("PBKDF2 derive_bits await failed: {:?}", e)))?;

    Ok(js_sys::Uint8Array::new(&derived_bits).to_vec())
}

/// Generates a cryptographically secure random salt.
pub fn generate_salt() -> Result<String, AppError> {
    let crypto = get_crypto()?;
    let salt = Uint8Array::new_with_length(SALT_LENGTH as u32);
    crypto
        .get_random_values_with_array_buffer_view(&salt)
        .map_err(|e| AppError::Crypto(format!("Failed to generate random salt: {:?}", e)))?;

    Ok(BASE64.encode(salt.to_vec()))
}

/// Hashes the client-provided master password hash with server-side PBKDF2.
/// This adds an additional layer of security to the stored password hash.
pub async fn hash_password_for_storage(
    client_password_hash: &str,
    salt: &str,
) -> Result<String, AppError> {
    let salt_bytes = BASE64
        .decode(salt)
        .map_err(|e| AppError::Crypto(format!("Failed to decode salt: {:?}", e)))?;

    let derived = pbkdf2_sha256(
        client_password_hash.as_bytes(),
        &salt_bytes,
        SERVER_PBKDF2_ITERATIONS,
        KEY_LENGTH_BITS,
    )
    .await?;

    Ok(BASE64.encode(derived))
}

/// Verifies a password against a stored hash.
/// Returns true if the password matches.
pub async fn verify_password(
    client_password_hash: &str,
    stored_hash: &str,
    salt: &str,
) -> Result<bool, AppError> {
    let computed_hash = hash_password_for_storage(client_password_hash, salt).await?;
    Ok(constant_time_eq(
        computed_hash.as_bytes(),
        stored_hash.as_bytes(),
    ))
}

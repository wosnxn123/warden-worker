use super::{cipher::Cipher, folder::FolderResponse};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_hint: Option<String>,
    pub security_stamp: String,
    pub object: String,
    pub premium_from_organization: bool,
    pub force_password_reset: bool,
    pub email_verified: bool,
    pub two_factor_enabled: bool,
    pub premium: bool,
    pub uses_key_connector: bool,
    pub creation_date: String,
    pub private_key: String,
    pub key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    pub folders: Vec<FolderResponse>,
    #[serde(default)]
    pub collections: Vec<Value>,
    #[serde(default)]
    pub policies: Vec<Value>,
    pub ciphers: Vec<Cipher>,
    pub domains: Value,
    #[serde(default)]
    pub sends: Vec<Value>,
    pub object: String,
}

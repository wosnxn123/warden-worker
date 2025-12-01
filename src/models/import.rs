use serde::Deserialize;
use serde_json::Value;

/// Cipher data structure for import requests.
/// Aligned with vaultwarden's CipherData used in /ciphers/import endpoint.
/// Note: The `key` field is omitted as this service's compatibility version doesn't support per-cipher encryption keys.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportCipher {
    /// Optional cipher ID (only used in bulk share scenarios, not import)
    #[allow(dead_code)]
    pub id: Option<String>,
    /// Folder ID is not included in import - determined by folder_relationships instead
    #[allow(dead_code)]
    pub folder_id: Option<String>,
    #[serde(alias = "organizationID")]
    pub organization_id: Option<String>,
    #[serde(rename = "type")]
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<Value>,
    // Only one of these should exist, depending on type
    pub login: Option<Value>,
    pub secure_note: Option<Value>,
    pub card: Option<Value>,
    pub identity: Option<Value>,
    #[serde(default)]
    pub favorite: Option<bool>,
    pub reprompt: Option<i32>,
    pub password_history: Option<Value>,
    /// The revision datetime (in ISO 8601 format) of the client's local copy
    #[allow(dead_code)]
    pub last_known_revision_date: Option<String>,
}

/// Folder data structure for import requests.
/// Aligned with vaultwarden's FolderData.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportFolder {
    /// Optional folder ID - if provided and exists, the existing folder is used
    pub id: Option<String>,
    pub name: String,
}

/// Relationship between cipher index and folder index in the import arrays.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FolderRelationship {
    /// Cipher index in the ciphers array
    pub key: usize,
    /// Folder index in the folders array
    pub value: usize,
}

/// Import request payload structure.
/// Aligned with vaultwarden's ImportData used in POST /ciphers/import.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    pub ciphers: Vec<ImportCipher>,
    pub folders: Vec<ImportFolder>,
    #[serde(default)]
    pub folder_relationships: Vec<FolderRelationship>,
}

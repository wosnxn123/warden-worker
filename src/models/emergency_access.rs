use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::d1_query;
use crate::{db, error::AppError};

/// Emergency access type.
/// 0 = View (grantee can view the vault), 1 = Takeover (grantee can take over).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EmergencyAccessType {
    View = 0,
    Takeover = 1,
}

impl EmergencyAccessType {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::View),
            1 => Some(Self::Takeover),
            _ => None,
        }
    }
}

/// Emergency access status.
/// Invited = 0, Accepted = 1, Confirmed = 2, RecoveryInitiated = -1.
pub const STATUS_INVITED: i32 = 0;
pub const STATUS_ACCEPTED: i32 = 1;
pub const STATUS_CONFIRMED: i32 = 2;
pub const STATUS_RECOVERY_INITIATED: i32 = -1;
/// Granted by the grantor approving a recovery request out-of-band.
pub const STATUS_APPROVED: i32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccess {
    pub id: String,
    pub grantor_id: String,
    pub grantee_id: Option<String>,
    pub grantee_email: Option<String>,
    pub key_encrypted: Option<String>,
    #[serde(rename = "atype")]
    pub atype: i32,
    pub status: i32,
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl EmergencyAccess {
    /// JSON representation as seen by the grantor (owner of the vault).
    pub fn to_json(&self, grantee_email: Option<&str>) -> Value {
        // The "granteeId" is only meaningful once the invite is accepted.
        let grantee_id = self.grantee_id.clone();
        // Email: prefer the resolved grantee email, fall back to the stored invite email.
        let email = grantee_email
            .map(str::to_owned)
            .or_else(|| self.grantee_email.clone());

        json!({
            "id": self.id,
            "grantorId": self.grantor_id,
            "granteeId": grantee_id,
            "email": email,
            "keyEncrypted": self.key_encrypted,
            "type": self.atype,
            "status": self.status,
            "waitTimeDays": self.wait_time_days,
            "creationDate": self.created_at,
            "recoveryInitiatedDate": self.recovery_initiated_at,
            "object": "emergencyAccess"
        })
    }

    pub async fn find_by_id(db: &db::Db, id: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM emergency_access WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .transpose()
    }

    /// All records where the current user is the grantor (trusted contacts).
    pub async fn list_by_grantor(db: &db::Db, grantor_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM emergency_access WHERE grantor_id = ?1 ORDER BY created_at ASC",
            grantor_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;
        rows.into_iter()
            .map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .collect()
    }

    /// All records where the current user is the grantee (granted access).
    pub async fn list_by_grantee(db: &db::Db, grantee_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM emergency_access WHERE grantee_id = ?1 ORDER BY created_at ASC",
            grantee_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;
        rows.into_iter()
            .map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .collect()
    }

    pub async fn insert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO emergency_access (id, grantor_id, grantee_id, grantee_email, key_encrypted, atype, status, wait_time_days, recovery_initiated_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            &self.id,
            &self.grantor_id,
            self.grantee_id.as_deref(),
            self.grantee_email.as_deref(),
            self.key_encrypted.as_deref(),
            self.atype,
            self.status,
            self.wait_time_days,
            self.recovery_initiated_at.as_deref(),
            &self.created_at,
            &self.updated_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn save(&self, db: &db::Db) -> Result<(), AppError> {
        let now = db::now_string();
        d1_query!(
            db,
            "UPDATE emergency_access SET grantee_id = ?1, grantee_email = ?2, key_encrypted = ?3, status = ?4, wait_time_days = ?5, recovery_initiated_at = ?6, updated_at = ?7 WHERE id = ?8",
            self.grantee_id.as_deref(),
            self.grantee_email.as_deref(),
            self.key_encrypted.as_deref(),
            self.status,
            self.wait_time_days,
            self.recovery_initiated_at.as_deref(),
            &now,
            &self.id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn delete(db: &db::Db, id: &str) -> Result<(), AppError> {
        d1_query!(db, "DELETE FROM emergency_access WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

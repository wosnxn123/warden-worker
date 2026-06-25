#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::d1_query;
use crate::{db, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    #[serde(rename = "type")]
    pub atype: i32,
    pub user_id: Option<String>,
    pub organization_id: Option<String>,
    pub cipher_id: Option<String>,
    pub collection_id: Option<String>,
    pub device_type: Option<i32>,
    pub ip: Option<String>,
    pub data: Option<String>,
    pub created_at: String,
}

impl Event {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "type": self.atype,
            "userId": self.user_id,
            "organizationId": self.organization_id,
            "cipherId": self.cipher_id,
            "collectionId": self.collection_id,
            "deviceType": self.device_type,
            "ipAddress": self.ip,
            "date": self.created_at,
            "object": "event"
        })
    }

    /// Record an audit event. Best-effort: errors are logged, not propagated.
    pub async fn record(
        db: &db::Db,
        atype: i32,
        user_id: Option<&str>,
        organization_id: Option<&str>,
        cipher_id: Option<&str>,
        device_type: Option<i32>,
        ip: Option<&str>,
    ) {
        let evt = Event {
            id: uuid::Uuid::new_v4().to_string(),
            atype,
            user_id: user_id.map(str::to_owned),
            organization_id: organization_id.map(str::to_owned),
            cipher_id: cipher_id.map(str::to_owned),
            collection_id: None,
            device_type,
            ip: ip.map(str::to_owned),
            data: None,
            created_at: db::now_string(),
        };
        if let Err(e) = evt.insert(db).await {
            log::warn!("Failed to record event: {e}");
        }
    }

    pub async fn insert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO events (id, type, user_id, organization_id, cipher_id, collection_id, device_type, ip, data, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &self.id,
            self.atype,
            self.user_id.as_deref(),
            self.organization_id.as_deref(),
            self.cipher_id.as_deref(),
            self.collection_id.as_deref(),
            self.device_type,
            self.ip.as_deref(),
            self.data.as_deref(),
            &self.created_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn list_by_org(db: &db::Db, org_id: &str, limit: i64) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM events WHERE organization_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            org_id,
            limit
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
}

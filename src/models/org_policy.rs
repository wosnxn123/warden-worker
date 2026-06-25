use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::d1_query;
use crate::{db, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicy {
    pub id: String,
    pub org_id: String,
    pub atype: i32,
    #[serde(with = "bool_from_int")]
    pub enabled: bool,
    pub data: String,
}

impl OrgPolicy {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "organizationId": self.org_id,
            "type": self.atype,
            "data": serde_json::from_str::<Value>(&self.data).unwrap_or(Value::Null),
            "enabled": self.enabled,
            "object": "policy"
        })
    }

    pub async fn list_by_org(db: &db::Db, org_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM org_policies WHERE org_id = ?1 ORDER BY atype ASC",
            org_id
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

    pub async fn upsert(
        db: &db::Db,
        org_id: &str,
        atype: i32,
        enabled: bool,
        data: &str,
    ) -> Result<(), AppError> {
        let id = uuid::Uuid::new_v4().to_string();
        d1_query!(
            db,
            "INSERT INTO org_policies (id, org_id, atype, enabled, data) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(org_id, atype) DO UPDATE SET enabled=?4, data=?5",
            &id,
            org_id,
            atype,
            enabled as i32,
            data
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

/// Organization policy types (subset of Bitwarden's enum).
#[allow(dead_code)]
pub mod policy_type {
    pub const TWO_FACTOR_AUTHENTICATION: i32 = 0;
    pub const MASTER_PASSWORD: i32 = 1;
    pub const PASSWORD_GENERATOR: i32 = 2;
    pub const SINGLE_ORG: i32 = 3;
    pub const REQUIRE_SSO: i32 = 4;
    pub const PERSONAL_OWNERSHIP: i32 = 5;
    pub const DISABLE_HIDE_EMAIL: i32 = 6;
    pub const SEND_OPTIONS: i32 = 7;
}

mod bool_from_int {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        Ok(i64::deserialize(d)? != 0)
    }
    pub fn serialize<S: Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
        if *v {
            s.serialize_i64(1)
        } else {
            s.serialize_i64(0)
        }
    }
}

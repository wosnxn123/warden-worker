#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::d1_query;
use crate::{db, error::AppError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Collection {
    /// `name` here is the encrypted collection name (already cipher-re-encrypted for the
    /// requesting user). The caller must supply the per-user-encrypted name.
    pub fn to_json(&self, encrypted_name: &str) -> Value {
        json!({
            "id": self.id,
            "organizationId": self.org_id,
            "name": encrypted_name,
            "object": "collection"
        })
    }

    pub async fn find_by_id(db: &db::Db, id: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM collections WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn list_by_org(db: &db::Db, org_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM collections WHERE org_id = ?1 ORDER BY created_at ASC",
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

    pub async fn insert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO collections (id, org_id, name, external_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &self.id,
            &self.org_id,
            &self.name,
            self.external_id.as_deref(),
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
            "UPDATE collections SET name = ?1, external_id = ?2, updated_at = ?3 WHERE id = ?4",
            &self.name,
            self.external_id.as_deref(),
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
        d1_query!(db, "DELETE FROM collections WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

/// Per-user access to a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionUser {
    pub user_id: String,
    pub collection_id: String,
    #[serde(with = "bool_from_int")]
    pub read_only: bool,
    #[serde(with = "bool_from_int")]
    pub hide_passwords: bool,
    #[serde(with = "bool_from_int")]
    pub manage: bool,
}

impl CollectionUser {
    pub async fn list_for_collection(
        db: &db::Db,
        collection_id: &str,
    ) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM users_collections WHERE collection_id = ?1",
            collection_id
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

    pub async fn upsert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO users_collections (user_id, collection_id, read_only, hide_passwords, manage)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id, collection_id) DO UPDATE SET read_only=?3, hide_passwords=?4, manage=?5",
            &self.user_id,
            &self.collection_id,
            self.read_only as i32,
            self.hide_passwords as i32,
            self.manage as i32
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn delete(db: &db::Db, user_id: &str, collection_id: &str) -> Result<(), AppError> {
        d1_query!(
            db,
            "DELETE FROM users_collections WHERE user_id = ?1 AND collection_id = ?2",
            user_id,
            collection_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

/// Cipher ↔ Collection association.
pub struct CollectionCipher;

impl CollectionCipher {
    pub async fn set_for_cipher(
        db: &db::Db,
        cipher_id: &str,
        collection_ids: &[String],
    ) -> Result<(), AppError> {
        d1_query!(
            db,
            "DELETE FROM ciphers_collections WHERE cipher_id = ?1",
            cipher_id
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        for cid in collection_ids {
            d1_query!(
                db,
                "INSERT OR IGNORE INTO ciphers_collections (cipher_id, collection_id) VALUES (?1, ?2)",
                cipher_id,
                cid
            )
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        }
        Ok(())
    }

    pub async fn list_for_cipher(db: &db::Db, cipher_id: &str) -> Result<Vec<String>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT collection_id FROM ciphers_collections WHERE cipher_id = ?1",
            cipher_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;
        rows.into_iter()
            .map(|r| {
                r.get("collection_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
                    .ok_or(AppError::Internal)
            })
            .collect()
    }

    /// All collections a user can access (via direct assignment or access_all membership).
    pub async fn list_collection_ids_for_user(
        db: &db::Db,
        user_id: &str,
    ) -> Result<Vec<String>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT uc.collection_id FROM users_collections uc WHERE uc.user_id = ?1",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;
        let mut ids: Vec<String> = rows
            .into_iter()
            .filter_map(|r| {
                r.get("collection_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
            .collect();

        // Also include collections of orgs where the user has access_all.
        let all_rows: Vec<Value> = d1_query!(
            db,
            "SELECT c.id FROM collections c
             JOIN users_organizations uo ON uo.org_id = c.org_id
             WHERE uo.user_id = ?1 AND uo.access_all = 1 AND uo.status = 2",
            user_id
        )
        .map_err(|_| AppError::Database)?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()
        .map_err(|_| AppError::Database)?;
        for r in all_rows {
            if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                ids.push(id.to_string());
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
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

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::d1_query;
use crate::{db, error::AppError};

/// Membership status in an organization.
pub const STATUS_INVITED: i32 = 0;
pub const STATUS_ACCEPTED: i32 = 1;
pub const STATUS_CONFIRMED: i32 = 2;

/// Membership type (role).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MembershipType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
}

impl MembershipType {
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Owner),
            1 => Some(Self::Admin),
            2 => Some(Self::User),
            3 => Some(Self::Manager),
            _ => None,
        }
    }

    pub fn has_admin_rights(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Organization {
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "billingEmail": self.billing_email,
            "enabled": true,
            "object": "organization"
        })
    }

    pub async fn find_by_id(db: &db::Db, id: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM organizations WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn insert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO organizations (id, name, billing_email, private_key, public_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &self.id,
            &self.name,
            &self.billing_email,
            self.private_key.as_deref(),
            self.public_key.as_deref(),
            &self.created_at,
            &self.updated_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn delete(db: &db::Db, id: &str) -> Result<(), AppError> {
        d1_query!(db, "DELETE FROM organizations WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub id: String,
    pub user_id: String,
    pub org_id: String,
    pub invited_by_email: Option<String>,
    #[serde(with = "bool_from_int")]
    pub access_all: bool,
    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Membership {
    /// JSON as seen in the user's profile (`profile.organizations`).
    pub fn to_profile_json(&self, org: &Organization) -> Value {
        json!({
            "id": self.org_id,
            "name": org.name,
            "usePolicies": true,
            "useGroups": true,
            "useDirectory": false,
            "useEvents": false,
            "useTotp": true,
            "use2fa": true,
            "useApi": true,
            "useSso": false,
            "useKeyConnector": false,
            "useScim": false,
            "useResetPassword": false,
            "selfHost": false,
            "useCustomPermissions": false,
            "useOrganizationDomainLinking": false,
            "businessName": null,
            "planType": "TeamsStarter",
            "seats": 10,
            "maxCollections": 0,
            "maxStorageGb": 1,
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "billingEmail": org.billing_email,
            "enabled": true,
            "userIsOwner": self.atype == MembershipType::Owner as i32,
            "userIsAdmin": self.atype == MembershipType::Admin as i32,
            "userId": self.user_id,
            "status": self.status,
            "type": self.atype,
            "enabled": true,
            "object": "profileOrganization"
        })
    }

    /// JSON as seen in the org's user list.
    pub fn to_user_json(&self, email: &str, name: Option<&str>) -> Value {
        json!({
            "id": self.id,
            "userId": self.user_id,
            "organizationId": self.org_id,
            "name": name,
            "email": email,
            "accessAll": self.access_all,
            "status": self.status,
            "type": self.atype,
            "object": "organizationUserUserDetails"
        })
    }

    pub async fn find_by_id(db: &db::Db, id: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> =
            d1_query!(db, "SELECT * FROM users_organizations WHERE id = ?1", id)
                .map_err(|_| AppError::Database)?
                .first(None)
                .await
                .map_err(|_| AppError::Database)?;
        row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .transpose()
    }

    /// The membership linking a user to an org (any status).
    pub async fn find_by_user_and_org(
        db: &db::Db,
        user_id: &str,
        org_id: &str,
    ) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(
            db,
            "SELECT * FROM users_organizations WHERE user_id = ?1 AND org_id = ?2",
            user_id,
            org_id
        )
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
            "SELECT * FROM users_organizations WHERE org_id = ?1 ORDER BY atype ASC, created_at ASC",
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

    /// All confirmed memberships of a user (for sync).
    pub async fn list_by_user(db: &db::Db, user_id: &str) -> Result<Vec<Self>, AppError> {
        let rows: Vec<Value> = d1_query!(
            db,
            "SELECT * FROM users_organizations WHERE user_id = ?1",
            user_id
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
            "INSERT INTO users_organizations (id, user_id, org_id, invited_by_email, access_all, akey, status, atype, reset_password_key, external_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &self.id,
            &self.user_id,
            &self.org_id,
            self.invited_by_email.as_deref(),
            self.access_all as i32,
            &self.akey,
            self.status,
            self.atype,
            self.reset_password_key.as_deref(),
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
            "UPDATE users_organizations SET access_all = ?1, akey = ?2, status = ?3, atype = ?4, reset_password_key = ?5, external_id = ?6, updated_at = ?7 WHERE id = ?8",
            self.access_all as i32,
            &self.akey,
            self.status,
            self.atype,
            self.reset_password_key.as_deref(),
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
        d1_query!(db, "DELETE FROM users_organizations WHERE id = ?1", id)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
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

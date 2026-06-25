use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::d1_query;
use crate::{db, error::AppError};

/// Temporary record tracking an in-flight OIDC login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoAuth {
    pub state: String,
    pub code_verifier: Option<String>,
    pub redirect_uri: String,
    pub user_email: Option<String>,
    pub code: Option<String>,
    pub code_response_error: Option<String>,
    pub created_at: String,
}

impl SsoAuth {
    pub async fn insert(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "INSERT INTO sso_auth (state, code_verifier, redirect_uri, user_email, code, code_response_error, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &self.state,
            self.code_verifier.as_deref(),
            &self.redirect_uri,
            self.user_email.as_deref(),
            self.code.as_deref(),
            self.code_response_error.as_deref(),
            &self.created_at
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn find_by_state(db: &db::Db, state: &str) -> Result<Option<Self>, AppError> {
        let row: Option<Value> = d1_query!(db, "SELECT * FROM sso_auth WHERE state = ?1", state)
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        row.map(|r| serde_json::from_value(r).map_err(|_| AppError::Internal))
            .transpose()
    }

    pub async fn save(&self, db: &db::Db) -> Result<(), AppError> {
        d1_query!(
            db,
            "UPDATE sso_auth SET code = ?1, user_email = ?2, code_response_error = ?3 WHERE state = ?4",
            self.code.as_deref(),
            self.user_email.as_deref(),
            self.code_response_error.as_deref(),
            &self.state
        )
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn delete(db: &db::Db, state: &str) -> Result<(), AppError> {
        d1_query!(db, "DELETE FROM sso_auth WHERE state = ?1", state)
            .map_err(|_| AppError::Database)?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}

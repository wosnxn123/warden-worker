use crate::error::AppError;
use std::sync::Arc;
use worker::{D1Database, Env};

pub fn get_db(env: &Arc<Env>) -> Result<D1Database, AppError> {
    env.d1("vault1").map_err(AppError::Worker)
}

/// Ensures the password_salt column exists in the users table.
/// This provides seamless migration for existing databases.
/// Ignores "duplicate column name" errors if the column already exists.
pub async fn ensure_schema(env: &Env) {
    let db = match env.d1("vault1") {
        Ok(db) => db,
        Err(e) => {
            log::error!("Failed to get database: {:?}", e);
            return;
        }
    };

    // Try to add the column
    if let Err(e) = db
        .prepare("ALTER TABLE users ADD COLUMN password_salt TEXT")
        .run()
        .await
    {
        let err_msg = format!("{:?}", e);
        // Ignore "duplicate column name" error (column already exists)
        if !err_msg.to_lowercase().contains("duplicate column name") {
            log::error!("Failed to ensure schema: {}", err_msg);
        }
    }
}

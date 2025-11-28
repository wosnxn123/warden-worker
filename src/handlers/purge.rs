//! Purge handler for cleaning up soft-deleted ciphers
//!
//! This module handles the automatic cleanup of ciphers that have been
//! soft-deleted (marked with deleted_at) for longer than the configured
//! retention period.

use chrono::{Duration, Utc};
use worker::{query, D1Database, Env};

/// Default number of days to keep soft-deleted items before purging
const DEFAULT_PURGE_DAYS: i64 = 30;

/// Get the purge threshold days from environment variable or use default
fn get_purge_days(env: &Env) -> i64 {
    env.var("TRASH_AUTO_DELETE_DAYS")
        .ok()
        .and_then(|v| v.to_string().parse::<i64>().ok())
        .unwrap_or(DEFAULT_PURGE_DAYS)
}

/// Purge soft-deleted ciphers that are older than the configured threshold.
///
/// This function:
/// 1. Calculates the cutoff timestamp based on TRASH_AUTO_DELETE_DAYS env var (default: 30 days)
/// 2. Deletes all ciphers where deleted_at is not null and older than the cutoff
/// 3. If TRASH_AUTO_DELETE_DAYS is set to 0 or negative, skips purging (disabled)
///
/// Returns the number of purged records on success.
pub async fn purge_deleted_ciphers(env: &Env) -> Result<u32, worker::Error> {
    let purge_days = get_purge_days(env);

    // If purge_days is 0 or negative, auto-purge is disabled
    if purge_days <= 0 {
        log::info!("Auto-purge is disabled (TRASH_AUTO_DELETE_DAYS <= 0)");
        return Ok(0);
    }

    let db: D1Database = env.d1("vault1")?;

    // Calculate the cutoff timestamp
    let now = Utc::now();
    let cutoff = now - Duration::days(purge_days);
    let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

    log::info!(
        "Purging soft-deleted ciphers older than {} days (before {})",
        purge_days,
        cutoff_str
    );

    // First, count the records to be deleted (for logging purposes)
    let count_result = query!(
        &db,
        "SELECT COUNT(*) as count FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
        cutoff_str
    )?
    .first::<CountResult>(None)
    .await?;

    let count = count_result.map(|r| r.count).unwrap_or(0);

    if count > 0 {
        // Delete the records
        query!(
            &db,
            "DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1",
            cutoff_str
        )?
        .run()
        .await?;

        log::info!("Successfully purged {} soft-deleted cipher(s)", count);
    } else {
        log::info!("No soft-deleted ciphers to purge");
    }

    Ok(count)
}

/// Helper struct for count query result
#[derive(serde::Deserialize)]
struct CountResult {
    count: u32,
}

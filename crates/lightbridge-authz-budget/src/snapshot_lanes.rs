//! The refresher's work-list selection, in two lanes — ADR-0034 §15.6.
//!
//! ## What §15 had, and what it cost
//!
//! One lane: "every account seen inside `active_window` (10 minutes), oldest reading first". An
//! account outside it was simply not refreshed. That is cheap and it reads as reasonable — until
//! you look at what the table actually shows in production, where every idle row carries
//! `refreshed_at ≈ last_seen_at + 10 min`: each account's balance freezes ten minutes after its
//! last request and stays frozen. Two consequences, both bad:
//!
//! - the gateway enforces on a reading that can be arbitrarily old while reporting an
//!   `budget_snapshot_age_seconds` that says so but that nothing acts on; and
//! - at 00:00 UTC on the 1st every one of those frozen readings becomes period-mismatched at once,
//!   i.e. **absent**, so every account that was merely quiet turns into `known: false` until it
//!   both sends a request and waits for a tick.
//!
//! Dropping an account from the work list was never the only option; refreshing it *less often*
//! was, and costs one spend query per idle account per [`SnapshotRefreshConfig::slow_lane_interval`].
//!
//! ## The two lanes
//!
//! | Lane | Membership | Cadence |
//! |---|---|---|
//! | fast | `last_seen_at` within `slow_lane_interval` | every tick (`interval`) |
//! | slow | `last_seen_at` older than that, within `active_window` | once per `slow_lane_interval` |
//!
//! `slow_lane_interval` is both the boundary and the slow cadence on purpose — two separate knobs
//! would let an operator configure a band in which an account belongs to neither lane and is
//! silently dropped, which is the bug this module exists to remove.
//!
//! A row that has never been computed (`refreshed_at IS NULL`) is always due, in either lane: it is
//! the one state that renders as `known: false` at the gateway, so it is never made to wait.

use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::error::BudgetError;
use crate::snapshot_config::SnapshotRefreshConfig;
use crate::snapshot_store::SnapshotStore;

/// `$1` active-window cutoff, `$2` slow-lane cutoff (doubles as the fast/slow boundary and as the
/// "due" test for the slow lane), `$3` batch limit.
///
/// `ORDER BY refreshed_at ASC NULLS FIRST` is unchanged from §15 and still load-bearing: a batch
/// that truncates the list must truncate it at the *freshest* rows, so a starved account cannot
/// stay starved, and a never-computed one always sorts first.
const DUE_SQL: &str = "SELECT budget_account_id FROM budget_remaining_snapshots \
     WHERE last_seen_at >= $1 \
       AND (last_seen_at >= $2 OR refreshed_at IS NULL OR refreshed_at < $2) \
     ORDER BY refreshed_at ASC NULLS FIRST LIMIT $3";

impl SnapshotStore {
    /// The accounts this tick should recompute: the fast lane in full, plus whichever slow-lane
    /// accounts are due, oldest reading first, at most `config.batch` of them.
    pub async fn due_accounts(
        &self,
        now: DateTime<Utc>,
        config: &SnapshotRefreshConfig,
    ) -> Result<Vec<String>, BudgetError> {
        let storage = |err: sqlx::Error| BudgetError::StorageFailed(err.to_string());
        let rows = sqlx::query(DUE_SQL)
            .bind(now - to_chrono(config.active_window, 24 * 60 * 60))
            .bind(now - to_chrono(config.slow_lane_interval, 600))
            .bind(config.batch)
            .fetch_all(self.pool_ref())
            .await
            .map_err(storage)?;
        rows.iter()
            .map(|row| {
                row.try_get::<String, _>("budget_account_id")
                    .map_err(storage)
            })
            .collect()
    }
}

/// `std::time::Duration` → `chrono::Duration`, falling back to `fallback_secs` for a value too
/// large for `chrono` to represent. Config is `u64` seconds, so an operator can write a number
/// `chrono` refuses; the fallback keeps the loop running on the documented default rather than
/// turning a typo into a panic or a zero-width window that drops every account.
pub(crate) fn to_chrono(value: std::time::Duration, fallback_secs: i64) -> chrono::Duration {
    chrono::Duration::from_std(value).unwrap_or_else(|_| chrono::Duration::seconds(fallback_secs))
}

//! ADR-0035 D9: storing a pool-aware snapshot reading. Kept beside `snapshot_store.rs` (which
//! sits near the 200-line rule) as a second `impl SnapshotStore` block.

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::snapshot_store::SnapshotStore;

const STORE_POOL_READING_SQL: &str = "UPDATE budget_remaining_snapshots SET \
     period = $2, ceiling_micros = $3, spent_micros = $4, remaining_micros = $5, \
     next_reset_at = $6, allowance_remaining_micros = $7, granted_remaining_micros = $8, \
     paid_remaining_micros = $9, debt_micros = $10, refreshed_at = now(), stale_since = NULL \
     WHERE budget_account_id = $1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolReading {
    /// All settled credit, every pool.
    pub ceiling_micros: i64,
    /// Debt plus the unsettled tail.
    pub spent_micros: i64,
    pub next_reset_at: DateTime<Utc>,
    pub allowance_remaining_micros: i64,
    pub granted_remaining_micros: i64,
    pub paid_remaining_micros: i64,
    pub debt_micros: i64,
}

impl SnapshotStore {
    pub async fn store_pool_reading(
        &self,
        budget_account_id: &str,
        period: &Period,
        reading: &PoolReading,
    ) -> Result<(), BudgetError> {
        sqlx::query(STORE_POOL_READING_SQL)
            .bind(budget_account_id)
            .bind(period.to_string())
            .bind(reading.ceiling_micros)
            .bind(reading.spent_micros)
            // Signed and unclamped, like ADR-0034's: overspend is reachable by construction.
            .bind(reading.ceiling_micros.saturating_sub(reading.spent_micros))
            .bind(reading.next_reset_at)
            .bind(reading.allowance_remaining_micros)
            .bind(reading.granted_remaining_micros)
            .bind(reading.paid_remaining_micros)
            .bind(reading.debt_micros)
            .execute(self.pool_ref())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }
}

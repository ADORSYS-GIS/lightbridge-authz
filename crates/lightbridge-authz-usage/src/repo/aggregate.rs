//! KPI aggregate existence checks (#587).
//!
//! Split out of `repo.rs` by the LoC gate: the query endpoints route to the KPI aggregates when
//! they exist and fall back to the raw grain table when absent, and these two helpers are the
//! routing decision. Keeping them here lets `repo.rs` stay under its grandfathered ceiling.

use crate::repo::StoreRepo;
use lightbridge_authz_core::{Error, Result};

impl StoreRepo {
    /// Whether a named KPI aggregate materialized view exists (#587). The query endpoints route to
    /// the aggregates when present and fall back to the raw grain table when absent (e.g. before
    /// migration 20260918000001 has run) -- the "prove the aggregate is read, not assumed" rule
    /// with a graceful degradation. `to_regclass` returns NULL for a missing relation.
    pub(crate) async fn aggregate_exists(&self, view: &str) -> Result<bool> {
        let exists: Option<bool> = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(view)
            .fetch_one(self.pool())
            .await
            .map_err(|e| Error::Database(format!("aggregate existence check failed: {e}")))?;
        Ok(exists.unwrap_or(false))
    }

    /// Whether ALL of the named KPI aggregate materialized views exist (#587). The day-facts query
    /// routes to the aggregates only when every view it joins exists -- checking a single one would
    /// route to a join that references a missing view and fail with a hard 500 instead of degrading
    /// to the raw table.
    pub(crate) async fn aggregates_exist(&self, views: &[&str]) -> Result<bool> {
        for view in views {
            if !self.aggregate_exists(view).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

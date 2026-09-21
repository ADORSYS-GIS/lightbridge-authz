//! KPI aggregate existence checks (#587).
//!
//! Split out of `repo.rs` by the LoC gate: the query endpoints route to the KPI aggregates when
//! they exist and fall back to the raw grain table when absent. The routing decision is cached with
//! a short TTL so the `to_regclass` probe does not run on every request (the #587 review's P2).

use crate::aggregate_refresh::AGGREGATE_VIEWS;
use crate::repo::StoreRepo;
use lightbridge_authz_core::{Error, Result};
use std::time::{Duration, Instant};

/// How long a cached aggregate-existence decision is trusted before the DB is probed again. The
/// views are created by one migration, so they either all exist or none do; a short TTL keeps the
/// graceful degradation (a server started before the migration serves raw, then picks the
/// aggregates up within a minute once the migration has run) while eliminating the per-request
/// probe.
const AGGREGATE_CACHE_TTL: Duration = Duration::from_secs(60);

/// TTL cache for the aggregate-existence routing decision. Held behind a `Mutex` (never across an
/// `.await`), shared by every query path via `StoreRepo`.
#[derive(Debug)]
pub(crate) struct AggregateCache {
    available: Option<bool>,
    checked_at: Option<Instant>,
}

impl AggregateCache {
    pub(crate) fn new() -> Self {
        Self {
            available: None,
            checked_at: None,
        }
    }
}

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

    /// Whether the KPI aggregate materialized views are available for routing, cached with a short
    /// TTL so the decision does not run a `to_regclass` probe on every request. The views are
    /// created by one migration, so they either all exist or none do -- a single cached boolean
    /// covers both the day-facts and seat routing paths.
    pub(crate) async fn aggregate_views_available(&self) -> Result<bool> {
        {
            let cache = self
                .aggregate_cache
                .lock()
                .expect("aggregate cache lock poisoned");
            if let Some(checked_at) = cache.checked_at
                && checked_at.elapsed() < AGGREGATE_CACHE_TTL
            {
                return Ok(cache.available.unwrap_or(false));
            }
        }

        // Cache miss or stale: probe the DB, then refresh the cache.
        let available = self.aggregates_exist(AGGREGATE_VIEWS).await?;
        let mut cache = self
            .aggregate_cache
            .lock()
            .expect("aggregate cache lock poisoned");
        cache.available = Some(available);
        cache.checked_at = Some(Instant::now());
        Ok(available)
    }
}

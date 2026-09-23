//! KPI aggregate existence + freshness checks (#587).
//!
//! Split out of `repo.rs` by the LoC gate: the query endpoints route to the KPI aggregates when
//! they exist AND are fresh, and fall back to the raw grain table otherwise. The routing decision
//! is cached with a short TTL so the `to_regclass` probe and the freshness read do not run on every
//! request (the #587 review's P2).

use crate::repo::StoreRepo;
use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long a cached aggregate-existence/freshness decision is trusted before the DB is probed
/// again. The views are created by one migration, so they either all exist or none do; a short TTL
/// keeps the graceful degradation (a server started before the migration serves raw, then picks the
/// aggregates up within a minute once the migration has run) while eliminating the per-request
/// probe.
const AGGREGATE_CACHE_TTL: Duration = Duration::from_secs(60);

/// Default staleness bound for the KPI aggregates: two hours. Matches the default refresh interval
/// (3600s) with one interval of slack, so a refresh that is merely late does not bounce the query
/// paths back to raw, but a disabled job (or a broken one) degrades to raw within two hours instead
/// of serving a stale snapshot forever.
const DEFAULT_AGGREGATE_STALENESS: Duration = Duration::from_secs(7200);

/// TTL cache for the aggregate routing decision. Held behind a `Mutex` (never across an `.await`),
/// shared by every query path via `StoreRepo`.
#[derive(Debug)]
pub(crate) struct AggregateCache {
    /// Per-view existence, TTL-cached: view name -> (exists, checked_at). Cached per view so the
    /// day-facts and seat grains degrade independently (the #587 review's P3).
    entries: HashMap<String, (bool, Instant)>,
    /// Global freshness of the aggregate set, TTL-cached: (fresh, checked_at). All aggregates are
    /// refreshed together, so freshness is one decision shared by every grain.
    fresh: Option<(bool, Instant)>,
    /// How old `last_refreshed_at` may be before the aggregate set is treated as stale and the
    /// query paths fall back to the raw grain table. Defaults to [`DEFAULT_AGGREGATE_STALENESS`];
    /// the server builder overrides it from the `aggregate_refresh.interval_seconds` config so it
    /// tracks the configured cadence (see `lib.rs`).
    staleness: Duration,
}

impl AggregateCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            fresh: None,
            staleness: DEFAULT_AGGREGATE_STALENESS,
        }
    }
}

impl StoreRepo {
    /// Sets the aggregate staleness bound (see [`AggregateCache::staleness`]). The server builder
    /// calls this with a bound derived from the configured refresh interval; tests use the default.
    pub fn with_aggregate_staleness(self, staleness: Duration) -> Self {
        self.aggregate_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .staleness = staleness;
        self
    }

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

    /// Whether the named KPI aggregate materialized views are available for routing, cached with a
    /// short TTL so the decision does not probe the DB on every request. `views` is the grain's own
    /// list (day-facts or seat), so each grain degrades independently (the #587 review's P3).
    ///
    /// Returns `true` only when EVERY named view exists AND the aggregate set is fresh (see
    /// [`StoreRepo::aggregate_is_fresh`]). The freshness half is what makes a disabled refresh
    /// degrade to the raw table instead of silently serving a one-time snapshot forever (the #587
    /// review's P2).
    pub(crate) async fn aggregate_views_available(&self, views: &[&str]) -> Result<bool> {
        for view in views {
            if !self.aggregate_exists_cached(view).await? {
                return Ok(false);
            }
        }
        self.aggregate_is_fresh().await
    }

    /// Per-view existence, TTL-cached.
    async fn aggregate_exists_cached(&self, view: &str) -> Result<bool> {
        {
            let cache = self
                .aggregate_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((exists, checked_at)) = cache.entries.get(view)
                && checked_at.elapsed() < AGGREGATE_CACHE_TTL
            {
                return Ok(*exists);
            }
        }

        let exists = self.aggregate_exists(view).await?;
        let mut cache = self
            .aggregate_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache
            .entries
            .insert(view.to_string(), (exists, Instant::now()));
        Ok(exists)
    }

    /// Whether the aggregate set is fresh: `last_refreshed_at` is within the cache's staleness
    /// bound. `NULL` (never refreshed) is stale. TTL-cached.
    ///
    /// This is what turns "the views exist" into "the views are worth reading": an aggregate that
    /// exists but has not been refreshed in a long time (e.g. the refresh job was disabled) would
    /// otherwise serve a stale snapshot forever, invisibly.
    async fn aggregate_is_fresh(&self) -> Result<bool> {
        let staleness = {
            let cache = self
                .aggregate_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some((fresh, checked_at)) = cache.fresh
                && checked_at.elapsed() < AGGREGATE_CACHE_TTL
            {
                return Ok(fresh);
            }
            cache.staleness
        };

        let last: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT last_refreshed_at FROM usage_aggregate_refresh_state WHERE id = TRUE",
        )
        .fetch_optional(self.pool())
        .await
        .map_err(|e| Error::Database(format!("aggregate freshness check failed: {e}")))?;
        // A `last_refreshed_at` in the future (clock skew) is treated as fresh: `to_std()` errors
        // on a negative duration, and `map_or(true, ...)` routes that to "fresh" rather than
        // bouncing the query paths back to raw.
        let fresh = last.is_some_and(|t| (Utc::now() - t).to_std().map_or(true, |d| d < staleness));

        let mut cache = self
            .aggregate_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.fresh = Some((fresh, Instant::now()));
        Ok(fresh)
    }
}

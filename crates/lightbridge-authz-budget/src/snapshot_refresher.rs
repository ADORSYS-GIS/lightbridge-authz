//! The background loop that keeps `budget_remaining_snapshots` warm — ADR-0034 §15.
//!
//! This is where the expensive half of the Dynamic Budget Limiter now lives. Everything the
//! request path used to pay for per request — an indexed `SUM` over `budget_grants`, an HTTPS
//! round trip to `authz-usage` for the spend `SUM`, a reset-schedule resolution — happens here, on
//! a timer, for the accounts that are actually being used.
//!
//! Four properties, and each is a decision rather than an implementation detail:
//!
//! - **It only refreshes ACTIVE accounts.** The work list is "budget accounts the request path has
//!   touched inside [`SnapshotRefreshConfig::active_window`]", oldest reading first. Cost scales
//!   with concurrently-active accounts, not with the size of the estate — the same property that
//!   makes ADR-0034's per-identity TTL viable, applied to the background loop.
//! - **It is replica-safe by exclusion, not by partitioning.** One session-scoped Postgres advisory
//!   lock guards a whole tick. A second replica's tick finds the lock held and returns immediately
//!   rather than recomputing the same rows — cheaper and simpler than `SKIP LOCKED` row claiming,
//!   because unlike the reset scheduler nothing here is *due* at a particular instant: a skipped
//!   tick costs at most one interval of freshness and no work is ever lost.
//! - **It fails soft.** An unreachable spend source stamps `stale_since` and leaves the PREVIOUS
//!   reading exactly where it is. Erasing a known balance because `authz-usage` blinked would turn
//!   one service's outage into `503`s for the whole fleet — the opposite of what the cached-grace
//!   design (ADR-0034 §5.3) exists to achieve.
//! - **It never fabricates.** An account whose spend was never readable keeps `remaining_micros
//!   NULL`, the introspection omits the field, and the gateway reads `known: false`. Unknown is
//!   never zero, at every layer (ADR-0034 D5).
//!
//! A refill does **not** wait for a tick: [`crate::repo::BudgetRepo::grant`] moves the snapshot by
//! the grant amount inside its own transaction, so a top-up is visible to the gateway on the very
//! next request. See `snapshot_store::APPLY_GRANT_DELTA_SQL`.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::BudgetRepo;
use crate::reset_scheduler::ResetScheduler;
use crate::snapshot::{RefreshReport, SnapshotRefreshConfig};
use crate::snapshot_refresh_one::refresh_one_account;
use crate::snapshot_store::SnapshotStore;
use crate::spend::SpendReader;

/// Advisory-lock key for the whole refresher. A fixed, arbitrary constant: Postgres advisory locks
/// are a flat `bigint` namespace shared process-wide, so the only requirement is that nothing else
/// in this estate picks the same number. Written in hex so it is greppable.
const REFRESH_ADVISORY_LOCK_KEY: i64 = 0x4255_4447_5F53_4E50;

/// Recomputes snapshots for active accounts, on a timer.
#[derive(Debug)]
pub struct SnapshotRefresher {
    store: SnapshotStore,
    repo: Arc<BudgetRepo>,
    spend_reader: Arc<dyn SpendReader>,
    reset_scheduler: Arc<ResetScheduler>,
    config: SnapshotRefreshConfig,
}

impl SnapshotRefresher {
    pub fn new(
        store: SnapshotStore,
        repo: Arc<BudgetRepo>,
        spend_reader: Arc<dyn SpendReader>,
        reset_scheduler: Arc<ResetScheduler>,
        config: SnapshotRefreshConfig,
    ) -> Self {
        Self {
            store,
            repo,
            spend_reader,
            reset_scheduler,
            config,
        }
    }

    /// Drives [`Self::tick`] forever on the configured interval. Spawned, never awaited, by
    /// `authz-budget`: a refresher failure must not take the RPC surface down, and a failed tick
    /// simply retries on the next interval with nothing lost.
    ///
    /// `MissedTickBehavior::Delay`, like the reset scheduler's loop: a tick that overruns the
    /// interval must not queue a backlog of immediate catch-up ticks behind it.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.config.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match self.tick(Utc::now()).await {
                    Ok(report) if !report.ran || report.considered == 0 => {}
                    Ok(report) => tracing::debug!(
                        considered = report.considered,
                        refreshed = report.refreshed,
                        kept_stale = report.kept_stale,
                        failed = report.failed,
                        "budget remaining snapshot refresh tick"
                    ),
                    Err(err) => tracing::error!(
                        error = %err,
                        "budget snapshot refresh tick failed; retrying on the next interval"
                    ),
                }
            }
        })
    }

    /// One pass over the active set, under the advisory lock.
    ///
    /// `now` is a parameter rather than a clock read, matching this crate's clock-free discipline
    /// (ADR-0007) — it decides the active-window cutoff and the period being computed.
    pub async fn tick(&self, now: DateTime<Utc>) -> Result<RefreshReport, BudgetError> {
        let mut conn = self
            .repo
            .pool()
            .acquire()
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;

        let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(REFRESH_ADVISORY_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        if !acquired {
            return Ok(RefreshReport::default());
        }

        let report = self.refresh_active(now).await;

        // Released explicitly rather than left to the session ending: this connection goes back to
        // the pool and will serve other work, and a session-scoped lock outliving the tick would
        // wedge every other replica's refresher until the pool happened to recycle it.
        let unlock: Result<(bool,), _> = sqlx::query_as("SELECT pg_advisory_unlock($1)")
            .bind(REFRESH_ADVISORY_LOCK_KEY)
            .fetch_one(&mut *conn)
            .await;
        if let Err(err) = unlock {
            tracing::warn!(error = %err, "failed to release the snapshot refresher advisory lock");
        }

        report
    }

    async fn refresh_active(&self, now: DateTime<Utc>) -> Result<RefreshReport, BudgetError> {
        let cutoff = now
            - chrono::Duration::from_std(self.config.active_window)
                .unwrap_or_else(|_| chrono::Duration::seconds(600));
        let accounts = self
            .store
            .active_accounts(cutoff, self.config.batch)
            .await?;
        let period = Period::current(now);

        let mut report = RefreshReport {
            ran: true,
            considered: accounts.len(),
            ..RefreshReport::default()
        };

        for chunk in accounts.chunks(self.config.concurrency.max(1)) {
            let mut set = tokio::task::JoinSet::new();
            for account_id in chunk {
                set.spawn(refresh_one_account(
                    self.store.clone(),
                    self.repo.clone(),
                    self.spend_reader.clone(),
                    self.reset_scheduler.clone(),
                    account_id.clone(),
                    period.clone(),
                    now,
                ));
            }
            while let Some(joined) = set.join_next().await {
                match joined {
                    Ok(Ok(true)) => report.refreshed += 1,
                    Ok(Ok(false)) => report.kept_stale += 1,
                    Ok(Err(err)) => {
                        report.failed += 1;
                        tracing::warn!(error = %err, "budget snapshot refresh failed for one account");
                    }
                    Err(err) => {
                        report.failed += 1;
                        tracing::warn!(error = %err, "budget snapshot refresh task panicked");
                    }
                }
            }
        }

        Ok(report)
    }
}

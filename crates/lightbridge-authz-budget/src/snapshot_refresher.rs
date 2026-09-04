//! The background loop that keeps `budget_remaining_snapshots` warm — ADR-0034 §15.
//!
//! This is where the expensive half of the Dynamic Budget Limiter now lives: the `SUM` over
//! `budget_grants`, the HTTPS round trip to `authz-usage` for the spend `SUM`, and the
//! reset-schedule resolution the request path used to pay for on every call — now on a timer, for
//! the accounts actually being used.
//!
//! Four properties, and each is a decision rather than an implementation detail:
//!
//! - **It SEEDS, then refreshes in two lanes** (§15.6). Every tick first guarantees a row for
//!   every account that can send metered traffic ([`crate::snapshot_seed`]) — coverage is a
//!   property of the estate, not of who happened to send a request since the table was created —
//!   then recomputes the fast lane in full and whichever slow-lane accounts are due
//!   ([`crate::snapshot_lanes`]), oldest reading first. §15's single ten-minute window is gone:
//!   an idle account is demoted, never dropped.
//! - **It reports coverage, not just work** (§15.6). `budget_snapshot_accounts_total` /
//!   `budget_snapshot_known_total` / `budget_snapshot_stale_total` /
//!   `budget_snapshot_uncovered_total` are counted from the table once per tick and logged, because
//!   every per-tick counter can read healthy while half the estate has no row at all — which is
//!   exactly what the Stage 1b watch found (~50 % coverage).
//! - **It is replica-safe by exclusion, not by partitioning.** One transaction-scoped Postgres
//!   advisory lock guards a whole tick (see [`SnapshotRefresher::tick`]). A second replica's tick
//!   finds it held and returns immediately rather than recomputing the same rows — simpler than
//!   `SKIP LOCKED` row claiming, because unlike the reset scheduler nothing here is *due* at a
//!   particular instant: a skipped tick costs one interval of freshness and loses no work.
//! - **It fails soft.** An unreachable spend source stamps `stale_since` and leaves the PREVIOUS
//!   reading in place; erasing a known balance because `authz-usage` blinked would turn one
//!   service's outage into `503`s fleet-wide (ADR-0034 §5.3).
//! - **It never fabricates.** An account whose spend was never readable keeps `remaining_micros
//!   NULL`, the introspection omits the field, and the gateway reads `known: false` — unknown is
//!   never zero, at every layer (ADR-0034 D5).
//!
//! A refill does not wait for a tick: [`crate::repo::BudgetRepo::grant`] moves the snapshot inside
//! its own transaction. See `snapshot_store::APPLY_GRANT_DELTA_SQL`.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::BudgetRepo;
use crate::reset_scheduler::ResetScheduler;
use crate::snapshot::{RefreshReport, SnapshotRefreshConfig};
use crate::snapshot_lanes::to_chrono;
use crate::snapshot_refresh_one::refresh_one_account;
use crate::snapshot_store::SnapshotStore;
use crate::spend::SpendReader;

/// Advisory-lock key for the whole refresher. A fixed, arbitrary constant: Postgres advisory locks
/// are a flat `bigint` namespace shared cluster-wide, so the only requirement is that nothing else
/// in this estate picks the same number. Written in hex so it is greppable. Taken with
/// `pg_try_advisory_xact_lock` — see [`SnapshotRefresher::tick`] for why session scope was wrong.
const REFRESH_ADVISORY_LOCK_KEY: i64 = 0x4255_4447_5F53_4E50;

/// Recomputes snapshots for active accounts, on a timer.
#[derive(Debug)]
pub struct SnapshotRefresher {
    store: SnapshotStore,
    repo: Arc<BudgetRepo>,
    spend_reader: Arc<dyn SpendReader>,
    reset_scheduler: Arc<ResetScheduler>,
    /// `pub(crate)` only so the timer loop in `snapshot_refresh_loop` can read `interval`; that
    /// module is this type's own `spawn`, split out under the LoC gate.
    pub(crate) config: SnapshotRefreshConfig,
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

    /// One pass over the active set, under the advisory lock.
    ///
    /// `now` is a parameter rather than a clock read, matching this crate's clock-free discipline
    /// (ADR-0007) — it decides the active-window cutoff and the period being computed.
    ///
    /// ## The lock is transaction-scoped, and that is the whole point
    ///
    /// Postgres releases a `pg_try_advisory_**xact**_lock` at COMMIT or ROLLBACK — including a
    /// rollback nobody asked for, since `sqlx::Transaction`'s `Drop` rolls back. So cancellation, a
    /// panic below, and a dying backend all release it.
    ///
    /// The session-scoped form this replaced had one bad path: anything that skipped the explicit
    /// `pg_advisory_unlock` returned the connection to the pool with the lock still held on its
    /// session, and **every other replica's refresher then stops** until that connection happens to
    /// be recycled — silently, visible only as `budget_snapshot_age_seconds` climbing.
    ///
    /// The cost is one connection `idle in transaction` for a tick: bounded by `batch` and
    /// `concurrency`, writing nothing, taking no row locks.
    pub async fn tick(&self, now: DateTime<Utc>) -> Result<RefreshReport, BudgetError> {
        let mut lock_tx = self
            .repo
            .pool()
            .begin()
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;

        let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(REFRESH_ADVISORY_LOCK_KEY)
            .fetch_one(&mut *lock_tx)
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        if !acquired {
            return Ok(RefreshReport::default());
        }

        let report = self.refresh_active(now).await;

        // Rollback, not commit: this transaction only scopes the lock and has written nothing. Its
        // `Drop` would do the same -- doing it explicitly surfaces a connection failure in the log.
        if let Err(err) = lock_tx.rollback().await {
            tracing::warn!(
                error = %err,
                "failed to close the snapshot refresher's lock transaction; the advisory lock is \
                 released regardless, by the backend ending the transaction"
            );
        }

        report
    }

    async fn refresh_active(&self, now: DateTime<Utc>) -> Result<RefreshReport, BudgetError> {
        let lookback_cutoff = now - self.seed_lookback();
        let seeded = self
            .store
            .seed(
                lookback_cutoff,
                now - to_chrono(self.config.active_window, 24 * 60 * 60),
            )
            .await?;
        let accounts = self.store.due_accounts(now, &self.config).await?;
        let period = Period::current(now);

        let mut report = RefreshReport {
            ran: true,
            seeded,
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

        report.coverage = self.store.coverage(&period, lookback_cutoff).await?;
        Ok(report)
    }

    /// The seed's lookback as a `chrono::Duration`. Days rather than a `Duration` in config
    /// because that is the unit the question is asked in ("has this account been used this
    /// month?"), and the fallback keeps a nonsense value from producing a zero-width window that
    /// would seed nothing at all.
    fn seed_lookback(&self) -> chrono::Duration {
        chrono::Duration::try_days(i64::from(self.config.seed_lookback_days))
            .unwrap_or_else(|| chrono::Duration::days(30))
    }
}

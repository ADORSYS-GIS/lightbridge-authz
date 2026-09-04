//! The coverage census — ADR-0034 §15.6's answer to "how many accounts would the gateway read as
//! `known` right now?".
//!
//! ## Why this is counted, not inferred
//!
//! Every counter the refresher had before §15.6 described *the work a tick did*: considered,
//! refreshed, kept stale, failed. All four can read perfectly healthy while half the estate has no
//! snapshot row at all, because an account with no row is an account no tick ever considered. That
//! is precisely the shape of the ~50 % coverage the Stage 1b rollout watch found, and no amount of
//! staring at tick logs would have surfaced it.
//!
//! So the census asks the table directly, once per tick, in one statement. It is four scalar
//! aggregates over a table with one row per budget account — cheap at this estate's size, and off
//! the request path in any case.
//!
//! ## `uncovered_total` is the number that matters
//!
//! The other three are context. `uncovered_total` counts accounts the seed predicate says CAN send
//! metered traffic and which the introspection would nonetheless answer `known: false` for — no
//! row, a row with no reading yet, or a reading describing a period that has rolled over. Each one
//! is an account that fails open under enforcement (ADR-0034 §15.3's narrowing, but by accident
//! rather than by decision) and an unexplained `budget_unavailable` under shadow. Stage 2's exit
//! criterion cites it.

use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::error::BudgetError;
use crate::period::Period;
use crate::snapshot_config::CoverageCounts;
use crate::snapshot_store::SnapshotStore;

/// `$1` is the current period, `$2` the seed lookback cutoff. The `eligible` CTE is the seed's
/// predicate restated — kept literally identical to `snapshot_seed::SEED_SQL`'s, because a census
/// measured against a different population than the one being seeded would report a coverage this
/// loop can never reach.
const COVERAGE_SQL: &str = "WITH eligible AS ( \
         SELECT a.id FROM accounts a \
         JOIN users u ON u.id = a.user_id \
         WHERE a.id IN ( \
             SELECT g.budget_account_id FROM budget_grants g WHERE g.created_at >= $2 \
             UNION \
             SELECT k.owner_account_id FROM api_keys k \
              WHERE k.deleted_at IS NULL AND k.status = 'active' AND k.last_used_at >= $2 \
         ) \
     ) \
     SELECT \
       (SELECT count(*) FROM budget_remaining_snapshots)::bigint AS accounts_total, \
       (SELECT count(*) FROM budget_remaining_snapshots \
         WHERE remaining_micros IS NOT NULL AND period = $1)::bigint AS known_total, \
       (SELECT count(*) FROM budget_remaining_snapshots \
         WHERE stale_since IS NOT NULL)::bigint AS stale_total, \
       (SELECT count(*) FROM eligible e \
         LEFT JOIN budget_remaining_snapshots s ON s.budget_account_id = e.id \
         WHERE s.budget_account_id IS NULL \
            OR s.remaining_micros IS NULL \
            OR s.period IS DISTINCT FROM $1)::bigint AS uncovered_total";

impl SnapshotStore {
    /// Counts the four coverage figures for `period`, over the accounts `seed_lookback_days`
    /// considers able to send traffic.
    pub async fn coverage(
        &self,
        period: &Period,
        lookback_cutoff: DateTime<Utc>,
    ) -> Result<CoverageCounts, BudgetError> {
        let storage = |err: sqlx::Error| BudgetError::StorageFailed(err.to_string());
        let row = sqlx::query(COVERAGE_SQL)
            .bind(period.to_string())
            .bind(lookback_cutoff)
            .fetch_one(self.pool_ref())
            .await
            .map_err(storage)?;

        Ok(CoverageCounts {
            accounts_total: row.try_get("accounts_total").map_err(storage)?,
            known_total: row.try_get("known_total").map_err(storage)?,
            stale_total: row.try_get("stale_total").map_err(storage)?,
            uncovered_total: row.try_get("uncovered_total").map_err(storage)?,
        })
    }
}

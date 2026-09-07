//! Seeding — the half of ADR-0034 §15.6 that makes coverage a property of the estate rather than
//! of who happened to send a request since the table was created.
//!
//! ## The gap this closes, measured
//!
//! §15 created rows lazily: the first introspection for an account upserts one
//! ([`crate::snapshot_store::SnapshotStore::touch`]), and the refresher fills it on the next tick.
//! That is correct and it converges — but only asymptotically, and only over accounts that are
//! sending traffic *right now*. The Stage 1b watch (ai-helm-values#390/#391) measured what that
//! means in production: **23 snapshot rows against 43 accounts with usage in the last 30 days**,
//! i.e. ~50 % coverage, with every uncovered account reading `known: false` at the gateway — a
//! permanent fail-open under enforcement, and noise in the decision table under shadow.
//!
//! Lazy creation also loses the race it is in: an account returning after a quiet spell gets its
//! row created by the touch, but the row carries no reading until the next tick, so its first
//! requests are answered `known: false` regardless.
//!
//! ## The predicate, and why it is these two facts
//!
//! An account is seeded when it is a real budget account — `accounts` joined to `users`, the exact
//! definition [`crate::known_account`] already uses, so this and `GET /budget/v1/remaining` cannot
//! drift about what "an account" is — **and** either of:
//!
//! - it has a **budget grant** booked inside the lookback window (it has a budget row), or
//! - it owns an **active, undeleted API key that has actually been used** inside the window (it can
//!   send metered traffic).
//!
//! Both facts live in this service's own database. "Usage in the last 30 days" as the usage store
//! records it does not: spend is read over HTTPS from `authz-usage`, which has no "list the
//! accounts that spent" surface, and adding one would put a second service inside the loop whose
//! job is to keep working when that service is down. `api_keys.last_used_at` is the same fact
//! recorded on this side of the wire.
//!
//! ## Idempotent, and re-arming rather than re-touching
//!
//! `ON CONFLICT` deliberately does **not** move `last_seen_at` on a row that is still inside the
//! active window: that column means "when the request path last asked", the fast/slow lane split
//! reads it, and a seed that stamped `now()` every tick would pin every seeded account in the fast
//! lane forever and make the window meaningless. It *does* move it for a row that has already aged
//! out — that account still qualifies, so it belongs back in the work list rather than frozen with
//! a reading that the next month boundary will invalidate.

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::snapshot_store::SnapshotStore;

/// Creates a row for every account that can send traffic, and re-arms one that has aged out.
///
/// `$1` is the lookback cutoff for both evidence tests; `$2` is the active-window cutoff that
/// decides whether an existing row is re-armed. Driven from the two small evidence sets rather
/// than from `accounts`, so the cost is one index range scan per source table plus a primary-key
/// probe per candidate — not two `EXISTS` probes per account in the estate.
const SEED_SQL: &str = "INSERT INTO budget_remaining_snapshots (budget_account_id, last_seen_at) \
     SELECT a.id, now() FROM accounts a \
     JOIN users u ON u.id = a.user_id \
     WHERE a.id IN ( \
         SELECT g.budget_account_id FROM budget_grants g WHERE g.created_at >= $1 \
         UNION \
         SELECT k.owner_account_id FROM api_keys k \
          WHERE k.deleted_at IS NULL AND k.status = 'active' AND k.last_used_at >= $1 \
     ) \
     ON CONFLICT (budget_account_id) DO UPDATE SET last_seen_at = now() \
     WHERE budget_remaining_snapshots.last_seen_at < $2";

impl SnapshotStore {
    /// Runs the seed once. Returns how many rows it created or re-armed — zero on a steady-state
    /// tick, which is the point: a non-zero value means the estate changed.
    ///
    /// Off the request path by construction (only [`crate::snapshot_refresher::SnapshotRefresher`]
    /// calls it), and safe to run concurrently with itself: every write is an upsert keyed on the
    /// primary key, so two replicas racing produce the same table.
    pub async fn seed(
        &self,
        lookback_cutoff: DateTime<Utc>,
        active_cutoff: DateTime<Utc>,
    ) -> Result<u64, BudgetError> {
        let result = sqlx::query(SEED_SQL)
            .bind(lookback_cutoff)
            .bind(active_cutoff)
            .execute(self.pool_ref())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(result.rows_affected())
    }
}

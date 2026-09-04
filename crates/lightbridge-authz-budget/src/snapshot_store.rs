//! The Postgres store behind [`crate::snapshot::BudgetSnapshot`] — every statement that touches
//! `budget_remaining_snapshots`, and nothing else (ADR-0034 §15).
//!
//! Split from [`crate::snapshot`] so the types and the trait stay readable next to the rules they
//! encode while the SQL lives in one auditable place, the same convention `remaining.rs` /
//! `remaining_service.rs` already follow in this crate.
//!
//! Three callers, three access patterns, and it is worth naming which is on the request path:
//!
//! | Caller | Statement | On the request path? |
//! |---|---|---|
//! | `authz-opa` introspection | [`SnapshotStore::read`] — primary-key probe | **yes**, awaited |
//! | `authz-opa` introspection | [`SnapshotStore::touch`] — one upsert | yes, but write-behind |
//! | [`crate::snapshot_refresher`] | `active_accounts` + `store_reading` | no, background |
//! | [`crate::repo::BudgetRepo::grant`] | [`SnapshotStore::apply_grant_delta_tx`] | no, ledger write |

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::error::BudgetError;
use crate::period::Period;
use crate::snapshot::{BudgetSnapshot, BudgetSnapshotReader};

const SELECT_SQL: &str = "SELECT budget_account_id, period, ceiling_micros, spent_micros, \
     remaining_micros, next_reset_at, refreshed_at, stale_since, last_seen_at \
     FROM budget_remaining_snapshots WHERE budget_account_id = $1";

/// The write-behind touch. `ON CONFLICT` rather than a bare `UPDATE` so an account the refresher
/// has never seen joins the active set on its very first metered request instead of waiting for
/// some other code path to create its row.
const TOUCH_SQL: &str = "INSERT INTO budget_remaining_snapshots (budget_account_id, last_seen_at) \
     VALUES ($1, now()) \
     ON CONFLICT (budget_account_id) DO UPDATE SET last_seen_at = now()";

/// The refresher's work list: accounts the request path has asked about recently, oldest reading
/// first so a starved row cannot stay starved. `LIMIT` bounds one tick's work — a tick that cannot
/// finish the list leaves the remainder for the next one, which is the correct behaviour for a
/// loop whose whole job is to stay cheap.
const ACTIVE_SQL: &str = "SELECT budget_account_id FROM budget_remaining_snapshots \
     WHERE last_seen_at >= $1 \
     ORDER BY refreshed_at ASC NULLS FIRST LIMIT $2";

const STORE_READING_SQL: &str = "UPDATE budget_remaining_snapshots SET \
     period = $2, ceiling_micros = $3, spent_micros = $4, remaining_micros = $5, \
     next_reset_at = $6, refreshed_at = now(), stale_since = NULL \
     WHERE budget_account_id = $1";

/// Fail-soft: the PREVIOUS reading is left exactly where it is and only `stale_since` is stamped,
/// and only when it is not already stamped (so it records when the outage *started*, not when it
/// was last noticed). Erasing a known balance because the spend source blinked would turn one
/// service's outage into the whole fleet's 503s.
const MARK_STALE_SQL: &str = "UPDATE budget_remaining_snapshots \
     SET stale_since = COALESCE(stale_since, now()) WHERE budget_account_id = $1";

/// Applied inside [`crate::repo::BudgetRepo::grant`]'s own transaction. A grant changes the
/// CEILING by exactly `amount_micros` and does not move spend at all, so the snapshot can be made
/// exactly correct here without reading anything — which is what makes a refill visible to the
/// gateway immediately rather than one refresh interval later.
///
/// Guarded three ways, and each guard is load-bearing: the row must already carry a reading
/// (`remaining_micros IS NOT NULL`, else there is no number to adjust), it must describe the SAME
/// period as the grant (a grant into next month must not move this month's balance), and the grant
/// must not be already-expired (`effective_balance` would not count it, so neither may this).
const APPLY_GRANT_DELTA_SQL: &str = "UPDATE budget_remaining_snapshots SET \
     ceiling_micros = ceiling_micros + $3, remaining_micros = remaining_micros + $3, \
     refreshed_at = now() \
     WHERE budget_account_id = $1 AND period = $2 AND remaining_micros IS NOT NULL";

/// Pool-backed store for `budget_remaining_snapshots`.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    pool: Arc<dyn DbPoolTrait>,
}

impl SnapshotStore {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    /// Budget accounts seen since `since`, oldest reading first, at most `limit` of them.
    pub async fn active_accounts(
        &self,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<String>, BudgetError> {
        let rows = sqlx::query(ACTIVE_SQL)
            .bind(since)
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        rows.iter()
            .map(|row| {
                row.try_get::<String, _>("budget_account_id")
                    .map_err(|err| BudgetError::StorageFailed(err.to_string()))
            })
            .collect()
    }

    /// Writes a fresh reading and clears any `stale_since`. A no-op when the row has since been
    /// deleted, which is correct: an account that no longer exists needs no snapshot.
    pub async fn store_reading(
        &self,
        budget_account_id: &str,
        period: &Period,
        ceiling_micros: i64,
        spent_micros: i64,
        next_reset_at: DateTime<Utc>,
    ) -> Result<(), BudgetError> {
        sqlx::query(STORE_READING_SQL)
            .bind(budget_account_id)
            .bind(period.to_string())
            .bind(ceiling_micros)
            .bind(spent_micros)
            .bind(ceiling_micros.saturating_sub(spent_micros))
            .bind(next_reset_at)
            .execute(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }

    /// Stamps the start of a spend-source outage, keeping the previous reading. See
    /// [`MARK_STALE_SQL`].
    pub async fn mark_stale(&self, budget_account_id: &str) -> Result<(), BudgetError> {
        sqlx::query(MARK_STALE_SQL)
            .bind(budget_account_id)
            .execute(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }

    /// Moves an existing reading by a booked grant's amount, inside that grant's own transaction.
    /// See [`APPLY_GRANT_DELTA_SQL`] for the three guards and why each one is there.
    pub async fn apply_grant_delta_tx(
        tx: &mut Transaction<'_, Postgres>,
        budget_account_id: &str,
        period: &str,
        amount_micros: i64,
    ) -> Result<(), BudgetError> {
        sqlx::query(APPLY_GRANT_DELTA_SQL)
            .bind(budget_account_id)
            .bind(period)
            .bind(amount_micros)
            .execute(&mut **tx)
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }
}

#[lightbridge_authz_core::async_trait]
impl BudgetSnapshotReader for SnapshotStore {
    async fn read(&self, budget_account_id: &str) -> Result<Option<BudgetSnapshot>, BudgetError> {
        let row = sqlx::query(SELECT_SQL)
            .bind(budget_account_id)
            .fetch_optional(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;

        let Some(row) = row else { return Ok(None) };
        let storage = |err: sqlx::Error| BudgetError::StorageFailed(err.to_string());
        let raw_period: Option<String> = row.try_get("period").map_err(storage)?;

        Ok(Some(BudgetSnapshot {
            budget_account_id: row.try_get("budget_account_id").map_err(storage)?,
            // A stored value that no longer parses is treated as NO period, which makes the whole
            // reading unusable rather than mis-attributed -- the conservative direction.
            period: raw_period.and_then(|value| Period::parse(&value).ok()),
            ceiling_micros: row.try_get("ceiling_micros").map_err(storage)?,
            spent_micros: row.try_get("spent_micros").map_err(storage)?,
            remaining_micros: row.try_get("remaining_micros").map_err(storage)?,
            next_reset_at: row.try_get("next_reset_at").map_err(storage)?,
            refreshed_at: row.try_get("refreshed_at").map_err(storage)?,
            stale_since: row.try_get("stale_since").map_err(storage)?,
            last_seen_at: row.try_get("last_seen_at").map_err(storage)?,
        }))
    }

    async fn touch(&self, budget_account_id: &str) -> Result<(), BudgetError> {
        sqlx::query(TOUCH_SQL)
            .bind(budget_account_id)
            .execute(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }
}

//! ADR-0035 D9: the settled side of an account's balance, per pool, read in ONE `REPEATABLE READ`
//! transaction. Reading the lots before a settlement commits and the watermark after it would
//! count the settled window in neither place (or, the other way round, twice); settlement writes
//! both atomically, so one consistent read is always correct.

use chrono::{DateTime, Utc};
use sqlx::Row;

use crate::error::BudgetError;
use crate::period::Period;
use crate::settlement::Settlement;
use crate::spend_units::period_bounds_utc;

const ALLOWANCE_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM budget_grants \
    WHERE budget_account_id = $1 AND pool = 'allowance' AND period = $2 \
      AND (expires_at IS NULL OR expires_at > $3) AND revoked_at IS NULL";
const LOTS_SQL: &str = "SELECT \
    COALESCE(SUM(remaining_micros) FILTER (WHERE pool = 'granted'), 0)::bigint AS granted, \
    COALESCE(SUM(remaining_micros) FILTER (WHERE pool = 'paid'), 0)::bigint AS paid \
    FROM credit_lots WHERE budget_account_id = $1 AND remaining_micros > 0 \
      AND (expires_at IS NULL OR expires_at > $2)";
const STATE_SQL: &str = "SELECT settled_through, debt_micros, allowance_period \
    FROM settlement_state WHERE budget_account_id = $1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledBalances {
    pub allowance_micros: i64,
    pub granted_micros: i64,
    pub paid_micros: i64,
    pub debt_micros: i64,
    pub settled_through: DateTime<Utc>,
}

impl SettledBalances {
    /// The ceiling the snapshot reports: all settled credit, every pool.
    pub fn settled_total(&self) -> i64 {
        self.allowance_micros
            .saturating_add(self.granted_micros)
            .saturating_add(self.paid_micros)
    }
}

impl Settlement {
    pub async fn settled_balances(
        &self,
        account: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<SettledBalances, BudgetError> {
        let storage = |err: sqlx::Error| BudgetError::StorageFailed(err.to_string());
        let mut tx = self.pool().begin().await.map_err(storage)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        let allowance_micros: i64 = sqlx::query(ALLOWANCE_SQL)
            .bind(account)
            .bind(period.to_string())
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?
            .get(0);
        let lots = sqlx::query(LOTS_SQL)
            .bind(account)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage)?;
        let state = sqlx::query(STATE_SQL)
            .bind(account)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;

        let (settled_through, debt_micros) = match state {
            // A new period renews the allowance and forgives the debt (D7), even before the next
            // settlement writes that down.
            Some(row) => {
                let same_period = row
                    .get::<Option<String>, _>("allowance_period")
                    .is_none_or(|last| last == period.to_string());
                let debt = if same_period {
                    row.get("debt_micros")
                } else {
                    0
                };
                (row.get("settled_through"), debt)
            }
            None => (period_bounds_utc(period).0, 0),
        };
        Ok(SettledBalances {
            allowance_micros,
            granted_micros: lots.get("granted"),
            paid_micros: lots.get("paid"),
            debt_micros,
            settled_through,
        })
    }

    /// D8: a reset settles the account first, then reads the settled allowance -- which already
    /// includes the settled consumption, so no spend is subtracted on top. `None` means spend was
    /// unavailable: the caller defers the account exactly as ADR-0032 D5 does.
    pub async fn settle_for_reset(
        &self,
        account: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<Option<i64>, BudgetError> {
        if self.settle_account(account, now).await? == crate::settlement::SettleOutcome::Deferred {
            return Ok(None);
        }
        Ok(Some(
            self.settled_balances(account, period, now)
                .await?
                .allowance_micros,
        ))
    }
}

//! How the ledger is read once ADR-0035 is withdrawn, over the rows its settlement left behind.
//!
//! Settlement ran in production before the withdrawal. For every settled micro-dollar it booked a
//! negative `consumption` row into `budget_grants` AND debited `budget_balances.effective_budget_micros`
//! by the same amount, in one transaction. Both stay: the ledger is append-only (ADR-0009) and the
//! projection is only ever moved by a grant. Every read the reverted code makes computes "credit
//! granted this period" and then subtracts the period's spend from the usage service itself, so a
//! settled row counted as credit would subtract that spend twice -- the bug #776 fixed for the RPCs,
//! applied to the gateway.
//!
//! Two reads, two corrections, one rule: a `consumption` row is never credit.
//!
//! - `EFFECTIVE_BALANCE_SQL` (`repo.rs`) excludes `consumption` by source. It is the ceiling for
//!   `GET /budget/v1/remaining`, the snapshot refresher, the reset scheduler and the refill facts.
//! - [`BudgetRepo::reported_balance`] adds `consumption` back onto the stored projection column, for
//!   `getMyBudgetBalance` / `getBudgetBalance`, whose `effectiveBudgetMicros` has always meant the
//!   credit granted.
//!
//! An allowance `expiry` row is the opposite case, and is counted. Settlement only ever booked
//! `expiry` against a lot, and a lot row has no period, so no period-scoped read can see one. Every
//! allowance `expiry` row came from the ADR-0035 reset scheduler, which booked a reset-down as
//! `expiry` where the reverted scheduler books a negative `correction`. That is less credit, not
//! spend. Skipping it would leave the account's ceiling at its pre-reset level.
//!
//! Neither read needs the `pool` column, which the contract migration drops: settlement only gave
//! allowance rows a period, so `period = $2` already leaves the granted and paid pools out.

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::{BalanceSnapshot, BudgetRepo};

/// The period's settled spend: `consumption` rows. Negative or zero.
const SETTLED_SPEND_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint \
    FROM budget_grants WHERE budget_account_id = $1 AND period = $2 \
    AND source = 'consumption'";

impl BudgetRepo {
    /// The account's balance for `period` as the RPCs report it: `effective_budget_micros` is the
    /// credit granted this period, whatever settlement booked against it before the withdrawal.
    /// An account with no balance row yet reads as [`BalanceSnapshot::zero`].
    pub async fn reported_balance(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<BalanceSnapshot, BudgetError> {
        let Some(mut snapshot) = self.get_balance(budget_account_id, period).await? else {
            return Ok(BalanceSnapshot::zero(budget_account_id, period));
        };
        let (settled,): (i64,) = sqlx::query_as(SETTLED_SPEND_SQL)
            .bind(budget_account_id)
            .bind(period.to_string())
            .fetch_one(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        snapshot.effective_budget_micros = snapshot.effective_budget_micros.saturating_sub(settled);
        Ok(snapshot)
    }
}

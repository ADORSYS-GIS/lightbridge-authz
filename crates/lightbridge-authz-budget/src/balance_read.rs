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
//! Two reads, two corrections, one rule: a `consumption` or `expiry` row is never credit.
//!
//! - `EFFECTIVE_BALANCE_SQL` (`repo.rs`) excludes them by source. It is the ceiling for
//!   `GET /budget/v1/remaining`, the snapshot refresher, the reset scheduler and the refill facts.
//! - [`BudgetRepo::reported_balance`] adds them back onto the stored projection column, for
//!   `getMyBudgetBalance` / `getBudgetBalance`, whose `effectiveBudgetMicros` has always meant the
//!   credit granted.
//!
//! Neither read needs the `pool` column, which the contract migration drops: settlement only gave
//! allowance rows a period, so `period = $2` already leaves the granted and paid pools out.

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::{BalanceSnapshot, BudgetRepo};

/// The period's settlement debits: `consumption` and `expiry` rows. Negative or zero.
const SETTLEMENT_DEBITS_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint \
    FROM budget_grants WHERE budget_account_id = $1 AND period = $2 \
    AND source IN ('consumption', 'expiry')";

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
        let (debits,): (i64,) = sqlx::query_as(SETTLEMENT_DEBITS_SQL)
            .bind(budget_account_id)
            .bind(period.to_string())
            .fetch_one(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        snapshot.effective_budget_micros = snapshot.effective_budget_micros.saturating_sub(debits);
        Ok(snapshot)
    }
}

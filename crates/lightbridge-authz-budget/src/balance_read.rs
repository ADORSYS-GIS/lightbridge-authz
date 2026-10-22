//! The balance the budget RPCs report (`getMyBudgetBalance`, `getBudgetBalance`).
//!
//! Since ADR-0035 D10, `budget_balances.effective_budget_micros` is the **settled** allowance
//! balance: settlement debits it with every allowance `consumption` and `expiry` row. That is what
//! settlement needs, but the RPC's `effectiveBudgetMicros` has always meant the credit granted this
//! period, and its consumers subtract this period's spend from it themselves -- the console's
//! budget card does exactly that. Handing them the settled figure counts every settled
//! micro-dollar twice (D10's own warning, about the four server-side callers it moved; the RPC is
//! the fifth). So this read adds the period's allowance debits back, and leaves the stored column,
//! and everything else in [`BalanceSnapshot`], as they are.

use crate::error::BudgetError;
use crate::period::Period;
use crate::repo::{BalanceSnapshot, BudgetRepo};

/// The period's allowance debits: settlement's `consumption` and `expiry` rows. Negative or zero.
const ALLOWANCE_DEBITS_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint \
    FROM budget_grants WHERE budget_account_id = $1 AND period = $2 \
    AND pool = 'allowance' AND source IN ('consumption', 'expiry')";

impl BudgetRepo {
    /// The account's balance for `period` as the RPCs report it: `effective_budget_micros` is the
    /// credit granted this period, whatever settlement has booked against it. An account with no
    /// balance row yet reads as [`BalanceSnapshot::zero`].
    pub async fn reported_balance(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<BalanceSnapshot, BudgetError> {
        let Some(mut snapshot) = self.get_balance(budget_account_id, period).await? else {
            return Ok(BalanceSnapshot::zero(budget_account_id, period));
        };
        let (debits,): (i64,) = sqlx::query_as(ALLOWANCE_DEBITS_SQL)
            .bind(budget_account_id)
            .bind(period.to_string())
            .fetch_one(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        snapshot.effective_budget_micros = snapshot.effective_budget_micros.saturating_sub(debits);
        Ok(snapshot)
    }
}

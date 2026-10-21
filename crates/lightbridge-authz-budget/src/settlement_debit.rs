//! One settlement debit (ADR-0035 D6): a negative ledger row plus its projection -- the lot for
//! granted/paid credit, `budget_balances` for allowance -- inside the settlement transaction.

use lightbridge_authz_core::cuid::cuid2;
use sqlx::{Postgres, Transaction};

use crate::credit_sql::{DEBIT_LOT_SQL, INSERT_DEBIT_SQL};
use crate::error::BudgetError;
use crate::period::Period;
use crate::pool::CreditPool;
use crate::source::GrantSource;

const BALANCE_DEBIT_SQL: &str = "UPDATE budget_balances SET \
    effective_budget_micros = effective_budget_micros + $3, version = version + 1, \
    updated_at = now() WHERE budget_account_id = $1 AND period = $2";

fn storage(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// One negative ledger row plus its projection: the lot for granted/paid, `budget_balances` for
/// allowance. A replayed `trigger_key` books nothing and moves nothing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn debit(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    pool: CreditPool,
    period: &Period,
    lot_id: Option<&str>,
    amount_micros: i64,
    source: GrantSource,
    trigger_key: &str,
) -> Result<(), BudgetError> {
    let period_value = (!pool.is_lot_tracked()).then(|| period.to_string());
    let inserted = sqlx::query(INSERT_DEBIT_SQL)
        .bind(cuid2())
        .bind(account)
        .bind(pool.as_str())
        .bind(&period_value)
        .bind(amount_micros)
        .bind(source.to_string())
        .bind(lot_id)
        .bind(None::<String>)
        .bind(Some("ADR-0035 settlement"))
        .bind(None::<String>)
        .bind(trigger_key)
        .bind(None::<String>)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?;
    if inserted.is_none() {
        return Ok(());
    }
    match (lot_id, period_value) {
        (Some(lot_id), _) => sqlx::query(DEBIT_LOT_SQL).bind(lot_id).bind(amount_micros),
        (None, Some(period)) => sqlx::query(BALANCE_DEBIT_SQL)
            .bind(account)
            .bind(period)
            .bind(amount_micros),
        (None, None) => unreachable!("a lot-tracked pool always names its lot"),
    }
    .execute(&mut **tx)
    .await
    .map_err(storage)?;
    Ok(())
}

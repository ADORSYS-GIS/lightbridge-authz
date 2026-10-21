//! ADR-0035 D11: reversing part of a purchase. The reversal names the purchase by the
//! `idempotency_key` it was booked under (commerce's order id), locks that purchase's lot, and is
//! capped at what is left of it: credit already consumed cannot be refunded as credit.

use lightbridge_authz_core::cuid::cuid2;
use sqlx::{Postgres, Row, Transaction};

use crate::credit_repo::{FundOutcome, FundRequest};
use crate::credit_sql::{DEBIT_LOT_SQL, INSERT_DEBIT_SQL, LOCK_LOT_SQL};
use crate::error::BudgetError;
use crate::pool::CreditPool;

const FIND_PURCHASE_SQL: &str = "SELECT id FROM budget_grants \
    WHERE idempotency_key = $1 AND budget_account_id = $2 AND source = 'purchase'";

fn storage(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

pub(crate) async fn book(
    tx: &mut Transaction<'_, Postgres>,
    request: &FundRequest,
    pool: CreditPool,
) -> Result<Option<FundOutcome>, BudgetError> {
    let purchase_key = request.reverses_idempotency_key.as_deref().ok_or_else(|| {
        BudgetError::FundingRefused(
            "a purchase_reversal must name the purchase it reverses".to_string(),
        )
    })?;
    let lot_id: String = sqlx::query(FIND_PURCHASE_SQL)
        .bind(purchase_key)
        .bind(&request.budget_account_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?
        .map(|row| row.get("id"))
        .ok_or_else(|| BudgetError::NotFound(format!("purchase '{purchase_key}'")))?;

    let remaining: i64 = sqlx::query(LOCK_LOT_SQL)
        .bind(&lot_id)
        .bind(&request.budget_account_id)
        .bind(pool.as_str())
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?
        .get("remaining_micros");
    if request.amount_micros > remaining {
        return Err(BudgetError::ReversalExceedsLot {
            requested: request.amount_micros,
            remaining,
        });
    }

    let id = cuid2();
    let signed = -request.amount_micros;
    let inserted = sqlx::query(INSERT_DEBIT_SQL)
        .bind(&id)
        .bind(&request.budget_account_id)
        .bind(pool.as_str())
        .bind(None::<String>)
        .bind(signed)
        .bind(request.source.to_string())
        .bind(&lot_id)
        .bind(&request.actor_id)
        .bind(&request.reason)
        .bind(&request.idempotency_key)
        .bind(None::<String>)
        .bind(&request.external_ref)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?;
    if inserted.is_none() {
        // A concurrent request with the same key committed first; the caller re-reads it.
        return Ok(None);
    }
    sqlx::query(DEBIT_LOT_SQL)
        .bind(&lot_id)
        .bind(signed)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;

    Ok(Some(FundOutcome {
        grant_id: id,
        lot_id,
        pool,
        amount_micros: signed,
        lot_remaining_micros: remaining - request.amount_micros,
        replayed: false,
    }))
}

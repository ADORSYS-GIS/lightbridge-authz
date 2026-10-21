//! ADR-0035 D11's write side: a purchase (or promotion / referral) books a lot-opening credit, a
//! reversal debits that lot -- each in ONE transaction with `credit_lots` and the gateway snapshot.
//! The caller's authorization lives in the REST crate. Amounts are micro-USD; no money enters.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::{Postgres, Row, Transaction};

use crate::credit_sql::*;
use crate::error::BudgetError;
use crate::pool::CreditPool;
use crate::source::GrantSource;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundRequest {
    pub budget_account_id: String,
    pub source: GrantSource,
    /// Always POSITIVE: the credit added, or for a reversal the credit removed.
    pub amount_micros: i64,
    /// Required (a purchase: the commerce order id). A replay returns the original booking.
    pub idempotency_key: String,
    pub external_ref: Option<String>,
    /// For `purchase_reversal` only: the `idempotency_key` of the purchase being reversed.
    pub reverses_idempotency_key: Option<String>,
    /// Granted credit only: the funding port refuses it on a purchase until counsel decides.
    pub expires_at: Option<DateTime<Utc>>,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundOutcome {
    pub grant_id: String,
    pub lot_id: String,
    pub pool: CreditPool,
    /// Signed, as stored: positive for a credit, negative for a reversal.
    pub amount_micros: i64,
    pub lot_remaining_micros: i64,
    /// True when the idempotency key had already been booked; nothing new was written.
    pub replayed: bool,
}

#[derive(Debug, Clone)]
pub struct CreditRepo {
    pool: Arc<dyn DbPoolTrait>,
}

fn storage(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

impl CreditRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    pub async fn fund(&self, request: FundRequest) -> Result<FundOutcome, BudgetError> {
        let pool = CreditPool::for_funding_source(request.source).ok_or_else(|| {
            BudgetError::FundingRefused(format!("'{}' is not a funding source", request.source))
        })?;
        if request.amount_micros <= 0 {
            return Err(BudgetError::InvalidAmount(request.amount_micros));
        }
        if request.idempotency_key.trim().is_empty() {
            return Err(BudgetError::FundingRefused(
                "idempotency_key is required".into(),
            ));
        }
        let mut tx = self.pool.pool().begin().await.map_err(storage)?;
        if sqlx::query(ACCOUNT_EXISTS_SQL)
            .bind(&request.budget_account_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage)?
            .is_none()
        {
            return Err(BudgetError::NotFound(format!(
                "budget account '{}'",
                request.budget_account_id
            )));
        }

        let sign = if request.source.is_debit() { -1 } else { 1 };
        let signed = sign * request.amount_micros;
        if let Some(existing) = replayed(&mut tx, &request, pool, signed).await? {
            return Ok(existing);
        }

        let booked = if request.source.is_debit() {
            crate::credit_reversal::book(&mut tx, &request, pool).await?
        } else {
            book_credit(&mut tx, &request, pool).await?
        };
        let Some(outcome) = booked else {
            drop(tx); // Lost a race to a concurrent request with this key: return its booking.
            let mut tx = self.pool.pool().begin().await.map_err(storage)?;
            return replayed(&mut tx, &request, pool, signed)
                .await?
                .ok_or(BudgetError::IdempotencyConflict(request.idempotency_key));
        };
        let snapshot_sql = match pool {
            CreditPool::Paid => SNAPSHOT_PAID_DELTA_SQL,
            _ => SNAPSHOT_GRANTED_DELTA_SQL,
        };
        sqlx::query(snapshot_sql)
            .bind(&request.budget_account_id)
            .bind(outcome.amount_micros)
            .execute(&mut *tx)
            .await
            .map_err(storage)?;
        tx.commit().await.map_err(storage)?;
        Ok(outcome)
    }
}

/// A replayed key returns the original booking -- but only if it is the same request. The same
/// key with another account, source or amount is a caller bug, never a silent success.
async fn replayed(
    tx: &mut Transaction<'_, Postgres>,
    request: &FundRequest,
    pool: CreditPool,
    signed: i64,
) -> Result<Option<FundOutcome>, BudgetError> {
    let Some(row) = sqlx::query(SELECT_BY_IDEMPOTENCY_KEY_SQL)
        .bind(&request.idempotency_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let account: String = row.get("budget_account_id");
    let source: String = row.get("source");
    let amount: i64 = row.get("amount_micros");
    if account != request.budget_account_id
        || source != request.source.to_string()
        || amount != signed
    {
        return Err(BudgetError::IdempotencyConflict(
            request.idempotency_key.clone(),
        ));
    }
    let grant_id: String = row.get("id");
    let lot_id: Option<String> = row.get("lot_id");
    Ok(Some(FundOutcome {
        lot_id: lot_id.unwrap_or_else(|| grant_id.clone()),
        grant_id,
        pool,
        amount_micros: amount,
        lot_remaining_micros: row.get("remaining"),
        replayed: true,
    }))
}

async fn book_credit(
    tx: &mut Transaction<'_, Postgres>,
    request: &FundRequest,
    pool: CreditPool,
) -> Result<Option<FundOutcome>, BudgetError> {
    let id = cuid2();
    let Some(row) = sqlx::query(INSERT_CREDIT_SQL)
        .bind(&id)
        .bind(&request.budget_account_id)
        .bind(pool.as_str())
        .bind(request.amount_micros)
        .bind(request.source.to_string())
        .bind(&request.actor_id)
        .bind(&request.reason)
        .bind(&request.idempotency_key)
        .bind(&request.external_ref)
        .bind(request.expires_at)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage)?
    else {
        return Ok(None);
    };
    let created_at: DateTime<Utc> = row.get("created_at");
    sqlx::query(INSERT_LOT_SQL)
        .bind(&id)
        .bind(&request.budget_account_id)
        .bind(pool.as_str())
        .bind(request.amount_micros)
        .bind(request.expires_at)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    Ok(Some(FundOutcome {
        grant_id: id.clone(),
        lot_id: id,
        pool,
        amount_micros: request.amount_micros,
        lot_remaining_micros: request.amount_micros,
        replayed: false,
    }))
}

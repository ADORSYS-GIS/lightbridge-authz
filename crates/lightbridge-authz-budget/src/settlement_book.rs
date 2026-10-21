//! ADR-0035 D6 step 4-6, inside ONE transaction: lock the watermark, pay debt and the window's
//! spend in spending order, expire granted lots whose time has passed, advance the watermark.
//! `settlement.rs` fetches the spend (an HTTP call) BEFORE opening this transaction, so no lock is
//! held across the network; the watermark check below makes that safe against a concurrent run.

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};

use crate::error::BudgetError;
use crate::period::Period;
use crate::pool::CreditPool;
use crate::settlement_alloc::{DrawTarget, OpenLot, allocate, sort_spending_order};
use crate::settlement_debit::debit;
use crate::source::GrantSource;

const BOOTSTRAP_STATE_SQL: &str = "INSERT INTO settlement_state (budget_account_id, settled_through) \
    VALUES ($1, $2) ON CONFLICT (budget_account_id) DO NOTHING";
const LOCK_STATE_SQL: &str = "SELECT settled_through, debt_micros, allowance_period \
    FROM settlement_state WHERE budget_account_id = $1 FOR UPDATE";
const ADVANCE_STATE_SQL: &str = "UPDATE settlement_state SET settled_through = $2, \
    debt_micros = $3, allowance_period = $4, updated_at = now() WHERE budget_account_id = $1";
// Serializes with every allowance write for this (account, period), exactly as BudgetRepo::grant.
const LOCK_BALANCE_SQL: &str = "INSERT INTO budget_balances (budget_account_id, period) \
    VALUES ($1, $2) ON CONFLICT (budget_account_id, period) DO UPDATE SET version = budget_balances.version \
    RETURNING budget_account_id";
const ALLOWANCE_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint FROM budget_grants \
    WHERE budget_account_id = $1 AND pool = 'allowance' AND period = $2 \
      AND (expires_at IS NULL OR expires_at > $3) AND revoked_at IS NULL";
const LOCK_LOTS_SQL: &str = "SELECT lot_id, pool, remaining_micros, expires_at, opened_at \
    FROM credit_lots WHERE budget_account_id = $1 AND remaining_micros > 0 FOR UPDATE";

/// What one settled window did. `None` from [`book`] means another run had already moved the
/// watermark: nothing was written.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Booked {
    pub consumption_rows: usize,
    pub expired_lots: usize,
    pub debt_micros: i64,
}

fn storage(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn book(
    tx: &mut Transaction<'_, Postgres>,
    account: &str,
    period: &Period,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    spend_micros: i64,
    now: DateTime<Utc>,
) -> Result<Option<Booked>, BudgetError> {
    let q = |sql| sqlx::query(sql).bind(account);
    q(BOOTSTRAP_STATE_SQL)
        .bind(from)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    let state = q(LOCK_STATE_SQL)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
    if state.get::<DateTime<Utc>, _>("settled_through") != from {
        return Ok(None);
    }
    let period_str = period.to_string();
    // D7: a renewed allowance (a new period) forgives the previous period's debt.
    let last_period: Option<String> = state.get("allowance_period");
    let debt: i64 = match last_period {
        Some(last) if last != period_str => 0,
        _ => state.get("debt_micros"),
    };

    q(LOCK_BALANCE_SQL)
        .bind(&period_str)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
    let allowance: i64 = q(ALLOWANCE_SQL)
        .bind(&period_str)
        .bind(now)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?
        .get(0);
    let mut lots = Vec::new();
    for row in q(LOCK_LOTS_SQL)
        .fetch_all(&mut **tx)
        .await
        .map_err(storage)?
    {
        lots.push(OpenLot {
            lot_id: row.get("lot_id"),
            pool: row.get::<String, _>("pool").parse()?,
            remaining_micros: row.get("remaining_micros"),
            expires_at: row.get("expires_at"),
            opened_at: row.get("opened_at"),
        });
    }
    // Spend in the window may use a lot that had not yet expired when the window closed.
    let mut usable: Vec<OpenLot> = lots
        .iter()
        .filter(|lot| lot.expires_at.is_none_or(|at| at > to))
        .cloned()
        .collect();
    sort_spending_order(&mut usable);
    let allocation = allocate(debt.saturating_add(spend_micros), allowance, &usable);

    let mut booked = Booked {
        debt_micros: allocation.debt_micros,
        ..Booked::default()
    };
    let window = format!("{}:{}", from.timestamp_micros(), to.timestamp_micros());
    for (index, draw) in allocation.draws.iter().enumerate() {
        let key = format!("settle:{account}:{window}:{index}");
        let (pool, lot_id) = match &draw.target {
            DrawTarget::Allowance => (CreditPool::Allowance, None),
            DrawTarget::Lot { lot_id, pool } => (*pool, Some(lot_id.as_str())),
        };
        debit(
            tx,
            account,
            pool,
            period,
            lot_id,
            -draw.amount_micros,
            GrantSource::Consumption,
            &key,
        )
        .await?;
        if let Some(lot) = lots
            .iter_mut()
            .find(|lot| Some(lot.lot_id.as_str()) == lot_id)
        {
            lot.remaining_micros -= draw.amount_micros;
        }
        booked.consumption_rows += 1;
    }

    for lot in lots.iter().filter(|lot| lot.remaining_micros > 0) {
        if lot.expires_at.is_some_and(|at| at <= now) {
            let key = format!("expire:{}", lot.lot_id);
            debit(
                tx,
                account,
                lot.pool,
                period,
                Some(&lot.lot_id),
                -lot.remaining_micros,
                GrantSource::Expiry,
                &key,
            )
            .await?;
            booked.expired_lots += 1;
        }
    }

    q(ADVANCE_STATE_SQL)
        .bind(to)
        .bind(allocation.debt_micros)
        .bind(&period_str)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    Ok(Some(booked))
}

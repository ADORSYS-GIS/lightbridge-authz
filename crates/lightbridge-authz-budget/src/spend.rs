//! Reads actual spend (`SUM(usage_events.total_cost)`) directly from the usage-events database
//! for a given account/period, so the budget domain's later augmentation logic (Phase 5) can
//! compare spend against a grant balance without calling `lightbridge-authz-usage`'s own
//! (unprotected) query HTTP API.
//!
//! The one rule this module exists to enforce: an aggregate `SUM` over zero matching rows is SQL
//! `NULL`, not zero. `lightbridge-authz-usage`'s own dashboard-facing query code
//! (`crates/lightbridge-authz-usage/src/repo.rs`) collapses that `NULL` into `0.0` via
//! `unwrap_or(0.0)`, which is a defensible default for a chart but not for a budget decision: an
//! account with no rows (broken ingest, retention rollout, or simply new) must never be
//! indistinguishable from an account that provably spent nothing. `Spend` keeps those two cases
//! as distinct variants so a caller deciding whether to grant more budget is forced to handle
//! "we don't know" separately from "zero" -- and routes the former to the strictest branch.

use std::sync::Arc;

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::BudgetError;
use crate::period::Period;

/// The result of summing `total_cost` for a scope/period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    /// `SUM(total_cost)` over at least one matching row, converted to non-negative micro-USD.
    /// Zero is a legitimate, common value here (e.g. an account whose only logged events cost
    /// nothing) -- it is NOT the same thing as `Unavailable` below, and callers must not
    /// conflate them.
    Known(i64),
    /// No matching rows for this scope/period (broken ingest, data aged past retention, or a
    /// brand-new account with no traffic yet) -- deliberately NOT represented as `Known(0)`.
    /// A caller deciding whether to grant or trigger something MUST treat this as "we don't
    /// know", routing to the strictest branch, never as "spent nothing, go ahead".
    Unavailable,
}

/// Reads summed spend for an account over a budget period. Implementations must preserve the
/// `Known`/`Unavailable` distinction described on [`Spend`] -- never collapse "no rows" into
/// `Known(0)`.
#[lightbridge_authz_core::async_trait]
pub trait SpendReader: Send + Sync + std::fmt::Debug {
    async fn spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<Spend, BudgetError>;
}

/// Converts a `total_cost` value (US dollars, as stored in `usage_events.total_cost`) into
/// non-negative micro-USD. Rejects non-finite and negative inputs, and anything that doesn't fit
/// in an `i64` once converted -- all three are infrastructure-level anomalies from a trusted
/// internal table, not normal caller-triggered validation errors, so they map to
/// `BudgetError::StorageFailed`.
fn cost_to_micros(total_cost: f64) -> Result<i64, BudgetError> {
    if !total_cost.is_finite() {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost is not finite: {total_cost}"
        )));
    }
    if total_cost < 0.0 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost is negative: {total_cost}"
        )));
    }

    let micros = (total_cost * 1_000_000.0).round();
    if micros > i64::MAX as f64 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost overflows i64 micro-USD: {total_cost}"
        )));
    }

    Ok(micros as i64)
}

/// Computes `[start of calendar month, start of next calendar month)` in UTC for `period`.
fn period_bounds_utc(period: &Period) -> (DateTime<Utc>, DateTime<Utc>) {
    let year = period.year();
    let month = period.month();

    // Safe: `Period` only ever holds a string that already passed `Period::parse`'s validation
    // (4-digit year, 2-digit month in 1..=12), so `year`/`month` here always form a valid
    // calendar date on the 1st of the month.
    let start_date = NaiveDate::from_ymd_opt(year as i32, u32::from(month), 1)
        .expect("Period invariant: year/month always form a valid calendar date");

    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let end_date = NaiveDate::from_ymd_opt(next_year as i32, u32::from(next_month), 1)
        .expect("Period invariant: year/month always form a valid calendar date");

    let start = start_date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();
    let end = end_date
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always a valid time")
        .and_utc();

    (start, end)
}

/// Reads spend directly from `usage_events` in the usage-events (Timescale-compatible) database.
#[derive(Debug, Clone)]
pub struct TimescaleSpendReader {
    pool: Arc<dyn lightbridge_authz_core::db::DbPoolTrait>,
}

impl TimescaleSpendReader {
    pub fn new(pool: Arc<dyn lightbridge_authz_core::db::DbPoolTrait>) -> Self {
        Self { pool }
    }
}

#[lightbridge_authz_core::async_trait]
impl SpendReader for TimescaleSpendReader {
    async fn spend_for_account(
        &self,
        account_id: &str,
        period: &Period,
    ) -> Result<Spend, BudgetError> {
        let (start, end) = period_bounds_utc(period);

        let total_cost: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
            "SELECT SUM(total_cost)::double precision FROM usage_events \
             WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3",
        )
        .bind(account_id)
        .bind(start)
        .bind(end)
        .fetch_one(self.pool.pool())
        .await
        .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;

        match total_cost {
            None => Ok(Spend::Unavailable),
            Some(total_cost) => cost_to_micros(total_cost).map(Spend::Known),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_to_micros_zero_is_zero() {
        assert_eq!(cost_to_micros(0.0).unwrap(), 0);
    }

    #[test]
    fn cost_to_micros_converts_dollars_to_micros() {
        assert_eq!(cost_to_micros(1.5).unwrap(), 1_500_000);
    }

    #[test]
    fn cost_to_micros_rounds_half_up() {
        assert_eq!(cost_to_micros(0.0000005).unwrap(), 1);
    }

    #[test]
    fn cost_to_micros_rejects_negative() {
        assert!(cost_to_micros(-0.01).is_err());
    }

    #[test]
    fn cost_to_micros_rejects_nan_and_infinite() {
        assert!(cost_to_micros(f64::NAN).is_err());
        assert!(cost_to_micros(f64::INFINITY).is_err());
        assert!(cost_to_micros(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn cost_to_micros_rejects_i64_overflow() {
        assert!(cost_to_micros(1e18).is_err());
    }

    #[test]
    fn period_bounds_utc_covers_a_calendar_month() {
        let period = Period::parse("2026-08").expect("valid period");
        let (start, end) = period_bounds_utc(&period);
        assert_eq!(start.to_rfc3339(), "2026-08-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2026-09-01T00:00:00+00:00");
    }

    #[test]
    fn period_bounds_utc_rolls_over_december_into_january() {
        let period = Period::parse("2026-12").expect("valid period");
        let (start, end) = period_bounds_utc(&period);
        assert_eq!(start.to_rfc3339(), "2026-12-01T00:00:00+00:00");
        assert_eq!(end.to_rfc3339(), "2027-01-01T00:00:00+00:00");
    }
}

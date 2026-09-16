//! Two pure helpers `spend.rs` uses to turn one `/usage/v1/spend/query` answer into budget-domain
//! terms: the `total_cost` unit/validity check, and the half-open UTC bounds of a calendar period.
//!
//! Split out of `spend.rs` verbatim — code moved, not rewritten — because that file sits on its
//! LoC-gate ceiling and ADR-0034 had to add the `SpendObservation` split beside it. The pairing is
//! unchanged: these are `pub(crate)` and `spend.rs` remains their only caller.

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::BudgetError;
use crate::period::Period;

/// Validates a `total_cost` value -- **micro-USD**, as stored in `usage_events.total_cost` --
/// and losslessly narrows it into `i64`. It does NOT scale: the stored value is already the
/// budget domain's unit.
///
/// ## Unit contract, settled (#488 -> #736/#737 -> #745)
///
/// This constant has now been argued three times, so the reasoning is recorded once, here:
///
/// * **#488** removed a `* 1_000_000.0`, reading the column as micro-USD. Correct for the
///   gateway's `llm_custom_total_cost` CEL writer, which is micro-USD.
/// * **#737** put the scaling back, reading the column as dollars. Correct for the normalizer
///   writer, which at the time divided `cost_micros` by `1_000_000.0` before storing.
/// * Both were half right, because `apply_normalizer`
///   (`crates/lightbridge-authz-usage/src/handlers/ingest.rs`) had TWO branches writing TWO
///   units into ONE column. No constant chosen here can be correct for both: this function sees
///   a bare `f64` and cannot tell which writer produced the row.
///
/// **#745 fixed the writer, not the reader.** Both ingest branches now emit micro-USD, the
/// 30,845 dollar-scale rows written between 2026-09-15 and 2026-09-16 were rescaled by
/// `migrations-usage/20260916000002_usage_events_total_cost_micro_usd.sql`, and this function is
/// back to validate-only. If spend ever looks ~10^6 out again, the bug is a writer that scaled,
/// not this function -- check `apply_normalizer` first.
///
/// Rounding is `f64::round` (ties away from zero), which matters because `SUM(total_cost)` over
/// many rows accumulates float drift. Overflow is rejected at `i64::MAX` micro-USD.
pub(crate) fn validate_total_cost_micros(total_cost: f64) -> Result<i64, BudgetError> {
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

    let micros = total_cost.round();
    if micros > i64::MAX as f64 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost overflows i64 micro-USD: {total_cost}"
        )));
    }

    Ok(micros as i64)
}

/// Computes `[start of calendar month, start of next calendar month)` in UTC for `period`.
pub(crate) fn period_bounds_utc(period: &Period) -> (DateTime<Utc>, DateTime<Utc>) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_total_cost_micros_zero_is_zero() {
        assert_eq!(validate_total_cost_micros(0.0).unwrap(), 0);
    }

    /// #745: the value is ALREADY micro-USD and must pass through unscaled. A row carrying
    /// `1234.0` is 1,234 micro-USD (about a tenth of a cent), never $1,234. Reintroducing a
    /// `* 1_000_000.0` here turns this into `1_234_000_000` and is exactly the incident that
    /// drove 40 of 49 production accounts to `budget_exhausted` on 2026-09-16.
    #[test]
    fn validate_total_cost_micros_does_not_scale_an_already_micro_usd_value() {
        assert_eq!(validate_total_cost_micros(1234.0).unwrap(), 1_234);
    }

    /// A fractional micro-USD can only come from float drift in `SUM(total_cost)` over many
    /// rows -- no writer emits one. It rounds to the nearest whole micro-USD, ties away from
    /// zero, per `f64::round`.
    #[test]
    fn validate_total_cost_micros_rounds_fractional_micro_usd_half_away_from_zero() {
        assert_eq!(validate_total_cost_micros(1234.6).unwrap(), 1_235);
        assert_eq!(validate_total_cost_micros(0.5).unwrap(), 1);
    }

    #[test]
    fn validate_total_cost_micros_rejects_negative() {
        assert!(validate_total_cost_micros(-0.01).is_err());
    }

    #[test]
    fn validate_total_cost_micros_rejects_nan_and_infinite() {
        assert!(validate_total_cost_micros(f64::NAN).is_err());
        assert!(validate_total_cost_micros(f64::INFINITY).is_err());
        assert!(validate_total_cost_micros(f64::NEG_INFINITY).is_err());
    }

    /// #745: with no scaling, the boundary is `i64::MAX` micro-USD itself (~9.223e18). `1e19`
    /// is over it; `1e13` -- which #736's boundary test relied on ONLY because it was multiplied
    /// by `1_000_000.0` -- is now comfortably valid, and asserting it still errors would be
    /// asserting the very scaling this fix removed.
    #[test]
    fn validate_total_cost_micros_rejects_i64_overflow() {
        assert!(validate_total_cost_micros(1e19).is_err());
        assert!(validate_total_cost_micros(1e13).is_ok());
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

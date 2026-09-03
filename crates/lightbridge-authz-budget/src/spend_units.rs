//! Two pure helpers `spend.rs` uses to turn one `/usage/v1/spend/query` answer into budget-domain
//! terms: the `total_cost` unit/validity check, and the half-open UTC bounds of a calendar period.
//!
//! Split out of `spend.rs` verbatim — code moved, not rewritten — because that file sits on its
//! LoC-gate ceiling and ADR-0034 had to add the `SpendObservation` split beside it. The pairing is
//! unchanged: these are `pub(crate)` and `spend.rs` remains their only caller.

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::BudgetError;
use crate::period::Period;

/// Validates and losslessly narrows a `total_cost` value -- **already micro-USD**, as stored in
/// `usage_events.total_cost` -- into `i64`.
///
/// ## Unit contract (#488)
///
/// `usage_events.total_cost` is micro-USD, not US dollars. The gateway's `llm_custom_total_cost`
/// CEL is the only production writer of this column (via
/// `crates/lightbridge-authz-usage/src/handlers/ingest.rs`'s `COST_KEYS` extraction, landed
/// verbatim, no scaling applied on the way in) and it emits micro-USD -- see the ai-helm
/// cost-tracking doc (`docs/models-chart-docs/cost-tracking.md`, *"Micro-USD ... the chart stores
/// request cost in this unit"*) in the `ADORSYS-GIS/ai-helm` repo. This function used to multiply
/// by `1_000_000.0` here, which was correct only if the stored value were US dollars -- it is
/// not, so that multiplication inflated every reported spend figure by roughly 10^6 and drove
/// self-service refill decisions to the fail-closed floor. See
/// https://github.com/ADORSYS-GIS/lightbridge-authz/issues/488.
///
/// This function therefore does not scale its input at all -- it only validates. The value still
/// arrives as `f64` over the wire (`SpendQueryResponse::total_cost`, a SQL `double precision`
/// `SUM`), so it must still be checked for the same three failure modes as before: non-finite
/// (`NaN`/`±inf`), negative (a cost can never be negative), and too large to round-trip into
/// `i64` exactly. All three are treated as an unusable response from the usage service by
/// `UsageServiceSpendReader` (see its doc comment), which routes them to `Spend::Unavailable`
/// rather than propagating an error.
///
/// Rounding: `f64` cannot represent every integer micro-USD value exactly (float summation drift
/// from `SUM(total_cost)` over many rows), so this rounds to the nearest whole micro-USD using
/// `f64::round` -- ties round away from zero (e.g. `1234.5` -> `1235`), not round-half-even. This
/// is the same rounding semantics the pre-#488 code already used for its (wrong-unit) conversion;
/// only the scaling factor changed, not the rounding rule.
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

    /// #488 prove-fail (test 1): a realistic gateway payload figure -- a request costing 1,234
    /// micro-USD (~$0.001234) -- passes through unchanged as 1,234 micro-USD. Break the fix by
    /// reintroducing `* 1_000_000.0` in `validate_total_cost_micros` and this fails with
    /// `1_234_000_000` instead.
    #[test]
    fn validate_total_cost_micros_passes_gateway_micro_usd_through_unscaled() {
        assert_eq!(validate_total_cost_micros(1234.0).unwrap(), 1_234);
    }

    /// #488 prove-fail (test 3): fractional micro-USD (float summation drift from `SUM` over many
    /// rows) rounds to the nearest whole micro-USD, ties away from zero -- `f64::round`'s
    /// semantics, documented on `validate_total_cost_micros` and unchanged by this fix (only the
    /// scaling factor was removed, not the rounding rule).
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

    #[test]
    fn validate_total_cost_micros_rejects_i64_overflow() {
        assert!(validate_total_cost_micros(1e19).is_err());
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

//! Two pure helpers `spend.rs` uses to turn one `/usage/v1/spend/query` answer into budget-domain
//! terms: the `total_cost` unit/validity check, and the half-open UTC bounds of a calendar period.
//!
//! Split out of `spend.rs` verbatim — code moved, not rewritten — because that file sits on its
//! LoC-gate ceiling and ADR-0034 had to add the `SpendObservation` split beside it. The pairing is
//! unchanged: these are `pub(crate)` and `spend.rs` remains their only caller.

use chrono::{DateTime, NaiveDate, Utc};

use crate::error::BudgetError;
use crate::period::Period;

/// Validates a `total_cost` value -- **US dollars**, as stored in `usage_events.total_cost` --
/// and losslessly narrows its scaled-to-micro-USD form into `i64`.
///
/// ## Unit contract, corrected (#488 -> #736)
///
/// `usage_events.total_cost` is dollars, not micro-USD, and this function must scale it up by
/// `1_000_000.0` to produce the budget domain's micro-USD unit. This is the *opposite* conclusion
/// from #488 (`0dde42f`, 2026-08-25, "usage_events.total_cost is micro-USD -- stop multiplying by
/// 1e6"), and #488 is not being reverted as a mistake: it was correct when written. Its own
/// commit message says it audited every consumer of `total_cost`, ingestion included, and found
/// them all unit-agnostic pass-through -- true on 2026-08-25. Thirteen days later, on
/// 2026-09-08, commit `6413db1` ("feat: implement normalizer registry and opencode pricing")
/// introduced `crates/lightbridge-authz-usage/src/handlers/ingest.rs`'s `apply_normalizer`
/// (`ingest.rs:492-495`):
///
/// ```text
/// let total_cost = norm.cost_micros.map(|c| c as f64 / 1_000_000.0).or_else(...);
/// ```
///
/// which divides each normalizer's already-correct micro-USD `cost_micros` by `1_000_000.0`
/// before it is stored -- converting the column to dollar-scale, matching
/// `docs/lightbridge-query-api.md`'s documented external contract (`"total_cost": 12.34`). Nobody
/// re-ran #488's audit against that later, unrelated change, so this function kept validating
/// (and NOT scaling) a value that had silently become dollars, not micro-USD -- undercounting
/// real spend by roughly 1,000,000x and starving the gateway's Dynamic Budget Limiter of any real
/// signal. See https://github.com/ADORSYS-GIS/lightbridge-authz/issues/488 for the original
/// (then-correct) reasoning and https://github.com/ADORSYS-GIS/lightbridge-authz/issues/736 for
/// this correction's full timeline and root cause. **`ingest.rs` and the documented dollar-scale
/// query-API contract are correct and untouched by this fix** -- only this reader's unit
/// assumption was wrong.
///
/// The value still arrives as `f64` over the wire (`SpendQueryResponse::total_cost`, a SQL
/// `double precision` `SUM`), so before scaling it is checked for the same three failure modes as
/// before: non-finite (`NaN`/`±inf`), negative (a cost can never be negative), and -- now
/// evaluated against the scaled micro-USD figure, since that is what must fit in `i64` -- too
/// large to round-trip exactly. All three are treated as an unusable response from the usage
/// service by `UsageServiceSpendReader` (see its doc comment), which routes them to
/// `Spend::Unavailable` rather than propagating an error.
///
/// Rounding: `f64` cannot represent every integer micro-USD value exactly (float summation drift
/// from `SUM(total_cost)` over many rows, plus the `* 1_000_000.0` scaling itself), so this
/// rounds to the nearest whole micro-USD using `f64::round` -- ties round away from zero (e.g.
/// `1234.5` micro-USD -> `1235`), not round-half-even. Reintroducing the multiplication also
/// moves the effective overflow ceiling: an input this large in *dollars* now overflows `i64`
/// micro-USD at roughly `i64::MAX / 1_000_000.0` (~$9.223 trillion), not at `i64::MAX` itself --
/// see `validate_total_cost_micros_rejects_i64_overflow_after_scaling` below, which picks a
/// boundary that only overflows because scaling is back, proving the fix rather than merely
/// reproducing a case that overflowed either way.
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

    let micros = (total_cost * 1_000_000.0).round();
    if micros > i64::MAX as f64 {
        return Err(BudgetError::StorageFailed(format!(
            "usage_events.total_cost overflows i64 micro-USD once scaled: {total_cost}"
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

    /// #736 prove-fail (test 1): a realistic dollar-scale figure straight off the wire -- a
    /// request costing $1,234.00 -- scales to 1,234,000,000 micro-USD. Before this fix,
    /// `validate_total_cost_micros` applied no scaling at all and this asserted `1_234` instead,
    /// which is the exact ~1,000,000x undercount this ticket fixes.
    #[test]
    fn validate_total_cost_micros_scales_dollars_to_micro_usd() {
        assert_eq!(validate_total_cost_micros(1234.0).unwrap(), 1_234_000_000);
    }

    /// #736 prove-fail (test 3): fractional dollars (float summation drift from `SUM` over many
    /// rows, and from the `* 1_000_000.0` scaling itself) round to the nearest whole micro-USD,
    /// ties away from zero -- `f64::round`'s semantics, documented on `validate_total_cost_micros`.
    /// `0.0012346` dollars scales to `1234.6` micro-USD (rounds up to `1235`); `0.0000005` dollars
    /// scales to exactly `0.5` micro-USD (rounds away from zero to `1`, not down to `0`).
    #[test]
    fn validate_total_cost_micros_rounds_fractional_micro_usd_half_away_from_zero() {
        assert_eq!(validate_total_cost_micros(0.0012346).unwrap(), 1_235);
        assert_eq!(validate_total_cost_micros(0.0000005).unwrap(), 1);
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

    /// #736: the overflow boundary moved once scaling was reintroduced. `1e19` dollars already
    /// overflowed `i64::MAX` even with NO scaling applied (the pre-fix, buggy behavior), so it
    /// would prove nothing about this fix -- a boundary check must pick a value that is safely
    /// within range unscaled but overflows once multiplied by `1_000_000.0`. `1e13` dollars
    /// (~$10 trillion) is well under `i64::MAX` (~9.223e18) on its own, but `1e13 * 1_000_000.0 =
    /// 1e19` overflows `i64::MAX` micro-USD -- this only fails because the multiplication runs.
    #[test]
    fn validate_total_cost_micros_rejects_i64_overflow_after_scaling() {
        assert!(validate_total_cost_micros(1e13).is_err());
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

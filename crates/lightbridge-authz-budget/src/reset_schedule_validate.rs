//! Input validation for budget reset schedules (ADR-0032, and its "forced next execution"
//! amendment).
//!
//! Carried out of [`crate::reset_schedule`], which sits on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown — the same reason
//! `lightbridge-authz-rest`'s `reset_schedule_convert.rs` exists. Nothing about the rules changed
//! in the move; the forced-`nextRunAt` check is the only addition.
//!
//! Both checks are deliberately duplicated against the database: the `CHECK` constraints on
//! `budget_reset_schedules` are the authority (nothing bypasses them), and these are the error
//! messages a human reads — an `InvalidSchedule` maps to HTTP 400, a raw constraint violation
//! would surface as a 500.

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::reset_schedule::{Cadence, ResetMode, ScheduleScopeKind};

/// Validates the closed-domain invariants the DB `CHECK`s also enforce, so a bad create/update is
/// a legible `InvalidSchedule` (HTTP 400) instead of a raw constraint violation surfaced as a 500.
pub(crate) fn validate_shape(
    name: &str,
    scope_kind: ScheduleScopeKind,
    scope_id: Option<&str>,
    cadence: Cadence,
    anchor: Option<i16>,
    amount_micros: i64,
    mode: ResetMode,
) -> Result<(), BudgetError> {
    if name.trim().is_empty() {
        return Err(BudgetError::InvalidSchedule(
            "name must not be empty".to_string(),
        ));
    }
    match (scope_kind, scope_id) {
        (ScheduleScopeKind::Global, Some(_)) => {
            return Err(BudgetError::InvalidSchedule(
                "a global schedule must not carry a scopeId".to_string(),
            ));
        }
        (ScheduleScopeKind::Global, None) => {}
        (_, None) | (_, Some("")) => {
            return Err(BudgetError::InvalidSchedule(format!(
                "a {scope_kind} schedule requires a non-empty scopeId"
            )));
        }
        (_, Some(id)) if id.trim().is_empty() => {
            return Err(BudgetError::InvalidSchedule(format!(
                "a {scope_kind} schedule requires a non-empty scopeId"
            )));
        }
        (_, Some(_)) => {}
    }
    match (cadence, anchor) {
        (Cadence::Daily, None) => {}
        (Cadence::Daily, Some(_)) => {
            return Err(BudgetError::InvalidSchedule(
                "a daily schedule must not carry an anchor".to_string(),
            ));
        }
        (Cadence::Weekly, Some(a)) if (1..=7).contains(&a) => {}
        (Cadence::Weekly, _) => {
            return Err(BudgetError::InvalidSchedule(
                "a weekly schedule requires an anchor in 1..=7 (ISO weekday, Monday = 1)"
                    .to_string(),
            ));
        }
        (Cadence::Monthly, Some(a)) if (1..=28).contains(&a) => {}
        (Cadence::Monthly, _) => {
            return Err(BudgetError::InvalidSchedule(
                "a monthly schedule requires an anchor in 1..=28 (day of month)".to_string(),
            ));
        }
    }
    match mode {
        ResetMode::TopUp if amount_micros <= 0 => {
            return Err(BudgetError::InvalidSchedule(
                "a top_up schedule requires a strictly positive amountMicros".to_string(),
            ));
        }
        ResetMode::Reset if amount_micros < 0 => {
            return Err(BudgetError::InvalidSchedule(
                "a reset schedule requires a non-negative amountMicros".to_string(),
            ));
        }
        _ => {}
    }
    Ok(())
}

/// An operator-forced `nextRunAt` must be STRICTLY in the future.
///
/// This is the one guard that makes a caller-supplied window safe. ADR-0032 D8 refused a
/// caller-supplied `nextRunAt` outright precisely because a backdated one fires on the very next
/// 60-second tick, across the whole estate, before anyone has dry-run it. Requiring the future
/// keeps that door shut while still letting an operator say "run this one on the 15th": the
/// schedule is still created disabled, and a human still has to enable it.
///
/// `now` is a parameter, never `Utc::now()`, per this crate's clock discipline.
pub(crate) fn validate_forced_next_run(
    next_run_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), BudgetError> {
    if next_run_at > now {
        return Ok(());
    }
    Err(BudgetError::InvalidSchedule(format!(
        "nextRunAt must be in the future: {} is not after {}",
        next_run_at.to_rfc3339(),
        now.to_rfc3339()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Cadence::{Daily, Monthly, Weekly};
    use ResetMode::{Reset, TopUp};
    use ScheduleScopeKind::{Account, Global};

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("valid UTC instant")
    }

    /// `validate_shape` with the one field no case below varies (the name) pinned.
    fn shape(
        kind: ScheduleScopeKind,
        scope_id: Option<&str>,
        cadence: Cadence,
        anchor: Option<i16>,
        amount: i64,
        mode: ResetMode,
    ) -> Result<(), BudgetError> {
        validate_shape("s", kind, scope_id, cadence, anchor, amount, mode)
    }

    #[test]
    fn validate_shape_rejects_mismatched_scope_and_anchor() {
        // A global schedule may not carry a scopeId, and every other kind must.
        assert!(shape(Global, Some("acc"), Daily, None, 1, TopUp).is_err());
        assert!(shape(Account, None, Daily, None, 1, TopUp).is_err());
        // Weekly anchors are ISO weekdays (1..=7); monthly ones are capped at 28 so no month
        // silently skips.
        assert!(shape(Global, None, Weekly, Some(9), 1, TopUp).is_err());
        assert!(shape(Global, None, Monthly, Some(31), 1, TopUp).is_err());
        // A zero-amount top_up would be an auditless no-op row...
        assert!(shape(Global, None, Daily, None, 0, TopUp).is_err());
        // ...but a `reset` to zero is legitimate: "cut everyone off at midnight".
        assert!(shape(Global, None, Daily, None, 0, Reset).is_ok());
    }

    #[test]
    fn a_forced_next_run_must_be_strictly_in_the_future() {
        let now = utc(2026, 9, 3, 12, 0);
        assert!(validate_forced_next_run(utc(2026, 9, 15, 0, 0), now).is_ok());
        // Exactly `now` is not the future — it would fire on the very next tick.
        assert!(validate_forced_next_run(now, now).is_err());
        let err = validate_forced_next_run(utc(2026, 9, 1, 0, 0), now).unwrap_err();
        assert!(
            err.to_string().contains("must be in the future"),
            "message should name the rule, got: {err}"
        );
    }
}

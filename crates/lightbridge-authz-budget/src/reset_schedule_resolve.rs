//! Resolving a [`NewBudgetResetSchedule`] into the row that would be written — validation plus
//! the one `next_run_at` decision — without touching the database.
//!
//! Split out of [`crate::reset_schedule::ResetScheduleRepo::create`] so a caller can ask "what
//! would this create?" and get **the same answer the write would produce**, by construction rather
//! than by a second copy of the rules. That caller is `lightbridge-authz budget schedule create
//! --dry-run`: a `global`-scoped schedule fires against every account in the estate, so the
//! ability to print the resolved row before writing it is not a convenience — it is the review
//! step ADR-0032 D8's "authored, dry-run, then enabled" sequence asks for.
//!
//! `create` now calls this too, so there is exactly one place that decides a new schedule's first
//! window. A duplicated copy here would be the classic release-pipeline failure: two lists of the
//! same facts, one of them quietly stale.
//!
//! Clock discipline, as everywhere in this crate: `now` is a parameter, never `Utc::now()`.

use chrono::{DateTime, Utc};

use crate::error::BudgetError;
use crate::reset_schedule::{NewBudgetResetSchedule, first_window_after};
use crate::reset_schedule_validate::{validate_forced_next_run, validate_shape};

/// Validates `input` and returns the `next_run_at` a create would store.
///
/// Two sources, in this precedence:
///
/// 1. **An operator-forced window** (`input.next_run_at`). Stored verbatim, and required to be
///    strictly in the future — the guard that keeps ADR-0032 D8's door shut, since a backdated
///    window fires on the very next 60-second tick across everything the scope matches.
/// 2. **The cadence's own grid**, via [`first_window_after`]: the earliest instant strictly after
///    `now` matching `cadence`/`anchor` at `run_at_utc`.
///
/// Note what this does *not* decide: `enabled`. A new schedule is always created disabled, and
/// that is the repository's business, not this function's.
pub fn resolve_next_run_at(
    input: &NewBudgetResetSchedule,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, BudgetError> {
    validate_shape(
        &input.name,
        input.scope_kind,
        input.scope_id.as_deref(),
        input.cadence,
        input.anchor,
        input.amount_micros,
        input.mode,
    )?;

    match input.next_run_at {
        Some(forced) => {
            validate_forced_next_run(forced, now)?;
            Ok(forced)
        }
        None => first_window_after(now, input.cadence, input.anchor, input.run_at_utc),
    }
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveTime, TimeZone};

    use super::*;
    use crate::reset_schedule::{Cadence, ResetMode, ScheduleScopeKind};

    fn utc(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, 0, 0)
            .single()
            .expect("valid UTC instant")
    }

    /// The exact shape #702 asks production for: global, weekly, Monday, midnight UTC, $8 —
    /// ISO weekday 1, the anchor that puts the window on 2026-09-07, the same tick the live
    /// `billing_plan=free` schedule already fires on.
    fn global_weekly_monday(next_run_at: Option<DateTime<Utc>>) -> NewBudgetResetSchedule {
        NewBudgetResetSchedule {
            name: "Global refill $8".to_string(),
            scope_kind: ScheduleScopeKind::Global,
            scope_id: None,
            cadence: Cadence::Weekly,
            anchor: Some(1),
            run_at_utc: NaiveTime::from_hms_opt(0, 0, 0).expect("valid time"),
            amount_micros: 8_000_000,
            mode: ResetMode::Reset,
            next_run_at,
        }
    }

    #[test]
    fn an_unforced_window_lands_on_the_cadences_own_grid() {
        // Saturday 2026-09-05 12:00 UTC -> the next ISO-weekday-1 (Monday) midnight is
        // 2026-09-07, which is exactly where the live free-plan schedule's next window sits.
        let resolved = resolve_next_run_at(&global_weekly_monday(None), utc(2026, 9, 5, 12))
            .expect("a well-formed global weekly schedule must resolve");
        assert_eq!(resolved, utc(2026, 9, 7, 0));
    }

    #[test]
    fn a_forced_window_is_stored_verbatim_and_must_be_in_the_future() {
        let forced = utc(2026, 9, 7, 0);
        assert_eq!(
            resolve_next_run_at(&global_weekly_monday(Some(forced)), utc(2026, 9, 5, 12))
                .expect("a future forced window is allowed"),
            forced
        );
        // Same instant, a clock that has already passed it: refused before anything is written.
        assert!(
            resolve_next_run_at(&global_weekly_monday(Some(forced)), utc(2026, 9, 8, 0)).is_err()
        );
    }

    #[test]
    fn a_global_schedule_carrying_a_scope_id_is_refused_before_the_window_is_computed() {
        let mut input = global_weekly_monday(None);
        input.scope_id = Some("free".to_string());
        let err = resolve_next_run_at(&input, utc(2026, 9, 5, 12)).expect_err("must be refused");
        assert!(
            err.to_string().contains("must not carry a scopeId"),
            "the message should name the rule, got: {err}"
        );
    }
}

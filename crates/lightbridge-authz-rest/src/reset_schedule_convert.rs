//! Wire converters and input parsers for the budget reset-schedule procedures (ADR-0032).
//!
//! Moved verbatim out of `lib.rs`, which sits on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown — the same reason
//! `budget_convert.rs` exists. `lib.rs` imports these four by name; nothing else changed.

use cratestack::CratestackError;
use lightbridge_authz_api::schema;

use crate::error_convert::budget_error_to_cratestack_error;

/// Maps a domain [`lightbridge_authz_budget::BudgetResetSchedule`] into the schema's wire
/// `BudgetResetSchedule` shape (ADR-0032). `scopeKind`/`cadence`/`mode` carry the exact strings
/// their Rust enums' `Display` impls render -- the same wire-string-as-`String` choice
/// `Decision.effect` already documents -- and `amountMicros` is a `String`-carried i64 like every
/// other micro-USD amount on this surface.
pub(crate) fn to_schema_budget_reset_schedule(
    schedule: lightbridge_authz_budget::BudgetResetSchedule,
) -> schema::BudgetResetSchedule {
    schema::BudgetResetSchedule {
        id: schedule.id,
        name: schedule.name,
        scopeKind: schedule.scope_kind.to_string(),
        scopeId: schedule.scope_id,
        cadence: schedule.cadence.to_string(),
        anchor: schedule.anchor.map(i64::from),
        runAtUtc: lightbridge_authz_budget::render_run_at_utc(schedule.run_at_utc),
        amountMicros: schedule.amount_micros.to_string(),
        mode: schedule.mode.to_string(),
        enabled: schedule.enabled,
        nextRunAt: schedule.next_run_at,
        lastRunAt: schedule.last_run_at,
        createdBy: schedule.created_by,
        createdAt: schedule.created_at,
        updatedAt: schedule.updated_at,
    }
}

/// The time of day a reset schedule fires when `createBudgetResetSchedule` omits `runAtUtc`,
/// matching the column's own `DEFAULT '00:00'`. Always UTC.
const DEFAULT_RESET_SCHEDULE_RUN_AT_UTC: chrono::NaiveTime =
    match chrono::NaiveTime::from_hms_opt(0, 0, 0) {
        Some(time) => time,
        None => unreachable!(),
    };

/// Parses the wire `runAtUtc` (`HH:MM`, always UTC), falling back to the column's own default when
/// the caller omitted it. A malformed value is a 400 naming the offending string, never a 500.
pub(crate) fn parse_run_at_or_default(
    raw: Option<&str>,
) -> std::result::Result<chrono::NaiveTime, CratestackError> {
    match raw {
        Some(raw) => lightbridge_authz_budget::parse_run_at_utc(raw)
            .map_err(budget_error_to_cratestack_error),
        None => Ok(DEFAULT_RESET_SCHEDULE_RUN_AT_UTC),
    }
}

/// Parses a wire `amountMicros` (a `String`-carried i64) into `i64`, mirroring `grantBudget`'s
/// identical parse so a malformed amount is a 400 with the offending value, never a 500.
pub(crate) fn parse_amount_micros(raw: &str) -> std::result::Result<i64, CratestackError> {
    raw.trim().parse::<i64>().map_err(|_| {
        CratestackError::BadRequest(format!("amountMicros must be a valid integer, got '{raw}'"))
    })
}

/// Narrows a wire `anchor` (`Int?`, i.e. `i64`) into the `i16` the column stores. Out-of-range is a
/// 400 rather than a silent truncation -- the DB `CHECK` would reject it anyway, but as an opaque
/// constraint violation surfaced as a 500.
pub(crate) fn parse_schedule_anchor(
    anchor: Option<i64>,
) -> std::result::Result<Option<i16>, CratestackError> {
    anchor
        .map(|value| {
            i16::try_from(value)
                .map_err(|_| CratestackError::BadRequest(format!("anchor {value} is out of range")))
        })
        .transpose()
}

/// Maps one [`lightbridge_authz_budget::ScheduleRunOutcome`] into the schema's
/// `BudgetResetScheduleRunResult`, shared by the dry-run and the real `runBudgetResetScheduleNow`
/// so the two can never render a different shape.
pub(crate) fn to_schema_reset_schedule_run_result(
    schedule_id: String,
    dry_run: bool,
    window_start: chrono::DateTime<chrono::Utc>,
    outcome: lightbridge_authz_budget::ScheduleRunOutcome,
) -> schema::BudgetResetScheduleRunResult {
    schema::BudgetResetScheduleRunResult {
        scheduleId: schedule_id,
        dryRun: dry_run,
        windowStart: window_start,
        entries: outcome
            .planned
            .into_iter()
            .map(|entry| schema::BudgetResetSchedulePlanEntry {
                budgetAccountId: entry.budget_account_id,
                remainingMicros: entry.remaining_micros.to_string(),
                deltaMicros: entry.delta_micros.to_string(),
            })
            .collect(),
        deferredAccountIds: outcome.deferred_account_ids,
        supersededAccountIds: outcome.superseded_account_ids,
    }
}

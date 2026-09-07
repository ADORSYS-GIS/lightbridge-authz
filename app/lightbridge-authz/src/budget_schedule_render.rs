//! How `budget schedule` prints a row, and how it decides two rows are the same schedule.
//!
//! Split from [`crate::budget_schedule_cmd`] so both stay under this repo's 200-LoC ceiling, and
//! because these two functions are the pair that has to agree: the fields
//! [`differences`] compares are exactly the fields [`render`] prints, so an operator reading a
//! refusal can see the disagreement in the line above it.
//!
//! One line per schedule, `key=value` and no table: the output is read out of a `kubectl logs`
//! pane, and it is grepped. Nothing here prints a credential — a schedule row carries none.

use lightbridge_authz_budget::reset_schedule::{
    BudgetResetSchedule, NewBudgetResetSchedule, render_run_at_utc,
};

fn dash(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".to_string())
}

/// One stored schedule, as a single greppable line.
pub fn render(schedule: &BudgetResetSchedule) -> String {
    format!(
        "id={} {} enabled={} next_run_at={} last_run_at={}",
        schedule.id,
        shape_of(schedule),
        schedule.enabled,
        schedule.next_run_at.to_rfc3339(),
        dash(schedule.last_run_at.map(|at| at.to_rfc3339())),
    )
}

/// The row a create WOULD write: everything [`render`] shows except the id, which does not exist
/// until the `INSERT` mints it. `enabled` is what the invocation asked for, not what the domain
/// layer will store on the first write — a schedule is always created disabled and enabled in a
/// second, explicit step (ADR-0032 D8), and the command says so on both lines.
pub fn render_resolved(
    input: &NewBudgetResetSchedule,
    next_run_at: chrono::DateTime<chrono::Utc>,
    enabled: bool,
) -> String {
    format!(
        "{} enabled={enabled} next_run_at={}",
        new_shape_of(input),
        next_run_at.to_rfc3339()
    )
}

/// The fields that make two rows the SAME schedule. Deliberately excludes `enabled`,
/// `next_run_at`, `last_run_at` and the timestamps: the first two are converged or left alone by a
/// re-run, and the last two are history, not configuration.
pub fn differences(existing: &BudgetResetSchedule, wanted: &NewBudgetResetSchedule) -> Vec<String> {
    let mut out = Vec::new();
    let mut check = |field: &str, have: String, want: String| {
        if have != want {
            out.push(format!("{field} is {have}, wanted {want}"));
        }
    };
    check(
        "scope",
        existing.scope_kind.to_string(),
        wanted.scope_kind.to_string(),
    );
    check(
        "scope_id",
        dash(existing.scope_id.clone()),
        dash(wanted.scope_id.clone()),
    );
    check(
        "cadence",
        existing.cadence.to_string(),
        wanted.cadence.to_string(),
    );
    check(
        "anchor",
        dash(existing.anchor.map(|a| a.to_string())),
        dash(wanted.anchor.map(|a| a.to_string())),
    );
    check(
        "run_at_utc",
        render_run_at_utc(existing.run_at_utc),
        render_run_at_utc(wanted.run_at_utc),
    );
    check(
        "amount_micros",
        existing.amount_micros.to_string(),
        wanted.amount_micros.to_string(),
    );
    check("mode", existing.mode.to_string(), wanted.mode.to_string());
    out
}

fn shape_of(schedule: &BudgetResetSchedule) -> String {
    fields(
        &schedule.name,
        &schedule.scope_kind.to_string(),
        schedule.scope_id.clone(),
        &schedule.cadence.to_string(),
        schedule.anchor,
        render_run_at_utc(schedule.run_at_utc),
        schedule.amount_micros,
        &schedule.mode.to_string(),
    )
}

fn new_shape_of(input: &NewBudgetResetSchedule) -> String {
    fields(
        input.name.trim(),
        &input.scope_kind.to_string(),
        input.scope_id.clone(),
        &input.cadence.to_string(),
        input.anchor,
        render_run_at_utc(input.run_at_utc),
        input.amount_micros,
        &input.mode.to_string(),
    )
}

#[allow(clippy::too_many_arguments)]
fn fields(
    name: &str,
    scope: &str,
    scope_id: Option<String>,
    cadence: &str,
    anchor: Option<i16>,
    run_at_utc: String,
    amount_micros: i64,
    mode: &str,
) -> String {
    format!(
        "name={name:?} scope={scope} scope_id={} cadence={cadence} anchor={} \
         run_at_utc={run_at_utc} amount_micros={amount_micros} mode={mode}",
        dash(scope_id),
        dash(anchor.map(|a| a.to_string())),
    )
}

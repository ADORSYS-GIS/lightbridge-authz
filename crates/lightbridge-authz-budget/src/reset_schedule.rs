//! Budget reset schedules (ADR-0032): the configured policies a background task executes against
//! the ledger, plus the calendar arithmetic that decides when each one is next due.
//!
//! This module owns the *data*: the row shape, its closed-value domains, the repository that
//! reads/writes `budget_reset_schedules`, and the cadence math. What a due schedule actually
//! *does* — enumerate matching budget accounts, read spend, write a grant — lives in
//! [`crate::reset_scheduler`], so this module has no dependency on the ledger or on spend.
//!
//! ## Clock discipline
//!
//! Every function here that needs "now" takes it as a parameter, the same discipline
//! [`crate::period::Period`] and [`crate::spend`] already follow. Nothing in this module reads the
//! clock, which is what makes "a schedule that missed six windows catches up to the next FUTURE
//! window in one step" a plain unit test rather than a timing-dependent one.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Datelike, Days, Months, NaiveDate, NaiveTime, TimeZone, Timelike, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::PgPool;

use crate::error::BudgetError;

/// Which budget accounts a schedule targets. Ordered most-general to most-specific so
/// [`ScheduleScopeKind::specificity`] can be a plain integer comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScheduleScopeKind {
    /// Every account that has a `users` row behind it (i.e. every real account — `accounts.user_id`
    /// is `NOT NULL` and FK-bound to `users`, so the join is a statement of intent, not a filter).
    Global,
    /// Every account with at least one project or API key on `scope_id`'s billing plan.
    BillingPlan,
    /// Exactly the one account named by `scope_id`.
    Account,
}

impl ScheduleScopeKind {
    /// Precedence rank: a higher number wins. `account` (2) > `billing_plan` (1) > `global` (0),
    /// the binding ruling in the story — an account covered by a more specific enabled schedule is
    /// skipped by every less specific one, so two schedules never both fire against one account.
    pub const fn specificity(self) -> u8 {
        match self {
            ScheduleScopeKind::Global => 0,
            ScheduleScopeKind::BillingPlan => 1,
            ScheduleScopeKind::Account => 2,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            ScheduleScopeKind::Global => "global",
            ScheduleScopeKind::BillingPlan => "billing_plan",
            ScheduleScopeKind::Account => "account",
        }
    }
}

impl fmt::Display for ScheduleScopeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ScheduleScopeKind {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "global" => Ok(ScheduleScopeKind::Global),
            "billing_plan" => Ok(ScheduleScopeKind::BillingPlan),
            "account" => Ok(ScheduleScopeKind::Account),
            other => Err(BudgetError::InvalidSchedule(format!(
                "unknown scope kind '{other}' (expected global, billing_plan or account)"
            ))),
        }
    }
}

/// How often a schedule fires. Deliberately a closed set of three: the finest cadence is daily, so
/// a 60-second tick is comfortably fine-grained, and nothing here needs a cron expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cadence {
    Daily,
    Weekly,
    Monthly,
}

impl Cadence {
    const fn as_str(self) -> &'static str {
        match self {
            Cadence::Daily => "daily",
            Cadence::Weekly => "weekly",
            Cadence::Monthly => "monthly",
        }
    }
}

impl fmt::Display for Cadence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Cadence {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "daily" => Ok(Cadence::Daily),
            "weekly" => Ok(Cadence::Weekly),
            "monthly" => Ok(Cadence::Monthly),
            other => Err(BudgetError::InvalidSchedule(format!(
                "unknown cadence '{other}' (expected daily, weekly or monthly)"
            ))),
        }
    }
}

/// What a firing schedule does to a matched account's remaining balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResetMode {
    /// Clamp remaining (`effective_budget - spend_to_date`) to exactly `amount_micros`, in BOTH
    /// directions — the owner's binding ruling. A shortfall is a positive `source = 'automatic'`
    /// grant; an excess is a NEGATIVE `source = 'correction'` row, the compensating entry ADR-0009
    /// already defines as the only way to reduce a balance without mutating the append-only ledger.
    Reset,
    /// Add `amount_micros` to the balance, whatever the current remaining is.
    TopUp,
}

impl ResetMode {
    const fn as_str(self) -> &'static str {
        match self {
            ResetMode::Reset => "reset",
            ResetMode::TopUp => "top_up",
        }
    }
}

impl fmt::Display for ResetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ResetMode {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "reset" => Ok(ResetMode::Reset),
            "top_up" => Ok(ResetMode::TopUp),
            other => Err(BudgetError::InvalidSchedule(format!(
                "unknown mode '{other}' (expected reset or top_up)"
            ))),
        }
    }
}

/// One `budget_reset_schedules` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetResetSchedule {
    pub id: String,
    pub name: String,
    pub scope_kind: ScheduleScopeKind,
    pub scope_id: Option<String>,
    pub cadence: Cadence,
    pub anchor: Option<i16>,
    pub run_at_utc: NaiveTime,
    pub amount_micros: i64,
    pub mode: ResetMode,
    pub enabled: bool,
    pub next_run_at: DateTime<Utc>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BudgetResetSchedule {
    /// The instant AFTER `self.next_run_at` this schedule is due, given `now`. Delegates to
    /// [`next_window_after`]; see that function for the catch-up contract.
    pub fn advance_from_next_run(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, BudgetError> {
        next_window_after(self.next_run_at, self.cadence, self.anchor, now)
    }
}

/// The caller-supplied half of a create. `enabled` is deliberately absent: a new schedule is
/// ALWAYS created disabled (see the migration's own comment), so a misconfigured `global` row
/// cannot grant across the estate before anyone has dry-run it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewBudgetResetSchedule {
    pub name: String,
    pub scope_kind: ScheduleScopeKind,
    pub scope_id: Option<String>,
    pub cadence: Cadence,
    pub anchor: Option<i16>,
    pub run_at_utc: NaiveTime,
    pub amount_micros: i64,
    pub mode: ResetMode,
}

/// A partial update. Every field is `Option`: `None` means "leave this column alone".
///
/// `scope_id` is read only when `scope_kind` is also supplied, so a scope change always moves both
/// halves together (a `billing_plan` row becoming `global` must drop its `scope_id`, and the DB
/// `CHECK` enforces that pairing anyway). There is deliberately no way to clear `scope_id` while
/// keeping `scope_kind` — that combination is invalid by construction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BudgetResetScheduleUpdate {
    pub name: Option<String>,
    pub scope: Option<(ScheduleScopeKind, Option<String>)>,
    pub cadence: Option<Cadence>,
    pub anchor: Option<Option<i16>>,
    pub run_at_utc: Option<NaiveTime>,
    pub amount_micros: Option<i64>,
    pub mode: Option<ResetMode>,
    pub enabled: Option<bool>,
}

/// Validates the closed-domain invariants the DB `CHECK`s also enforce, so a bad create/update is
/// a legible `InvalidSchedule` (HTTP 400) instead of a raw constraint violation surfaced as a 500.
/// Deliberately duplicated across both layers rather than trusted to one: the DB is the authority
/// (nothing bypasses it), this is the error message a human reads.
fn validate_shape(
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

/// The first instant a freshly created schedule fires: the earliest instant STRICTLY after `now`
/// that matches `cadence`/`anchor` at `run_at_utc`.
pub fn first_window_after(
    now: DateTime<Utc>,
    cadence: Cadence,
    anchor: Option<i16>,
    run_at_utc: NaiveTime,
) -> Result<DateTime<Utc>, BudgetError> {
    let today = now.date_naive();
    let candidate = match cadence {
        Cadence::Daily => at_time(today, run_at_utc),
        Cadence::Weekly => {
            let target = anchor.ok_or_else(|| {
                BudgetError::InvalidSchedule("a weekly schedule requires an anchor".to_string())
            })?;
            let current = i16::try_from(today.weekday().number_from_monday())
                .expect("chrono weekday number_from_monday() is always 1..=7");
            let delta = i64::from((target - current).rem_euclid(7));
            at_time(add_days(today, delta)?, run_at_utc)
        }
        Cadence::Monthly => {
            let day = anchor.ok_or_else(|| {
                BudgetError::InvalidSchedule("a monthly schedule requires an anchor".to_string())
            })?;
            let day = u32::try_from(day).map_err(|_| {
                BudgetError::InvalidSchedule(format!("monthly anchor {day} is out of range"))
            })?;
            let this_month =
                NaiveDate::from_ymd_opt(today.year(), today.month(), day).ok_or_else(|| {
                    BudgetError::InvalidSchedule(format!(
                        "monthly anchor {day} is not a valid day of month"
                    ))
                })?;
            at_time(this_month, run_at_utc)
        }
    };

    if candidate > now {
        Ok(candidate)
    } else {
        next_window_after(candidate, cadence, anchor, now)
    }
}

/// The next window strictly after `now`, computed from `previous` by repeated cadence steps —
/// never from `now` itself.
///
/// This is the anti-drift contract in the acceptance criteria, and the catch-up one at the same
/// time: a schedule whose `previous` is six windows in the past lands on the next FUTURE window in
/// one call (it does not fire six times), and a schedule that is only one window behind lands
/// exactly one step on, with no accumulated seconds of drift — because every step is measured off
/// the stored instant, not off whenever the tick happened to wake up.
///
/// A daily/weekly step is calendar days, not a fixed duration, but everything here is UTC (the
/// column is `TIMESTAMPTZ`, the time-of-day column is `TIME` documented as UTC), so there is no DST
/// discontinuity to absorb: in UTC a calendar day is always exactly 24 hours.
pub fn next_window_after(
    previous: DateTime<Utc>,
    cadence: Cadence,
    anchor: Option<i16>,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, BudgetError> {
    let run_at = previous.time();
    match cadence {
        Cadence::Daily => step_days(previous, now, 1),
        Cadence::Weekly => step_days(previous, now, 7),
        Cadence::Monthly => {
            let day = match anchor {
                Some(a) => u32::try_from(a).map_err(|_| {
                    BudgetError::InvalidSchedule(format!("monthly anchor {a} is out of range"))
                })?,
                None => previous.day(),
            };
            // Whole months elapsed, floored, then one more — the same "closed form, then one
            // correction step" shape as `step_days`. `Months::new` is calendar-correct and, with
            // the anchor capped at 28 by the DB `CHECK`, can never land on a day that does not
            // exist.
            let mut months = elapsed_months(previous, now).max(0) as u32;
            loop {
                let base = previous
                    .date_naive()
                    .with_day(1)
                    .expect("day 1 exists in every month")
                    .checked_add_months(Months::new(months))
                    .ok_or_else(|| {
                        BudgetError::InvalidSchedule(
                            "monthly schedule overflowed the calendar".to_string(),
                        )
                    })?;
                let date = base.with_day(day).ok_or_else(|| {
                    BudgetError::InvalidSchedule(format!(
                        "monthly anchor {day} is not a valid day of month"
                    ))
                })?;
                let candidate = at_time(date, run_at);
                if candidate > now {
                    return Ok(candidate);
                }
                months += 1;
            }
        }
    }
}

/// `previous + k*step_days`, for the smallest `k >= 1` that lands strictly after `now`. Closed
/// form (one division), then a single `while` that can iterate at most once — it exists only to
/// absorb the sub-step remainder, not to walk the calendar.
fn step_days(
    previous: DateTime<Utc>,
    now: DateTime<Utc>,
    step: i64,
) -> Result<DateTime<Utc>, BudgetError> {
    let elapsed_days = (now - previous).num_days().max(0);
    let mut steps = (elapsed_days / step).max(0);
    loop {
        steps += 1;
        let candidate = previous
            .checked_add_days(Days::new(u64::try_from(steps * step).map_err(|_| {
                BudgetError::InvalidSchedule("schedule step overflowed".to_string())
            })?))
            .ok_or_else(|| {
                BudgetError::InvalidSchedule("schedule step overflowed the calendar".to_string())
            })?;
        if candidate > now {
            return Ok(candidate);
        }
    }
}

/// Whole calendar months from `previous` to `now`, floored at zero. Only used as the closed-form
/// starting guess in [`next_window_after`]'s monthly branch, which then corrects upward.
fn elapsed_months(previous: DateTime<Utc>, now: DateTime<Utc>) -> i64 {
    if now <= previous {
        return 0;
    }
    let years = i64::from(now.year() - previous.year());
    let months = years * 12 + i64::from(now.month() as i32 - previous.month() as i32);
    months.max(0)
}

fn add_days(date: NaiveDate, days: i64) -> Result<NaiveDate, BudgetError> {
    let days = u64::try_from(days)
        .map_err(|_| BudgetError::InvalidSchedule("negative day offset".to_string()))?;
    date.checked_add_days(Days::new(days))
        .ok_or_else(|| BudgetError::InvalidSchedule("date overflowed the calendar".to_string()))
}

/// A `NaiveDate` + `NaiveTime` pinned to UTC. `single()` cannot fail for `Utc` (no ambiguous or
/// skipped local times exist in a fixed-offset zone), so the `expect` is a total function, not a
/// hopeful one.
fn at_time(date: NaiveDate, time: NaiveTime) -> DateTime<Utc> {
    Utc.from_utc_datetime(&date.and_time(time))
}

/// Renders a `run_at_utc` as the `HH:MM` wire form the RPC surface exchanges. Seconds are dropped
/// deliberately — the column is minute-granular in practice and the console renders "every day at
/// 00:00 UTC".
pub fn render_run_at_utc(time: NaiveTime) -> String {
    format!("{:02}:{:02}", time.hour(), time.minute())
}

/// Parses the `HH:MM` (or `HH:MM:SS`) wire form back into a `NaiveTime`.
pub fn parse_run_at_utc(raw: &str) -> Result<NaiveTime, BudgetError> {
    NaiveTime::parse_from_str(raw, "%H:%M")
        .or_else(|_| NaiveTime::parse_from_str(raw, "%H:%M:%S"))
        .map_err(|_| {
            BudgetError::InvalidSchedule(format!("runAtUtc must be HH:MM (UTC), got '{raw}'"))
        })
}

#[derive(Debug, sqlx::FromRow)]
struct ScheduleRow {
    id: String,
    name: String,
    scope_kind: String,
    scope_id: Option<String>,
    cadence: String,
    anchor: Option<i16>,
    run_at_utc: NaiveTime,
    amount_micros: i64,
    mode: String,
    enabled: bool,
    next_run_at: DateTime<Utc>,
    last_run_at: Option<DateTime<Utc>>,
    created_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<ScheduleRow> for BudgetResetSchedule {
    type Error = BudgetError;

    fn try_from(row: ScheduleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            name: row.name,
            scope_kind: row.scope_kind.parse()?,
            scope_id: row.scope_id,
            cadence: row.cadence.parse()?,
            anchor: row.anchor,
            run_at_utc: row.run_at_utc,
            amount_micros: row.amount_micros,
            mode: row.mode.parse()?,
            enabled: row.enabled,
            next_run_at: row.next_run_at,
            last_run_at: row.last_run_at,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// The projection every read/RETURNING below shares. Spelled out per query rather than
/// interpolated: sqlx 0.9's `SqlSafeStr` bound only accepts `&'static str`, so a `format!`-built
/// query is rejected at compile time (deliberately -- it is the injection guard). `concat!` over
/// this literal keeps the list in one place while staying `'static`.
macro_rules! schedule_columns {
    () => {
        "id, name, scope_kind, scope_id, cadence, anchor, run_at_utc, amount_micros, mode, \
         enabled, next_run_at, last_run_at, created_by, created_at, updated_at"
    };
}

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// Persistence for `budget_reset_schedules`. Hand-written sqlx, per ADR-0010: the budget domain is
/// procedures and a hand-written repository, never generated cratestack CRUD.
#[derive(Debug, Clone)]
pub struct ResetScheduleRepo {
    pool: Arc<dyn DbPoolTrait>,
}

impl ResetScheduleRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    /// Every schedule, enabled or not, oldest first. Per ADR-0039 the ordering key is `created_at`
    /// (never the CUID2 id); `name` is only a deterministic tie-break for rows created in the same
    /// microsecond.
    pub async fn list(&self) -> Result<Vec<BudgetResetSchedule>, BudgetError> {
        let rows: Vec<ScheduleRow> = sqlx::query_as(concat!(
            "SELECT ",
            schedule_columns!(),
            " FROM budget_reset_schedules ORDER BY created_at ASC, name ASC"
        ))
        .fetch_all(self.pool())
        .await
        .map_err(storage_failed)?;

        rows.into_iter()
            .map(BudgetResetSchedule::try_from)
            .collect()
    }

    /// Only the enabled schedules — the set precedence resolution is computed over. A disabled
    /// schedule never wins and never blocks a less specific one, which is what makes "disable it
    /// and the global schedule takes over" behave the way an operator expects.
    pub async fn list_enabled(&self) -> Result<Vec<BudgetResetSchedule>, BudgetError> {
        let rows: Vec<ScheduleRow> = sqlx::query_as(concat!(
            "SELECT ",
            schedule_columns!(),
            " FROM budget_reset_schedules WHERE enabled ORDER BY created_at ASC, name ASC"
        ))
        .fetch_all(self.pool())
        .await
        .map_err(storage_failed)?;

        rows.into_iter()
            .map(BudgetResetSchedule::try_from)
            .collect()
    }

    pub async fn get(&self, id: &str) -> Result<BudgetResetSchedule, BudgetError> {
        let row: Option<ScheduleRow> = sqlx::query_as(concat!(
            "SELECT ",
            schedule_columns!(),
            " FROM budget_reset_schedules WHERE id = $1"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(storage_failed)?;

        row.ok_or_else(|| BudgetError::NotFound(format!("budget reset schedule '{id}'")))?
            .try_into()
    }

    /// Creates a schedule, always DISABLED, with `next_run_at` seeded from the cadence rather than
    /// from the caller — a caller cannot backdate a window to force an immediate estate-wide fire.
    pub async fn create(
        &self,
        input: NewBudgetResetSchedule,
        created_by: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<BudgetResetSchedule, BudgetError> {
        validate_shape(
            &input.name,
            input.scope_kind,
            input.scope_id.as_deref(),
            input.cadence,
            input.anchor,
            input.amount_micros,
            input.mode,
        )?;

        let next_run_at = first_window_after(now, input.cadence, input.anchor, input.run_at_utc)?;

        let row: ScheduleRow = sqlx::query_as(concat!(
            "INSERT INTO budget_reset_schedules ",
            "(id, name, scope_kind, scope_id, cadence, anchor, run_at_utc, amount_micros, mode, ",
            " enabled, next_run_at, created_by) ",
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, FALSE, $10, $11) RETURNING ",
            schedule_columns!()
        ))
        .bind(cuid2())
        .bind(input.name.trim())
        .bind(input.scope_kind.to_string())
        .bind(input.scope_id.as_deref())
        .bind(input.cadence.to_string())
        .bind(input.anchor)
        .bind(input.run_at_utc)
        .bind(input.amount_micros)
        .bind(input.mode.to_string())
        .bind(next_run_at)
        .bind(created_by)
        .fetch_one(self.pool())
        .await
        .map_err(storage_failed)?;

        row.try_into()
    }

    /// Applies a partial update. Any change to `cadence`/`anchor`/`run_at_utc` re-seeds
    /// `next_run_at` from the NEW cadence (a schedule that becomes weekly must not keep firing on
    /// yesterday's daily window), so this reads the current row first rather than issuing a blind
    /// `UPDATE`.
    pub async fn update(
        &self,
        id: &str,
        update: BudgetResetScheduleUpdate,
        now: DateTime<Utc>,
    ) -> Result<BudgetResetSchedule, BudgetError> {
        let current = self.get(id).await?;

        let name = update.name.unwrap_or(current.name);
        let (scope_kind, scope_id) = update
            .scope
            .unwrap_or((current.scope_kind, current.scope_id));
        let cadence = update.cadence.unwrap_or(current.cadence);
        // An explicit `Some(None)` clears the anchor (daily); an absent field keeps it, EXCEPT
        // when the cadence changed to daily, where the old anchor would violate the DB CHECK.
        let anchor = match update.anchor {
            Some(value) => value,
            None if cadence == Cadence::Daily => None,
            None => current.anchor,
        };
        let run_at_utc = update.run_at_utc.unwrap_or(current.run_at_utc);
        let amount_micros = update.amount_micros.unwrap_or(current.amount_micros);
        let mode = update.mode.unwrap_or(current.mode);
        let enabled = update.enabled.unwrap_or(current.enabled);

        validate_shape(
            &name,
            scope_kind,
            scope_id.as_deref(),
            cadence,
            anchor,
            amount_micros,
            mode,
        )?;

        let timing_changed = cadence != current.cadence
            || anchor != current.anchor
            || run_at_utc != current.run_at_utc;
        let next_run_at = if timing_changed {
            first_window_after(now, cadence, anchor, run_at_utc)?
        } else {
            current.next_run_at
        };

        let row: ScheduleRow = sqlx::query_as(concat!(
            "UPDATE budget_reset_schedules SET ",
            "name = $2, scope_kind = $3, scope_id = $4, cadence = $5, anchor = $6, ",
            "run_at_utc = $7, amount_micros = $8, mode = $9, enabled = $10, next_run_at = $11, ",
            "updated_at = $12 WHERE id = $1 RETURNING ",
            schedule_columns!()
        ))
        .bind(id)
        .bind(name.trim())
        .bind(scope_kind.to_string())
        .bind(scope_id.as_deref())
        .bind(cadence.to_string())
        .bind(anchor)
        .bind(run_at_utc)
        .bind(amount_micros)
        .bind(mode.to_string())
        .bind(enabled)
        .bind(next_run_at)
        .bind(now)
        .fetch_one(self.pool())
        .await
        .map_err(storage_failed)?;

        row.try_into()
    }

    /// Deletes a schedule. Grants it already wrote stay in the ledger forever (ADR-0009) — this
    /// removes the future, never the past.
    pub async fn delete(&self, id: &str) -> Result<(), BudgetError> {
        let affected = sqlx::query("DELETE FROM budget_reset_schedules WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(storage_failed)?
            .rows_affected();

        if affected == 0 {
            return Err(BudgetError::NotFound(format!(
                "budget reset schedule '{id}'"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0)
            .single()
            .expect("valid UTC instant")
    }

    fn midnight() -> NaiveTime {
        NaiveTime::from_hms_opt(0, 0, 0).expect("00:00 is a valid time")
    }

    #[test]
    fn scope_kinds_and_cadences_round_trip() {
        for kind in [
            ScheduleScopeKind::Global,
            ScheduleScopeKind::BillingPlan,
            ScheduleScopeKind::Account,
        ] {
            assert_eq!(kind.to_string().parse::<ScheduleScopeKind>().unwrap(), kind);
        }
        for cadence in [Cadence::Daily, Cadence::Weekly, Cadence::Monthly] {
            assert_eq!(cadence.to_string().parse::<Cadence>().unwrap(), cadence);
        }
        for mode in [ResetMode::Reset, ResetMode::TopUp] {
            assert_eq!(mode.to_string().parse::<ResetMode>().unwrap(), mode);
        }
    }

    #[test]
    fn precedence_is_account_then_plan_then_global() {
        assert!(
            ScheduleScopeKind::Account.specificity() > ScheduleScopeKind::BillingPlan.specificity()
        );
        assert!(
            ScheduleScopeKind::BillingPlan.specificity() > ScheduleScopeKind::Global.specificity()
        );
    }

    #[test]
    fn daily_advances_one_day_when_on_time() {
        let previous = utc(2026, 9, 2, 0, 0);
        let now = utc(2026, 9, 2, 0, 0);
        let next = next_window_after(previous, Cadence::Daily, None, now).unwrap();
        assert_eq!(next, utc(2026, 9, 3, 0, 0));
    }

    /// The anti-drift criterion: the tick woke up 47 seconds late, and the next window is still
    /// exactly midnight, not midnight-plus-47-seconds.
    #[test]
    fn daily_next_window_is_computed_from_the_schedule_not_from_now() {
        let previous = utc(2026, 9, 2, 0, 0);
        let now = utc(2026, 9, 2, 0, 0) + chrono::Duration::seconds(47);
        let next = next_window_after(previous, Cadence::Daily, None, now).unwrap();
        assert_eq!(next, utc(2026, 9, 3, 0, 0));
    }

    /// The catch-up criterion: six missed daily windows collapse into ONE advance to the next
    /// future window, not six fires.
    #[test]
    fn daily_catches_up_to_the_next_future_window_in_one_step() {
        let previous = utc(2026, 9, 2, 0, 0);
        let now = utc(2026, 9, 8, 9, 30);
        let next = next_window_after(previous, Cadence::Daily, None, now).unwrap();
        assert_eq!(next, utc(2026, 9, 9, 0, 0));
    }

    #[test]
    fn weekly_steps_seven_days_and_keeps_the_weekday() {
        // 2026-09-02 is a Wednesday.
        let previous = utc(2026, 9, 2, 6, 30);
        let now = utc(2026, 9, 2, 6, 30);
        let next = next_window_after(previous, Cadence::Weekly, Some(3), now).unwrap();
        assert_eq!(next, utc(2026, 9, 9, 6, 30));
        assert_eq!(next.weekday(), previous.weekday());
    }

    #[test]
    fn weekly_catches_up_across_several_missed_weeks() {
        let previous = utc(2026, 9, 2, 6, 30);
        let now = utc(2026, 9, 30, 0, 0);
        let next = next_window_after(previous, Cadence::Weekly, Some(3), now).unwrap();
        assert_eq!(next, utc(2026, 9, 30, 6, 30));
        assert_eq!(next.weekday(), previous.weekday());
    }

    #[test]
    fn monthly_keeps_the_anchor_day_across_february() {
        let previous = utc(2027, 1, 28, 0, 0);
        let now = utc(2027, 1, 28, 0, 1);
        let next = next_window_after(previous, Cadence::Monthly, Some(28), now).unwrap();
        assert_eq!(next, utc(2027, 2, 28, 0, 0));
        let after = next_window_after(next, Cadence::Monthly, Some(28), next).unwrap();
        assert_eq!(after, utc(2027, 3, 28, 0, 0));
    }

    #[test]
    fn monthly_catches_up_across_a_year_boundary() {
        let previous = utc(2026, 11, 15, 3, 0);
        let now = utc(2027, 2, 20, 0, 0);
        let next = next_window_after(previous, Cadence::Monthly, Some(15), now).unwrap();
        assert_eq!(next, utc(2027, 3, 15, 3, 0));
    }

    #[test]
    fn first_window_is_always_strictly_in_the_future() {
        // Daily, before the run time today.
        let now = utc(2026, 9, 2, 6, 0);
        let run_at = NaiveTime::from_hms_opt(23, 0, 0).unwrap();
        assert_eq!(
            first_window_after(now, Cadence::Daily, None, run_at).unwrap(),
            utc(2026, 9, 2, 23, 0)
        );

        // Daily, exactly at the run time -> tomorrow, never "now".
        let now = utc(2026, 9, 2, 23, 0);
        assert_eq!(
            first_window_after(now, Cadence::Daily, None, run_at).unwrap(),
            utc(2026, 9, 3, 23, 0)
        );

        // Weekly on Monday (ISO 1) from a Wednesday.
        let now = utc(2026, 9, 2, 12, 0);
        assert_eq!(
            first_window_after(now, Cadence::Weekly, Some(1), midnight()).unwrap(),
            utc(2026, 9, 7, 0, 0)
        );

        // Monthly on the 1st from the 2nd -> next month.
        assert_eq!(
            first_window_after(now, Cadence::Monthly, Some(1), midnight()).unwrap(),
            utc(2026, 10, 1, 0, 0)
        );
    }

    #[test]
    fn run_at_utc_round_trips_through_the_wire_form() {
        let time = NaiveTime::from_hms_opt(7, 5, 0).unwrap();
        assert_eq!(render_run_at_utc(time), "07:05");
        assert_eq!(parse_run_at_utc("07:05").unwrap(), time);
        assert_eq!(parse_run_at_utc("07:05:00").unwrap(), time);
        assert!(parse_run_at_utc("noon").is_err());
    }

    #[test]
    fn validate_shape_rejects_mismatched_scope_and_anchor() {
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Global,
                Some("acc"),
                Cadence::Daily,
                None,
                1,
                ResetMode::TopUp
            )
            .is_err()
        );
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Account,
                None,
                Cadence::Daily,
                None,
                1,
                ResetMode::TopUp
            )
            .is_err()
        );
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Global,
                None,
                Cadence::Weekly,
                Some(9),
                1,
                ResetMode::TopUp
            )
            .is_err()
        );
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Global,
                None,
                Cadence::Monthly,
                Some(31),
                1,
                ResetMode::TopUp
            )
            .is_err()
        );
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Global,
                None,
                Cadence::Daily,
                None,
                0,
                ResetMode::TopUp
            )
            .is_err()
        );
        // A `reset` to zero is legitimate: "cut everyone off at midnight".
        assert!(
            validate_shape(
                "s",
                ScheduleScopeKind::Global,
                None,
                Cadence::Daily,
                None,
                0,
                ResetMode::Reset
            )
            .is_ok()
        );
    }
}

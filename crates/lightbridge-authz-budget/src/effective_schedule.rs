//! "Which reset schedule governs this budget account, and what would it reset it to?" — the one
//! answer `getEffectiveResetSchedule` returns, the scheduler's own precedence rule, and (since
//! #697) the amount a brand-new account's starting grant must equal.
//!
//! Extracted from [`crate::reset_scheduler`] because it now has two callers with very different
//! shapes. [`crate::reset_scheduler::ResetScheduler`] holds a [`crate::spend::SpendReader`] it
//! genuinely needs (a reset in `mode: reset` must never grant on unknown spend);
//! [`crate::starting_grant::StartingGrantService`] needs none of that — resolving the winning
//! schedule reads `budget_reset_schedules`, `accounts`, `projects` and `api_keys` and nothing
//! else. Keeping the resolution here means the starting grant cannot end up on a second,
//! subtly-different precedence rule from the tick that has to be a no-op after it.
//!
//! ## Precedence, and the one place it is decided
//!
//! `account > billing_plan > global`, ties broken by "the oldest enabled schedule wins" — which
//! falls out of [`crate::reset_schedule::ResetScheduleRepo::list_enabled`]'s `created_at ASC,
//! name ASC` ordering without a second sort here, because a later candidate only displaces the
//! incumbent on a STRICTLY greater specificity.
//!
//! ## An account's billing plans are derived, not stored
//!
//! There is no `accounts.billing_plan` column. A plan reaches an account through its projects
//! (`projects.billing_plan`) and their API keys (`api_keys.billing_plan`), so an account with
//! neither — every account between `createAccount` and its first project — matches **no**
//! `billing_plan`-scoped schedule at all. That is a real, load-bearing consequence for #697, not
//! an edge case: see [`crate::starting_grant`] for what the starting grant does about it.

use std::collections::{HashMap, HashSet};

use chrono::DateTime;
use chrono::Utc;
use sqlx::{PgPool, Row};

use crate::error::BudgetError;
use crate::reset_schedule::{BudgetResetSchedule, ResetScheduleRepo, ScheduleScopeKind};

/// The winning schedule for one budget account, plus when it next fires — the answer
/// `getEffectiveResetSchedule` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSchedule {
    pub schedule: BudgetResetSchedule,
    pub next_run_at: DateTime<Utc>,
}

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// The most specific ENABLED schedule that covers `budget_account_id`, or `None` when nothing
/// does. Gated at `budget:read`, not `budget:schedule-manage`, so an account's budget card can
/// render "next reset: <date> → $X" without granting the caller the ability to author schedules.
pub async fn effective_schedule(
    pool: &PgPool,
    schedules: &ResetScheduleRepo,
    budget_account_id: &str,
) -> Result<Option<EffectiveSchedule>, BudgetError> {
    let enabled = schedules.list_enabled().await?;
    if enabled.is_empty() {
        return Ok(None);
    }
    let ids = vec![budget_account_id.to_string()];
    let plans = billing_plans_for_accounts(pool, &ids).await?;
    let empty = HashSet::new();
    let account_plans = plans.get(budget_account_id).unwrap_or(&empty);

    Ok(
        winning_schedule(budget_account_id, account_plans, &enabled).map(|schedule| {
            EffectiveSchedule {
                next_run_at: schedule.next_run_at,
                schedule: schedule.clone(),
            }
        }),
    )
}

/// Every billing plan each of `account_ids` touches, through its projects and their API keys.
/// One query for the whole candidate set, not one per account — a `global` schedule over the
/// estate would otherwise issue an N+1 storm just to answer "is a plan schedule more specific
/// than me here".
pub(crate) async fn billing_plans_for_accounts(
    pool: &PgPool,
    account_ids: &[String],
) -> Result<HashMap<String, HashSet<String>>, BudgetError> {
    if account_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let rows = sqlx::query(
        "SELECT p.account_id AS account_id, p.billing_plan AS billing_plan \
         FROM projects p WHERE p.account_id = ANY($1) \
         UNION \
         SELECT p.account_id AS account_id, k.billing_plan AS billing_plan \
         FROM api_keys k JOIN projects p ON p.id = k.project_id \
         WHERE p.account_id = ANY($1)",
    )
    .bind(account_ids)
    .fetch_all(pool)
    .await
    .map_err(storage_failed)?;

    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for row in rows {
        out.entry(row.get::<String, _>("account_id"))
            .or_default()
            .insert(row.get::<String, _>("billing_plan"));
    }
    Ok(out)
}

/// The most specific schedule in `enabled` that matches `account_id`, or `None`.
///
/// `enabled` is expected in `ResetScheduleRepo::list_enabled`'s order (`created_at ASC, name ASC`),
/// which makes the tie-break at equal specificity "the oldest schedule wins" without a second sort
/// here: a later candidate only displaces the incumbent on a STRICTLY greater specificity.
pub(crate) fn winning_schedule<'a>(
    account_id: &str,
    account_plans: &HashSet<String>,
    enabled: &'a [BudgetResetSchedule],
) -> Option<&'a BudgetResetSchedule> {
    let mut best: Option<&BudgetResetSchedule> = None;
    for candidate in enabled {
        let matches = match candidate.scope_kind {
            ScheduleScopeKind::Account => candidate.scope_id.as_deref() == Some(account_id),
            ScheduleScopeKind::BillingPlan => candidate
                .scope_id
                .as_ref()
                .is_some_and(|plan| account_plans.contains(plan)),
            ScheduleScopeKind::Global => true,
        };
        if !matches {
            continue;
        }
        let wins = match best {
            None => true,
            Some(incumbent) => {
                candidate.scope_kind.specificity() > incumbent.scope_kind.specificity()
            }
        };
        if wins {
            best = Some(candidate);
        }
    }
    best
}

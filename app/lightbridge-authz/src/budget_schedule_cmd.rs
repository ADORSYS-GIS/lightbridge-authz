//! `lightbridge-authz budget schedule create|list` — authoring a reset schedule from a Job.
//!
//! ## Why this exists when `createBudgetResetSchedule` already does
//!
//! The same argument [`crate::budget_cmd`] makes about money, applied to the rule that moves it.
//! `createBudgetResetSchedule` and `updateBudgetResetSchedule` are `@allow`-gated on
//! `auth().permBudgetScheduleManage`, a permission that reaches a subject through a platform role
//! on a **human** identity; ADR-0030 is explicit that a `client_credentials` token mints
//! `sub = "svc:<client_id>"`, carries no `roles` claim, and therefore holds zero permissions
//! against every RPC op-id. A Job has no credential that can call either procedure.
//!
//! So this adds a **caller** to [`ResetScheduleRepo`], never a second writer: the same
//! `validate_shape`, the same window derivation
//! ([`lightbridge_authz_budget::reset_schedule_resolve::resolve_next_run_at`]), the same
//! `INSERT`/`UPDATE`. A hand-written `INSERT` would bypass all three and could author a `global`
//! row the DB `CHECK`s happen not to catch.
//!
//! ## The three properties a Job depends on
//!
//! - **Idempotent on `--name`.** `budget_reset_schedules` has no `idempotency_key` column, so the
//!   name is the natural key here. A re-run resolves to the row that already exists rather than
//!   authoring a second schedule that fires against the same accounts on the same tick.
//! - **A disagreeing row is a refusal, not a success.** If a schedule with that name exists but
//!   its scope, cadence, amount or mode differs from the flags, the command exits non-zero naming
//!   the field. "Already done" must mean the same thing was done, or the check is theatre.
//! - **`--dry-run` resolves without writing.** A `global` schedule fires against every account in
//!   the estate; ADR-0032 D8's sequence is author → dry-run → enable, and the row is created
//!   DISABLED by the domain layer regardless of what this command was asked for.

use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_budget::reset_schedule::{
    BudgetResetScheduleUpdate, Cadence, NewBudgetResetSchedule, ResetMode, ResetScheduleRepo,
    ScheduleScopeKind, parse_run_at_utc,
};
use lightbridge_authz_budget::reset_schedule_resolve::resolve_next_run_at;
use lightbridge_authz_core::db::DbPoolTrait;
use lightbridge_authz_core::error::{Error, Result};

use crate::budget_schedule_render::{differences, render, render_resolved};

/// The `budget schedule` operations, decoupled from clap's shape so this module's public API does
/// not depend on how the binary parses its arguments — the arrangement [`crate::budget_cmd`] and
/// `rbac_cmd` already have, and what lets the integration tests call [`dispatch`] directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleAction {
    Create(Box<CreateSchedule>),
    List,
}

/// The flags of `budget schedule create`, still as strings: parsing them is this module's job, and
/// doing it here rather than in clap keeps every refusal message in one place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSchedule {
    pub name: String,
    pub scope: String,
    pub scope_id: Option<String>,
    pub cadence: String,
    pub anchor: Option<i16>,
    pub run_at_utc: String,
    pub amount_micros: i64,
    pub mode: String,
    pub next_run_at: Option<String>,
    pub enable: bool,
    pub dry_run: bool,
}

pub async fn dispatch(
    pool: Arc<dyn DbPoolTrait>,
    action: ScheduleAction,
    now: DateTime<Utc>,
) -> Result<()> {
    let repo = ResetScheduleRepo::new(pool);
    match action {
        ScheduleAction::List => list(&repo).await,
        ScheduleAction::Create(input) => create(&repo, *input, now).await,
    }
}

async fn list(repo: &ResetScheduleRepo) -> Result<()> {
    for schedule in repo.list().await.map_err(server)? {
        println!("{}", render(&schedule));
    }
    Ok(())
}

async fn create(repo: &ResetScheduleRepo, input: CreateSchedule, now: DateTime<Utc>) -> Result<()> {
    let enable = input.enable;
    let dry_run = input.dry_run;
    let wanted = parse(input)?;

    // Resolve first, always — even on the path that will find an existing row. A `--dry-run` that
    // skipped validation would print a row the real write would refuse, which is worse than no
    // dry-run at all.
    let next_run_at = resolve_next_run_at(&wanted, now).map_err(bad_request)?;
    if dry_run {
        println!(
            "would-create {}",
            render_resolved(&wanted, next_run_at, enable)
        );
        return Ok(());
    }

    let existing = repo
        .list()
        .await
        .map_err(server)?
        .into_iter()
        .find(|s| s.name == wanted.name.trim());

    let schedule = match existing {
        Some(found) => {
            let diffs = differences(&found, &wanted);
            if !diffs.is_empty() {
                return Err(Error::BadRequest(format!(
                    "a schedule named '{}' already exists ({}) and disagrees with these flags: \
                     {}; refusing to treat a DIFFERENT schedule as this one having been created",
                    found.name,
                    found.id,
                    diffs.join(", ")
                )));
            }
            println!("exists {}", render(&found));
            found
        }
        None => {
            let created = repo
                .create(wanted, Some(CREATED_BY), now)
                .await
                .map_err(server)?;
            println!("created {}", render(&created));
            created
        }
    };

    if enable && !schedule.enabled {
        let enabled = repo
            .update(
                &schedule.id,
                BudgetResetScheduleUpdate {
                    enabled: Some(true),
                    ..Default::default()
                },
                now,
            )
            .await
            .map_err(server)?;
        println!("enabled {}", render(&enabled));
    }
    Ok(())
}

/// What `created_by` records on a row this command authors. `platform_role_grants` uses NULL for
/// the same situation and `rbac grant` documents why; here a literal is more useful, because the
/// console renders this column and "who configured the estate-wide schedule" has exactly one
/// honest answer that is not a user id.
const CREATED_BY: &str = "cli:budget-schedule-create";

fn parse(input: CreateSchedule) -> Result<NewBudgetResetSchedule> {
    Ok(NewBudgetResetSchedule {
        name: input.name,
        scope_kind: ScheduleScopeKind::from_str(&input.scope).map_err(bad_request)?,
        scope_id: input.scope_id,
        cadence: Cadence::from_str(&input.cadence).map_err(bad_request)?,
        anchor: input.anchor,
        run_at_utc: parse_run_at_utc(&input.run_at_utc).map_err(bad_request)?,
        amount_micros: input.amount_micros,
        mode: ResetMode::from_str(&input.mode).map_err(bad_request)?,
        next_run_at: input
            .next_run_at
            .as_deref()
            .map(parse_instant)
            .transpose()?,
    })
}

fn parse_instant(raw: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|err| {
            Error::BadRequest(format!(
                "--next-run-at {raw} is not an RFC 3339 instant (e.g. 2026-09-07T00:00:00Z): {err}"
            ))
        })
}

fn bad_request(err: lightbridge_authz_budget::error::BudgetError) -> Error {
    Error::BadRequest(err.to_string())
}

fn server(err: lightbridge_authz_budget::error::BudgetError) -> Error {
    Error::Server(err.to_string())
}

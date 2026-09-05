// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests` (clippy.toml) does
// not reach their free helper functions.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! Tests for `lightbridge-authz budget schedule create|list`.
//!
//! This command authors the rule that moves money across an arbitrary number of accounts at once,
//! from an unattended Job. So, exactly as in `budget_cmd_tests`, the tests that matter are the
//! refusals and the idempotency, not the happy path — `ResetScheduleRepo::create` has its own
//! DB-backed suite.
//!
//! What each one defends:
//!
//! - **Created disabled, enabled only when asked.** ADR-0032 D8: a misconfigured `global` schedule
//!   would grant across the whole estate, so the domain layer refuses to create an enabled row and
//!   `--enable` is a separate, explicit `UPDATE`.
//! - **`--dry-run` writes nothing.** The review step is worthless if it has side effects.
//! - **Idempotent on `--name`.** A retried Job must not author a second schedule firing against
//!   the same accounts on the same tick.
//! - **A same-named, different-shaped schedule is a refusal.** "Already done" has to mean the same
//!   thing was done.

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz::budget_schedule_cmd::{CreateSchedule, ScheduleAction, dispatch};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use sqlx::PgPool;

fn pool_of(pool: &PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool.clone()))
}

/// Saturday, two days before the 2026-09-07 tick the live `"Refill $8"` schedule fires on.
fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 5, 12, 0, 0).single().unwrap()
}

/// #702's exact request: global, weekly, ISO weekday 1 (Monday), midnight UTC, `reset` to $8.
fn global_refill(enable: bool, dry_run: bool) -> ScheduleAction {
    ScheduleAction::Create(Box::new(CreateSchedule {
        name: "Global refill $8".to_string(),
        scope: "global".to_string(),
        scope_id: None,
        cadence: "weekly".to_string(),
        anchor: Some(1),
        run_at_utc: "00:00".to_string(),
        amount_micros: 8_000_000,
        mode: "reset".to_string(),
        next_run_at: Some("2026-09-07T00:00:00Z".to_string()),
        enable,
        dry_run,
    }))
}

async fn rows(pool: &PgPool) -> Vec<(String, String, Option<String>, i64, bool, DateTime<Utc>)> {
    sqlx::query_as(
        "SELECT id, name, scope_id, amount_micros, enabled, next_run_at \
         FROM budget_reset_schedules ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_dry_run_writes_nothing(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(true, true), now())
        .await
        .expect("a dry run of a valid schedule must succeed");

    assert!(
        rows(&pool).await.is_empty(),
        "--dry-run must not author a row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_with_enable_authors_an_enabled_schedule_on_the_forced_window(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(true, false), now())
        .await
        .expect("creating the global schedule must succeed");

    let rows = rows(&pool).await;
    assert_eq!(rows.len(), 1);
    let (_, name, scope_id, amount, enabled, next_run_at) = &rows[0];
    assert_eq!(name, "Global refill $8");
    assert_eq!(*scope_id, None, "a global schedule carries no scope_id");
    assert_eq!(*amount, 8_000_000);
    assert!(
        *enabled,
        "--enable must flip the row the domain created off"
    );
    assert_eq!(
        *next_run_at,
        Utc.with_ymd_and_hms(2026, 9, 7, 0, 0, 0).single().unwrap(),
        "the forced window must be stored verbatim, so the global schedule fires on the same \
         tick as the free-plan one"
    );
}

/// Without `--enable` the row exists and is inert — ADR-0032 D8's "authored, dry-run, then
/// enabled" sequence, pinned so nobody makes `create` enable by default.
#[sqlx::test(migrations = "../../migrations")]
async fn create_without_enable_leaves_the_schedule_disabled(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(false, false), now())
        .await
        .expect("creating a disabled schedule must succeed");

    let rows = rows(&pool).await;
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].4, "a schedule is always created disabled");
}

/// The property a retried Job depends on: same name twice leaves ONE schedule.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rerun_with_the_same_name_is_a_no_op(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(true, false), now())
        .await
        .expect("first run");
    let first = rows(&pool).await;

    dispatch(pool_of(&pool), global_refill(true, false), now())
        .await
        .expect("a replay must succeed, not error");
    let second = rows(&pool).await;

    assert_eq!(
        second.len(),
        1,
        "a replay must not author a second schedule"
    );
    assert_eq!(first, second, "a replay must change nothing at all");
}

/// A re-run whose flags disagree with the stored row is the dangerous case: silently accepting it
/// would report success while the estate runs on a schedule nobody asked for.
#[sqlx::test(migrations = "../../migrations")]
async fn a_same_named_schedule_with_a_different_amount_is_refused(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(true, false), now())
        .await
        .expect("first run");

    let ScheduleAction::Create(mut changed) = global_refill(true, false) else {
        unreachable!("global_refill builds a Create")
    };
    changed.amount_micros = 15_000_000;

    let err = dispatch(pool_of(&pool), ScheduleAction::Create(changed), now())
        .await
        .expect_err("a disagreeing re-run must be refused");
    let message = err.to_string();
    assert!(
        message.contains("amount_micros is 8000000, wanted 15000000"),
        "the refusal must name the disagreeing field and both values, got: {message}"
    );
    assert_eq!(
        rows(&pool).await[0].3,
        8_000_000,
        "nothing may be rewritten"
    );
}

/// The shape check runs before the window is computed and before anything is written, so a
/// malformed `global` invocation cannot leave a half-authored row behind.
#[sqlx::test(migrations = "../../migrations")]
async fn a_global_schedule_carrying_a_scope_id_is_refused(pool: PgPool) {
    let ScheduleAction::Create(mut bad) = global_refill(true, false) else {
        unreachable!("global_refill builds a Create")
    };
    bad.scope_id = Some("free".to_string());

    let err = dispatch(pool_of(&pool), ScheduleAction::Create(bad), now())
        .await
        .expect_err("a global schedule with a scopeId must be refused");
    assert!(err.to_string().contains("must not carry a scopeId"));
    assert!(rows(&pool).await.is_empty());
}

/// A forced window in the past would fire on the very next 60-second tick, across the whole
/// estate, before anyone had read the row.
#[sqlx::test(migrations = "../../migrations")]
async fn a_backdated_forced_window_is_refused(pool: PgPool) {
    let past = Utc
        .with_ymd_and_hms(2026, 9, 14, 12, 0, 0)
        .single()
        .unwrap();

    let err = dispatch(pool_of(&pool), global_refill(true, false), past)
        .await
        .expect_err("a window already in the past must be refused");
    assert!(err.to_string().contains("must be in the future"));
    assert!(rows(&pool).await.is_empty());
}

#[sqlx::test(migrations = "../../migrations")]
async fn list_reads_without_writing(pool: PgPool) {
    dispatch(pool_of(&pool), global_refill(true, false), now())
        .await
        .expect("first run");
    let before = rows(&pool).await;

    dispatch(pool_of(&pool), ScheduleAction::List, now())
        .await
        .expect("listing must succeed");

    assert_eq!(rows(&pool).await, before);
}

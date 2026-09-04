#![cfg(feature = "it-tests")]
//! `budget_remaining_snapshots` against a real Postgres — ADR-0034 §15.
//!
//! The properties under test are the ones whose wrong answer is a `402` for an account that has
//! money: a row with no reading must read back as UNKNOWN (never zero), a stored reading must be
//! refused once the period rolls over, a spend outage must KEEP the previous reading, and a booked
//! grant must move the reading inside the grant's own transaction so a refill is visible without
//! waiting for a refresher tick.

use std::sync::Arc;

use chrono::{Duration, Utc};
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::snapshot::{BudgetSnapshotReader, SnapshotRefreshConfig};
use lightbridge_authz_budget::snapshot_store::SnapshotStore;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

fn period() -> Period {
    Period::current(Utc::now())
}

async fn account(pool: &PgPool) -> String {
    let id = cuid2();
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
    id
}

fn store(pool: &PgPool) -> SnapshotStore {
    SnapshotStore::new(Arc::new(DbPool::from_pool(pool.clone())))
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_untouched_account_has_no_row_at_all(pool: PgPool) {
    let id = account(&pool).await;
    assert_eq!(
        store(&pool).read(&id).await.expect("read must succeed"),
        None,
        "no request has ever asked about this account, so there is nothing to read"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_touched_account_reads_back_as_unknown_never_zero(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");

    let snapshot = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("the touch must have created the row");

    assert_eq!(
        snapshot.remaining_micros, None,
        "a seen-but-not-yet-computed account must read UNKNOWN -- a zero here reaches the gateway \
         as 402 budget_exhausted for an account that may be fully funded"
    );
    assert_eq!(snapshot.remaining_for(&period()), None);
    assert_eq!(snapshot.age_seconds(Utc::now()), None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stored_reading_reads_back_with_an_age(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");
    let reset_at = Utc::now() + Duration::days(7);
    store
        .store_reading(&id, &period(), 24_000_000, 3_210_000, reset_at)
        .await
        .expect("storing a reading must succeed");

    let snapshot = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("the row must exist");

    assert_eq!(snapshot.remaining_for(&period()), Some(20_790_000));
    assert_eq!(snapshot.ceiling_micros, Some(24_000_000));
    assert_eq!(snapshot.spent_micros, Some(3_210_000));
    assert!(
        snapshot.age_seconds(Utc::now()).is_some(),
        "a stored reading always carries a refreshed_at, so its age is always reportable"
    );
    assert_eq!(snapshot.stale_since, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reading_from_another_period_is_refused_not_served(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");
    let last_month = period().previous();
    store
        .store_reading(&id, &last_month, 24_000_000, 0, Utc::now())
        .await
        .expect("storing a reading must succeed");

    let snapshot = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("the row must exist");

    assert_eq!(snapshot.remaining_for(&last_month), Some(24_000_000));
    assert_eq!(
        snapshot.remaining_for(&period()),
        None,
        "at a month boundary every stored reading describes LAST month; serving it would hand the \
         fleet a balance it has already spent"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn marking_stale_keeps_the_previous_reading(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");
    store
        .store_reading(&id, &period(), 24_000_000, 4_000_000, Utc::now())
        .await
        .expect("storing a reading must succeed");

    store
        .mark_stale(&id)
        .await
        .expect("mark_stale must succeed");
    let first = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("row must exist");
    assert_eq!(
        first.remaining_for(&period()),
        Some(20_000_000),
        "a spend-source outage must never erase a known balance"
    );
    let started = first.stale_since.expect("stale_since must be stamped");

    store
        .mark_stale(&id)
        .await
        .expect("a second mark_stale must succeed");
    let second = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("row must exist");
    assert_eq!(
        second.stale_since,
        Some(started),
        "stale_since records when the outage STARTED, not when it was last noticed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_booked_grant_moves_the_snapshot_in_the_same_transaction(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");
    store
        .store_reading(&id, &period(), 10_000_000, 4_000_000, Utc::now())
        .await
        .expect("storing a reading must succeed");

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    repo.grant(GrantRequest {
        budget_account_id: id.clone(),
        account_id: id.clone(),
        project_id: None,
        period: period(),
        amount_micros: 5_000_000,
        source: GrantSource::SelfService,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    })
    .await
    .expect("the grant must succeed");

    let snapshot = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("row must exist");
    assert_eq!(
        snapshot.remaining_for(&period()),
        Some(11_000_000),
        "a refill must be visible on the very next request, not one refresher tick later"
    );
    assert_eq!(snapshot.ceiling_micros, Some(15_000_000));
    assert_eq!(
        snapshot.spent_micros,
        Some(4_000_000),
        "a grant moves the ceiling and never the spend"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_grant_against_an_account_with_no_reading_fabricates_nothing(pool: PgPool) {
    let id = account(&pool).await;
    let store = store(&pool);
    store.touch(&id).await.expect("touch must succeed");

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    repo.grant(GrantRequest {
        budget_account_id: id.clone(),
        account_id: id.clone(),
        project_id: None,
        period: period(),
        amount_micros: 5_000_000,
        source: GrantSource::Admin,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    })
    .await
    .expect("the grant must succeed");

    let snapshot = store
        .read(&id)
        .await
        .expect("read must succeed")
        .expect("row must exist");
    assert_eq!(
        snapshot.remaining_micros, None,
        "there was no reading to move, and a delta is not a balance -- the refresher computes the \
         first reading, this path never invents one"
    );
}

/// The work list is bounded by `active_window` — the OUTER bound since ADR-0034 §15.6, which is
/// what an account has to fall past before it stops being refreshed at all. Both accounts here
/// carry no reading, so both are due in whichever lane they land in; the one an hour outside a
/// ten-minute window is the only one excluded.
#[sqlx::test(migrations = "../../migrations")]
async fn the_active_set_is_bounded_by_recency_and_ordered_oldest_reading_first(pool: PgPool) {
    let store = store(&pool);
    let stale_account = account(&pool).await;
    let fresh_account = account(&pool).await;
    store.touch(&stale_account).await.expect("touch");
    store.touch(&fresh_account).await.expect("touch");

    // Push one account's `last_seen_at` outside any plausible active window.
    sqlx::query("UPDATE budget_remaining_snapshots SET last_seen_at = now() - interval '1 hour' WHERE budget_account_id = $1")
        .bind(&stale_account)
        .execute(&pool)
        .await
        .expect("backdating last_seen_at must succeed");

    let config = SnapshotRefreshConfig {
        active_window: std::time::Duration::from_secs(600),
        ..SnapshotRefreshConfig::default()
    };
    let active = store
        .due_accounts(Utc::now(), &config)
        .await
        .expect("due_accounts must succeed");

    assert_eq!(
        active,
        vec![fresh_account],
        "the work list is exactly the accounts the request path has asked about recently"
    );
}

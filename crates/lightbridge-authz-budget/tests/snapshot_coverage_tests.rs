#![cfg(feature = "it-tests")]
//! Snapshot COVERAGE — ADR-0034 §15.6, against a real Postgres.
//!
//! ## The gap these model
//!
//! §15 created a snapshot row lazily, from the introspection's touch, and refreshed only accounts
//! seen inside a ten-minute window. The Stage 1b rollout watch (ai-helm-values#390/#391) measured
//! what that produces in production: **23 snapshot rows against 43 accounts with usage in the last
//! 30 days** — every one of the other 20 reading `known: false` at the gateway, i.e. a permanent
//! fail-open under enforcement and noise in the decision table under shadow.
//!
//! The first test here is that estate in miniature: an account that has a budget grant and a used
//! API key, and has not sent a request since the table existed. Before §15.6 a tick left it with no
//! row at all; the assertion below is that a tick now gives it a reading without anyone having
//! introspected it.
//!
//! The rest pin the three properties that make that hold rather than accidentally pass: the slow
//! lane (an idle account is demoted, never dropped), the slow lane's cadence (it does not become a
//! second fast lane), and the seed's idempotence (it must not stamp `last_seen_at` on a live row,
//! which would pin every account in the fast lane forever).

use std::sync::Arc;

use chrono::Utc;
use lightbridge_authz_budget::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::reset_scheduler::ResetScheduler;
use lightbridge_authz_budget::snapshot::{BudgetSnapshotReader, SnapshotRefreshConfig};
use lightbridge_authz_budget::snapshot_refresher::SnapshotRefresher;
use lightbridge_authz_budget::snapshot_store::SnapshotStore;
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_budget::spend::{Spend, SpendObservation, SpendReader};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

fn period() -> Period {
    Period::current(Utc::now())
}

fn config() -> SnapshotRefreshConfig {
    SnapshotRefreshConfig::default()
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

/// An account with a booked grant this period — the first arm of the seed predicate ("has a budget
/// row"), and the shape of every funded account in the estate.
async fn funded_account(pool: &PgPool, repo: &BudgetRepo, ceiling_micros: i64) -> String {
    let id = account(pool).await;
    repo.grant(GrantRequest {
        budget_account_id: id.clone(),
        account_id: id.clone(),
        project_id: None,
        period: period(),
        amount_micros: ceiling_micros,
        source: GrantSource::Base,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    })
    .await
    .expect("booking a base grant must succeed");
    id
}

/// An account with no grant at all but an active API key used `used_days_ago` ago — the second arm
/// of the seed predicate ("can send metered traffic"). This is the account §15 could never cover
/// until it happened to make a request.
async fn keyed_account(pool: &PgPool, used_days_ago: i64) -> String {
    let id = account(pool).await;
    let project_id = cuid2();
    sqlx::query(
        "INSERT INTO projects (id, account_id, name, billing_plan, billing_identity) \
         VALUES ($1, $2, 'seed-test', 'free', $2)",
    )
    .bind(&project_id)
    .bind(&id)
    .execute(pool)
    .await
    .expect("inserting a test project must succeed");
    sqlx::query(
        "INSERT INTO api_keys \
           (id, project_id, name, key_prefix, key_hash, expires_at, status, billing_plan, \
            owner_account_id, last_used_at) \
         VALUES ($1, $2, 'seed-test', 'lb_seed', $1, now() + interval '30 days', 'active', 'free', \
                 $3, now() - ($4 || ' days')::interval)",
    )
    .bind(cuid2())
    .bind(&project_id)
    .bind(&id)
    .bind(used_days_ago.to_string())
    .execute(pool)
    .await
    .expect("inserting a test api key must succeed");
    id
}

fn build(
    pool: &PgPool,
    spend: Arc<dyn SpendReader>,
    config: SnapshotRefreshConfig,
) -> (SnapshotStore, Arc<BudgetRepo>, SnapshotRefresher) {
    let db = Arc::new(DbPool::from_pool(pool.clone()));
    let store = SnapshotStore::new(db.clone());
    let repo = Arc::new(BudgetRepo::new(db.clone()));
    let scheduler = Arc::new(ResetScheduler::new(db, repo.clone(), spend.clone()));
    (
        store.clone(),
        repo.clone(),
        SnapshotRefresher::new(store, repo, spend, scheduler, config),
    )
}

async fn backdate_last_seen(pool: &PgPool, account_id: &str, minutes: i64) {
    sqlx::query(
        "UPDATE budget_remaining_snapshots SET last_seen_at = now() - ($2 || ' minutes')::interval \
         WHERE budget_account_id = $1",
    )
    .bind(account_id)
    .bind(minutes.to_string())
    .execute(pool)
    .await
    .expect("backdating last_seen_at must succeed");
}

/// **The regression this whole change exists for.** An account that is funded and holds a used API
/// key, and that the request path has never touched, must end a tick with a usable reading.
///
/// Before §15.6 this failed at the first `expect`: no introspection ever ran for this account, so
/// nothing created its row, so `active_accounts` never saw it and `read` returned `None`. That is
/// the production shape — 20 of 43 accounts with recent usage sitting at `known: false` forever.
#[sqlx::test(migrations = "../../migrations")]
async fn a_tick_seeds_and_computes_an_account_that_never_sent_a_request(pool: PgPool) {
    let (store, repo, refresher) = build(&pool, Arc::new(FixedSpend(4_000_000)), config());
    let funded = funded_account(&pool, &repo, 24_000_000).await;
    let keyed = keyed_account(&pool, 2).await;

    assert!(
        store.read(&funded).await.expect("read").is_none(),
        "the fixture must start with no row -- otherwise this test proves nothing"
    );

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert!(report.ran);
    assert_eq!(report.seeded, 2, "both accounts must be seeded by the tick");

    let snapshot = store
        .read(&funded)
        .await
        .expect("read")
        .expect("the seed must have created a row for a funded account nobody introspected");
    assert_eq!(
        snapshot.remaining_for(&period()),
        Some(20_000_000),
        "24 USD granted minus 4 USD spent, in micro-USD -- a usable reading, not a NULL"
    );

    assert!(
        store
            .read(&keyed)
            .await
            .expect("read")
            .expect("an account with a used, active API key can send traffic and must be covered")
            .remaining_for(&period())
            .is_some(),
        "coverage is about accounts that CAN send traffic, not only funded ones"
    );

    assert_eq!(
        report.coverage.uncovered_total, 0,
        "the census must agree with the rows: nothing eligible left unknown"
    );
    assert_eq!(report.coverage.accounts_total, 2);
    assert_eq!(report.coverage.known_total, 2);
}

/// The census is the number the runbook cites, so it must count the gap even when the refresher has
/// been told not to close it. With `seed_lookback_days: 0` nothing is eligible and nothing is
/// seeded; with the real lookback the same estate reports two uncovered accounts before the tick
/// that fixes them.
#[sqlx::test(migrations = "../../migrations")]
async fn the_census_counts_an_eligible_account_with_no_row_as_uncovered(pool: PgPool) {
    let db = Arc::new(DbPool::from_pool(pool.clone()));
    let store = SnapshotStore::new(db.clone());
    let repo = BudgetRepo::new(db);
    funded_account(&pool, &repo, 10_000_000).await;
    keyed_account(&pool, 1).await;

    let counts = store
        .coverage(&period(), Utc::now() - chrono::Duration::days(30))
        .await
        .expect("census must succeed");
    assert_eq!(
        (counts.accounts_total, counts.uncovered_total),
        (0, 2),
        "no rows exist yet, and both accounts can send traffic -- that is a coverage gap of two"
    );
}

/// §15 dropped an account from the work list ten minutes after its last request, freezing its
/// reading there. §15.6 demotes it instead: still refreshed, just less often.
#[sqlx::test(migrations = "../../migrations")]
async fn an_idle_account_is_demoted_to_the_slow_lane_not_dropped(pool: PgPool) {
    let (store, repo, refresher) = build(&pool, Arc::new(FixedSpend(1_000_000)), config());
    let id = funded_account(&pool, &repo, 9_000_000).await;
    store.touch(&id).await.expect("touch");
    backdate_last_seen(&pool, &id, 45).await;

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!(
        (report.considered, report.refreshed),
        (1, 1),
        "45 minutes idle is outside the old ten-minute window and well inside the 24-hour one"
    );
    assert_eq!(
        store
            .read(&id)
            .await
            .expect("read")
            .expect("row")
            .remaining_for(&period()),
        Some(8_000_000)
    );
}

/// The slow lane must actually be slow: an idle account whose reading is younger than
/// `slow_lane_interval` is not recomputed again on the next tick. Without this the "demotion" would
/// be a rename of the fast lane and the spend-query load would scale with the whole estate.
#[sqlx::test(migrations = "../../migrations")]
async fn the_slow_lane_skips_an_idle_account_whose_reading_is_still_young(pool: PgPool) {
    let (store, repo, refresher) = build(&pool, Arc::new(FixedSpend(1_000_000)), config());
    let id = funded_account(&pool, &repo, 9_000_000).await;
    store.touch(&id).await.expect("touch");
    backdate_last_seen(&pool, &id, 45).await;

    refresher
        .tick(Utc::now())
        .await
        .expect("the first tick must succeed");
    let second = refresher
        .tick(Utc::now())
        .await
        .expect("the second tick must succeed");
    assert_eq!(
        (second.considered, second.refreshed),
        (0, 0),
        "the reading is seconds old and the account is idle -- it is not due again for ten minutes"
    );
}

/// `last_seen_at` means "when the request path last asked", and the fast/slow split reads it. A
/// seed that stamped `now()` on every tick would pin every seeded account in the fast lane forever
/// and make both windows meaningless.
#[sqlx::test(migrations = "../../migrations")]
async fn the_seed_does_not_move_last_seen_at_on_a_row_inside_the_active_window(pool: PgPool) {
    let (store, repo, refresher) = build(&pool, Arc::new(FixedSpend(0)), config());
    let id = funded_account(&pool, &repo, 5_000_000).await;
    store.touch(&id).await.expect("touch");
    backdate_last_seen(&pool, &id, 45).await;
    let before = store
        .read(&id)
        .await
        .expect("read")
        .expect("row")
        .last_seen_at;

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!(report.seeded, 0, "an in-window row must not be re-armed");
    assert_eq!(
        store
            .read(&id)
            .await
            .expect("read")
            .expect("row")
            .last_seen_at,
        before,
        "the seed must leave a live row's recency exactly as the request path wrote it"
    );
}

/// An account that has aged out of the active window entirely, but still qualifies, is put back —
/// otherwise a 24-hour window is just a slower version of the ten-minute one, and the account is
/// frozen at whatever the month boundary does to it next.
#[sqlx::test(migrations = "../../migrations")]
async fn the_seed_rearms_an_eligible_account_that_aged_out_of_the_window(pool: PgPool) {
    let (store, repo, refresher) = build(&pool, Arc::new(FixedSpend(2_000_000)), config());
    let id = funded_account(&pool, &repo, 12_000_000).await;
    store.touch(&id).await.expect("touch");
    backdate_last_seen(&pool, &id, 3 * 24 * 60).await;

    let report = refresher.tick(Utc::now()).await.expect("tick must succeed");
    assert_eq!(
        report.seeded, 1,
        "a lapsed but still-eligible account is re-armed"
    );
    assert_eq!((report.considered, report.refreshed), (1, 1));
    assert_eq!(report.coverage.uncovered_total, 0);
}

#[derive(Debug)]
struct FixedSpend(i64);

#[lightbridge_authz_core::async_trait]
impl SpendReader for FixedSpend {
    async fn spend_for_account(
        &self,
        _budget_account_id: &str,
        _period: &Period,
    ) -> Result<Spend, BudgetError> {
        Ok(Spend::Known(self.0))
    }

    async fn observe_spend_for_account(
        &self,
        _budget_account_id: &str,
        _period: &Period,
    ) -> Result<SpendObservation, BudgetError> {
        Ok(SpendObservation::Answered(self.0))
    }
}

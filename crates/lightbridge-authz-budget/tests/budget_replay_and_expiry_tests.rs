#![cfg(feature = "it-tests")]

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, DerivedBalance, GrantRequest};
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const PERIOD_A: &str = "2026-08";
const PERIOD_B: &str = "2026-09";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

fn request(
    account_id: &str,
    period: &str,
    source: GrantSource,
    amount_micros: i64,
) -> GrantRequest {
    GrantRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(period).expect("valid period"),
        amount_micros,
        source,
        actor_id: None,
        reason: None,
        policy_revision: None,
        matched_rule_ids: None,
        idempotency_key: None,
        trigger_key: None,
        expires_at: None,
    }
}

#[derive(Debug, sqlx::FromRow, PartialEq)]
struct RawBalanceRow {
    budget_account_id: String,
    period: String,
    base_total_micros: i64,
    self_service_total_micros: i64,
    admin_total_micros: i64,
    automatic_total_micros: i64,
    refund_total_micros: i64,
    effective_budget_micros: i64,
    self_service_grant_count: i32,
    automatic_grant_count: i32,
}

async fn fetch_raw_balance(pool: &PgPool, account_id: &str, period: &str) -> RawBalanceRow {
    sqlx::query_as(
        "SELECT budget_account_id, period, base_total_micros, self_service_total_micros, \
         admin_total_micros, automatic_total_micros, refund_total_micros, \
         effective_budget_micros, self_service_grant_count, automatic_grant_count \
         FROM budget_balances WHERE budget_account_id = $1 AND period = $2",
    )
    .bind(account_id)
    .bind(period)
    .fetch_one(pool)
    .await
    .expect("balance row must exist")
}

fn assert_derived_matches_raw(derived: &DerivedBalance, raw: &RawBalanceRow) {
    assert_eq!(derived.budget_account_id, raw.budget_account_id);
    assert_eq!(derived.period, raw.period);
    assert_eq!(derived.base_total_micros, raw.base_total_micros);
    assert_eq!(
        derived.self_service_total_micros,
        raw.self_service_total_micros
    );
    assert_eq!(derived.admin_total_micros, raw.admin_total_micros);
    assert_eq!(derived.automatic_total_micros, raw.automatic_total_micros);
    assert_eq!(derived.refund_total_micros, raw.refund_total_micros);
    assert_eq!(derived.effective_budget_micros, raw.effective_budget_micros);
    assert_eq!(
        derived.self_service_grant_count,
        raw.self_service_grant_count
    );
    assert_eq!(derived.automatic_grant_count, raw.automatic_grant_count);
}

#[sqlx::test(migrations = "../../migrations")]
async fn replaying_the_ledger_reproduces_live_balances_exactly(pool: PgPool) {
    let account_a = cuid2();
    let account_b = cuid2();
    insert_account(&pool, &account_a).await;
    insert_account(&pool, &account_b).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    repo.grant(request(
        &account_a,
        PERIOD_A,
        GrantSource::SelfService,
        15_000_000,
    ))
    .await
    .expect("self_service grant must succeed");
    repo.grant(request(
        &account_a,
        PERIOD_A,
        GrantSource::Admin,
        30_000_000,
    ))
    .await
    .expect("admin grant must succeed");
    repo.grant(request(
        &account_a,
        PERIOD_A,
        GrantSource::Correction,
        -5_000_000,
    ))
    .await
    .expect("correction must succeed");

    repo.grant(request(
        &account_b,
        PERIOD_B,
        GrantSource::Automatic,
        7_000_000,
    ))
    .await
    .expect("automatic grant must succeed");
    repo.grant(request(
        &account_b,
        PERIOD_B,
        GrantSource::Refund,
        2_000_000,
    ))
    .await
    .expect("refund grant must succeed");

    let derived_balances = repo
        .rebuild_all_balances()
        .await
        .expect("rebuild_all_balances must succeed");

    let derived_a = derived_balances
        .iter()
        .find(|b| b.budget_account_id == account_a && b.period == PERIOD_A)
        .expect("derived balance for account A must exist");
    let derived_b = derived_balances
        .iter()
        .find(|b| b.budget_account_id == account_b && b.period == PERIOD_B)
        .expect("derived balance for account B must exist");

    let raw_a = fetch_raw_balance(&pool, &account_a, PERIOD_A).await;
    let raw_b = fetch_raw_balance(&pool, &account_b, PERIOD_B).await;

    assert_derived_matches_raw(derived_a, &raw_a);
    assert_derived_matches_raw(derived_b, &raw_b);
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_grant_excluded_from_effective_balance_without_mutating_the_row(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    let past_expiry: DateTime<Utc> = "2020-01-01T00:00:00Z".parse().expect("valid timestamp");
    let mut req = request(&account_id, PERIOD_A, GrantSource::SelfService, 15_000_000);
    req.expires_at = Some(past_expiry);

    repo.grant(req)
        .await
        .expect("grant with past expiry must still succeed to insert");

    let raw_before = fetch_raw_balance(&pool, &account_id, PERIOD_A).await;
    assert_eq!(
        raw_before.effective_budget_micros, 15_000_000,
        "the raw stored projection must still reflect the full amount, expiry-unaware"
    );

    let as_of: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().expect("valid timestamp");
    let period = Period::parse(PERIOD_A).expect("valid period");
    let effective = repo
        .effective_balance(&account_id, &period, as_of)
        .await
        .expect("effective_balance must succeed");

    assert_eq!(
        effective, 0,
        "an expired grant must not count toward the effective balance"
    );

    let raw_after = fetch_raw_balance(&pool, &account_id, PERIOD_A).await;
    assert_eq!(
        raw_before, raw_after,
        "calling effective_balance must not mutate the stored budget_balances row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn not_yet_expired_grant_still_counts(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    let future_expiry: DateTime<Utc> = "2027-01-01T00:00:00Z".parse().expect("valid timestamp");
    let mut req = request(&account_id, PERIOD_A, GrantSource::SelfService, 15_000_000);
    req.expires_at = Some(future_expiry);

    repo.grant(req)
        .await
        .expect("grant with future expiry must succeed");

    let as_of: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().expect("valid timestamp");
    let period = Period::parse(PERIOD_A).expect("valid period");
    let effective = repo
        .effective_balance(&account_id, &period, as_of)
        .await
        .expect("effective_balance must succeed");

    assert_eq!(
        effective, 15_000_000,
        "a grant that has not yet expired as of the query time must still count"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn revoked_at_insert_grant_excluded_from_effective_balance(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    repo.grant(request(
        &account_id,
        PERIOD_A,
        GrantSource::SelfService,
        10_000_000,
    ))
    .await
    .expect("ordinary grant must succeed");

    sqlx::query(
        "INSERT INTO budget_grants \
         (id, budget_account_id, account_id, project_id, period, amount_micros, source, \
          revoked_at) \
         VALUES ($1, $2, $2, NULL, $3, $4, 'migration', now())",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD_A)
    .bind(20_000_000_i64)
    .execute(&pool)
    .await
    .expect("inserting a revoked-at-insert row directly must succeed");

    let as_of: DateTime<Utc> = Utc::now();
    let period = Period::parse(PERIOD_A).expect("valid period");
    let effective = repo
        .effective_balance(&account_id, &period, as_of)
        .await
        .expect("effective_balance must succeed");

    assert_eq!(
        effective, 10_000_000,
        "a grant with revoked_at set at insert time must be excluded from the effective balance"
    );
}

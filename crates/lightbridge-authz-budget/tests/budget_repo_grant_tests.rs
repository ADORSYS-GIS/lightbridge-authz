#![cfg(feature = "it-tests")]

use std::sync::Arc;

use lightbridge_authz_budget::error::BudgetError;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::{BudgetRepo, GrantRequest};
use lightbridge_authz_budget::source::GrantSource;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const PERIOD: &str = "2026-08";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

fn base_request(account_id: &str, source: GrantSource, amount_micros: i64) -> GrantRequest {
    GrantRequest {
        budget_account_id: account_id.to_string(),
        account_id: account_id.to_string(),
        project_id: None,
        period: Period::parse(PERIOD).expect("valid period"),
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

async fn fetch_balance_row(
    pool: &PgPool,
    account_id: &str,
) -> (i64, i64, i64, i64, i64, i64, i32, i32, i64) {
    sqlx::query_as(
        "SELECT base_total_micros, self_service_total_micros, admin_total_micros, \
         automatic_total_micros, refund_total_micros, effective_budget_micros, \
         self_service_grant_count, automatic_grant_count, version \
         FROM budget_balances WHERE budget_account_id = $1 AND period = $2",
    )
    .bind(account_id)
    .bind(PERIOD)
    .fetch_one(pool)
    .await
    .expect("balance row must exist after a grant")
}

#[sqlx::test(migrations = "../../migrations")]
async fn first_grant_creates_balance_and_updates_it(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    let request = base_request(&account_id, GrantSource::SelfService, 15_000_000);

    let grant = repo
        .grant(request)
        .await
        .expect("first grant for a new account+period must succeed");

    assert_eq!(grant.budget_account_id, account_id);
    assert_eq!(grant.account_id, account_id);
    assert_eq!(grant.amount_micros, 15_000_000);
    assert_eq!(grant.source, GrantSource::SelfService);
    assert_eq!(grant.period, Period::parse(PERIOD).expect("valid period"));

    let (
        base,
        self_service,
        admin,
        automatic,
        refund,
        effective,
        self_service_count,
        automatic_count,
        version,
    ) = fetch_balance_row(&pool, &account_id).await;

    assert_eq!(base, 0);
    assert_eq!(self_service, 15_000_000);
    assert_eq!(admin, 0);
    assert_eq!(automatic, 0);
    assert_eq!(refund, 0);
    assert_eq!(effective, 15_000_000);
    assert_eq!(self_service_count, 1);
    assert_eq!(automatic_count, 0);
    assert_eq!(version, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn second_grant_same_period_accumulates(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    repo.grant(base_request(
        &account_id,
        GrantSource::SelfService,
        15_000_000,
    ))
    .await
    .expect("self_service grant must succeed");
    repo.grant(base_request(&account_id, GrantSource::Admin, 30_000_000))
        .await
        .expect("admin grant must succeed");

    let (
        _base,
        self_service,
        admin,
        _automatic,
        _refund,
        effective,
        self_service_count,
        automatic_count,
        version,
    ) = fetch_balance_row(&pool, &account_id).await;

    assert_eq!(self_service, 15_000_000);
    assert_eq!(admin, 30_000_000);
    assert_eq!(effective, 45_000_000);
    assert_eq!(self_service_count, 1);
    assert_eq!(automatic_count, 0);
    assert_eq!(version, 2);
}

#[sqlx::test(migrations = "../../migrations")]
async fn correction_adjusts_effective_only(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));

    repo.grant(base_request(
        &account_id,
        GrantSource::SelfService,
        15_000_000,
    ))
    .await
    .expect("self_service grant must succeed");
    repo.grant(base_request(
        &account_id,
        GrantSource::Correction,
        -5_000_000,
    ))
    .await
    .expect("negative correction must succeed");

    let (
        _base,
        self_service,
        _admin,
        _automatic,
        _refund,
        effective,
        self_service_count,
        _automatic_count,
        _version,
    ) = fetch_balance_row(&pool, &account_id).await;

    assert_eq!(
        self_service, 15_000_000,
        "a correction must not touch the self_service bucket"
    );
    assert_eq!(
        effective, 10_000_000,
        "effective_budget_micros must reflect the correction"
    );
    assert_eq!(
        self_service_count, 1,
        "a correction is not itself a self-service grant"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn idempotency_key_replay_returns_original_and_does_not_double_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool.clone())));
    let idempotency_key = cuid2();

    let mut request = base_request(&account_id, GrantSource::SelfService, 15_000_000);
    request.idempotency_key = Some(idempotency_key.clone());

    let first = repo
        .grant(request.clone())
        .await
        .expect("first grant must succeed");
    let second = repo
        .grant(request)
        .await
        .expect("replayed grant must succeed and return the original");

    assert_eq!(first.id, second.id);

    let (_base, _self_service, _admin, _automatic, _refund, effective, _sc, _ac, _version) =
        fetch_balance_row(&pool, &account_id).await;
    assert_eq!(
        effective, 15_000_000,
        "a replayed idempotency key must not double-count the balance"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_grants_with_same_idempotency_key_produce_exactly_one_grant(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let db_pool = Arc::new(DbPool::from_pool(pool.clone()));
    let repo_a = BudgetRepo::new(db_pool.clone());
    let repo_b = BudgetRepo::new(db_pool);

    let idempotency_key = cuid2();
    let mut request = base_request(&account_id, GrantSource::SelfService, 15_000_000);
    request.idempotency_key = Some(idempotency_key.clone());
    let request_a = request.clone();
    let request_b = request;

    let task_a = tokio::spawn(async move { repo_a.grant(request_a).await });
    let task_b = tokio::spawn(async move { repo_b.grant(request_b).await });

    let (result_a, result_b) = tokio::try_join!(task_a, task_b).expect("neither task should panic");
    let grant_a = result_a.expect("concurrent grant A must succeed");
    let grant_b = result_b.expect("concurrent grant B must succeed");

    assert_eq!(
        grant_a.id, grant_b.id,
        "both concurrent callers must observe the same grant id"
    );

    let grant_rows: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM budget_grants WHERE idempotency_key = $1")
            .bind(&idempotency_key)
            .fetch_all(&pool)
            .await
            .expect("query must succeed");
    assert_eq!(
        grant_rows.len(),
        1,
        "exactly one budget_grants row must exist for this idempotency key"
    );

    let (_base, _self_service, _admin, _automatic, _refund, effective, _sc, _ac, _version) =
        fetch_balance_row(&pool, &account_id).await;
    assert_eq!(
        effective, 15_000_000,
        "concurrent duplicate submissions must only be counted once"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_amount_is_rejected_before_hitting_the_database(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));
    let request = base_request(&account_id, GrantSource::SelfService, -1);

    let result = repo.grant(request).await;

    assert!(matches!(result, Err(BudgetError::InvalidAmount(-1))));
}

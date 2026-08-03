#![cfg(feature = "it-tests")]

use lightbridge_authz_core::cuid::cuid2;
use sqlx::PgPool;

const PERIOD: &str = "2026-08";

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_valid_grant(pool: &PgPool, grant_id: &str, account_id: &str) {
    sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source)
         VALUES ($1, $2, $2, $3, $4, 'self_service')",
    )
    .bind(grant_id)
    .bind(account_id)
    .bind(PERIOD)
    .bind(100_i64)
    .execute(pool)
    .await
    .expect("inserting a valid grant row must succeed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_against_budget_grants_row_is_rejected(pool: PgPool) {
    let account_id = cuid2();
    let grant_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_valid_grant(&pool, &grant_id, &account_id).await;

    let result = sqlx::query("UPDATE budget_grants SET reason = 'x' WHERE id = $1")
        .bind(&grant_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "expected the append-only trigger to reject UPDATE, but it succeeded"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn delete_against_budget_grants_row_is_rejected(pool: PgPool) {
    let account_id = cuid2();
    let grant_id = cuid2();
    insert_account(&pool, &account_id).await;
    insert_valid_grant(&pool, &grant_id, &account_id).await;

    let result = sqlx::query("DELETE FROM budget_grants WHERE id = $1")
        .bind(&grant_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "expected the append-only trigger to reject DELETE, but it succeeded"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn negative_amount_is_rejected_for_non_correction_source(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let result = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source)
         VALUES ($1, $2, $2, $3, $4, 'self_service')",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(-100_i64)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "expected the sign CHECK to reject a negative amount for a non-correction source"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn zero_amount_is_rejected_for_correction_source(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let result = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source)
         VALUES ($1, $2, $2, $3, $4, 'correction')",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(0_i64)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "expected the sign CHECK to reject a zero amount for a correction (no-op, unauditable row)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn correction_source_may_be_negative(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let result = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source)
         VALUES ($1, $2, $2, $3, $4, 'correction')",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(-50_000_000_i64)
    .execute(&pool)
    .await;

    assert!(
        result.is_ok(),
        "a correction must be allowed to carry a negative amount: {:?}",
        result.err()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn duplicate_idempotency_key_is_rejected(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;
    let idempotency_key = cuid2();

    let first = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source, idempotency_key)
         VALUES ($1, $2, $2, $3, $4, 'self_service', $5)",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(100_i64)
    .bind(&idempotency_key)
    .execute(&pool)
    .await;
    assert!(first.is_ok());

    let second = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source, idempotency_key)
         VALUES ($1, $2, $2, $3, $4, 'self_service', $5)",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(100_i64)
    .bind(&idempotency_key)
    .execute(&pool)
    .await;

    assert!(
        second.is_err(),
        "expected the partial unique index to reject a duplicate idempotency_key"
    );

    let null_key_first = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source, idempotency_key)
         VALUES ($1, $2, $2, $3, $4, 'self_service', NULL)",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(100_i64)
    .execute(&pool)
    .await;
    assert!(null_key_first.is_ok());

    let null_key_second = sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source, idempotency_key)
         VALUES ($1, $2, $2, $3, $4, 'self_service', NULL)",
    )
    .bind(cuid2())
    .bind(&account_id)
    .bind(PERIOD)
    .bind(100_i64)
    .execute(&pool)
    .await;
    assert!(
        null_key_second.is_ok(),
        "two NULL idempotency_key rows must not collide under the partial unique index"
    );
}

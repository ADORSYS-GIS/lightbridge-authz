#![cfg(feature = "it-tests")]
//! `20261023000002_adr_0035_contract.sql` drops the withdrawn ADR-0035 schema and returns
//! `budget_grants` to its pre-#774 shape, plus one deliberate exception: `consumption` and `expiry`
//! stay admitted, negative only, because settlement left rows with those sources in the
//! append-only ledger. These tests pin both halves against a database migrated the way production
//! is.

use lightbridge_authz_core::cuid::cuid2;
use sqlx::PgPool;

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_grant(
    pool: &PgPool,
    account_id: &str,
    period: Option<&str>,
    amount_micros: i64,
    source: &str,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO budget_grants
            (id, budget_account_id, account_id, period, amount_micros, source)
         VALUES ($1, $2, $2, $3, $4, $5)",
    )
    .bind(cuid2())
    .bind(account_id)
    .bind(period)
    .bind(amount_micros)
    .bind(source)
    .execute(pool)
    .await
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_withdrawn_schema_is_gone(pool: PgPool) {
    let (columns,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.columns
         WHERE (table_name = 'budget_grants' AND column_name IN ('pool', 'lot_id', 'external_ref'))
            OR (table_name = 'budget_remaining_snapshots' AND column_name IN (
                'allowance_remaining_micros', 'granted_remaining_micros',
                'paid_remaining_micros', 'debt_micros'))",
    )
    .fetch_one(&pool)
    .await
    .expect("information_schema must be readable");
    assert_eq!(columns, 0, "every ADR-0035 column must be dropped");

    let (tables,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.tables
         WHERE table_name IN ('credit_lots', 'settlement_state')",
    )
    .fetch_one(&pool)
    .await
    .expect("information_schema must be readable");
    assert_eq!(
        tables, 0,
        "credit_lots and settlement_state must be dropped"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn settlement_sources_stay_admitted_negative_only(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    for source in ["consumption", "expiry"] {
        insert_grant(&pool, &account_id, Some("2026-10"), -1, source)
            .await
            .unwrap_or_else(|err| panic!("a negative {source} row must be admitted: {err}"));
        assert!(
            insert_grant(&pool, &account_id, Some("2026-10"), 1, source)
                .await
                .is_err(),
            "a positive {source} row must be refused"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_pre_adr_0035_invariants_are_back(pool: PgPool) {
    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    assert!(
        insert_grant(&pool, &account_id, None, 100, "base")
            .await
            .is_err(),
        "period is NOT NULL again"
    );
    for source in ["purchase", "purchase_reversal", "referral"] {
        assert!(
            insert_grant(&pool, &account_id, Some("2026-10"), 100, source)
                .await
                .is_err(),
            "{source} was an ADR-0035-only source and must be refused"
        );
    }
    insert_grant(&pool, &account_id, Some("2026-10"), -100, "correction")
        .await
        .expect("a negative correction stays admitted");
    assert!(
        insert_grant(&pool, &account_id, Some("2026-10"), -100, "base")
            .await
            .is_err(),
        "only correction, consumption and expiry may be negative"
    );
}

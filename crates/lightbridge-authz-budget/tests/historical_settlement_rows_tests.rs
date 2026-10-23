#![cfg(feature = "it-tests")]
//! Settlement ran in a real environment before ADR-0035 was withdrawn, so `budget_grants` holds
//! allowance rows with source `consumption` and `expiry`, forever (append-only, ADR-0009). The
//! ledger-history reads must still return them; before `GrantSource` learned the two read-only
//! variants, both reads below failed with `StorageFailed` (a 500 on the RPC).

use std::sync::Arc;

use lightbridge_authz_budget::GrantSource;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::repo::BudgetRepo;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

async fn seed_historical_settlement_rows(pool: &PgPool) {
    sqlx::query("INSERT INTO accounts (id) VALUES ('hist-a')")
        .execute(pool)
        .await
        .expect("seed account");
    sqlx::query(
        "INSERT INTO budget_grants \
         (id, budget_account_id, account_id, period, amount_micros, source, trigger_key) \
         VALUES \
         ('h1', 'hist-a', 'hist-a', '2026-09', 5000000, 'base', NULL), \
         ('h2', 'hist-a', 'hist-a', '2026-09', -1000000, 'consumption', 'settle:h2'), \
         ('h3', 'hist-a', 'hist-a', '2026-09', -250000, 'expiry', 'expire:h3')",
    )
    .execute(pool)
    .await
    .expect("seed rows shaped as ADR-0035 settlement booked them");
}

#[sqlx::test(migrations = "../../migrations")]
async fn unscoped_ledger_listing_survives_historical_settlement_rows(pool: PgPool) {
    seed_historical_settlement_rows(&pool).await;
    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));

    let listed = repo
        .list_grants("hist-a", None, None, 50)
        .await
        .expect("an unscoped ledger listing must survive historical settlement rows");
    assert_eq!(listed.len(), 3);

    let past = Period::parse("2026-09").expect("valid period");
    let scoped = repo
        .list_grants("hist-a", Some(&past), None, 50)
        .await
        .expect("a period-scoped listing must survive them too");
    assert_eq!(scoped.len(), 3);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_historical_settlement_row_reads_back_with_its_source(pool: PgPool) {
    seed_historical_settlement_rows(&pool).await;
    let repo = BudgetRepo::new(Arc::new(DbPool::from_pool(pool)));

    let consumption = repo.get_grant_by_id("h2").await.expect("consumption row");
    assert_eq!(consumption.source, GrantSource::Consumption);
    let expiry = repo.get_grant_by_id("h3").await.expect("expiry row");
    assert_eq!(expiry.source, GrantSource::Expiry);
}

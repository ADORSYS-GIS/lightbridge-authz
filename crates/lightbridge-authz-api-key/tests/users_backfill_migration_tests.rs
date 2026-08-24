// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! Live-database coverage for `20260825000001_users_and_federated_identities`: the ADR-0024
//! migration that adds `users`, backfills one `users` row per pre-existing `accounts` row keyed
//! by the account's own id, and installs the `accounts_set_user` trigger so every FUTURE account
//! insert (Rust or raw SQL, with or without an explicit `user_id`) also ends up with one.
//!
//! Mirrors `model_policy_backfill_migration_tests.rs`'s shape for the same reason that file gives
//! for itself: `#[sqlx::test(migrations = "../../migrations")]` applies every migration,
//! including the one under test, before the test body gets to insert a row -- so there would be
//! nothing left to backfill. Instead: run migrations up to (and including) the LAST migration
//! before this one, seed accounts directly with raw SQL, then run the rest and inspect the
//! result.

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use sqlx::PgPool;
use std::sync::Arc;

/// The migration immediately before `20260825000001_users_and_federated_identities` in
/// `migrations/` -- run_to's argument is the numeric prefix of a migration file, not a string.
const LAST_MIGRATION_BEFORE_USERS: i64 = 20260824000003;

async fn insert_bare_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a pre-existing-shaped account must succeed");
}

#[sqlx::test(migrations = false)]
async fn backfill_gives_every_pre_existing_account_a_user_keyed_by_its_own_id(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    migrator
        .run_to(LAST_MIGRATION_BEFORE_USERS, &pool)
        .await
        .expect("migrations up to and including the one right before the users migration apply");

    let account_ids = [cuid2(), cuid2(), cuid2()];
    for account_id in &account_ids {
        insert_bare_account(&pool, account_id).await;
    }

    migrator
        .run(&pool)
        .await
        .expect("the users/federated_identities migration applies on top of the seeded rows");

    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("counting users must succeed");
    assert_eq!(
        user_count, 3,
        "every pre-existing account must get exactly one backfilled user row"
    );

    let null_user_id_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM accounts WHERE user_id IS NULL")
            .fetch_one(&pool)
            .await
            .expect("counting NULL user_id accounts must succeed");
    assert_eq!(
        null_user_id_count, 0,
        "accounts.user_id must be backfilled non-NULL for every pre-existing row -- the migration's \
         SET NOT NULL would itself fail if any row were left NULL, so this also proves that \
         constraint didn't silently no-op"
    );

    for account_id in &account_ids {
        let user_id: String = sqlx::query_scalar("SELECT user_id FROM accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .expect("the seeded account must still exist after the migration runs");
        assert_eq!(
            &user_id, account_id,
            "the backfill must reuse the account's own id as its user's id (ADR-0024 Q5: an \
             id-reuse, not a remap)"
        );

        let user_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
                .bind(account_id)
                .fetch_one(&pool)
                .await
                .expect("checking the backfilled user row must succeed");
        assert!(
            user_exists,
            "a users row keyed by the account's own id must exist for account {account_id}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_trigger_provisions_a_user_for_an_account_inserted_without_one(pool: PgPool) {
    let account_id = cuid2();

    // The exact bare-INSERT shape every existing Rust writer (StoreRepo::create_account) and
    // every raw-SQL test fixture across the workspace already uses -- no user_id supplied.
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(&account_id)
        .execute(&pool)
        .await
        .expect("a bare account insert with no user_id must still succeed post-migration");

    let user_id: String = sqlx::query_scalar("SELECT user_id FROM accounts WHERE id = $1")
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .expect("the inserted account must exist");
    assert_eq!(
        user_id, account_id,
        "the accounts_set_user trigger must provision a user_id equal to the account's own id \
         when none is supplied"
    );

    let user_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(&account_id)
        .fetch_one(&pool)
        .await
        .expect("checking the trigger-provisioned user row must succeed");
    assert!(
        user_exists,
        "the trigger must have inserted a users row for the new account, not just set the \
         foreign key to a nonexistent id"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_still_works_and_is_still_conflict_on_a_second_call(pool: PgPool) {
    let repo = StoreRepo::new(Arc::new(DbPool::from_pool(pool)));
    let subject = "conflict-subject";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("StoreRepo::create_account must be unchanged by the accounts_set_user trigger");
    assert_eq!(account.id, subject);

    let err = repo
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect_err("a second create_account call for the same subject must still be a conflict");
    assert!(matches!(err, Error::Conflict(_)));
}

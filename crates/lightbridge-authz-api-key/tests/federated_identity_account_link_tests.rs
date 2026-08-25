// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! ADR-0024 Correction (2026-08-25): pins the corrected semantic -- a federated identity links to
//! an ACCOUNT, never directly to a user. There is no mint-a-user branch any more: a Keycloak
//! subject with no pre-existing `accounts` row is REFUSED at the same transaction that would
//! otherwise insert, not silently given a brand-new orphaned `users` row. The person is always
//! DERIVED (`federated_identities.account_id -> accounts.user_id -> users.id`), never stored a
//! second time.
//!
//! Written before the fix lands (see `docs/../repo.rs`'s `upsert_federated_identity` and
//! `migrations/20260825000002_federated_identities_link_accounts_not_users.sql`) -- several of
//! these are expected to fail today, some by assertion, one (test 2) by compile error against the
//! pre-correction `Option<String>` shape of `FederatedIdentityRow::account_id`. That is the
//! prove-fail-first artifact for this change.

use lightbridge_authz_api_key::entities::federated_identity_row::UpsertFederatedIdentity;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use sqlx::PgPool;
use std::sync::Arc;

/// The migration this correction's own migration
/// (`20260825000002_federated_identities_link_accounts_not_users`) sits immediately on top of --
/// `run_to`'s argument is the numeric prefix of a migration file, not a string.
const USERS_AND_FEDERATED_IDENTITIES_MIGRATION: i64 = 20260825000001;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

fn bare_upsert(issuer: &str, subject: &str) -> UpsertFederatedIdentity {
    UpsertFederatedIdentity {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        token_envelope: None,
        token_sealed_at: None,
        access_expires_at: None,
        refresh_expires_at: None,
        scope: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn upsert_federated_identity_refuses_a_subject_with_no_account(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "accountless-subject";

    let err = repo
        .upsert_federated_identity(
            bare_upsert("https://issuer.example", subject),
            "https://issuer.example",
        )
        .await
        .expect_err(
            "a subject with no pre-existing accounts row must be refused, not minted a user",
        );
    assert!(
        matches!(err, Error::Forbidden(_)),
        "expected Error::Forbidden, got {err:?}"
    );

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(
        fi_count, 0,
        "a refused login must leave no federated_identities row behind"
    );

    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("counting users must succeed");
    assert_eq!(
        user_count, 0,
        "a refused login must never mint a users row -- there is no mint-a-user branch any more"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn upsert_federated_identity_adopts_the_account_and_derives_its_user(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "adopting-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation must succeed");

    let row = repo
        .upsert_federated_identity(
            bare_upsert("https://issuer.example", subject),
            "https://issuer.example",
        )
        .await
        .expect("a subject matching a pre-existing account must be adopted");
    assert_eq!(
        row.account_id, subject,
        "the adopted account's id must be the subject itself"
    );

    let derived_user_id: String = sqlx::query_scalar(
        r#"
        SELECT u.id
        FROM federated_identities f
        JOIN accounts a ON a.id = f.account_id
        JOIN users u ON u.id = a.user_id
        WHERE f.id = $1
        "#,
    )
    .bind(&row.id)
    .fetch_one(&pool)
    .await
    .expect("the user must be derivable via federated_identities -> accounts -> users");
    assert_eq!(
        derived_user_id, subject,
        "the adopted account's own (trigger-provisioned) user must be the derived user"
    );
}

/// ADR-0025 Finding 2: `upsert_federated_identity`'s first-adoption branch must refuse a subject
/// presented by any issuer OTHER than the configured grandfather issuer, even when NOTHING has
/// adopted the account yet -- i.e. the refusal must come from the issuer pin itself, not from a
/// downstream unique-index collision with some other issuer's prior adoption. Deliberately run
/// with no prior adoption at all (an entirely fresh account) so there is nothing to "lose a race"
/// against; this is what distinguishes the pin from `federated_identities_account_uidx`'s
/// structural backstop, which only bites once a FIRST adoption already exists.
#[sqlx::test(migrations = "../../migrations")]
async fn upsert_federated_identity_refuses_adoption_from_a_non_grandfather_issuer(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "not-yet-adopted-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation must succeed");

    let err = repo
        .upsert_federated_identity(
            bare_upsert("https://rogue-issuer.example", subject),
            "https://issuer.example",
        )
        .await
        .expect_err(
            "a subject matching a pre-existing account, presented by a non-grandfather issuer, \
             must be refused",
        );
    assert!(
        matches!(err, Error::Forbidden(_)),
        "expected Error::Forbidden, got {err:?}"
    );

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(
        fi_count, 0,
        "a refused non-grandfather adoption must leave no federated_identities row behind"
    );

    // The SAME subject, presented by the actual grandfather issuer, must still adopt normally --
    // proving the refusal above is specific to the mismatched issuer, not the account/subject.
    let row = repo
        .upsert_federated_identity(
            bare_upsert("https://issuer.example", subject),
            "https://issuer.example",
        )
        .await
        .expect("the grandfather issuer must still be able to adopt the same account");
    assert_eq!(row.account_id, subject);
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_the_account_removes_its_federated_identity_but_not_its_user(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "deletable-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation must succeed");
    repo.upsert_federated_identity(
        bare_upsert("https://issuer.example", subject),
        "https://issuer.example",
    )
    .await
    .expect("adopting the pre-existing account must succeed");

    let user_id: String = sqlx::query_scalar("SELECT user_id FROM accounts WHERE id = $1")
        .bind(subject)
        .fetch_one(&pool)
        .await
        .expect("the account's user_id must be readable before deletion");

    repo.delete_account(&AccountId::assert_already_resolved(subject), subject)
        .await
        .expect("deleting the account must succeed");

    let federation = repo
        .find_federated_identity("https://issuer.example", subject)
        .await
        .expect("looking up the federated identity must not error");
    assert!(
        federation.is_none(),
        "deleting the adopted account must remove its federated_identities row (ON DELETE \
         CASCADE), not leave an orphaned row behind"
    );

    let user_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
        .bind(&user_id)
        .fetch_one(&pool)
        .await
        .expect("checking the user row must succeed");
    assert!(
        user_exists,
        "the person (users row {user_id}) must survive the deletion of the account/federated \
         identity that logged in as them"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn account_id_is_structurally_not_null(pool: PgPool) {
    let err =
        sqlx::query("INSERT INTO federated_identities (id, issuer, subject) VALUES ($1, $2, $3)")
            .bind(cuid2())
            .bind("https://issuer.example")
            .bind("no-account-id-subject")
            .execute(&pool)
            .await
            .expect_err("inserting a federated_identities row with no account_id must fail");

    let sqlx::Error::Database(db_err) = &err else {
        panic!("expected a database error, got {err:?}");
    };
    assert_eq!(
        db_err.code().as_deref(),
        Some("23502"),
        "the failure must be a NOT NULL violation (23502), got {db_err:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_correction_migration_removes_accountless_rows_and_keeps_adopted_ones(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    migrator
        .run_to(USERS_AND_FEDERATED_IDENTITIES_MIGRATION, &pool)
        .await
        .expect("migrations up to and including the original users/federated_identities migration apply");

    // An accountless pair, shaped exactly like the pre-correction mint-a-user branch produced.
    let accountless_user_id = cuid2();
    sqlx::query("INSERT INTO users (id) VALUES ($1)")
        .bind(&accountless_user_id)
        .execute(&pool)
        .await
        .expect("seeding the accountless user must succeed");
    let accountless_fi_id = cuid2();
    sqlx::query(
        "INSERT INTO federated_identities (id, user_id, issuer, subject, account_id) \
         VALUES ($1, $2, $3, $4, NULL)",
    )
    .bind(&accountless_fi_id)
    .bind(&accountless_user_id)
    .bind("https://issuer-a.example")
    .bind("accountless-subject")
    .execute(&pool)
    .await
    .expect("seeding the accountless federated identity must succeed");

    // An adopted pair: a real account (via StoreRepo::create_account, which already works against
    // this schema stage) plus its adopting federated identity.
    let repo = build_repo(pool.clone());
    let adopted_subject = "adopted-subject";
    repo.create_account(
        adopted_subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("seeding the adopted account must succeed");
    let adopted_user_id: String = sqlx::query_scalar("SELECT user_id FROM accounts WHERE id = $1")
        .bind(adopted_subject)
        .fetch_one(&pool)
        .await
        .expect("the trigger-provisioned user_id must be readable");
    let adopted_fi_id = cuid2();
    sqlx::query(
        "INSERT INTO federated_identities (id, user_id, issuer, subject, account_id) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&adopted_fi_id)
    .bind(&adopted_user_id)
    .bind("https://issuer-b.example")
    .bind(adopted_subject)
    .bind(adopted_subject)
    .execute(&pool)
    .await
    .expect("seeding the adopted federated identity must succeed");

    migrator
        .run(&pool)
        .await
        .expect("the correction migration applies on top of the seeded rows");

    let accountless_user_gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(&accountless_user_id)
            .fetch_one(&pool)
            .await
            .expect("checking the accountless user must succeed");
    assert!(
        accountless_user_gone,
        "the correction migration must delete the users row minted for an accountless login"
    );

    let accountless_fi_gone: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM federated_identities WHERE id = $1)")
            .bind(&accountless_fi_id)
            .fetch_one(&pool)
            .await
            .expect("checking the accountless federated identity must succeed");
    assert!(
        accountless_fi_gone,
        "the correction migration must delete the accountless federated_identities row"
    );

    let adopted_fi_survives: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM federated_identities WHERE id = $1 AND account_id = $2)",
    )
    .bind(&adopted_fi_id)
    .bind(adopted_subject)
    .fetch_one(&pool)
    .await
    .expect("checking the adopted federated identity must succeed");
    assert!(
        adopted_fi_survives,
        "an adopted federated identity must survive the correction migration untouched"
    );

    let adopted_user_survives: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(&adopted_user_id)
            .fetch_one(&pool)
            .await
            .expect("checking the adopted account's user must succeed");
    assert!(
        adopted_user_survives,
        "the adopted account's user must survive the correction migration"
    );

    let adopted_account_survives: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)")
            .bind(adopted_subject)
            .fetch_one(&pool)
            .await
            .expect("checking the adopted account must succeed");
    assert!(
        adopted_account_survives,
        "the adopted account itself must be untouched by the correction migration"
    );
}

#![cfg(feature = "it-tests")]
#![allow(clippy::unwrap_used)]

//! Postgres-backed coverage for `StoreRepo::provision_account` (#720): the admin-targets-an-
//! arbitrary-subject account bootstrap. Two things this file exists specifically to prove:
//!
//! 1. A single call creates BOTH the anchor `accounts` row AND its mandatory default `projects`
//!    row, transactionally -- an account with no `is_default` project still dead-ends the browser
//!    SSO callback one step later (`find_default_project_id`), so provisioning the account alone
//!    would not actually have fixed the incident this method exists to close.
//! 2. Neither half can be created twice for the same subject/email: a duplicate subject is
//!    `Error::Conflict`, a colliding `billing_identity` is `Error::Conflict`, and in the second
//!    case the transaction leaves nothing behind -- no orphaned account with no default project.

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use sqlx::PgPool;
use std::sync::Arc;

fn repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

#[sqlx::test(migrations = "../../migrations")]
async fn provision_account_creates_anchor_account_and_default_project(pool: PgPool) {
    let repo = repo(pool.clone());
    let subject = format!(
        "provision-subject-{}",
        lightbridge_authz_core::cuid::cuid2()
    );
    let email = format!("{subject}@example.test");

    let account = repo
        .provision_account(
            &AccountId::assert_already_resolved(&subject),
            &email,
            Some("Joel Wanko"),
        )
        .await
        .unwrap();

    assert_eq!(
        account.id, subject,
        "provisionAccount must mint the subject's ANCHOR account (id == subject), matching the \
         invariant federated_identities adoption depends on"
    );
    assert_eq!(account.name.as_deref(), Some("Joel Wanko"));

    let project: (String, bool, String, String) = sqlx::query_as(
        r#"SELECT name, is_default, billing_identity, billing_plan
           FROM projects WHERE account_id = $1"#,
    )
    .bind(&subject)
    .fetch_one(&pool)
    .await
    .expect("provisionAccount must have created exactly one project row");

    assert_eq!(project.0, "Default Project");
    assert!(
        project.1,
        "the sole project for a freshly provisioned account must be is_default (computed by the \
         projects_set_is_default trigger)"
    );
    assert_eq!(project.2, email);
    assert_eq!(project.3, "free");

    let user_row_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(&subject)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        user_row_exists,
        "the accounts_set_user trigger must have provisioned the anchor's users row"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn provision_account_for_existing_subject_is_a_conflict(pool: PgPool) {
    let repo = repo(pool);
    let subject = format!("provision-dup-{}", lightbridge_authz_core::cuid::cuid2());
    let account_id = AccountId::assert_already_resolved(&subject);

    repo.provision_account(&account_id, "first@example.test", None)
        .await
        .unwrap();

    let err = repo
        .provision_account(&account_id, "second@example.test", None)
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::Conflict(_)),
        "a second provisionAccount for the same subject must be Error::Conflict, not a silent \
         overwrite or a new row (unlike create_account's ADR-0026 several-accounts-per-identity \
         contract -- provisionAccount only ever creates the FIRST account for a subject)"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn provision_account_with_colliding_billing_identity_is_a_conflict(pool: PgPool) {
    let repo = repo(pool.clone());
    let email = format!(
        "shared-{}@example.test",
        lightbridge_authz_core::cuid::cuid2()
    );
    let first_subject = format!(
        "provision-collide-a-{}",
        lightbridge_authz_core::cuid::cuid2()
    );
    let second_subject = format!(
        "provision-collide-b-{}",
        lightbridge_authz_core::cuid::cuid2()
    );

    repo.provision_account(
        &AccountId::assert_already_resolved(&first_subject),
        &email,
        None,
    )
    .await
    .unwrap();

    let err = repo
        .provision_account(
            &AccountId::assert_already_resolved(&second_subject),
            &email,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::Conflict(_)),
        "a colliding billing_identity on the default project must be Error::Conflict"
    );

    let second_account_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1)")
            .bind(&second_subject)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !second_account_exists,
        "the billing_identity collision on the SECOND insert must have rolled back the whole \
         transaction, including the accounts row already inserted earlier in it -- never an \
         orphaned account with no default project"
    );
}

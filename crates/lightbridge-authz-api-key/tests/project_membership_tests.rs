#![cfg(feature = "it-tests")]

//! Project roster coverage (ADR-0006). Replaces `membership_tests.rs`, which exercised the
//! account-level roster that no longer exists — an account is one person now, so there is nothing
//! to add anyone to at that level. Grouping happens on `project_members` instead, and the
//! interesting authorization question moved with it: not "are you a member of this account" but
//! "are you a lead on this project".

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

async fn seed_account(repo: &StoreRepo, subject: &str) -> String {
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation should succeed")
    .id
}

/// Seeds an account plus a project under it. Note the project is that account's FIRST, so the
/// `set_project_is_default` trigger marks it default — which matters for the roster-less-default
/// assertion below.
async fn seed_account_and_project(repo: &StoreRepo, subject: &str) -> (String, String) {
    let account_id = seed_account(repo, subject).await;
    let project = repo
        .create_project(
            subject,
            &account_id,
            CreateProject {
                name: "proj".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            cuid2(),
        )
        .await
        .expect("project creation should succeed");
    (account_id, project.id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn account_owner_can_add_a_member_who_then_sees_the_project(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "member-subject").await;

    assert!(
        repo.get_project("member-subject", &project_id)
            .await
            .unwrap()
            .is_none(),
        "a non-member must not see the project at all"
    );

    repo.add_project_member("owner", &project_id, &member_account, None)
        .await
        .expect("the project's account owner may seed the roster");

    assert!(
        repo.get_project("member-subject", &project_id)
            .await
            .unwrap()
            .is_some(),
        "a roster row grants visibility"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_plain_member_cannot_manage_the_roster_but_a_lead_can(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "plain-member").await;
    let third_account = seed_account(&repo, "third").await;

    repo.add_project_member("owner", &project_id, &member_account, Some("member"))
        .await
        .unwrap();

    // Forbidden, not NotFound: this caller already knows the project exists, so refusing with 404
    // would leak nothing but would misdescribe the failure.
    let denied = repo
        .add_project_member("plain-member", &project_id, &third_account, None)
        .await
        .unwrap_err();
    assert!(matches!(denied, Error::Forbidden(_)));

    repo.set_project_member_role("owner", &project_id, &member_account, "lead")
        .await
        .unwrap();

    repo.add_project_member("plain-member", &project_id, &third_account, None)
        .await
        .expect("a lead may manage the roster");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_non_member_gets_not_found_rather_than_forbidden(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let outsider_account = seed_account(&repo, "outsider").await;

    let err = repo
        .add_project_member("outsider", &project_id, &outsider_account, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::NotFound),
        "existence must not leak to a caller with no relationship to the project"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn quota_tier_is_settable_by_a_lead_and_removable(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "member-subject").await;

    repo.add_project_member("owner", &project_id, &member_account, None)
        .await
        .unwrap();

    repo.set_project_member_quota_tier("owner", &project_id, &member_account, Some("t-xs"))
        .await
        .expect("a lead may set a member's ceiling");

    repo.set_project_member_quota_tier("owner", &project_id, &member_account, None)
        .await
        .expect("clearing the ceiling back to unset is allowed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn removing_a_member_revokes_their_visibility(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "member-subject").await;

    repo.add_project_member("owner", &project_id, &member_account, None)
        .await
        .unwrap();
    assert!(
        repo.get_project("member-subject", &project_id)
            .await
            .unwrap()
            .is_some()
    );

    repo.remove_project_member("owner", &project_id, &member_account)
        .await
        .unwrap();

    assert!(
        repo.get_project("member-subject", &project_id)
            .await
            .unwrap()
            .is_none(),
        "removal must revoke access immediately -- there is no cached membership anywhere"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn adding_a_member_is_idempotent(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "member-subject").await;

    repo.add_project_member("owner", &project_id, &member_account, None)
        .await
        .unwrap();
    repo.add_project_member("owner", &project_id, &member_account, None)
        .await
        .expect("re-adding an existing member must not error");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invalid_role_is_rejected(pool: PgPool) {
    let repo = build_repo(pool);
    let (_owner_account, project_id) = seed_account_and_project(&repo, "owner").await;
    let member_account = seed_account(&repo, "member-subject").await;

    // Guarded in Rust as well as by the table's CHECK constraint, so the error is a clean
    // BadRequest rather than a database violation surfacing as a 500.
    let err = repo
        .add_project_member("owner", &project_id, &member_account, Some("admin"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BadRequest(_)));
}

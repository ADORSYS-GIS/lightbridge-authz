#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

async fn seed_project(repo: &StoreRepo, subject: &str) -> (String, String) {
    let account_id = AccountId::assert_already_resolved(subject);
    let account = repo
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("account creation should succeed");
    let project = repo
        .create_project(
            &account_id,
            &account.id,
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
    (account.id, project.id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolves_context_for_a_member(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (account_id, project_id) = seed_project(&repo, subject).await;

    let context = repo
        .resolve_context(&AccountId::assert_already_resolved(subject), &project_id)
        .await
        .expect("a member should resolve context");
    assert_eq!(context.account_id, account_id);
    assert_eq!(context.project_id, project_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolution_is_repeatable(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (account_id, project_id) = seed_project(&repo, subject).await;

    for _ in 0..3 {
        let context = repo
            .resolve_context(&AccountId::assert_already_resolved(subject), &project_id)
            .await
            .expect("resolution is stateless and repeatable");
        assert_eq!(context.account_id, account_id);
        assert_eq!(context.project_id, project_id);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn rejects_non_member(pool: PgPool) {
    let repo = build_repo(pool);
    let (_account_id, project_id) = seed_project(&repo, "owner").await;

    let err = repo
        .resolve_context(&AccountId::assert_already_resolved("outsider"), &project_id)
        .await
        .expect_err("a non-member must not resolve someone else's project");
    assert!(matches!(err, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn rejects_unknown_project(pool: PgPool) {
    let repo = build_repo(pool);
    let err = repo
        .resolve_context(
            &AccountId::assert_already_resolved("user-1"),
            "proj_does_not_exist",
        )
        .await
        .expect_err("an unknown project must not resolve");
    assert!(matches!(err, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_default_project_id_returns_the_auto_provisioned_project(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (_account_id, project_id) = seed_project(&repo, subject).await;

    let default_project_id = repo
        .find_default_project_id(&AccountId::assert_already_resolved(subject))
        .await
        .expect("query succeeds")
        .expect("the subject's first project is its auto-provisioned default");
    assert_eq!(default_project_id, project_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn find_default_project_id_is_none_without_any_projects(pool: PgPool) {
    let repo = build_repo(pool);
    repo.create_account(
        "user-1",
        lightbridge_authz_core::CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation should succeed");

    let default_project_id = repo
        .find_default_project_id(&AccountId::assert_already_resolved("user-1"))
        .await
        .expect("query succeeds");
    assert_eq!(
        default_project_id, None,
        "an account with zero projects has no default project to resolve"
    );
}

/// ADR-0024: `resolve_context` reads only `projects`/`project_members` -- it never touches
/// `accounts` or the new `users` table at all (see `StoreRepo::resolve_context`'s own doc
/// comment, "Every downstream consumer proven unchanged"). This asserts the ownership branch, the
/// membership branch, and the uniform-`NotFound` non-member branch are all still exactly as they
/// were before `20260825000001_users_and_federated_identities.sql` -- including for an account
/// whose backing `users` row has been marked `suspended` directly, which must have ZERO effect
/// here (status gating for a suspended identity is `require_active_project_and_account`'s job,
/// not this function's).
#[sqlx::test(migrations = "../../migrations")]
async fn resolve_context_is_unchanged_for_an_account_created_before_the_users_migration(
    pool: PgPool,
) {
    let repo = build_repo(pool.clone());
    let owner = "owner-subject";
    let (owner_account_id, project_id) = seed_project(&repo, owner).await;

    // The account's `users` row (trigger-provisioned at INSERT time, id-reused from the account
    // id per ADR-0024's Q5 backfill) is marked suspended directly -- resolve_context must not
    // care, proving it reads no user status at all.
    sqlx::query("UPDATE users SET status = 'suspended' WHERE id = $1")
        .bind(&owner_account_id)
        .execute(&pool)
        .await
        .expect("marking the backing user row suspended must succeed");

    let member = "member-subject";
    repo.create_account(
        member,
        lightbridge_authz_core::CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("member account creation should succeed");
    repo.add_project_member(
        &AccountId::assert_already_resolved(owner),
        &project_id,
        member,
        None,
    )
    .await
    .expect("owner must be able to add a member to their own project");

    let owner_context = repo
        .resolve_context(&AccountId::assert_already_resolved(owner), &project_id)
        .await
        .expect("the ownership branch must resolve exactly as before, suspended user row or not");
    assert_eq!(owner_context.account_id, owner_account_id);
    assert_eq!(owner_context.project_id, project_id);

    let member_context = repo
        .resolve_context(&AccountId::assert_already_resolved(member), &project_id)
        .await
        .expect("the membership branch must resolve exactly as before");
    assert_eq!(member_context.account_id, owner_account_id);
    assert_eq!(member_context.project_id, project_id);

    let err = repo
        .resolve_context(
            &AccountId::assert_already_resolved("outsider-subject"),
            &project_id,
        )
        .await
        .expect_err("a non-member must still resolve to a uniform NotFound");
    assert!(matches!(err, Error::NotFound));
}

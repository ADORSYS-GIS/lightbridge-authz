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
            &AccountId::assert_already_resolved(subject),
            CreateAccount {
                default_quota: None,
                name: None,
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

/// The owner authorizing over their own account scope -- the #570 happy path.
#[sqlx::test(migrations = "../../migrations")]
async fn authorizes_account_scope_for_the_owning_subject(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "tenant-a";
    let (account_id, _project_id) = seed_project(&repo, subject).await;

    repo.authorize_usage_scope(
        &AccountId::assert_already_resolved(subject),
        "account",
        &account_id,
    )
    .await
    .expect("the owning subject must authorize their own account scope");
}

/// #570's decisive negative case: a second, unrelated tenant must never authorize against the
/// first tenant's account -- proves this is a real ownership check, not a permissive stub. Break
/// `authorize_usage_scope`'s `"account"` arm (e.g. drop the `owned.user_id = ...` predicate and
/// just check `owned.id = $1`) and this test goes from failing (as intended, pre-fix) to passing
/// once the predicate is real.
#[sqlx::test(migrations = "../../migrations")]
async fn refuses_account_scope_for_a_different_tenant(pool: PgPool) {
    let repo = build_repo(pool);
    let (account_a, _project_a) = seed_project(&repo, "tenant-a").await;
    let (_account_b, _project_b) = seed_project(&repo, "tenant-b").await;

    let err = repo
        .authorize_usage_scope(
            &AccountId::assert_already_resolved("tenant-b"),
            "account",
            &account_a,
        )
        .await
        .expect_err("tenant-b must never authorize against tenant-a's account");
    assert!(matches!(err, Error::NotFound));
}

/// The owner authorizing over their own project scope.
#[sqlx::test(migrations = "../../migrations")]
async fn authorizes_project_scope_for_the_owner(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "tenant-a";
    let (_account_id, project_id) = seed_project(&repo, subject).await;

    repo.authorize_usage_scope(
        &AccountId::assert_already_resolved(subject),
        "project",
        &project_id,
    )
    .await
    .expect("the owner must authorize their own project scope");
}

/// A roster member (not the owning account) must also authorize -- same visibility boundary as
/// `resolve_context`'s membership branch.
#[sqlx::test(migrations = "../../migrations")]
async fn authorizes_project_scope_for_a_roster_member(pool: PgPool) {
    let repo = build_repo(pool);
    let owner = "owner-subject";
    let (_account_id, project_id) = seed_project(&repo, owner).await;

    let member = "member-subject";
    repo.create_account(
        &AccountId::assert_already_resolved(member),
        CreateAccount {
            default_quota: None,
            name: None,
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

    repo.authorize_usage_scope(
        &AccountId::assert_already_resolved(member),
        "project",
        &project_id,
    )
    .await
    .expect("a roster member must authorize the project scope they belong to");
}

/// The two-tenant negative case for project scope: a non-member of ANY roster or ownership must
/// never authorize.
#[sqlx::test(migrations = "../../migrations")]
async fn refuses_project_scope_for_a_non_member(pool: PgPool) {
    let repo = build_repo(pool);
    let (_account_id, project_id) = seed_project(&repo, "owner-subject").await;

    let err = repo
        .authorize_usage_scope(
            &AccountId::assert_already_resolved("outsider-subject"),
            "project",
            &project_id,
        )
        .await
        .expect_err("a non-member must never authorize someone else's project");
    assert!(matches!(err, Error::NotFound));
}

/// Uniform 404 for a scope_id that does not exist at all -- must be indistinguishable from "known
/// but not owned", never a distinct status that would leak existence.
#[sqlx::test(migrations = "../../migrations")]
async fn refuses_unknown_scope_id_uniformly(pool: PgPool) {
    let repo = build_repo(pool);
    repo.create_account(
        &AccountId::assert_already_resolved("tenant-a"),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("account creation should succeed");

    let err = repo
        .authorize_usage_scope(
            &AccountId::assert_already_resolved("tenant-a"),
            "account",
            "acct_does_not_exist",
        )
        .await
        .expect_err("an unknown scope_id must not resolve");
    assert!(matches!(err, Error::NotFound));

    let err = repo
        .authorize_usage_scope(
            &AccountId::assert_already_resolved("tenant-a"),
            "project",
            "proj_does_not_exist",
        )
        .await
        .expect_err("an unknown scope_id must not resolve");
    assert!(matches!(err, Error::NotFound));
}

/// `user`/`api_key` (and any other unrecognized scope string) have no resolvable ownership
/// predicate and must refuse immediately -- no query, no oracle.
#[sqlx::test(migrations = "../../migrations")]
async fn refuses_scopes_with_no_resolvable_authority(pool: PgPool) {
    let repo = build_repo(pool);
    let (account_id, _project_id) = seed_project(&repo, "tenant-a").await;

    for scope in ["user", "api_key", "bogus"] {
        let err = repo
            .authorize_usage_scope(
                &AccountId::assert_already_resolved("tenant-a"),
                scope,
                &account_id,
            )
            .await
            .expect_err(&format!("scope '{scope}' must never authorize"));
        assert!(matches!(err, Error::NotFound));
    }
}

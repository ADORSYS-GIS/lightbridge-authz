#![cfg(feature = "it-tests")]

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

async fn seed_project(repo: &StoreRepo, subject: &str) -> (String, String) {
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
            subject,
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
        .resolve_context(subject, &project_id)
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
            .resolve_context(subject, &project_id)
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
        .resolve_context("outsider", &project_id)
        .await
        .expect_err("a non-member must not resolve someone else's project");
    assert!(matches!(err, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn rejects_unknown_project(pool: PgPool) {
    let repo = build_repo(pool);
    let err = repo
        .resolve_context("user-1", "proj_does_not_exist")
        .await
        .expect_err("an unknown project must not resolve");
    assert!(matches!(err, Error::NotFound));
}

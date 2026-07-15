#![cfg(feature = "it-tests")]

use chrono::Utc;
use lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::{ApiKeyStatus, CreateAccount, CreateProject, ResourceStatus};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

/// Seed an account -> project -> API key (with the given expiry) and return their ids plus the
/// key hash.
async fn seed_key(
    repo: &StoreRepo,
    subject: &str,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> (String, String, String) {
    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: format!("tenant-{}", cuid2()),
            },
            cuid2(),
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
            },
            cuid2(),
        )
        .await
        .expect("project creation should succeed");
    let key_hash = format!("hash-{}", cuid2());
    repo.create_api_key(
        subject,
        NewApiKeyRow {
            id: cuid2(),
            project_id: project.id.clone(),
            name: "k".to_string(),
            key_prefix: "lbk_test".to_string(),
            key_hash: key_hash.clone(),
            created_at: Utc::now(),
            expires_at,
            status: ApiKeyStatus::Active.to_string(),
            last_used_at: None,
            last_ip: None,
            revoked_at: None,
            billing_plan: "free".to_string(),
        },
    )
    .await
    .expect("api key creation should succeed");
    (account.id, project.id, key_hash)
}

async fn effective_status(repo: &StoreRepo, key_hash: &str) -> String {
    repo.find_api_key_validation_by_hash(key_hash)
        .await
        .expect("validation lookup should succeed")
        .expect("validation row should exist")
        .effective_status
}

#[sqlx::test(migrations = "../../migrations")]
async fn suspending_account_invalidates_its_keys(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (account_id, _project_id, key_hash) = seed_key(&repo, subject, None).await;

    assert_eq!(effective_status(&repo, &key_hash).await, "active");

    repo.set_account_status(subject, &account_id, ResourceStatus::Suspended)
        .await
        .expect("suspend should succeed");
    assert_eq!(
        effective_status(&repo, &key_hash).await,
        "account_suspended"
    );

    repo.set_account_status(subject, &account_id, ResourceStatus::Active)
        .await
        .expect("re-enable should succeed");
    assert_eq!(effective_status(&repo, &key_hash).await, "active");
}

#[sqlx::test(migrations = "../../migrations")]
async fn suspending_project_invalidates_its_keys(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (_account_id, project_id, key_hash) = seed_key(&repo, subject, None).await;

    assert_eq!(effective_status(&repo, &key_hash).await, "active");

    repo.set_project_status(subject, &project_id, ResourceStatus::Suspended)
        .await
        .expect("suspend should succeed");
    assert_eq!(
        effective_status(&repo, &key_hash).await,
        "project_suspended"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn expired_key_reports_key_expired(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let past = Utc::now() - chrono::Duration::minutes(5);
    let (_account_id, _project_id, key_hash) = seed_key(&repo, subject, Some(past)).await;

    assert_eq!(effective_status(&repo, &key_hash).await, "key_expired");
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_account_status_requires_membership(pool: PgPool) {
    let repo = build_repo(pool);
    let (account_id, _project_id, _key_hash) = seed_key(&repo, "owner", None).await;

    let err = repo
        .set_account_status("intruder", &account_id, ResourceStatus::Suspended)
        .await
        .expect_err("a non-member must not suspend the account");
    assert!(matches!(
        err,
        lightbridge_authz_core::error::Error::NotFound
    ));
}

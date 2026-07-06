#![cfg(feature = "it-tests")]

use chrono::{Duration, Utc};
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
    (account.id, project.id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn mint_then_consume_returns_context_once(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (account_id, project_id) = seed_project(&repo, subject).await;

    let expires_at = Utc::now() + Duration::minutes(5);
    let request = repo
        .create_identity_request(subject, &project_id, expires_at, format!("req_{}", cuid2()))
        .await
        .expect("mint should succeed for a member");
    assert_eq!(request.account_id, account_id);
    assert_eq!(request.project_id, project_id);
    assert_eq!(request.subject, subject);

    let context = repo
        .consume_identity_request(&request.id, subject)
        .await
        .expect("first consume should resolve context");
    assert_eq!(context.account_id, account_id);
    assert_eq!(context.project_id, project_id);

    let second = repo
        .consume_identity_request(&request.id, subject)
        .await
        .expect_err("single-use: second consume should fail");
    assert!(matches!(second, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_consume_allows_exactly_one(pool: PgPool) {
    let repo = Arc::new(build_repo(pool));
    let subject = "user-1";
    let (_account_id, project_id) = seed_project(&repo, subject).await;

    let expires_at = Utc::now() + Duration::minutes(5);
    let request = repo
        .create_identity_request(subject, &project_id, expires_at, format!("req_{}", cuid2()))
        .await
        .unwrap();

    let first = {
        let repo = repo.clone();
        let id = request.id.clone();
        tokio::spawn(async move { repo.consume_identity_request(&id, subject).await })
    };
    let second = {
        let repo = repo.clone();
        let id = request.id.clone();
        tokio::spawn(async move { repo.consume_identity_request(&id, subject).await })
    };
    let (a, b) = tokio::join!(first, second);
    let results = [a.expect("task a"), b.expect("task b")];

    let ok = results.iter().filter(|r| r.is_ok()).count();
    let not_found = results
        .iter()
        .filter(|r| matches!(r, Err(Error::NotFound)))
        .count();
    assert_eq!(ok, 1, "exactly one concurrent consume must win");
    assert_eq!(
        not_found, 1,
        "the other concurrent consume must get NotFound"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn consume_rejects_wrong_subject_without_consuming(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (_account_id, project_id) = seed_project(&repo, subject).await;

    let expires_at = Utc::now() + Duration::minutes(5);
    let request = repo
        .create_identity_request(subject, &project_id, expires_at, format!("req_{}", cuid2()))
        .await
        .unwrap();

    let wrong = repo
        .consume_identity_request(&request.id, "attacker")
        .await
        .expect_err("subject mismatch should fail");
    assert!(matches!(wrong, Error::NotFound));

    let context = repo
        .consume_identity_request(&request.id, subject)
        .await
        .expect("the legitimate subject can still redeem an unconsumed request");
    assert_eq!(context.project_id, project_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn consume_rejects_expired_request(pool: PgPool) {
    let repo = build_repo(pool);
    let subject = "user-1";
    let (_account_id, project_id) = seed_project(&repo, subject).await;

    let expires_at = Utc::now() - Duration::seconds(1);
    let request = repo
        .create_identity_request(subject, &project_id, expires_at, format!("req_{}", cuid2()))
        .await
        .unwrap();

    let err = repo
        .consume_identity_request(&request.id, subject)
        .await
        .expect_err("expired request should fail");
    assert!(matches!(err, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn mint_rejects_non_member(pool: PgPool) {
    let repo = build_repo(pool);
    let (_account_id, project_id) = seed_project(&repo, "owner").await;

    let expires_at = Utc::now() + Duration::minutes(5);
    let err = repo
        .create_identity_request(
            "outsider",
            &project_id,
            expires_at,
            format!("req_{}", cuid2()),
        )
        .await
        .expect_err("a non-member must not mint for someone else's project");
    assert!(matches!(err, Error::NotFound));
}

#[sqlx::test(migrations = "../../migrations")]
async fn consume_rejects_unknown_request(pool: PgPool) {
    let repo = build_repo(pool);
    let err = repo
        .consume_identity_request("req_does_not_exist", "user-1")
        .await
        .expect_err("unknown request should fail");
    assert!(matches!(err, Error::NotFound));
}

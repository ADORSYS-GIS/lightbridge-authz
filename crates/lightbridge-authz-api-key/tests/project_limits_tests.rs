#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::{CreateAccount, CreateProject, DefaultLimits, UpdateProject};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = "../../migrations")]
async fn test_project_limits_persistence(pool: PgPool) {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    let repo = StoreRepo::new(db_pool);

    let subject = "test-subject";

    // 1. Create Account
    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "test-limits-acct".to_string(),
                owners_admins: vec![],
            },
            "acct_1".to_string(),
        )
        .await
        .unwrap();

    // 2. Create Project with limits
    let limits = DefaultLimits {
        requests_per_second: Some(10),
        requests_per_day: Some(1000),
        concurrent_requests: Some(5),
    };

    let project = repo
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "test-project".to_string(),
                allowed_models: None,
                default_limits: Some(limits.clone()),
                billing_plan: "pro".to_string(),
            },
            "proj_1".to_string(),
        )
        .await
        .unwrap();

    assert_eq!(project.default_limits, Some(limits));

    // 3. Retrieve and verify
    let retrieved = repo
        .get_project(subject, &project.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.default_limits, project.default_limits);

    // 4. Update limits
    let new_limits = DefaultLimits {
        requests_per_second: Some(20),
        requests_per_day: None,
        concurrent_requests: Some(10),
    };

    let updated = repo
        .update_project(
            subject,
            &project.id,
            UpdateProject {
                name: None,
                allowed_models: None,
                default_limits: Some(new_limits.clone()),
                billing_plan: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.default_limits, Some(new_limits.clone()));

    // 5. Verify persistence of update
    let retrieved_updated = repo
        .get_project(subject, &project.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved_updated.default_limits, Some(new_limits));
}

#[sqlx::test(migrations = "../../migrations")]
async fn test_create_project_without_limits_uses_default(pool: PgPool) {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    let repo = StoreRepo::new(db_pool);

    let subject = "test-subject-default-limits";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "test-no-limits-acct".to_string(),
                owners_admins: vec![],
            },
            "acct_default_limits".to_string(),
        )
        .await
        .unwrap();

    let project = repo
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "project-default-limits".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "starter".to_string(),
            },
            "proj_default_limits".to_string(),
        )
        .await
        .unwrap();

    assert_eq!(project.default_limits, Some(DefaultLimits::default()));
}

#[sqlx::test(migrations = "../../migrations")]
async fn test_update_project_clears_allowed_models(pool: PgPool) {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    let repo = StoreRepo::new(db_pool);

    let subject = "test-subject-clear-models";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "test-clear-models-acct".to_string(),
                owners_admins: vec![],
            },
            "acct_clear_models".to_string(),
        )
        .await
        .unwrap();

    let initial_models = vec!["gpt-4.1-mini".to_string()];

    let project = repo
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "project-clear-models".to_string(),
                allowed_models: Some(initial_models.clone()),
                default_limits: None,
                billing_plan: "starter".to_string(),
            },
            "proj_clear_models".to_string(),
        )
        .await
        .unwrap();

    assert_eq!(project.allowed_models, Some(initial_models.clone()));

    let updated = repo
        .update_project(
            subject,
            &project.id,
            UpdateProject {
                name: None,
                allowed_models: Some(None),
                default_limits: None,
                billing_plan: None,
            },
        )
        .await
        .unwrap();

    assert!(updated.allowed_models.is_none());

    let reloaded = repo
        .get_project(subject, &project.id)
        .await
        .unwrap()
        .unwrap();
    assert!(reloaded.allowed_models.is_none());
}

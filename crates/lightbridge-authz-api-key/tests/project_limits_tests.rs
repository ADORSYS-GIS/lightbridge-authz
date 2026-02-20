use std::sync::Arc;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::{CreateAccount, CreateProject, DefaultLimits, UpdateProject};
use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations")]
async fn test_project_limits_persistence(pool: PgPool) {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    let repo = StoreRepo::new(db_pool);

    // 1. Create Account
    let account = repo
        .create_account(
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
    let retrieved = repo.get_project(&project.id).await.unwrap().unwrap();
    assert_eq!(retrieved.default_limits, project.default_limits);

    // 4. Update limits
    let new_limits = DefaultLimits {
        requests_per_second: Some(20),
        requests_per_day: None,
        concurrent_requests: Some(10),
    };

    let updated = repo
        .update_project(
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
    let retrieved_updated = repo.get_project(&project.id).await.unwrap().unwrap();
    assert_eq!(retrieved_updated.default_limits, Some(new_limits));
}

#![cfg(feature = "it-tests")]

use chrono::Utc;
use lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{ApiKeyStatus, CreateAccount, CreateProject};
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = "../../migrations")]
async fn rotate_rolls_back_on_create_failure(pool: PgPool) {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    let repo = StoreRepo::new(db_pool);

    let subject = "test-rotate-rollback";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "rollback-acct".to_string(),
            },
            "acct_rollback".to_string(),
        )
        .await
        .unwrap();

    let project = repo
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "rollback-project".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "starter".to_string(),
            },
            "proj_rollback".to_string(),
        )
        .await
        .unwrap();

    let initial_row = NewApiKeyRow {
        id: cuid2(),
        project_id: project.id.clone(),
        name: "initial".to_string(),
        key_prefix: "lbk_init".to_string(),
        key_hash: "hash_init".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        status: ApiKeyStatus::Active.to_string(),
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
    };

    let api_key = repo.create_api_key(subject, initial_row).await.unwrap();

    let failure_row = NewApiKeyRow {
        id: cuid2(),
        project_id: "missing_proj".to_string(),
        name: "new".to_string(),
        key_prefix: "lbk_new".to_string(),
        key_hash: "hash_new".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        status: ApiKeyStatus::Active.to_string(),
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
    };

    let err = repo
        .rotate_api_key_transaction(
            subject,
            &api_key.id,
            ApiKeyStatus::Revoked,
            Some(Utc::now()),
            None,
            failure_row,
        )
        .await
        .unwrap_err();

    assert!(matches!(err, Error::NotFound));

    let reloaded = repo
        .get_api_key(subject, &api_key.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(reloaded.status, ApiKeyStatus::Active);
    assert!(reloaded.revoked_at.is_none());
}

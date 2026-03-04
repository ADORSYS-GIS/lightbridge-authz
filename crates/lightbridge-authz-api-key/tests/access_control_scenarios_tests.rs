#![cfg(feature = "it-tests")]

use chrono::Utc;
use lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{
    ApiKeyStatus, CreateAccount, CreateProject, UpdateAccount, UpdateApiKey, UpdateProject,
};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    let db_pool = Arc::new(DbPool::from_pool(pool));
    StoreRepo::new(db_pool)
}

fn build_new_api_key_row(project_id: &str, name: &str, key_hash: &str) -> NewApiKeyRow {
    NewApiKeyRow {
        id: cuid2(),
        project_id: project_id.to_string(),
        name: name.to_string(),
        key_prefix: "lbk_test".to_string(),
        key_hash: key_hash.to_string(),
        created_at: Utc::now(),
        expires_at: None,
        status: ApiKeyStatus::Active.to_string(),
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn access_control_allows_members_and_rejects_non_members(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let owner = "owner-sub";
    let invited = "invited-sub";
    let outsider = "outsider-sub";

    let account = repo
        .create_account(
            owner,
            CreateAccount {
                billing_identity: "tenant-a".to_string(),
            },
            "acct_access".to_string(),
        )
        .await
        .unwrap();
    assert!(account.owners_admins.iter().any(|m| m == owner));

    let outsider_accounts = repo.list_accounts(outsider, 0, 50).await.unwrap();
    assert!(outsider_accounts.is_empty());
    assert!(
        repo.get_account(outsider, &account.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_account_update = repo
        .update_account(
            outsider,
            &account.id,
            UpdateAccount {
                billing_identity: Some("hijack".to_string()),
                owners_admins: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_account_update, Error::NotFound));

    let invited_account = repo
        .update_account(
            owner,
            &account.id,
            UpdateAccount {
                billing_identity: None,
                owners_admins: Some(vec![invited.to_string()]),
            },
        )
        .await
        .unwrap();
    assert!(invited_account.owners_admins.iter().any(|m| m == owner));
    assert!(invited_account.owners_admins.iter().any(|m| m == invited));
    assert_eq!(repo.list_accounts(invited, 0, 50).await.unwrap().len(), 1);
    assert_eq!(repo.list_accounts(invited, 1, 50).await.unwrap().len(), 0);

    let project = repo
        .create_project(
            invited,
            &account.id,
            CreateProject {
                name: "proj-a".to_string(),
                allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                default_limits: None,
                billing_plan: "pro".to_string(),
            },
            "proj_access".to_string(),
        )
        .await
        .unwrap();

    let unauthorized_project_create = repo
        .create_project(
            outsider,
            &account.id,
            CreateProject {
                name: "proj-nope".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
            },
            "proj_forbidden".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_project_create, Error::NotFound));
    assert_eq!(
        repo.list_projects(outsider, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        0
    );
    assert!(
        repo.get_project(outsider, &project.id)
            .await
            .unwrap()
            .is_none()
    );

    let updated_project = repo
        .update_project(
            invited,
            &project.id,
            UpdateProject {
                name: Some("proj-a-renamed".to_string()),
                allowed_models: None,
                default_limits: None,
                billing_plan: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(updated_project.name, "proj-a-renamed");

    let unauthorized_project_update = repo
        .update_project(
            outsider,
            &project.id,
            UpdateProject {
                name: Some("illegal".to_string()),
                allowed_models: None,
                default_limits: None,
                billing_plan: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_project_update, Error::NotFound));

    let api_key = repo
        .create_api_key(
            invited,
            build_new_api_key_row(&project.id, "key-a", "hash_access_member"),
        )
        .await
        .unwrap();

    let unauthorized_key_create = repo
        .create_api_key(
            outsider,
            build_new_api_key_row(&project.id, "key-bad", "hash_access_outsider"),
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_key_create, Error::NotFound));
    assert_eq!(
        repo.list_api_keys(outsider, &project.id, 0, 50)
            .await
            .unwrap()
            .len(),
        0
    );
    assert!(
        repo.get_api_key(outsider, &api_key.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_key_update = repo
        .update_api_key(
            outsider,
            &api_key.id,
            UpdateApiKey {
                name: Some("illegal-key".to_string()),
                expires_at: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(unauthorized_key_update, Error::NotFound),
        "unexpected unauthorized_key_update error: {unauthorized_key_update:?}"
    );

    let updated_key = repo
        .update_api_key(
            invited,
            &api_key.id,
            UpdateApiKey {
                name: Some("key-a-renamed".to_string()),
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(updated_key.name, "key-a-renamed");

    let unauthorized_status_update = repo
        .set_api_key_status(
            outsider,
            &api_key.id,
            ApiKeyStatus::Revoked,
            Some(Utc::now()),
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_status_update, Error::NotFound));

    let revoked_key = repo
        .set_api_key_status(
            invited,
            &api_key.id,
            ApiKeyStatus::Revoked,
            Some(Utc::now()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(revoked_key.status, ApiKeyStatus::Revoked);

    let by_hash = repo
        .find_api_key_by_hash(&api_key.key_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_hash.id, api_key.id);

    let usage = repo
        .record_api_key_usage(&api_key.id, Some("203.0.113.5".to_string()))
        .await
        .unwrap();
    assert_eq!(usage.last_ip.as_deref(), Some("203.0.113.5"));
    assert!(usage.last_used_at.is_some());

    let unauthorized_key_delete = repo
        .delete_api_key(outsider, &api_key.id)
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_key_delete, Error::NotFound));
    repo.delete_api_key(invited, &api_key.id).await.unwrap();
    assert!(
        repo.get_api_key(invited, &api_key.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_project_delete = repo
        .delete_project(outsider, &project.id)
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_project_delete, Error::NotFound));
    repo.delete_project(invited, &project.id).await.unwrap();
    assert!(
        repo.get_project(invited, &project.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_account_delete = repo
        .delete_account(outsider, &account.id)
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_account_delete, Error::NotFound));
    repo.delete_account(invited, &account.id).await.unwrap();
    assert!(repo.get_account_by_id(&account.id).await.unwrap().is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_last_membership_deletes_account_projects_and_keys(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "solo-owner";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "tenant-cascade".to_string(),
            },
            "acct_cascade".to_string(),
        )
        .await
        .unwrap();

    let project = repo
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "proj-cascade".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "starter".to_string(),
            },
            "proj_cascade".to_string(),
        )
        .await
        .unwrap();

    let api_key = repo
        .create_api_key(
            subject,
            build_new_api_key_row(&project.id, "key-cascade", "hash_cascade"),
        )
        .await
        .unwrap();

    sqlx::query("DELETE FROM account_memberships WHERE account_id = $1")
        .bind(&account.id)
        .execute(&pool)
        .await
        .unwrap();

    assert!(repo.get_account_by_id(&account.id).await.unwrap().is_none());
    assert!(repo.get_project_by_id(&project.id).await.unwrap().is_none());
    assert!(
        repo.find_api_key_by_hash(&api_key.key_hash)
            .await
            .unwrap()
            .is_none()
    );
}

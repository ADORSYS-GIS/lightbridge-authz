#![cfg(feature = "it-tests")]

use lightbridge_authz_api::contract::AuthzStore;
use lightbridge_authz_core::config::Billing;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{
    ApiKeyStatus, CreateAccount, CreateApiKey, CreateProject, RotateApiKey, UpdateAccount,
    UpdateApiKey, UpdateProject,
};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;
use std::sync::Arc;

fn store(pool: PgPool) -> AuthzStoreImpl {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    AuthzStoreImpl::with_pool(pool).with_billing(Billing {
        plans: vec!["free".to_string(), "pro".to_string()],
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn store_drives_full_account_project_apikey_lifecycle(pool: PgPool) {
    let store = store(pool);
    let subject = "owner-store";

    let account = store
        .create_account(
            subject,
            CreateAccount {
                billing_identity: "tenant-store".to_string(),
            },
        )
        .await
        .expect("create account");
    assert!(store.list_accounts(subject, 0, 50).await.unwrap().len() == 1);
    assert_eq!(
        store.get_account(subject, &account.id).await.unwrap().id,
        account.id
    );

    let account = store
        .update_account(
            subject,
            &account.id,
            UpdateAccount {
                billing_identity: Some("tenant-store-2".to_string()),
                owners_admins: None,
            },
        )
        .await
        .expect("update account");
    assert_eq!(account.billing_identity, "tenant-store-2");

    let project = store
        .create_project(
            subject,
            &account.id,
            CreateProject {
                name: "proj-store".to_string(),
                allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                default_limits: None,
                billing_plan: "free".to_string(),
            },
        )
        .await
        .expect("create project");
    assert_eq!(
        store
            .list_projects(subject, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.get_project(subject, &project.id).await.unwrap().id,
        project.id
    );

    let project = store
        .update_project(
            subject,
            &project.id,
            UpdateProject {
                name: Some("proj-store-renamed".to_string()),
                allowed_models: None,
                default_limits: None,
                billing_plan: None,
            },
        )
        .await
        .expect("update project");
    assert_eq!(project.name, "proj-store-renamed");

    let created = store
        .create_api_key(
            subject,
            None,
            &project.id,
            CreateApiKey {
                name: "key-store".to_string(),
                expires_at: None,
                billing_plan: "free".to_string(),
            },
        )
        .await
        .expect("create api key");
    assert!(
        created.secret.starts_with("lbk_secret_"),
        "issuance disabled should yield an opaque secret, got: {}",
        created.secret
    );
    assert_eq!(created.api_key.billing_plan, "free");
    let key_id = created.api_key.id.clone();

    assert_eq!(
        store
            .list_api_keys(subject, &project.id, 0, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store.get_api_key(subject, &key_id).await.unwrap().id,
        key_id
    );

    let updated = store
        .update_api_key(
            subject,
            &key_id,
            UpdateApiKey {
                name: Some("key-store-renamed".to_string()),
                expires_at: None,
            },
        )
        .await
        .expect("update api key");
    assert_eq!(updated.name, "key-store-renamed");

    let rotated = store
        .rotate_api_key(
            subject,
            None,
            &key_id,
            RotateApiKey {
                name: None,
                expires_at: None,
                grace_period_seconds: Some(60),
            },
        )
        .await
        .expect("rotate api key");
    assert!(rotated.secret.starts_with("lbk_secret_"));
    assert_eq!(
        rotated.api_key.billing_plan, "free",
        "rotation must preserve the billing plan"
    );
    let rotated_id = rotated.api_key.id.clone();

    let revoked = store
        .revoke_api_key(subject, &rotated_id)
        .await
        .expect("revoke api key");
    assert_eq!(revoked.status, ApiKeyStatus::Revoked);

    store
        .delete_api_key(subject, &rotated_id)
        .await
        .expect("delete api key");
    assert!(store.get_api_key(subject, &rotated_id).await.is_err());

    store
        .delete_project(subject, &project.id)
        .await
        .expect("delete project");
    store
        .delete_account(subject, &account.id)
        .await
        .expect("delete account");
    assert!(
        store
            .list_accounts(subject, 0, 50)
            .await
            .unwrap()
            .is_empty()
    );
}

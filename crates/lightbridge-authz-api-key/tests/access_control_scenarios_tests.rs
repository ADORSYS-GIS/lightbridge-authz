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
        // `api_keys.expires_at` is `NOT NULL` (lightbridge-authz#395) -- a real, far-future value
        // here stands in for the pre-#395 "no expiry" fixture.
        expires_at: Some(Utc::now() + chrono::Duration::days(30)),
        status: ApiKeyStatus::Active.to_string(),
        last_used_at: None,
        last_ip: None,
        revoked_at: None,
        billing_plan: "free".to_string(),
    }
}

/// Rewritten per #220: the pre-ADR-0006 version of this test exercised an account-level
/// "invited member" concept (`account_memberships`) that no longer exists -- an account IS its
/// owner, full stop (see the account-scoped assertions below, which are still valid and kept).
/// Project-scoped sharing since ADR-0006 happens exclusively through `project_members`, so
/// "invited" here is seeded as a genuine roster row via `add_project_member` rather than assumed
/// from account co-location. This closes the coverage gap #220 identified: no existing test
/// exercised the full `Project`/`ApiKey` CRUD surface for a real project member against a true
/// outsider (`project_membership_tests.rs` covers roster management and a single-operation
/// (`get_project`) visibility toggle, not this).
///
/// `invited` is seeded as a `lead` (not a plain `member`) specifically so this test also reaches
/// `create_api_key`'s lead gate (`authorize_project_lead`) -- the one operation on this surface
/// that is not "any member", matching production behavior rather than glossing over it.
#[sqlx::test(migrations = "../../migrations")]
async fn access_control_allows_project_members_and_rejects_non_members(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let owner = "owner-sub";
    let invited = "invited-sub";
    let outsider = "outsider-sub";

    let account = repo
        .create_account(
            owner,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .unwrap();
    // ADR-0006: an account IS its owner, so ownership is the id itself rather than a roster.
    assert_eq!(account.id, owner);

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
                default_quota: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_account_update, Error::NotFound));

    let self_account_update = repo
        .update_account(
            owner,
            &account.id,
            UpdateAccount {
                default_quota: None,
            },
        )
        .await
        .unwrap();
    // No account-level roster exists to invite into any more; sharing happens per project.
    assert_eq!(self_account_update.id, owner);
    assert!(repo.list_accounts(owner, 0, 50).await.unwrap().len() == 1);

    // `invited` needs its own account row: `project_members.account_id` is a real FK (ADR-0006 --
    // a project member IS an account, not a raw subject string), so seeding the roster requires a
    // real account to point at first.
    let invited_account = repo
        .create_account(
            invited,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(invited_account.id, invited);

    let project = repo
        .create_project(
            owner,
            &account.id,
            CreateProject {
                name: "proj-a".to_string(),
                allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                default_limits: None,
                billing_plan: "pro".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            "proj_access".to_string(),
        )
        .await
        .unwrap();

    // `create_project` is owner-only -- no `project_members` check exists on it at all -- so
    // neither `invited` (not yet on the roster) nor `outsider` may create a project under
    // `owner`'s account.
    let unauthorized_project_create_by_invited = repo
        .create_project(
            invited,
            &account.id,
            CreateProject {
                name: "proj-nope-invited".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            "proj_forbidden_invited".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized_project_create_by_invited,
        Error::NotFound
    ));
    let unauthorized_project_create_by_outsider = repo
        .create_project(
            outsider,
            &account.id,
            CreateProject {
                name: "proj-nope-outsider".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            "proj_forbidden_outsider".to_string(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized_project_create_by_outsider,
        Error::NotFound
    ));

    // Before `invited` is added to the roster, they see nothing -- identical to `outsider`.
    assert!(
        repo.get_project(invited, &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_project(outsider, &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.list_projects(invited, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        repo.list_projects(outsider, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        0
    );

    // The owner (or an existing lead -- there is none yet, so it must be the owner) grants
    // `invited` a real roster row. This is the ADR-0006 mechanism this test exists to exercise.
    repo.add_project_member(owner, &project.id, &invited_account.id, Some("lead"))
        .await
        .unwrap();

    let seen_by_invited = repo
        .get_project(invited, &project.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen_by_invited.id, project.id);
    assert_eq!(
        repo.list_projects(invited, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        1
    );
    // `outsider` is still not on the roster and remains rejected identically to before.
    assert!(
        repo.get_project(outsider, &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.list_projects(outsider, &account.id, 0, 50)
            .await
            .unwrap()
            .len(),
        0
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
    // ADR-0006 collapses this: there is no member/owner role on an account any more, because an
    // account IS one person. `invited` is simply a different subject, so it gets the same NotFound
    // an outsider does -- no existence leak, and nothing to distinguish "member but not owner".
    let other_subject_delete = repo.delete_account(invited, &account.id).await.unwrap_err();
    assert!(matches!(other_subject_delete, Error::NotFound));

    // And a subject can only ever have one account: the id IS their subject, so a second
    // createAccount is a Conflict rather than a second row.
    let second_attempt = repo
        .create_account(
            owner,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(second_attempt, Error::Conflict(_)));

    repo.delete_account(owner, &account.id).await.unwrap();
    assert!(repo.get_account_by_id(&account.id).await.unwrap().is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_an_account_deletes_its_projects_and_keys(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "solo-owner";

    let account = repo
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
            },
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
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
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

    // Before ADR-0006 the cascade root was the membership table: deleting the last membership row
    // orphaned and removed the account. Membership is gone, and the account row is now the root
    // directly -- one account is one person, so deleting it is the same operation that used to be
    // "remove the last member".
    repo.delete_account(subject, &account.id).await.unwrap();

    assert!(repo.get_account_by_id(&account.id).await.unwrap().is_none());
    assert!(repo.get_project_by_id(&project.id).await.unwrap().is_none());
    assert!(
        repo.find_api_key_by_hash(&api_key.key_hash)
            .await
            .unwrap()
            .is_none()
    );
}

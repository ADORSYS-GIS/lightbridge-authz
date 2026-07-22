#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateAccount, ResourceStatus};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

async fn seed_account(repo: &StoreRepo, owner: &str) -> String {
    repo.create_account(
        owner,
        CreateAccount {
            billing_identity: format!("tenant-{}", cuid2()),
        },
        cuid2(),
    )
    .await
    .expect("account creation should succeed")
    .id
}

#[sqlx::test(migrations = "../../migrations")]
async fn add_member_grants_access(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;
    assert!(
        repo.get_account("invitee", &account_id)
            .await
            .expect("query should succeed")
            .is_none()
    );

    let account = repo
        .add_account_member("owner", &account_id, "invitee", "member")
        .await
        .expect("owner should add a member");
    assert!(account.owners_admins.contains(&"owner".to_string()));
    assert!(account.owners_admins.contains(&"invitee".to_string()));
    assert!(
        repo.get_account("invitee", &account_id)
            .await
            .expect("query should succeed")
            .is_some()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn add_member_is_idempotent(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;

    repo.add_account_member("owner", &account_id, "invitee", "member")
        .await
        .expect("first add succeeds");
    let account = repo
        .add_account_member("owner", &account_id, "invitee", "member")
        .await
        .expect("re-adding is a no-op, not an error");
    let invitee_count = account
        .owners_admins
        .iter()
        .filter(|m| *m == "invitee")
        .count();
    assert_eq!(invitee_count, 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn add_rejects_empty_subject(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;

    let err = repo
        .add_account_member("owner", &account_id, "   ", "member")
        .await
        .expect_err("an empty/whitespace member subject must be rejected");
    assert!(matches!(err, Error::BadRequest(_)));
}

#[sqlx::test(migrations = "../../migrations")]
async fn non_member_cannot_add(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;

    let err = repo
        .add_account_member("stranger", &account_id, "invitee", "member")
        .await
        .expect_err("a non-member must not add members");
    assert!(matches!(err, Error::NotFound));
    assert!(
        repo.get_account("invitee", &account_id)
            .await
            .expect("query should succeed")
            .is_none()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn remove_member_revokes_access(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;
    repo.add_account_member("owner", &account_id, "invitee", "member")
        .await
        .expect("add succeeds");

    let account = repo
        .remove_account_member("owner", &account_id, "invitee")
        .await
        .expect("owner should remove a member");
    assert!(!account.owners_admins.contains(&"invitee".to_string()));
    assert!(
        repo.get_account("invitee", &account_id)
            .await
            .expect("query should succeed")
            .is_none()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cannot_remove_last_member(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;

    let err = repo
        .remove_account_member("owner", &account_id, "owner")
        .await
        .expect_err("removing the last member must be refused");
    assert!(matches!(err, Error::Conflict(_)));
    assert!(
        repo.get_account("owner", &account_id)
            .await
            .expect("query should succeed")
            .is_some()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_removes_cannot_empty_the_account(pool: PgPool) {
    let repo = Arc::new(build_repo(pool));
    let account_id = seed_account(&repo, "owner").await;
    // Both members are "owner" here deliberately: this test exercises the last-member/last-owner
    // race guard itself, not the role gate (an "admin" or "member" invitee removing an "owner"
    // would hit the separate "only an owner can remove another owner" Forbidden path instead of
    // the race condition under test).
    repo.add_account_member("owner", &account_id, "invitee", "owner")
        .await
        .expect("add succeeds");

    let first = {
        let repo = repo.clone();
        let account_id = account_id.clone();
        tokio::spawn(async move {
            repo.remove_account_member("owner", &account_id, "invitee")
                .await
        })
    };
    let second = {
        let repo = repo.clone();
        let account_id = account_id.clone();
        tokio::spawn(async move {
            repo.remove_account_member("invitee", &account_id, "owner")
                .await
        })
    };
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("task 1 joins");
    let second = second.expect("task 2 joins");

    let succeeded = [first.is_ok(), second.is_ok()]
        .into_iter()
        .filter(|ok| *ok)
        .count();
    assert!(succeeded >= 1, "at least one remove should succeed");

    let account = repo
        .get_account_by_id(&account_id)
        .await
        .expect("query should succeed")
        .expect("the account must NOT have been pruned to zero members");
    assert!(
        !account.owners_admins.is_empty(),
        "account must retain at least one member after concurrent removes"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn added_admin_can_manage_the_account(pool: PgPool) {
    // Suspend/resume is owner-or-admin since membership roles landed (previously any member).
    // A plain "member" role is covered separately by `member_role_cannot_suspend_the_account`.
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;
    repo.add_account_member("owner", &account_id, "invitee", "admin")
        .await
        .expect("add succeeds");
    let account = repo
        .set_account_status("invitee", &account_id, ResourceStatus::Suspended)
        .await
        .expect("an admin should be able to suspend the account");
    assert_eq!(account.status, ResourceStatus::Suspended);
}

#[sqlx::test(migrations = "../../migrations")]
async fn member_role_cannot_suspend_the_account(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "owner").await;
    repo.add_account_member("owner", &account_id, "invitee", "member")
        .await
        .expect("add succeeds");
    let err = repo
        .set_account_status("invitee", &account_id, ResourceStatus::Suspended)
        .await
        .expect_err("a plain member must not be able to suspend the account");
    assert!(matches!(err, Error::Forbidden(_)));
}

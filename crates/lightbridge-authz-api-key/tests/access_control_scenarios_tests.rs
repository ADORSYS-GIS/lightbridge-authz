#![cfg(feature = "it-tests")]

use chrono::Utc;
use lightbridge_authz_api_key::entities::new_api_key_row::NewApiKeyRow;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
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
            &AccountId::assert_already_resolved(owner),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    // ADR-0006: an account IS its owner, so ownership is the id itself rather than a roster.
    assert_eq!(account.id, owner);

    let outsider_accounts = repo
        .list_accounts(&AccountId::assert_already_resolved(outsider), 0, 50)
        .await
        .unwrap();
    assert!(outsider_accounts.is_empty());
    assert!(
        repo.get_account(&AccountId::assert_already_resolved(outsider), &account.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_account_update = repo
        .update_account(
            &AccountId::assert_already_resolved(outsider),
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
            &AccountId::assert_already_resolved(owner),
            &account.id,
            UpdateAccount {
                default_quota: None,
            },
        )
        .await
        .unwrap();
    // No account-level roster exists to invite into any more; sharing happens per project.
    assert_eq!(self_account_update.id, owner);
    assert!(
        repo.list_accounts(&AccountId::assert_already_resolved(owner), 0, 50)
            .await
            .unwrap()
            .len()
            == 1
    );

    // `invited` needs its own account row: `project_members.account_id` is a real FK (ADR-0006 --
    // a project member IS an account, not a raw subject string), so seeding the roster requires a
    // real account to point at first.
    let invited_account = repo
        .create_account(
            &AccountId::assert_already_resolved(invited),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(invited_account.id, invited);

    let project = repo
        .create_project(
            &AccountId::assert_already_resolved(owner),
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
            &AccountId::assert_already_resolved(invited),
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
            &AccountId::assert_already_resolved(outsider),
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
        repo.get_project(&AccountId::assert_already_resolved(invited), &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_project(&AccountId::assert_already_resolved(outsider), &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.list_projects(
            &AccountId::assert_already_resolved(invited),
            &account.id,
            0,
            50
        )
        .await
        .unwrap()
        .len(),
        0
    );
    assert_eq!(
        repo.list_projects(
            &AccountId::assert_already_resolved(outsider),
            &account.id,
            0,
            50
        )
        .await
        .unwrap()
        .len(),
        0
    );

    // The owner (or an existing lead -- there is none yet, so it must be the owner) grants
    // `invited` a real roster row. This is the ADR-0006 mechanism this test exists to exercise.
    repo.add_project_member(
        &AccountId::assert_already_resolved(owner),
        &project.id,
        &invited_account.id,
        Some("lead"),
    )
    .await
    .unwrap();

    let seen_by_invited = repo
        .get_project(&AccountId::assert_already_resolved(invited), &project.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen_by_invited.id, project.id);
    assert_eq!(
        repo.list_projects(
            &AccountId::assert_already_resolved(invited),
            &account.id,
            0,
            50
        )
        .await
        .unwrap()
        .len(),
        1
    );
    // `outsider` is still not on the roster and remains rejected identically to before.
    assert!(
        repo.get_project(&AccountId::assert_already_resolved(outsider), &project.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.list_projects(
            &AccountId::assert_already_resolved(outsider),
            &account.id,
            0,
            50
        )
        .await
        .unwrap()
        .len(),
        0
    );

    let updated_project = repo
        .update_project(
            &AccountId::assert_already_resolved(invited),
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
            &AccountId::assert_already_resolved(outsider),
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
            &AccountId::assert_already_resolved(invited),
            build_new_api_key_row(&project.id, "key-a", "hash_access_member"),
        )
        .await
        .unwrap();

    let unauthorized_key_create = repo
        .create_api_key(
            &AccountId::assert_already_resolved(outsider),
            build_new_api_key_row(&project.id, "key-bad", "hash_access_outsider"),
        )
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_key_create, Error::NotFound));
    assert_eq!(
        repo.list_api_keys(
            &AccountId::assert_already_resolved(outsider),
            &project.id,
            0,
            50
        )
        .await
        .unwrap()
        .len(),
        0
    );
    assert!(
        repo.get_api_key(&AccountId::assert_already_resolved(outsider), &api_key.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_key_update = repo
        .update_api_key(
            &AccountId::assert_already_resolved(outsider),
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
            &AccountId::assert_already_resolved(invited),
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
            &AccountId::assert_already_resolved(outsider),
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
            &AccountId::assert_already_resolved(invited),
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

    // `StoreRepo::delete_api_key` (a hand-written hard delete) was removed as dead/unsafe code
    // (PR #429 follow-up) -- the only production api-key delete path is cratestack's generated
    // soft-delete. The ownership half of the `ApiKey` policy's read/update/delete disjunction
    // (`project.account.id == auth().id || project.members.some.accountId == auth().id`) is
    // covered by `api_key_ownership_boundary_refuses_a_non_member_stranger` in
    // `crates/lightbridge-authz-rest/tests/rpc_it_tests.rs`. `api_key` is left active here;
    // `delete_project` below cascade-deletes it (`api_keys.project_id ... ON DELETE CASCADE`,
    // `migrations/20260203000001_init_authz.sql`), so this test still proves the project/account
    // deletion authorization it was already covering.

    let unauthorized_project_delete = repo
        .delete_project(&AccountId::assert_already_resolved(outsider), &project.id)
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_project_delete, Error::NotFound));
    repo.delete_project(&AccountId::assert_already_resolved(invited), &project.id)
        .await
        .unwrap();
    assert!(
        repo.get_project(&AccountId::assert_already_resolved(invited), &project.id)
            .await
            .unwrap()
            .is_none()
    );

    let unauthorized_account_delete = repo
        .delete_account(&AccountId::assert_already_resolved(outsider), &account.id)
        .await
        .unwrap_err();
    assert!(matches!(unauthorized_account_delete, Error::NotFound));
    // ADR-0006 collapses this: there is no member/owner role on an account any more, because an
    // account IS one person. `invited` is simply a different subject, so it gets the same NotFound
    // an outsider does -- no existence leak, and nothing to distinguish "member but not owner".
    let other_subject_delete = repo
        .delete_account(&AccountId::assert_already_resolved(invited), &account.id)
        .await
        .unwrap_err();
    assert!(matches!(other_subject_delete, Error::NotFound));

    // ADR-0026 reverses what this used to assert. A second `createAccount` for the same subject was
    // a `Conflict` (the id WAS the subject, so the second row collided on the primary key); it is
    // now an ordinary success, and the two accounts are distinguished by how they are identified:
    // the first keeps `id = subject` because it anchors the identity, the second gets a minted
    // CUID2 because it anchors nothing.
    let second = repo
        .create_account(
            &AccountId::assert_already_resolved(owner),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    assert_ne!(second.id, account.id, "a second account is a second row");
    assert_ne!(
        second.id, owner,
        "only the identity's ANCHOR account is keyed by the subject"
    );
    assert_eq!(
        second.user_id, account.user_id,
        "both accounts belong to the same person -- this is what the `userId == auth().id` read \
         policy matches on"
    );
    assert_eq!(
        account.user_id, owner,
        "the home account owns itself: the LOAD-BEARING INVARIANT the read policy rests on"
    );

    // Both list for that subject -- issue #563's acceptance criterion, and the thing the old
    // `WHERE id = $1` lookup could not do however the policy was written.
    let owned = repo
        .list_accounts(&AccountId::assert_already_resolved(owner), 0, 50)
        .await
        .unwrap();
    let mut owned_ids: Vec<&str> = owned.iter().map(|a| a.id.as_str()).collect();
    owned_ids.sort_unstable();
    let mut expected = vec![account.id.as_str(), second.id.as_str()];
    expected.sort_unstable();
    assert_eq!(owned_ids, expected, "an owner sees every account they own");

    // A stranger sees neither of them -- by OWNERSHIP now, not by identity equality. (`invited`
    // holds an account of their own from earlier in this test, so the assertion is "none of
    // owner's", not "nothing at all" -- which is also the sharper property: the widened
    // `user_id`-scoped lookup must not have widened into someone else's rows.)
    let invited_sees = repo
        .list_accounts(&AccountId::assert_already_resolved(invited), 0, 50)
        .await
        .unwrap();
    assert!(
        !invited_sees
            .iter()
            .any(|a| a.id == account.id || a.id == second.id),
        "ownership-scoped listing must not leak another person's accounts: {invited_sees:?}"
    );
    assert!(
        repo.get_account(&AccountId::assert_already_resolved(invited), &second.id)
            .await
            .unwrap()
            .is_none(),
        "a secondary account is no more reachable to an outsider than a primary one"
    );

    // The anchor cannot be deleted out from under the account it owns -- doing so would cascade
    // away the `federated_identities` row and strand `second` permanently.
    let orphaning_delete = repo
        .delete_account(&AccountId::assert_already_resolved(owner), &account.id)
        .await
        .unwrap_err();
    assert!(
        matches!(orphaning_delete, Error::BadRequest(_)),
        "deleting the primary while others are owned must be refused explicitly, not surface as \
         NotFound: got {orphaning_delete:?}"
    );

    // Delete the secondary first, and the primary becomes deletable again exactly as before.
    repo.delete_account(&AccountId::assert_already_resolved(owner), &second.id)
        .await
        .unwrap();
    repo.delete_account(&AccountId::assert_already_resolved(owner), &account.id)
        .await
        .unwrap();
    assert!(repo.get_account_by_id(&account.id).await.unwrap().is_none());
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_an_account_deletes_its_projects_and_keys(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "solo-owner";

    let account = repo
        .create_account(
            &AccountId::assert_already_resolved(subject),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();

    let project = repo
        .create_project(
            &AccountId::assert_already_resolved(subject),
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
            &AccountId::assert_already_resolved(subject),
            build_new_api_key_row(&project.id, "key-cascade", "hash_cascade"),
        )
        .await
        .unwrap();

    // Before ADR-0006 the cascade root was the membership table: deleting the last membership row
    // orphaned and removed the account. Membership is gone, and the account row is now the root
    // directly -- one account is one person, so deleting it is the same operation that used to be
    // "remove the last member".
    repo.delete_account(&AccountId::assert_already_resolved(subject), &account.id)
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

/// Issue #563's "policies grant the owner the same rights on both" criterion, at the level the
/// cratestack `@@allow` clauses cannot reach: the hand-written procedure surface.
///
/// Every ownership check in `repo.rs` used to read `projects.account_id = <acting account>`, which
/// silently means "the project's account IS me". Once a person owns a second account, a project
/// inside it is theirs but its `account_id` is NOT their acting id, so every one of those checks
/// would have returned `NotFound` on the owner's own project. This pins the widened form (compare
/// by OWNER, via `accounts.user_id`) across the three shapes that matter: a lead-gated mutation
/// (`create_api_key` -> `authorize_project_lead`), a project-scoped read (`list_api_keys`), and a
/// project mutation (`update_project`).
#[sqlx::test(migrations = "../../migrations")]
async fn an_owner_has_the_same_rights_inside_a_secondary_account(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let owner = "multi-owner";
    let stranger = "stranger-sub";

    let anchor = repo
        .create_account(
            &AccountId::assert_already_resolved(owner),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    let secondary = repo
        .create_account(
            &AccountId::assert_already_resolved(owner),
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .unwrap();
    assert_ne!(secondary.id, anchor.id);

    let project = repo
        .create_project(
            &AccountId::assert_already_resolved(owner),
            &secondary.id,
            CreateProject {
                name: "inside-the-second-account".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "pro".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            "proj_secondary".to_string(),
        )
        .await
        .expect("the owner must be able to create a project in an account they own");

    let key = repo
        .create_api_key(
            &AccountId::assert_already_resolved(owner),
            build_new_api_key_row(&project.id, "secondary-key", "hash_secondary_owner"),
        )
        .await
        .expect("minting a key in an owned account's project must be authorized by ownership");

    let listed = repo
        .list_api_keys(
            &AccountId::assert_already_resolved(owner),
            &project.id,
            0,
            50,
        )
        .await
        .unwrap();
    assert!(listed.iter().any(|k| k.id == key.id));

    repo.update_project(
        &AccountId::assert_already_resolved(owner),
        &project.id,
        UpdateProject {
            name: Some("renamed".to_string()),
            allowed_models: None,
            default_limits: None,
            billing_plan: None,
        },
    )
    .await
    .expect("the owner must be able to update a project in an account they own");

    // Widening by owner must not widen to anyone else: a stranger holding their own account has a
    // different `user_id`, so none of the three paths open up.
    repo.create_account(
        &AccountId::assert_already_resolved(stranger),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .unwrap();
    let stranger_key_create = repo
        .create_api_key(
            &AccountId::assert_already_resolved(stranger),
            build_new_api_key_row(&project.id, "nope", "hash_stranger"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(stranger_key_create, Error::NotFound),
        "ownership widening must not leak across owners: got {stranger_key_create:?}"
    );
    assert!(
        repo.list_api_keys(
            &AccountId::assert_already_resolved(stranger),
            &project.id,
            0,
            50
        )
        .await
        .unwrap()
        .is_empty()
    );
}

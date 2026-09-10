// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! DB-backed coverage for `platform_role_grants` (ADR-0033): the mint-path read, the idempotent
//! grant, the CAS revoke, the partial-unique-index contract, the listing filters, and the email →
//! person resolver the `rbac` CLI's ambiguity refusal is built on.
//!
//! The properties pinned here are the ones the story calls non-negotiable: a grant is idempotent,
//! a revoked grant frees the (user, role) pair for a fresh one, a second revoke of the same grant
//! does NOT re-stamp `revoked_at` over the audit fact, a person with no grants reads back an empty
//! list (never an error), and an email matching two people resolves to two rows so the caller can
//! refuse rather than guess.

use lightbridge_authz_api_key::entities::platform_role_grant_row::{
    NewPlatformRoleGrant, PlatformRoleGrantFilter,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use sqlx::PgPool;
use std::sync::Arc;

const ADMIN: &str = "lightbridge-admin";
const VIEWER: &str = "lightbridge-viewer";

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

/// Seeds an account whose `accounts_set_user` trigger provisions `users.id == subject`, so the
/// returned value is BOTH the account id and the person id — the grandfathered shape every
/// pre-ADR-0026 row has.
async fn seed_person(repo: &StoreRepo, subject: &str) -> String {
    repo.create_account(
        &AccountId::assert_already_resolved(subject),
        CreateAccount {
            default_quota: None,
            name: None,
        },
    )
    .await
    .expect("account creation should succeed");
    subject.to_string()
}

fn new_grant(user_id: &str, role: &str, granted_by: Option<&str>) -> NewPlatformRoleGrant {
    NewPlatformRoleGrant {
        id: cuid2(),
        user_id: user_id.to_string(),
        role: role.to_string(),
        granted_by: granted_by.map(str::to_string),
        reason: Some("because the story says so".to_string()),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_person_with_no_grants_reads_back_empty_not_an_error(pool: PgPool) {
    let repo = build_repo(pool);
    let user = seed_person(&repo, &format!("nobody-{}", cuid2())).await;
    assert_eq!(
        repo.active_platform_roles_for_user(&user).await.unwrap(),
        Vec::<String>::new(),
        "an empty grant set is an ANSWER, not a lookup failure -- the claim mapper's fail-closed \
         refusal must fire only on a database error"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn granting_twice_returns_the_same_row_and_keeps_the_original_reason(pool: PgPool) {
    let repo = build_repo(pool);
    let user = seed_person(&repo, &format!("idem-{}", cuid2())).await;

    let first = repo
        .grant_platform_role(new_grant(&user, ADMIN, None))
        .await
        .unwrap();
    let second = repo
        .grant_platform_role(NewPlatformRoleGrant {
            reason: Some("a different reason nobody asked to record".to_string()),
            ..new_grant(&user, ADMIN, Some("someone-else"))
        })
        .await
        .unwrap();

    assert_eq!(
        first.id, second.id,
        "a repeat grant must return the EXISTING row, not mint a second one"
    );
    assert_eq!(
        second.reason.as_deref(),
        Some("because the story says so"),
        "a repeat grant is not a new decision: the original reason and granter stand"
    );
    assert_eq!(second.granted_by, None);
    assert_eq!(
        repo.active_platform_roles_for_user(&user).await.unwrap(),
        vec![ADMIN.to_string()],
        "one active row, not two"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_partial_unique_index_permits_regranting_after_a_revoke(pool: PgPool) {
    let repo = build_repo(pool);
    let user = seed_person(&repo, &format!("regrant-{}", cuid2())).await;

    let first = repo
        .grant_platform_role(new_grant(&user, ADMIN, None))
        .await
        .unwrap();
    repo.revoke_platform_role(&first.id, Some("offboarded"))
        .await
        .unwrap()
        .expect("the active grant is revocable");
    assert_eq!(
        repo.active_platform_roles_for_user(&user).await.unwrap(),
        Vec::<String>::new()
    );

    let second = repo
        .grant_platform_role(new_grant(&user, ADMIN, None))
        .await
        .unwrap();
    assert_ne!(
        first.id, second.id,
        "the index is partial over ACTIVE rows, so grant -> revoke -> grant is a normal history, \
         not a conflict"
    );

    let history = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(user.clone()),
            include_revoked: true,
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(history.len(), 2, "both rows survive: {history:?}");
    assert_eq!(history.iter().filter(|row| row.is_active()).count(), 1);
}

#[sqlx::test(migrations = "../../migrations")]
async fn revoking_twice_does_not_overwrite_the_original_revocation_timestamp(pool: PgPool) {
    let repo = build_repo(pool);
    let user = seed_person(&repo, &format!("double-revoke-{}", cuid2())).await;
    let grant = repo
        .grant_platform_role(new_grant(&user, ADMIN, None))
        .await
        .unwrap();

    let first = repo
        .revoke_platform_role(&grant.id, Some("first"))
        .await
        .unwrap()
        .expect("the active grant is revocable");
    let second = repo
        .revoke_platform_role(&grant.id, Some("second"))
        .await
        .unwrap();

    assert!(
        second.is_none(),
        "a second revoke must be a no-op, not a re-stamp: the original revoked_at IS the audit \
         fact this table exists to record"
    );
    let history = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(user),
            include_revoked: true,
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(history[0].revoked_at, first.revoked_at);
    assert_eq!(history[0].reason.as_deref(), Some("first"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn revoking_an_unknown_grant_id_is_none_not_an_error(pool: PgPool) {
    let repo = build_repo(pool);
    assert!(
        repo.revoke_platform_role("definitely-not-a-grant", None)
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn granting_to_an_unknown_person_is_refused_before_the_foreign_key(pool: PgPool) {
    let repo = build_repo(pool);
    let err = repo
        .grant_platform_role(new_grant("no-such-person", ADMIN, None))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadRequest(ref message) if message.contains("no-such-person")),
        "an unknown user must be a clean, self-explaining refusal, never an opaque 23503: {err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_listing_filters_and_defaults_to_active_only(pool: PgPool) {
    let repo = build_repo(pool);
    let alice = seed_person(&repo, &format!("alice-{}", cuid2())).await;
    let bob = seed_person(&repo, &format!("bob-{}", cuid2())).await;

    let alice_admin = repo
        .grant_platform_role(new_grant(&alice, ADMIN, None))
        .await
        .unwrap();
    repo.grant_platform_role(new_grant(&alice, VIEWER, Some(&bob)))
        .await
        .unwrap();
    repo.grant_platform_role(new_grant(&bob, ADMIN, None))
        .await
        .unwrap();
    repo.revoke_platform_role(&alice_admin.id, None)
        .await
        .unwrap()
        .unwrap();

    let admins = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            role: Some(ADMIN.to_string()),
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert!(
        admins.iter().all(|row| row.user_id != alice),
        "alice's admin grant is revoked, so the default (active-only) view must not show it: \
         {admins:?}"
    );
    assert!(admins.iter().any(|row| row.user_id == bob));

    let alice_all = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(alice.clone()),
            include_revoked: true,
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(
        alice_all.len(),
        2,
        "audit view shows the history: {alice_all:?}"
    );

    // Newest first, and the cursor walks strictly backwards from it.
    let page = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(alice.clone()),
            include_revoked: true,
            limit: Some(1),
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    let next = repo
        .list_platform_role_grants(&PlatformRoleGrantFilter {
            user_id: Some(alice),
            include_revoked: true,
            after: Some(page[0].granted_at),
            ..PlatformRoleGrantFilter::default()
        })
        .await
        .unwrap();
    assert!(
        next.iter().all(|row| row.granted_at < page[0].granted_at),
        "the cursor is exclusive: {next:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_limit_over_the_ceiling_clamps_rather_than_erroring(pool: PgPool) {
    let filter = PlatformRoleGrantFilter {
        limit: Some(10_000),
        ..PlatformRoleGrantFilter::default()
    };
    assert_eq!(filter.page_size(), 200);
    assert_eq!(
        PlatformRoleGrantFilter::default().page_size(),
        50,
        "the default page size is the documented one"
    );
    // The clamped query still runs against a real database rather than only being unit-asserted.
    let repo = build_repo(pool);
    assert!(
        repo.list_platform_role_grants(&filter)
            .await
            .unwrap()
            .is_empty()
    );
}

/// The CLI's ambiguity refusal depends entirely on this returning EVERY match rather than picking
/// one: two people can genuinely share an email string, because `federated_identities` is unique on
/// `(issuer, subject)`, not on `email`.
#[sqlx::test(migrations = "../../migrations")]
async fn an_email_shared_by_two_people_resolves_to_two_rows(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let one = seed_person(&repo, &format!("shared-one-{}", cuid2())).await;
    let two = seed_person(&repo, &format!("shared-two-{}", cuid2())).await;
    let email = format!("Shared.{}@example.com", cuid2());

    for (index, account) in [&one, &two].into_iter().enumerate() {
        sqlx::query(
            r#"
            INSERT INTO federated_identities
                (id, issuer, subject, account_id, email, email_verified, name,
                 last_authenticated_at, created_at, updated_at)
            VALUES ($1, $2, $3, $3, $4, true, 'Shared Person', now(), now(), now())
            "#,
        )
        .bind(cuid2())
        .bind(format!("https://issuer-{index}.example"))
        .bind(account)
        .bind(&email)
        .execute(&pool)
        .await
        .unwrap();
    }

    // Deliberately searched in a different case from the one stored, to pin the
    // case-insensitivity an operator typing an address by hand depends on.
    let matches = repo
        .find_users_by_email(&email.to_lowercase())
        .await
        .unwrap();
    assert_eq!(
        matches.len(),
        2,
        "both people must come back so the caller can REFUSE rather than guess: {matches:?}"
    );
    assert!(matches.iter().any(|row| row.user_id == one));
    assert!(matches.iter().any(|row| row.user_id == two));

    assert!(
        repo.find_users_by_email("nobody@example.com")
            .await
            .unwrap()
            .is_empty()
    );
}

/// ADR-0026: a platform role follows the PERSON across every account they own, and revocation's
/// session fan-out needs all of them.
#[sqlx::test(migrations = "../../migrations")]
async fn one_person_many_accounts_resolves_both_directions(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let home = seed_person(&repo, &format!("many-{}", cuid2())).await;
    let second_account = cuid2();
    sqlx::query(
        "INSERT INTO accounts (id, user_id, created_at, updated_at) VALUES ($1, $2, now(), now())",
    )
    .bind(&second_account)
    .bind(&home)
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        repo.resolve_user_id_for_account(&second_account)
            .await
            .unwrap(),
        Some(home.clone()),
        "the second account resolves to the SAME person, not to itself"
    );
    let mut accounts = repo.account_ids_for_user(&home).await.unwrap();
    accounts.sort();
    let mut expected = vec![home.clone(), second_account];
    expected.sort();
    assert_eq!(accounts, expected);

    assert_eq!(
        repo.resolve_user_id_for_account("no-such-account")
            .await
            .unwrap(),
        None,
        "an unknown account resolves to None -- never to a fabricated id"
    );
    assert!(repo.user_exists(&home).await.unwrap());
    assert!(!repo.user_exists("no-such-person").await.unwrap());
}

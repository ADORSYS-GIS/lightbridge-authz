// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! DB-backed coverage for admin identity resolution (#647):
//! `resolve_user_profiles` / `resolve_account_labels` / `resolve_project_labels` /
//! `search_user_profiles`, the four queries behind the `resolveUserProfiles`,
//! `resolveActorLabels` and `searchUsers` procedures.
//!
//! The properties pinned here are the ones the story calls non-negotiable: an unknown id is
//! ABSENT rather than fabricated, a known user with no federated identity still resolves (to three
//! nulls), a user holding several identities resolves to the most recently updated one, an
//! over-cap batch is REJECTED rather than silently truncated, and search is bounded, matches all
//! three display columns, and orders deterministically.

use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_api_key::entities::identity_label_row::{
    MAX_IDENTITY_BATCH, MAX_USER_SEARCH_LIMIT,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

fn at(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, 12, 0, 0).unwrap()
}

/// Seeds an anchor account (`accounts.id == subject`, so `accounts.user_id` is provisioned to the
/// same value by the `accounts_set_user` trigger — i.e. the user id IS `subject`).
async fn seed_account(repo: &StoreRepo, subject: &str) -> String {
    repo.create_account(
        &AccountId::assert_already_resolved(subject),
        CreateAccount {
            default_quota: None,
            name: Some(format!("{subject}'s account")),
        },
    )
    .await
    .expect("account creation should succeed")
    .id
}

/// Raw insert rather than `upsert_federated_identity`, so a test can own `updated_at` exactly —
/// the column the "several identities, pick the freshest" rule turns on — and can attach a second
/// identity to a second account owned by the same person.
async fn seed_identity(
    pool: &PgPool,
    account_id: &str,
    name: Option<&str>,
    email: Option<&str>,
    username: Option<&str>,
    updated_at: DateTime<Utc>,
) {
    sqlx::query(
        r#"
        INSERT INTO federated_identities
            (id, issuer, subject, account_id, email, email_verified, preferred_username, name,
             last_authenticated_at, created_at, updated_at)
        VALUES ($1, 'https://issuer.example', $2, $2, $3, true, $4, $5, $6, $6, $6)
        "#,
    )
    .bind(cuid2())
    .bind(account_id)
    .bind(email)
    .bind(username)
    .bind(name)
    .bind(updated_at)
    .execute(pool)
    .await
    .expect("seeding a federated identity should succeed");
}

/// A second account for an EXISTING person: `user_id` supplied explicitly, which the
/// `accounts_set_user` trigger leaves alone (20260830000003).
async fn seed_extra_account_for(pool: &PgPool, account_id: &str, owner_user_id: &str) {
    sqlx::query(
        r#"
        INSERT INTO accounts (id, user_id, default_quota, name, created_at, updated_at)
        VALUES ($1, $2, NULL, NULL, now(), now())
        "#,
    )
    .bind(account_id)
    .bind(owner_user_id)
    .execute(pool)
    .await
    .expect("seeding a second account should succeed");
}

#[sqlx::test(migrations = "../../migrations")]
async fn resolve_user_profiles_returns_claims_and_omits_unknown_ids(pool: PgPool) {
    let repo = build_repo(pool.clone());
    seed_account(&repo, "known-user").await;
    seed_identity(
        &pool,
        "known-user",
        Some("Stephane Segning"),
        Some("selast@example.com"),
        Some("selast"),
        at(1),
    )
    .await;

    let profiles = repo
        .resolve_user_profiles(&[
            "known-user".to_string(),
            "no-such-user".to_string(),
            "also-missing".to_string(),
        ])
        .await
        .expect("resolving should succeed");

    assert_eq!(
        profiles.len(),
        1,
        "the two unknown ids must be absent, never placeholder rows: {profiles:?}"
    );
    let profile = &profiles[0];
    assert_eq!(profile.user_id, "known-user");
    assert_eq!(profile.display_name.as_deref(), Some("Stephane Segning"));
    assert_eq!(profile.email.as_deref(), Some("selast@example.com"));
    assert_eq!(profile.username.as_deref(), Some("selast"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_with_no_federated_identity_still_resolves_to_three_nulls(pool: PgPool) {
    let repo = build_repo(pool);
    seed_account(&repo, "claimless-user").await;

    let profiles = repo
        .resolve_user_profiles(&["claimless-user".to_string()])
        .await
        .expect("resolving should succeed");

    assert_eq!(
        profiles.len(),
        1,
        "the user itself is known, so it resolves"
    );
    assert_eq!(profiles[0].user_id, "claimless-user");
    assert_eq!(profiles[0].display_name, None);
    assert_eq!(profiles[0].email, None);
    assert_eq!(profiles[0].username, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_with_several_identities_resolves_to_the_most_recently_updated(pool: PgPool) {
    let repo = build_repo(pool.clone());
    seed_account(&repo, "multi-user").await;
    seed_identity(
        &pool,
        "multi-user",
        Some("Stale Name"),
        Some("stale@example.com"),
        Some("stale"),
        at(1),
    )
    .await;

    let second_account = cuid2();
    seed_extra_account_for(&pool, &second_account, "multi-user").await;
    seed_identity(
        &pool,
        &second_account,
        Some("Fresh Name"),
        Some("fresh@example.com"),
        Some("fresh"),
        at(9),
    )
    .await;

    let profiles = repo
        .resolve_user_profiles(&["multi-user".to_string()])
        .await
        .expect("resolving should succeed");

    assert_eq!(
        profiles.len(),
        1,
        "one row per user, never one per identity"
    );
    assert_eq!(profiles[0].display_name.as_deref(), Some("Fresh Name"));
    assert_eq!(profiles[0].email.as_deref(), Some("fresh@example.com"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_batch_over_the_cap_is_rejected_not_truncated(pool: PgPool) {
    let repo = build_repo(pool);
    let too_many: Vec<String> = (0..=MAX_IDENTITY_BATCH).map(|i| format!("u{i}")).collect();

    let err = repo
        .resolve_user_profiles(&too_many)
        .await
        .expect_err("an over-cap batch must be refused");
    assert!(
        matches!(err, Error::BadRequest(_)),
        "expected Error::BadRequest, got {err:?}"
    );

    // Same contract on the other two kinds — a truncated label batch is just as misleading.
    assert!(matches!(
        repo.resolve_account_labels(&too_many).await.unwrap_err(),
        Error::BadRequest(_)
    ));
    assert!(matches!(
        repo.resolve_project_labels(&too_many).await.unwrap_err(),
        Error::BadRequest(_)
    ));
}

#[sqlx::test(migrations = "../../migrations")]
async fn account_and_project_labels_resolve_estate_wide_with_no_ownership_filter(pool: PgPool) {
    let repo = build_repo(pool);
    let account_id = seed_account(&repo, "labelled-owner").await;
    let project = repo
        .create_project(
            &AccountId::assert_already_resolved("labelled-owner"),
            &account_id,
            CreateProject {
                name: "Atlas".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            cuid2(),
        )
        .await
        .expect("project creation should succeed");

    let accounts = repo
        .resolve_account_labels(&[account_id.clone(), "no-such-account".to_string()])
        .await
        .expect("resolving accounts should succeed");
    assert_eq!(accounts.len(), 1, "unknown account ids are absent");
    assert_eq!(accounts[0].account_id, account_id);
    assert_eq!(
        accounts[0].name.as_deref(),
        Some("labelled-owner's account")
    );
    assert_eq!(
        accounts[0].owner_user_id, "labelled-owner",
        "the owner edge is what lets a console chain to the user lens"
    );

    let projects = repo
        .resolve_project_labels(&[project.id.clone(), "no-such-project".to_string()])
        .await
        .expect("resolving projects should succeed");
    assert_eq!(projects.len(), 1, "unknown project ids are absent");
    assert_eq!(projects[0].project_id, project.id);
    assert_eq!(projects[0].name, "Atlas");
    assert_eq!(projects[0].account_id, account_id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_matches_name_email_and_username_case_insensitively(pool: PgPool) {
    let repo = build_repo(pool.clone());
    for (subject, name, email, username) in [
        ("by-name", "Zadie Nkeng", "zn@example.com", "zadie"),
        ("by-email", "Someone Else", "findme@example.com", "someone"),
        (
            "by-username",
            "Third Person",
            "third@example.com",
            "findme2",
        ),
        ("no-match", "Nobody", "nobody@example.com", "nobody"),
    ] {
        seed_account(&repo, subject).await;
        seed_identity(
            &pool,
            subject,
            Some(name),
            Some(email),
            Some(username),
            at(1),
        )
        .await;
    }

    let by_name = repo.search_user_profiles("ZADIE", None).await.unwrap();
    assert_eq!(
        by_name.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["by-name"],
        "name matching must be case-insensitive"
    );

    let by_email = repo.search_user_profiles("FiNdMe@", None).await.unwrap();
    assert_eq!(
        by_email.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["by-email"]
    );

    let by_username = repo.search_user_profiles("findme2", None).await.unwrap();
    assert_eq!(
        by_username.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["by-username"]
    );

    // Substring, not just prefix: "erson" appears mid-word in "Third Person".
    let by_substring = repo.search_user_profiles("erson", None).await.unwrap();
    assert_eq!(
        by_substring.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["by-username"]
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_clamps_the_limit_rejects_a_short_query_and_orders_deterministically(pool: PgPool) {
    let repo = build_repo(pool.clone());
    // 60 matches, above MAX_USER_SEARCH_LIMIT (50), so the clamp is observable.
    for i in 0..60 {
        let subject = format!("match-{i:02}");
        seed_account(&repo, &subject).await;
        seed_identity(
            &pool,
            &subject,
            Some(&format!("Needle Person {i:02}")),
            Some(&format!("needle{i:02}@example.com")),
            Some(&format!("needle{i:02}")),
            at(1),
        )
        .await;
    }

    let defaulted = repo.search_user_profiles("needle", None).await.unwrap();
    assert_eq!(defaulted.len(), 20, "the documented default limit applies");

    let clamped = repo
        .search_user_profiles("needle", Some(500))
        .await
        .unwrap();
    assert_eq!(
        i64::try_from(clamped.len()).unwrap(),
        MAX_USER_SEARCH_LIMIT,
        "an over-max limit is clamped, never honoured"
    );

    let first = repo.search_user_profiles("needle", Some(5)).await.unwrap();
    let again = repo.search_user_profiles("needle", Some(5)).await.unwrap();
    assert_eq!(first, again, "order must not depend on physical row order");
    assert_eq!(
        first.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["match-00", "match-01", "match-02", "match-03", "match-04"],
        "ties break by label then user id, so the order is fully specified"
    );

    let err = repo
        .search_user_profiles("n", None)
        .await
        .expect_err("a one-character query must be refused");
    assert!(
        matches!(err, Error::BadRequest(_)),
        "expected Error::BadRequest, got {err:?}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn search_treats_like_metacharacters_as_literal_text(pool: PgPool) {
    let repo = build_repo(pool.clone());
    seed_account(&repo, "percent-user").await;
    seed_identity(
        &pool,
        "percent-user",
        Some("100% Cotton"),
        Some("cotton@example.com"),
        Some("cotton"),
        at(1),
    )
    .await;
    seed_account(&repo, "other-user").await;
    seed_identity(
        &pool,
        "other-user",
        Some("Unrelated"),
        Some("unrelated@example.com"),
        Some("unrelated"),
        at(1),
    )
    .await;

    let hits = repo.search_user_profiles("0% c", None).await.unwrap();
    assert_eq!(
        hits.iter().map(|p| &p.user_id).collect::<Vec<_>>(),
        vec!["percent-user"],
        "a `%` in the query is literal text, not a wildcard that matches everyone"
    );
}

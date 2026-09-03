// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! DB-backed coverage for `StoreRepo::resolve_api_key_labels` — the query behind
//! `resolveActorLabels`' `apiKeyIds` kind (#647, owner feedback 2026-09-03).
//!
//! The properties pinned here are this query's own, NOT the authorization above it: visibility is
//! decided by the caller (`actor_api_key_labels.rs` reads the ids through `db.api_key()` first), and
//! the end-to-end row-scoping — admin resolves a foreign key, a member resolves their project's, a
//! stranger gets an empty list rather than a 403 — is `rpc_it_tests.rs`'
//! `resolve_actor_labels_names_api_keys_row_scoped_without_user_read`.
//!
//! What IS this query's own: the account edge the `ApiKey` model has no relation path for, the
//! derived `revoked` flag, an unknown id being ABSENT rather than fabricated, a soft-deleted key
//! still resolving (the label a usage row for a deleted key needs), and the 200-id cap being
//! REJECTED rather than truncated.

use lightbridge_authz_api_key::entities::identity_label_row::MAX_IDENTITY_BATCH;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::CreateProject;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use sqlx::PgPool;
use std::sync::Arc;

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

/// An account plus one project under it. `accounts.id == subject`, so the `accounts_set_user`
/// trigger provisions `accounts.user_id` to the same value.
async fn seed_account_and_project(repo: &StoreRepo, subject: &str) -> (String, String) {
    let account_id = repo
        .create_account(
            &AccountId::assert_already_resolved(subject),
            CreateAccount {
                default_quota: None,
                name: Some(format!("{subject}'s account")),
            },
        )
        .await
        .expect("account creation should succeed")
        .id;
    let project = repo
        .create_project(
            &AccountId::assert_already_resolved(subject),
            &account_id,
            CreateProject {
                name: format!("{subject}-project"),
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
    (account_id, project.id)
}

/// Raw insert rather than `create_api_key`, so a test can own `status`/`revoked_at`/`deleted_at`
/// exactly — the three columns the derived `revoked` flag and the soft-delete rule turn on.
#[allow(clippy::too_many_arguments)]
async fn seed_api_key(
    pool: &PgPool,
    project_id: &str,
    owner_account_id: &str,
    name: &str,
    status: &str,
    revoked: bool,
    soft_deleted: bool,
) -> String {
    let id = cuid2();
    sqlx::query(
        r#"
        INSERT INTO api_keys
            (id, project_id, name, key_prefix, key_hash, created_at, expires_at, status,
             last_used_at, last_ip, revoked_at, billing_plan, owner_account_id, updated_at,
             deleted_at)
        VALUES ($1, $2, $3, 'lb_test', $4, now(), now() + interval '30 days', $5,
                NULL, NULL, CASE WHEN $6 THEN now() ELSE NULL END, 'free', $7, now(),
                CASE WHEN $8 THEN now() ELSE NULL END)
        "#,
    )
    .bind(&id)
    .bind(project_id)
    .bind(name)
    .bind(format!("hash-{}", cuid2()))
    .bind(status)
    .bind(revoked)
    .bind(owner_account_id)
    .bind(soft_deleted)
    .execute(pool)
    .await
    .expect("seeding an api key should succeed");
    id
}

#[sqlx::test(migrations = "../../migrations")]
async fn labels_carry_the_account_edge_and_omit_unknown_ids(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let (account_id, project_id) =
        seed_account_and_project(&repo, &format!("keys-{}", cuid2())).await;
    let key_id = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "Production ingest",
        "active",
        false,
        false,
    )
    .await;

    let labels = repo
        .resolve_api_key_labels(&[key_id.clone(), "no-such-key".to_string()])
        .await
        .expect("resolving api key labels should succeed");

    assert_eq!(
        labels.len(),
        1,
        "the unknown id must be absent, never a placeholder row: {labels:?}"
    );
    let label = &labels[0];
    assert_eq!(label.api_key_id, key_id);
    assert_eq!(label.name, "Production ingest");
    assert_eq!(label.project_id, project_id);
    assert_eq!(
        label.account_id, account_id,
        "the account edge is the whole reason this is a JOIN rather than a `db.api_key()` read — \
         the ApiKey model has no relation path to Account"
    );
    assert!(!label.revoked, "an active key is not revoked");
}

/// `revoked` is DERIVED, and from EITHER signal: `revoke_api_key` stamps `revoked_at` and flips
/// `status`, but a row that carries only one of the two (a hand-repaired row, a future status this
/// enum does not know) must still read as unusable rather than as a live cost centre.
#[sqlx::test(migrations = "../../migrations")]
async fn revoked_is_derived_from_either_revoked_at_or_a_non_active_status(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let (account_id, project_id) =
        seed_account_and_project(&repo, &format!("rev-{}", cuid2())).await;

    let both = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "both",
        "revoked",
        true,
        false,
    )
    .await;
    let stamp_only = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "stamp",
        "active",
        true,
        false,
    )
    .await;
    let status_only = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "status",
        "revoked",
        false,
        false,
    )
    .await;
    let active = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "active",
        "active",
        false,
        false,
    )
    .await;

    let labels = repo
        .resolve_api_key_labels(&[
            both.clone(),
            stamp_only.clone(),
            status_only.clone(),
            active.clone(),
        ])
        .await
        .expect("resolving should succeed");
    let revoked_of = |id: &str| {
        labels
            .iter()
            .find(|label| label.api_key_id == id)
            .unwrap_or_else(|| panic!("{id} should be present"))
            .revoked
    };

    assert!(revoked_of(&both));
    assert!(
        revoked_of(&stamp_only),
        "a revoked_at stamp alone is enough"
    );
    assert!(
        revoked_of(&status_only),
        "a non-active status alone is enough"
    );
    assert!(!revoked_of(&active));
}

/// A usage row can name a key that was deleted after the spend was recorded, and "the key you
/// deleted last week" is exactly the label that row needs — so this query does NOT filter
/// `deleted_at`. (A non-admin never reaches such a row anyway: the member path goes through
/// `db.api_key()`, whose `@@soft_delete` filter excludes it. That asymmetry is the model policy's
/// answer, not a second rule invented here — see `api_key_labels.rs`.)
#[sqlx::test(migrations = "../../migrations")]
async fn a_soft_deleted_key_still_resolves_to_its_name(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let (account_id, project_id) =
        seed_account_and_project(&repo, &format!("del-{}", cuid2())).await;
    let key_id = seed_api_key(
        &pool,
        &project_id,
        &account_id,
        "Retired loader",
        "revoked",
        true,
        true,
    )
    .await;

    let labels = repo
        .resolve_api_key_labels(std::slice::from_ref(&key_id))
        .await
        .expect("resolving should succeed");
    assert_eq!(labels.len(), 1, "a soft-deleted key still has a name");
    assert_eq!(labels[0].name, "Retired loader");
    assert!(labels[0].revoked);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_over_cap_batch_is_rejected_not_truncated(pool: PgPool) {
    let repo = build_repo(pool);
    let ids: Vec<String> = (0..=MAX_IDENTITY_BATCH).map(|_| cuid2()).collect();

    let error = repo
        .resolve_api_key_labels(&ids)
        .await
        .expect_err("an over-cap batch must be refused");
    match error {
        Error::BadRequest(message) => {
            assert!(
                message.contains("apiKeyIds") && message.contains(&MAX_IDENTITY_BATCH.to_string()),
                "the refusal must name the kind and the cap: {message}"
            );
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }

    // Exactly at the cap is fine — the boundary is `> MAX`, not `>=`.
    let at_cap: Vec<String> = ids.iter().take(MAX_IDENTITY_BATCH).cloned().collect();
    let labels = repo
        .resolve_api_key_labels(&at_cap)
        .await
        .expect("a batch exactly at the cap must be accepted");
    assert!(labels.is_empty(), "none of those ids exist");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_empty_batch_is_a_no_op(pool: PgPool) {
    let repo = build_repo(pool);
    let labels = repo
        .resolve_api_key_labels(&[])
        .await
        .expect("an empty batch is legal — a caller resolving only users sends one");
    assert!(labels.is_empty());
}

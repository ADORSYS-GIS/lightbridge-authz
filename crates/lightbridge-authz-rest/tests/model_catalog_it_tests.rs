// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database coverage for #415 (ADR-0018 Decision 5): `ModelCatalog::invalid_ids` wired into
//! `AuthzStoreImpl::set_project_allowed_models` -- the sole write path for `Project.allowedModels`
//! now that it is `@readonly` on both generic `model.Project.create`/`.update` verbs (same
//! `@readonly` + hand-written-procedure precedent #379/#397 already established for
//! `Project.projectQuota`, see `quota_tier_it_tests.rs`, which this file deliberately mirrors --
//! same seeding helper shape, same 4-case matrix per write path: accepted entries, a rejected
//! entry with no write reaching the DB, `None` accepted/clears, and an empty catalogue accepting
//! anything).
//!
//! Gated behind `it-tests` / `just it-tests` (needs a migrated Postgres via `DATABASE_URL`), same
//! as `quota_tier_it_tests.rs`.
#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{ModelCatalog, ModelCatalogEntry};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;
use std::sync::Arc;

fn core_pool(pool: PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool))
}

fn configured_catalog() -> ModelCatalog {
    ModelCatalog {
        models: vec![
            ModelCatalogEntry {
                id: "gpt-4.1-mini".to_string(),
                name: "GPT-4.1 Mini".to_string(),
            },
            ModelCatalogEntry {
                id: "claude-3.7".to_string(),
                name: "Claude 3.7".to_string(),
            },
        ],
    }
}

/// Seeds an owner account with a fresh (roster-less) project -- `set_project_allowed_models`'s
/// authorization is "account owner or any roster member", same as `model.Project.update`'s own
/// dropped `@@allow` policy (and `setProjectQuota`'s, which this mirrors), so an owner alone (no
/// roster) already suffices to authorize it.
async fn seed_owner_and_project(core: Arc<dyn DbPoolTrait>) -> (String, String) {
    let repo = StoreRepo::new(core);
    let owner_subject = format!("owner-{}", cuid2());

    let owner_account = repo
        .create_account(
            &owner_subject,
            CreateAccount {
                default_quota: None,
                name: None,
            },
        )
        .await
        .expect("owner account creation");

    let project = repo
        .create_project(
            &AccountId::assert_already_resolved(owner_subject.clone()),
            &owner_account.id,
            CreateProject {
                name: "proj".to_string(),
                allowed_models: None,
                default_limits: None,
                billing_plan: "free".to_string(),
                billing_identity: format!("bill-{}", cuid2()),
                project_quota: None,
            },
            cuid2(),
        )
        .await
        .expect("project creation");

    (owner_subject, project.id)
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_allowed_models_accepts_configured_entries(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_model_catalog(configured_catalog());

    let project = store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["gpt-4.1-mini".to_string(), "claude-3.7".to_string()]),
        )
        .await
        .expect("configured entries must be accepted");

    assert_eq!(
        project.allowed_models,
        Some(vec!["gpt-4.1-mini".to_string(), "claude-3.7".to_string()])
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_allowed_models_rejects_an_unconfigured_entry(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_model_catalog(configured_catalog());

    let err = store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["gpt-4.1-mini".to_string(), "gtp-4.1-typo".to_string()]),
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown allowedModels") && m.contains("gtp-4.1-typo")),
        "got: {err}"
    );
    // The rejected write must never have reached the DB -- still NULL from seeding.
    let repo = StoreRepo::new(core);
    let project = repo
        .get_project_by_id(&project_id)
        .await
        .expect("lookup should succeed")
        .expect("project must exist");
    assert_eq!(project.allowed_models, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_allowed_models_accepts_none_to_clear(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_model_catalog(configured_catalog());

    // First set a real allowlist, then clear it with `None` -- proving `None` both passes
    // validation and still reaches the repo's clearing behavior end to end.
    store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["gpt-4.1-mini".to_string()]),
        )
        .await
        .expect("setup: configured entry must be accepted");
    let project = store
        .set_project_allowed_models(&owner_subject, &project_id, None)
        .await
        .expect("None must always be accepted, even against a non-empty catalogue");

    assert_eq!(project.allowed_models, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_allowed_models_accepts_anything_when_catalogue_is_empty(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    // No `.with_model_catalog(...)` -- exercises the default empty catalogue.
    let store = AuthzStoreImpl::with_pool(core.clone());

    let project = store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["anything-goes".to_string()]),
        )
        .await
        .expect("an empty/absent catalogue must accept any value");

    assert_eq!(
        project.allowed_models,
        Some(vec!["anything-goes".to_string()])
    );
}

/// Pre-existing rows are NOT re-validated -- a project that already carries a stale/renamed id
/// from before this validation existed keeps it on read; only a fresh write through
/// `set_project_allowed_models` is checked (documented on `allowedModels`'s own schema field
/// comment, `crates/lightbridge-authz-api/schema/authz.cstack`).
#[sqlx::test(migrations = "../../migrations")]
async fn set_project_allowed_models_does_not_retroactively_validate_pre_existing_entries(
    pool: PgPool,
) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let repo = StoreRepo::new(core.clone());

    // Seed a stale entry directly, bypassing the validated write path entirely -- simulates a row
    // written before this validation existed.
    sqlx::query("UPDATE projects SET allowed_models = $1 WHERE id = $2")
        .bind(serde_json::json!(["already-stale-id"]))
        .bind(&project_id)
        .execute(core.pool())
        .await
        .expect("seed a pre-existing stale entry");

    let store = AuthzStoreImpl::with_pool(core.clone()).with_model_catalog(configured_catalog());
    let project = repo
        .get_project_by_id(&project_id)
        .await
        .expect("lookup should succeed")
        .expect("project must exist");
    assert_eq!(
        project.allowed_models,
        Some(vec!["already-stale-id".to_string()]),
        "a pre-existing stale entry must survive untouched until the next write"
    );

    // Only a FRESH write through the validated procedure is checked.
    let err = store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["already-stale-id".to_string()]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("already-stale-id")),
        "got: {err}"
    );
}

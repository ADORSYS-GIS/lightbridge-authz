// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database coverage for `setProjectModelPolicy` (ADR-0018 Decision 5's own tracked
//! follow-up, unblocked by #415's `allowedModels` catalogue validation): `ModelPolicy::parse_strict`
//! wired into `AuthzStoreImpl::set_project_model_policy`, and the "refuse `allowlist` while
//! `allowedModels` is empty" business rule wired into `StoreRepo::set_project_model_policy`'s own
//! transaction. Mirrors `model_catalog_it_tests.rs`/`quota_tier_it_tests.rs`'s seeding-helper shape.
//!
//! Gated behind `it-tests` / `just it-tests` (needs a migrated Postgres via `DATABASE_URL`), same
//! as those two files.
#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::identity::AccountId;
use lightbridge_authz_core::{CreateAccount, CreateProject, ModelPolicy};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;
use std::sync::Arc;

fn core_pool(pool: PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool))
}

/// Seeds an owner account with a fresh (roster-less) project -- `set_project_model_policy`'s
/// authorization is "account owner or any roster member", same as `model.Project.update`'s own
/// dropped `@@allow` policy (and `setProjectQuota`'s/`setProjectAllowedModels`'s, which this
/// mirrors), so an owner alone (no roster) already suffices to authorize it.
async fn seed_owner_and_project(core: Arc<dyn DbPoolTrait>) -> (String, String) {
    let repo = StoreRepo::new(core);
    let owner_subject = format!("owner-{}", cuid2());

    let owner_account = repo
        .create_account(
            &owner_subject,
            CreateAccount {
                default_quota: None,
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
async fn set_project_model_policy_round_trips_all_three_values(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    // A brand-new project already starts `allow_all` (the migration default) -- assert the
    // round-trip starting from a REAL transition, not a no-op.
    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "deny_all")
        .await
        .expect("allow_all -> deny_all must succeed");
    assert_eq!(project.model_policy, ModelPolicy::DenyAll);

    // deny_all -> allowlist needs a non-empty `allowedModels` first (see the dedicated empty-list
    // tests below) -- populate it via the real validated write path.
    let project = store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["gpt-4.1-mini".to_string()]),
        )
        .await
        .expect("setup: populate allowedModels");
    assert_eq!(project.model_policy, ModelPolicy::DenyAll, "unchanged yet");

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .expect("deny_all -> allowlist must succeed once allowedModels is non-empty");
    assert_eq!(project.model_policy, ModelPolicy::Allowlist);

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allow_all")
        .await
        .expect("allowlist -> allow_all must succeed");
    assert_eq!(project.model_policy, ModelPolicy::AllowAll);
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_model_policy_rejects_an_unrecognized_value(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    let err = store
        .set_project_model_policy(&owner_subject, &project_id, "bogus")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown modelPolicy") && m.contains("bogus")),
        "got: {err}"
    );

    // The rejected write must never have reached the DB -- still the migration default.
    let repo = StoreRepo::new(core);
    let project = repo
        .get_project_by_id(&project_id)
        .await
        .expect("lookup should succeed")
        .expect("project must exist");
    assert_eq!(project.model_policy, ModelPolicy::AllowAll);
}

/// The house decision under test (see `setProjectModelPolicy`'s own schema doc comment for the
/// full reasoning): switching to `allowlist` while `allowedModels` is empty/absent is REFUSED, not
/// silently allowed and not merely warned about -- `deny_all` already exists as the named,
/// unambiguous way to block every model, so this loses no expressiveness, and it turns a silent
/// "every model stops working" outage into an actionable `BadRequest` the frontend can react to.
#[sqlx::test(migrations = "../../migrations")]
async fn set_project_model_policy_refuses_allowlist_when_allowed_models_is_absent(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    // A brand-new project starts `allowedModels = NULL` ("all models allowed", unchanged meaning).
    let err = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("allowlist") && m.contains("empty")),
        "got: {err}"
    );

    let repo = StoreRepo::new(core);
    let project = repo
        .get_project_by_id(&project_id)
        .await
        .expect("lookup should succeed")
        .expect("project must exist");
    assert_eq!(
        project.model_policy,
        ModelPolicy::AllowAll,
        "the refused transition must never reach the DB"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_model_policy_refuses_allowlist_when_allowed_models_is_an_empty_list(
    pool: PgPool,
) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    // An explicit `[]` is a DIFFERENT wire shape from `NULL` (`allowedModels`'s own long-documented
    // NULL/[] == "everything" collapse when `model_policy` is not `allowlist`) -- assert the guard
    // catches both, not only the NULL case above.
    store
        .set_project_allowed_models(&owner_subject, &project_id, Some(vec![]))
        .await
        .expect("setup: an empty list is always accepted");

    let err = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("allowlist") && m.contains("empty")),
        "got: {err}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_model_policy_allows_allowlist_when_allowed_models_is_non_empty(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    store
        .set_project_allowed_models(
            &owner_subject,
            &project_id,
            Some(vec!["gpt-4.1-mini".to_string()]),
        )
        .await
        .expect("setup: populate allowedModels");

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .expect("allowlist must be accepted once allowedModels is non-empty");
    assert_eq!(project.model_policy, ModelPolicy::Allowlist);
}

/// The other deliberate decision under test: `setProjectModelPolicy` never touches
/// `allowedModels`. Switching `allow_all` -> `allowlist` -> `allow_all` must preserve the list
/// across both transitions, so toggling restriction back on later restores the previous selection
/// instead of forcing the caller to re-enter it.
#[sqlx::test(migrations = "../../migrations")]
async fn set_project_model_policy_preserves_allowed_models_across_transitions(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone());

    let selection = vec!["gpt-4.1-mini".to_string(), "claude-3.7".to_string()];
    store
        .set_project_allowed_models(&owner_subject, &project_id, Some(selection.clone()))
        .await
        .expect("setup: populate allowedModels");

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .expect("allow_all -> allowlist");
    assert_eq!(
        project.allowed_models,
        Some(selection.clone()),
        "allowedModels must survive the allow_all -> allowlist transition untouched"
    );

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allow_all")
        .await
        .expect("allowlist -> allow_all");
    assert_eq!(
        project.allowed_models,
        Some(selection.clone()),
        "allowedModels must NOT be cleared by switching to allow_all -- it is preserved so \
         toggling back to allowlist restores the previous selection"
    );

    let project = store
        .set_project_model_policy(&owner_subject, &project_id, "allowlist")
        .await
        .expect("allow_all -> allowlist again, without re-populating allowedModels");
    assert_eq!(
        project.model_policy,
        ModelPolicy::Allowlist,
        "the preserved list must still be non-empty, so this transition must succeed without a \
         fresh setProjectAllowedModels call"
    );
    assert_eq!(project.allowed_models, Some(selection));
}

// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database coverage for #177/#375/#379: `QuotaTiers::is_allowed` wired into all 5 real write
//! paths for `Account.defaultQuota` / `Project.projectQuota` / `ProjectMember.quotaTier`:
//! `AuthzStoreImpl::create_account` (`Account.defaultQuota`, #375),
//! `AuthzStoreImpl::update_account_default_quota` (`Account.defaultQuota`, #379),
//! `AuthzStoreImpl::set_project_member_quota_tier` (`ProjectMember.quotaTier`, #375), and
//! `AuthzStoreImpl::set_project_quota` (`Project.projectQuota`, #379). Gated behind `it-tests` /
//! `just it-tests` (needs a migrated Postgres via `DATABASE_URL`), same as
//! `crates/lightbridge-authz-api-key/tests/project_membership_tests.rs`, whose seeding helpers
//! this mirrors.
//!
//! #375 originally shipped only the first and third of the four methods above: `Account.defaultQuota`
//! via the generic `model.Account.update` verb and `Project.projectQuota` via the generic
//! `model.Project.create`/`model.Project.update` verbs had no extension point for a
//! runtime-configured catalogue check (cratestack 0.8.0's generated `validate()` on create/update
//! input structs is assembled purely from static `@length`/`@range`/`@regex`/`@email`/`@uri`/
//! `@iso4217` field attributes -- confirmed against this workspace's actual pin, not the stale
//! "0.5.1" AGENTS.md previously carried; `AuditSink::record` only fires *after* the write's
//! transaction has already committed, so it cannot reject anything either). #379 closes that gap by
//! marking both fields `@readonly` on the generic verbs (`crates/lightbridge-authz-api/schema/
//! authz.cstack`) and adding `updateAccountDefaultQuota`/`setProjectQuota` as the sole remaining
//! write paths -- this file now covers all four hand-written-procedure paths symmetrically.
#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{QuotaTier, QuotaTiers};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{CreateAccount, CreateProject};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;
use std::sync::Arc;

fn core_pool(pool: PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool))
}

fn configured_tiers() -> QuotaTiers {
    QuotaTiers {
        tiers: vec![
            QuotaTier {
                id: "bronze".to_string(),
                name: "Bronze".to_string(),
            },
            QuotaTier {
                id: "gold".to_string(),
                name: "Gold".to_string(),
            },
        ],
    }
}

// ---------------------------------------------------------------------------------------------
// createAccount / Account.defaultQuota
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_accepts_a_configured_default_quota(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool)).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());

    let account = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: Some("gold".to_string()),
            },
        )
        .await
        .expect("a configured tier must be accepted");

    assert_eq!(account.default_quota.as_deref(), Some("gold"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_rejects_an_unconfigured_default_quota(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());

    let err = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: Some("medim".to_string()),
            },
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown defaultQuota") && m.contains("medim")),
        "got: {err}"
    );

    // The rejected create must never have reached the DB.
    let repo = StoreRepo::new(core);
    let account = repo
        .get_account_by_id(&subject)
        .await
        .expect("lookup should succeed");
    assert!(
        account.is_none(),
        "a rejected create must not leave a row behind"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_accepts_missing_default_quota(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool)).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());

    let account = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("None must always be accepted, even against a non-empty catalogue");

    assert_eq!(account.default_quota, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_accepts_anything_when_catalogue_is_empty(pool: PgPool) {
    // `AuthzStoreImpl::with_pool` defaults to `QuotaTiers::default()` (empty) -- no
    // `.with_quota_tiers(...)` call, deliberately, to exercise that default.
    let store = AuthzStoreImpl::with_pool(core_pool(pool));
    let subject = format!("subj-{}", cuid2());

    let account = store
        .create_account(
            &subject,
            CreateAccount {
                default_quota: Some("anything-goes".to_string()),
            },
        )
        .await
        .expect("an empty/absent catalogue must accept any value (same default as Billing's is-empty-vs-absent semantics for quota tiers, see QuotaTiers' own doc comment)");

    assert_eq!(account.default_quota.as_deref(), Some("anything-goes"));
}

// ---------------------------------------------------------------------------------------------
// updateAccountDefaultQuota / Account.defaultQuota (#379 -- the generic model.Account.update
// verb's replacement now that the field is `@readonly` there)
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn update_account_default_quota_accepts_a_configured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());
    StoreRepo::new(core)
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("seed account creation");

    let account = store
        .update_account_default_quota(&subject, &subject, Some("gold"))
        .await
        .expect("a configured tier must be accepted");

    assert_eq!(account.default_quota.as_deref(), Some("gold"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_account_default_quota_rejects_an_unconfigured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());
    let repo = StoreRepo::new(core.clone());
    repo.create_account(
        &subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("seed account creation");

    let err = store
        .update_account_default_quota(&subject, &subject, Some("medim"))
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown defaultQuota") && m.contains("medim")),
        "got: {err}"
    );
    // The rejected update must never have reached the DB -- still NULL from seeding.
    let account = repo
        .get_account_by_id(&subject)
        .await
        .expect("lookup should succeed")
        .expect("account must exist");
    assert_eq!(account.default_quota, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_account_default_quota_accepts_none_to_clear(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());
    let subject = format!("subj-{}", cuid2());
    StoreRepo::new(core)
        .create_account(
            &subject,
            CreateAccount {
                default_quota: Some("gold".to_string()),
            },
        )
        .await
        .expect("seed account creation");

    let account = store
        .update_account_default_quota(&subject, &subject, None)
        .await
        .expect("None must always be accepted, even against a non-empty catalogue");

    assert_eq!(account.default_quota, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn update_account_default_quota_accepts_anything_when_catalogue_is_empty(pool: PgPool) {
    let core = core_pool(pool);
    // No `.with_quota_tiers(...)` -- exercises the default empty catalogue.
    let store = AuthzStoreImpl::with_pool(core.clone());
    let subject = format!("subj-{}", cuid2());
    StoreRepo::new(core)
        .create_account(
            &subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("seed account creation");

    let account = store
        .update_account_default_quota(&subject, &subject, Some("anything-goes"))
        .await
        .expect("an empty/absent catalogue must accept any value");

    assert_eq!(account.default_quota.as_deref(), Some("anything-goes"));
}

// ---------------------------------------------------------------------------------------------
// setProjectMemberQuotaTier / ProjectMember.quotaTier
// ---------------------------------------------------------------------------------------------

/// Seeds a lead account with a (roster-bearing, non-default) project, plus a second account added
/// to that project's roster as a plain member -- the target of every `set_project_member_quota_tier`
/// call below. Mirrors `project_membership_tests.rs::seed_account_and_project` plus its
/// `add_project_member` usage.
async fn seed_lead_and_target(core: Arc<dyn DbPoolTrait>) -> (String, String, String) {
    let repo = StoreRepo::new(core);
    let lead_subject = format!("lead-{}", cuid2());
    let target_subject = format!("target-{}", cuid2());

    let lead_account = repo
        .create_account(
            &lead_subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("lead account creation");
    repo.create_account(
        &target_subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("target account creation");

    let project = repo
        .create_project(
            &lead_subject,
            &lead_account.id,
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

    repo.add_project_member(&lead_subject, &project.id, &target_subject, Some("member"))
        .await
        .expect("add target as a project member");

    (lead_subject, project.id, target_subject)
}

async fn roster_quota_tier(
    core: Arc<dyn DbPoolTrait>,
    project_id: &str,
    target_subject: &str,
) -> Option<String> {
    let repo = StoreRepo::new(core);
    let roster = repo
        .list_project_roster(target_subject, project_id)
        .await
        .expect("roster read should succeed");
    roster
        .into_iter()
        .find(|m| m.account_id == target_subject)
        .expect("target must be on the roster")
        .quota_tier
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_member_quota_tier_accepts_a_configured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let (lead_subject, project_id, target_subject) = seed_lead_and_target(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    store
        .set_project_member_quota_tier(&lead_subject, &project_id, &target_subject, Some("bronze"))
        .await
        .expect("a configured tier must be accepted");

    assert_eq!(
        roster_quota_tier(core, &project_id, &target_subject).await,
        Some("bronze".to_string())
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_member_quota_tier_rejects_an_unconfigured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let (lead_subject, project_id, target_subject) = seed_lead_and_target(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    let err = store
        .set_project_member_quota_tier(&lead_subject, &project_id, &target_subject, Some("medim"))
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown quotaTier") && m.contains("medim")),
        "got: {err}"
    );
    // The rejected write must never have reached the DB -- still NULL from seeding.
    assert_eq!(
        roster_quota_tier(core, &project_id, &target_subject).await,
        None
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_member_quota_tier_accepts_none_to_clear(pool: PgPool) {
    let core = core_pool(pool);
    let (lead_subject, project_id, target_subject) = seed_lead_and_target(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    // First set a real tier, then clear it with `None` -- proving `None` both passes validation
    // and still reaches the repo's clearing behavior end to end.
    store
        .set_project_member_quota_tier(&lead_subject, &project_id, &target_subject, Some("gold"))
        .await
        .expect("setup: configured tier must be accepted");
    store
        .set_project_member_quota_tier(&lead_subject, &project_id, &target_subject, None)
        .await
        .expect("None must always be accepted, even against a non-empty catalogue");

    assert_eq!(
        roster_quota_tier(core, &project_id, &target_subject).await,
        None
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_member_quota_tier_accepts_anything_when_catalogue_is_empty(pool: PgPool) {
    let core = core_pool(pool);
    let (lead_subject, project_id, target_subject) = seed_lead_and_target(core.clone()).await;
    // No `.with_quota_tiers(...)` -- exercises the default empty catalogue.
    let store = AuthzStoreImpl::with_pool(core.clone());

    store
        .set_project_member_quota_tier(
            &lead_subject,
            &project_id,
            &target_subject,
            Some("anything-goes"),
        )
        .await
        .expect("an empty/absent catalogue must accept any value");

    assert_eq!(
        roster_quota_tier(core, &project_id, &target_subject).await,
        Some("anything-goes".to_string())
    );
}

// ---------------------------------------------------------------------------------------------
// setProjectQuota / Project.projectQuota (#379 -- the generic model.Project.create/.update verbs'
// replacement now that the field is `@readonly` on both)
// ---------------------------------------------------------------------------------------------

/// Seeds an owner account with a fresh (roster-less) project -- `set_project_quota`'s
/// authorization is "account owner or any roster member", same as `model.Project.update`'s own
/// dropped `@@allow` policy, so an owner alone (no roster) already suffices to authorize it.
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
            &owner_subject,
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
async fn set_project_quota_accepts_a_configured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    let project = store
        .set_project_quota(&owner_subject, &project_id, Some("bronze"))
        .await
        .expect("a configured tier must be accepted");

    assert_eq!(project.project_quota.as_deref(), Some("bronze"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_quota_rejects_an_unconfigured_tier(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    let err = store
        .set_project_quota(&owner_subject, &project_id, Some("medim"))
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::BadRequest(ref m) if m.contains("unknown projectQuota") && m.contains("medim")),
        "got: {err}"
    );
    // The rejected write must never have reached the DB -- still NULL from seeding.
    let repo = StoreRepo::new(core);
    let project = repo
        .get_project_by_id(&project_id)
        .await
        .expect("lookup should succeed")
        .expect("project must exist");
    assert_eq!(project.project_quota, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_quota_accepts_none_to_clear(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    let store = AuthzStoreImpl::with_pool(core.clone()).with_quota_tiers(configured_tiers());

    // First set a real tier, then clear it with `None` -- proving `None` both passes validation
    // and still reaches the repo's clearing behavior end to end.
    store
        .set_project_quota(&owner_subject, &project_id, Some("gold"))
        .await
        .expect("setup: configured tier must be accepted");
    let project = store
        .set_project_quota(&owner_subject, &project_id, None)
        .await
        .expect("None must always be accepted, even against a non-empty catalogue");

    assert_eq!(project.project_quota, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn set_project_quota_accepts_anything_when_catalogue_is_empty(pool: PgPool) {
    let core = core_pool(pool);
    let (owner_subject, project_id) = seed_owner_and_project(core.clone()).await;
    // No `.with_quota_tiers(...)` -- exercises the default empty catalogue.
    let store = AuthzStoreImpl::with_pool(core.clone());

    let project = store
        .set_project_quota(&owner_subject, &project_id, Some("anything-goes"))
        .await
        .expect("an empty/absent catalogue must accept any value");

    assert_eq!(project.project_quota.as_deref(), Some("anything-goes"));
}

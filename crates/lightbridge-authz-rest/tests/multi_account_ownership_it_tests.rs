// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database, live-router coverage for ADR-0026 ("one identity may own many accounts") at the
//! RPC/POLICY level — the layer the `lightbridge-authz-api-key` repository tests cannot reach,
//! because the thing under test there is hand-written SQL and the thing under test here is the
//! `@@allow` expression cratestack lowers into the generated query's `WHERE` clause.
//!
//! The change these tests pin is one substitution repeated across three models
//! (`crates/lightbridge-authz-api/schema/authz.cstack`):
//!
//! | clause | before | after |
//! |---|---|---|
//! | `Account` read | `id == auth().id` | `userId == auth().id` |
//! | `Project` create/read/update/delete | `account.id == auth().id` | `account.userId == auth().id` |
//! | `ApiKey` read/update/delete | `project.account.id == auth().id` | `project.account.userId == auth().id` |
//!
//! `auth().id` does not move (ADR-0026 D2): it stays the acting *account*, which is always the
//! identity's home account. What makes the substitution sound is the invariant recorded on
//! `Account.userId` — `accounts.user_id` is ALWAYS the owner's home-account id — so `userId ==
//! auth().id` reads "owned by the same person as me" without needing an `auth().userId`.
//!
//! Every test here is one that could not have passed before the change, for one of two reasons:
//! either a second `createAccount` was `Error::Conflict` outright, or the account it would have
//! produced was invisible to its own owner under the narrower `id == auth().id` clause.
//!
//! The widening is only half the property. A policy that widened *across* owners would satisfy
//! every acceptance criterion in #563 and be a cross-tenant read; so each widening test is paired
//! with a stranger who must see none of it. Read policies FILTER rather than reject in cratestack
//! (`@@allow("read", ...)` lowers into `WHERE`), so the stranger assertions are on returned rows
//! and on `get`'s uniform 404 — never on a 403, which reads would never produce.
//!
//! Gated behind `it-tests` / `just it-tests` (needs a migrated Postgres via `DATABASE_URL` *and*
//! Redis via `AUTHZ_REDIS_URL`/localhost, both reached by the assembled `build_api_router`), same
//! as `rpc_it_tests.rs`, whose harness this mirrors.
#![cfg(feature = "it-tests")]

mod common;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use common::{MapBearer, Wire, admin_perms, rpc_call, token_info};
use cratestack::SqlxIdempotencyStore;
use cratestack::{Json, Value as CValue, ratelimit::RateLimitStore};
use lightbridge_authz_api::schema;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::config::{Billing, BillingPlan};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for it-tests (just it-tests)")
}

fn redis_url() -> String {
    std::env::var("AUTHZ_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn billing() -> Billing {
    Billing {
        plans: vec![BillingPlan {
            id: "free".to_string(),
            name: "Free".to_string(),
            limits: None,
        }],
    }
}

/// Same reasoning as `rpc_it_tests.rs`'s own constant: every test builds two pools of its own, so
/// a small per-test cap keeps a fully parallel run under Postgres's `max_connections`.
const TEST_POOL_MAX_CONNECTIONS: u32 = 2;

/// See `rpc_it_tests.rs`: `SqlxIdempotencyStore::ensure_schema()`'s DDL is not concurrency-safe,
/// and is process-wide idempotent, so it runs once per test binary.
static IDEMPOTENCY_SCHEMA_READY: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// The fully assembled `build_api_router` against live Postgres + Redis, plus the raw pool the
/// ownership-column assertions read through (the `userId` invariant is a database fact, and a
/// test that only ever asked the API about it could be satisfied by an API that lies).
struct Ctx {
    router: Router,
    verify: sqlx::PgPool,
}

async fn setup(bearer: Arc<dyn BearerTokenServiceTrait>) -> Ctx {
    let pool = PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .connect(&database_url())
        .await
        .expect("connect core pool");
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));

    let cpool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .max_connections(TEST_POOL_MAX_CONNECTIONS)
        .connect(&database_url())
        .await
        .expect("connect cratestack pool");
    let cdb = schema::Cratestack::builder(cpool.clone()).build();

    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing()));
    let idempotency = Arc::new(SqlxIdempotencyStore::new(cpool));
    IDEMPOTENCY_SCHEMA_READY
        .get_or_init(|| async {
            idempotency
                .ensure_schema()
                .await
                .expect("ensure idempotency schema");
        })
        .await;

    let rate_limit: Arc<dyn RateLimitStore> = build_redis_rate_limit_store(
        &redis_url(),
        None,
        format!("authz-multi-account-it-{}", cuid2()),
    )
    .expect("redis rate-limit store");

    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            core.clone(),
            "budget-refill",
            10_000,
        )
        .await
        .expect("migrations seed an active budget-refill revision"),
    );
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        core.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        core.clone(),
    ));
    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_store.engine(),
        Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));

    // ADR-0032: `Procedures`/`build_*_router` take the reset scheduler unconditionally (see
    // `Procedures`'s own field doc). The interval task is spawned only by `start_budget_server`,
    // so this is an inert handle over the same pool.
    let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
        core.clone(),
        budget_repo.clone(),
        Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
    ));

    let router = lightbridge_authz_rest::build_api_router(
        bearer,
        common::test_resolver(),
        issuer,
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        std::sync::Arc::new(lightbridge_authz_core::platform_role::known_platform_roles(
            &lightbridge_authz_core::authz::Rbac::default(),
        )),
        cdb,
        core,
        idempotency,
        rate_limit,
        false,
        None,
    );

    let verify = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url())
        .await
        .expect("connect verify pool");

    Ctx { router, verify }
}

/// A bearer serving several identities off one router, keyed by token string. Every identity here
/// holds `admin_perms()` deliberately: the coarse RBAC gate must never be what refuses a
/// cross-owner read, or the model policy under test would go unexercised.
fn bearer_for(identities: &[(&str, &str)]) -> Arc<dyn BearerTokenServiceTrait> {
    let mut map = MapBearer::new();
    for (token, subject) in identities {
        map = map.with(token, token_info(subject, admin_perms()));
    }
    Arc::new(map)
}

fn json_body(bytes: &[u8]) -> Value {
    Wire::Cbor.decode(bytes)
}

/// `procedure.createAccount` over the wire, returning the created account's id and asserting 200.
async fn create_account(router: &Router, token: &str) -> String {
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.createAccount",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some(token),
    )
    .await;
    assert!(
        status.is_success(),
        "createAccount: {status} {}",
        String::from_utf8_lossy(&body)
    );
    json_body(&body)["id"]
        .as_str()
        .expect("account id")
        .to_string()
}

fn project_input(id: &str, account_id: &str, name: &str) -> schema::inputs::CreateProjectInput {
    schema::inputs::CreateProjectInput {
        id: id.to_string(),
        accountId: account_id.to_string(),
        name: name.to_string(),
        defaultLimits: Json(CValue::Map(std::collections::BTreeMap::new())),
        billingPlan: "free".to_string(),
        billingIdentity: format!("bill-{}", cuid2()),
    }
}

/// `model.Account.list` (a `@@paged` model, so `Page<T>`), returning just the ids it yielded.
async fn list_account_ids(router: &Router, token: &str) -> Vec<String> {
    let (status, body) = rpc_call(
        router.clone(),
        "model.Account.list",
        Wire::Cbor,
        &json!({}),
        Some(token),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Account.list: {}",
        String::from_utf8_lossy(&body)
    );
    json_body(&body)["items"]
        .as_array()
        .expect("Account.list is @@paged")
        .iter()
        .map(|a| a["id"].as_str().expect("account id").to_string())
        .collect()
}

/// The database's own view of `(id, user_id)` — the invariant the policies rest on, read outside
/// the API that is being tested with it.
async fn ownership_row(verify: &sqlx::PgPool, account_id: &str) -> (String, String) {
    sqlx::query_as::<_, (String, String)>("SELECT id, user_id FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(verify)
        .await
        .expect("the account should exist")
}

// ---------------------------------------------------------------------------------------------
// The cardinality change itself
// ---------------------------------------------------------------------------------------------

/// Pins ADR-0026 D4 at the wire: a second `createAccount` from one identity is an ordinary
/// success, not the `Error::Conflict` the old `id = subject` insert produced against the
/// `accounts` primary key. The two accounts must be distinct rows, and the second must carry a
/// minted id rather than reusing the subject.
///
/// This is the precondition every other test in this file depends on, so it also asserts the
/// ownership shape the policies read: the first account anchors the identity (`id == user_id ==
/// subject`) and the second inherits that owner rather than becoming its own.
#[tokio::test]
async fn a_second_create_account_succeeds_and_inherits_the_first_accounts_owner() {
    let subject = format!("owner-second-account-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &subject)])).await;

    let first = create_account(&ctx.router, "owner").await;
    let second = create_account(&ctx.router, "owner").await;

    assert_eq!(
        first, subject,
        "the identity's first account anchors it and keeps id = subject, or federated adoption \
         (which matches accounts.id == subject) breaks for every new signup"
    );
    assert_ne!(
        first, second,
        "a second createAccount must produce a distinct account, not a Conflict and not an upsert"
    );

    let (first_id, first_user) = ownership_row(&ctx.verify, &first).await;
    let (second_id, second_user) = ownership_row(&ctx.verify, &second).await;
    assert_eq!(
        first_id, first_user,
        "the home account owns itself -- the LOAD-BEARING INVARIANT the `userId == auth().id` \
         clauses rest on"
    );
    assert_ne!(
        second_id, second_user,
        "a secondary account must not own itself; it would then be indistinguishable from a home \
         account, and addProjectMember's guard would let it onto a roster"
    );
    assert_eq!(
        second_user, first_user,
        "the second account must inherit the owner's user_id, or it is a different person's \
         tenant and its owner can never read it"
    );
}

// ---------------------------------------------------------------------------------------------
// `Account`'s widened read policy — issue #563's headline acceptance criterion
// ---------------------------------------------------------------------------------------------

/// The property #563 actually asks for, and the reason `@@allow("read", userId == auth().id)`
/// exists: an owner listing their accounts sees ALL of them, not only the one that IS them.
/// Under the previous `id == auth().id` clause the second account was structurally unreadable by
/// the only person entitled to it — created successfully and then invisible.
#[tokio::test]
async fn account_list_returns_every_account_the_owner_owns() {
    let subject = format!("owner-list-all-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &subject)])).await;

    let home = create_account(&ctx.router, "owner").await;
    let secondary = create_account(&ctx.router, "owner").await;

    let ids = list_account_ids(&ctx.router, "owner").await;

    assert!(
        ids.contains(&home),
        "the home account must be listed (it always was): got {ids:?}"
    );
    assert!(
        ids.contains(&secondary),
        "the secondary account must be listed -- this is the widened read clause's entire purpose: \
         got {ids:?}"
    );
}

/// The other half of the same clause, and the one that would make the widening a security bug if
/// it failed: `userId == auth().id` must widen across a person's own accounts and not across
/// people. The stranger holds every RBAC permission, so the coarse gate cannot be what refuses
/// them — only the model policy stands between them and another owner's rows.
///
/// Read policies filter rather than reject, so the assertion is on the rows returned (the stranger
/// still sees their own account, proving the call was served rather than emptied by an error) and
/// on `get`'s uniform 404, never on a 403.
#[tokio::test]
async fn account_list_does_not_leak_another_owners_accounts() {
    let owner = format!("owner-no-leak-{}", cuid2());
    let stranger = format!("stranger-no-leak-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &owner), ("stranger", &stranger)])).await;

    let home = create_account(&ctx.router, "owner").await;
    let secondary = create_account(&ctx.router, "owner").await;
    let stranger_home = create_account(&ctx.router, "stranger").await;

    let ids = list_account_ids(&ctx.router, "stranger").await;

    assert!(
        ids.contains(&stranger_home),
        "the stranger must still see their own account, or this test would pass on an empty list \
         for the wrong reason: got {ids:?}"
    );
    assert!(
        !ids.contains(&home),
        "the widened clause must not expose another owner's home account: got {ids:?}"
    );
    assert!(
        !ids.contains(&secondary),
        "nor their secondary account: got {ids:?}"
    );

    for target in [&home, &secondary] {
        let (status, body) = rpc_call(
            ctx.router.clone(),
            "model.Account.get",
            Wire::Cbor,
            &json!({ "id": target }),
            Some("stranger"),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a filtered read is a uniform not-found, never a row: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

// ---------------------------------------------------------------------------------------------
// `Project`'s widened relation clauses — `account.userId == auth().id`
// ---------------------------------------------------------------------------------------------

/// A secondary account is a fully owned tenant (ADR-0026 D7), not a row that merely exists: the
/// owner must be able to create and read projects inside it. This traverses the one relation hop
/// `Project.account.userId`, which is what `@@allow("create"/"read", account.userId ==
/// auth().id)` compiles to; under the previous `account.id == auth().id` the create would have
/// been denied outright, since the secondary account's id is never `auth().id`.
///
/// `Project.accountId` must stay a plain settable field for this to work at all — a create policy
/// with a relation predicate returns `false` outright when the parent column is absent from the
/// create input — so a passing create here also pins that constraint.
#[tokio::test]
async fn the_owner_can_create_and_read_a_project_inside_their_secondary_account() {
    let subject = format!("owner-secondary-project-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &subject)])).await;

    let home = create_account(&ctx.router, "owner").await;
    let secondary = create_account(&ctx.router, "owner").await;
    assert_ne!(secondary, home);

    let project_id = cuid2();
    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.create",
        Wire::Cbor,
        &project_input(&project_id, &secondary, "proj-in-secondary"),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "creating a project in an owned secondary account must be permitted: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["accountId"], secondary);

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner must be able to read it back: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(json_body(&body)["id"], project_id);

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.list",
        Wire::Cbor,
        &json!({}),
        Some("owner"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        json_body(&body)["items"]
            .as_array()
            .expect("Project.list is @@paged")
            .iter()
            .any(|p| p["id"] == project_id.as_str()),
        "and to find it by listing, not only by id"
    );
}

/// The same relation clause, from the other side: widening `Project` onto the owner must not
/// widen it onto anybody else. A stranger with every RBAC permission and no relationship to the
/// secondary account gets the uniform 404 on read and a refusal on create — the latter proving
/// the create policy is evaluating the submitted `accountId`'s owner rather than merely accepting
/// any well-formed parent id.
#[tokio::test]
async fn a_stranger_cannot_see_or_write_into_someone_elses_secondary_account() {
    let owner = format!("owner-secondary-boundary-{}", cuid2());
    let stranger = format!("stranger-secondary-boundary-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &owner), ("stranger", &stranger)])).await;

    create_account(&ctx.router, "owner").await;
    let secondary = create_account(&ctx.router, "owner").await;
    create_account(&ctx.router, "stranger").await;

    let project_id = cuid2();
    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.create",
        Wire::Cbor,
        &project_input(&project_id, &secondary, "proj-in-secondary"),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "setup: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("stranger"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a stranger must not read a project in another person's secondary account: {}",
        String::from_utf8_lossy(&body)
    );

    let ids: Vec<String> = {
        let (status, body) = rpc_call(
            ctx.router.clone(),
            "model.Project.list",
            Wire::Cbor,
            &json!({}),
            Some("stranger"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        json_body(&body)["items"]
            .as_array()
            .expect("Project.list is @@paged")
            .iter()
            .map(|p| p["id"].as_str().expect("project id").to_string())
            .collect()
    };
    assert!(
        !ids.contains(&project_id),
        "nor find it by listing: got {ids:?}"
    );

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.create",
        Wire::Cbor,
        &project_input(&cuid2(), &secondary, "hijacked"),
        Some("stranger"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "nor create one inside it: {}",
        String::from_utf8_lossy(&body)
    );
}

// ---------------------------------------------------------------------------------------------
// ADR-0026 D5 — the roster guard that closes the footgun the cardinality change opens
// ---------------------------------------------------------------------------------------------

/// The roster stays account-keyed and `members.some.accountId == auth().id` deliberately keeps
/// comparing `auth().id` (ADR-0026 D5), which makes a non-home account on a roster a silent dead
/// end: the row exists, the member is listed, and they never gain access, because `auth().id` is
/// only ever their home account. `addProjectMember` refuses it up front instead.
///
/// Both branches are asserted in one test on purpose: a guard that refused everything would pass
/// the refusal half alone, and the roster is the mechanism half the platform's project sharing
/// runs on.
#[tokio::test]
async fn add_project_member_refuses_a_secondary_account_but_accepts_a_home_account() {
    let owner = format!("owner-roster-guard-{}", cuid2());
    let member = format!("member-roster-guard-{}", cuid2());
    let ctx = setup(bearer_for(&[("owner", &owner), ("member", &member)])).await;

    let owner_home = create_account(&ctx.router, "owner").await;
    let member_home = create_account(&ctx.router, "member").await;
    let member_secondary = create_account(&ctx.router, "member").await;
    assert_ne!(member_home, member_secondary);

    let project_id = cuid2();
    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.create",
        Wire::Cbor,
        &project_input(&project_id, &owner_home, "proj-roster-guard"),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "setup: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "procedure.addProjectMember",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "accountId": member_secondary } }),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a secondary account on a roster can never be `auth().id`, so it must be refused at the \
         point of insert rather than stored as an entry that cannot work: {}",
        String::from_utf8_lossy(&body)
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM project_members WHERE project_id = $1 AND account_id = $2",
    )
    .bind(&project_id)
    .bind(&member_secondary)
    .fetch_one(&ctx.verify)
    .await
    .expect("count should succeed");
    assert_eq!(rows, 0, "the refused roster entry must leave no row behind");

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "procedure.addProjectMember",
        Wire::Cbor,
        &json!({ "args": { "projectId": project_id, "accountId": member_home } }),
        Some("owner"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the member's home account must still be accepted -- the guard rejects a shape, not the \
         feature: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = rpc_call(
        ctx.router.clone(),
        "model.Project.get",
        Wire::Cbor,
        &json!({ "id": project_id }),
        Some("member"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "and the accepted entry must actually grant access, which is what makes the refused one a \
         dead end rather than a matter of taste: {}",
        String::from_utf8_lossy(&body)
    );
}

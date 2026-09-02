// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Hermetic tests for the assembled authz-api RPC router (`build_api_router`), re-porting the
//! route-shape coverage the deleted `router_tests.rs`/`controllers_tests.rs` had (health probes,
//! dev-CORS) onto the cratestack RPC surface, plus the **fail-closed half** of the RBAC gate
//! (`docs/rbac.md`, `rpc_authorize.rs`).
//!
//! `build_api_router` no longer mounts OIDC discovery/JWKS or native token-exchange at all — that
//! surface moved exclusively to `authz-idp` (`build_idp_router`) once the `auth.ai.camer.digital`
//! ingress was repointed there (see `build_api_router`'s own doc comment). This file's
//! `well_known_and_token_exchange_paths_are_never_served_by_api_router` proves the fail-closed
//! response those paths now get here.
//!
//! Everything here is offline: the cratestack CRUD client / idempotency store / rate-limit store are
//! lazily connected to an unreachable address and never queried, because every request either
//!   * hits a non-RPC route (`/healthz*`, CORS preflight, or an unmapped path like `/.well-known/*`),
//!   * is rejected by the outermost `rpc_authorize` gate (403/401) **before** dispatch, idempotency,
//!     or rate-limiting run, or
//!   * is a `POST /rpc/batch` call the gate *does* let through (it only requires a valid token, not a
//!     per-op permission — see `docs/rbac.md`, "Batch RPC: per-frame RBAC") and therefore fails later
//!     against the dead Redis/Postgres instead; this file only proves the gate itself stopped
//!     rejecting once the token is valid, not that dispatch succeeds.
//!
//! The *allow* half of the gate (viewer reads → 200, admin → 200 on every mapped op) reaches
//! dispatch and therefore needs a live DB + Redis; it lives in `rpc_it_tests.rs`.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{MapBearer, Wire, admin_perms, as_json, rpc_call, token_info, viewer_perms};
use cratestack::SqlxIdempotencyStore;
use cratestack::ratelimit::RateLimitStore;
use lightbridge_authz_api::schema;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::authz::{Permission, PermissionSet};
use lightbridge_authz_core::config::{Billing, ModelCatalog};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const DEAD_PG: &str = "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz";
const DEAD_REDIS: &str = "redis://127.0.0.1:6379";

fn lazy_core_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy core pool");
    Arc::new(DbPool::from_pool(pool))
}

fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    schema::Cratestack::builder(pool).build()
}

fn lazy_idempotency() -> Arc<SqlxIdempotencyStore> {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    Arc::new(SqlxIdempotencyStore::new(pool))
}

fn lazy_rate_limit() -> Arc<dyn RateLimitStore> {
    build_redis_rate_limit_store(DEAD_REDIS, None, "authz-api-test").expect("rate limit store")
}

/// A `PolicyStore` built with no database query at all (`PolicyStore::from_engine`), matching how
/// every other dependency in this file is lazily wired to an unreachable Postgres and never
/// actually queried -- none of this file's tests reach a budget-policy procedure.
fn lazy_policy_store(core: Arc<dyn DbPoolTrait>) -> Arc<lightbridge_authz_budget::PolicyStore> {
    let engine = lightbridge_authz_budget::RuleDataEngine::new(
        lightbridge_authz_budget::default_rule_set_json(),
        10_000,
    )
    .expect("default rule set is valid");
    Arc::new(lightbridge_authz_budget::PolicyStore::from_engine(
        core,
        "budget-refill",
        engine,
    ))
}

/// A `RefillService`/`ReviewService` pair built with no live database query at all -- matching
/// how every other dependency in this file is lazily wired to an unreachable Postgres and never
/// actually queried (none of this file's tests reach a budget-refill procedure).
/// `UnavailableSpendReader` needs no database at all, so it needs no "lazy" qualifier.
fn lazy_refill_and_review_services(
    core: Arc<dyn DbPoolTrait>,
    policy_store: &lightbridge_authz_budget::PolicyStore,
) -> (
    Arc<lightbridge_authz_budget::RefillService>,
    Arc<lightbridge_authz_budget::ReviewService>,
    Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    Arc<lightbridge_authz_budget::ResetScheduler>,
) {
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
    // ADR-0032: `build_api_router` takes the reset scheduler unconditionally (see `Procedures`'s
    // own field doc). Inert here -- the interval task is spawned only by `start_budget_server`,
    // and `RpcScope::Crud` refuses every schedule op-id on this router anyway.
    let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
        core,
        budget_repo.clone(),
        Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
    ));
    (refill_service, review_service, budget_repo, reset_scheduler)
}

/// Assemble the full API router with a caller-supplied bearer, everything else lazily wired to
/// unreachable backends. `build_api_router` no longer takes `oauth2`/`signing_repo`/
/// `token_exchange` params at all — it stopped mounting OIDC discovery/JWKS and token-exchange
/// once that surface moved exclusively to `authz-idp` (see its doc comment).
fn build_router(bearer: Arc<dyn BearerTokenServiceTrait>, dev_cors: bool) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()));
    let policy_store = lazy_policy_store(core.clone());
    let (refill_service, review_service, budget_repo, reset_scheduler) =
        lazy_refill_and_review_services(core.clone(), &policy_store);
    lightbridge_authz_rest::build_api_router(
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
        lazy_cratestack_db(),
        core,
        lazy_idempotency(),
        lazy_rate_limit(),
        dev_cors,
        // Root mount (`/rpc/<op_id>`) for the shared helper; the configured-base-path mount is
        // exercised by `rpc_surface_honours_configured_base_path` via `build_router_at`.
        None,
    )
}

/// Like [`build_router`], but with a caller-supplied [`Billing`] catalogue instead of the
/// default (empty) one -- for exercising `listBillingPlans`, the one procedure in this file whose
/// response body actually depends on config rather than being uniformly unreachable/lazy DB.
fn build_router_with_billing(bearer: Arc<dyn BearerTokenServiceTrait>, billing: Billing) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_billing(billing));
    let policy_store = lazy_policy_store(core.clone());
    let (refill_service, review_service, budget_repo, reset_scheduler) =
        lazy_refill_and_review_services(core.clone(), &policy_store);
    lightbridge_authz_rest::build_api_router(
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
        lazy_cratestack_db(),
        core,
        lazy_idempotency(),
        lazy_rate_limit(),
        false,
        None,
    )
}

/// Like [`build_router`], but with a caller-supplied [`ModelCatalog`] instead of the default
/// (empty) one -- for exercising `listModelCatalog`, mirroring `build_router_with_billing` above.
fn build_router_with_models(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    models: ModelCatalog,
) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()).with_model_catalog(models));
    let policy_store = lazy_policy_store(core.clone());
    let (refill_service, review_service, budget_repo, reset_scheduler) =
        lazy_refill_and_review_services(core.clone(), &policy_store);
    lightbridge_authz_rest::build_api_router(
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
        lazy_cratestack_db(),
        core,
        lazy_idempotency(),
        lazy_rate_limit(),
        false,
        None,
    )
}

/// Like [`build_router`] but mounts the RPC surface under `rpc_base_path` (e.g. `/api`), for the
/// configurable-mount test.
fn build_router_at(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    rpc_base_path: Option<&str>,
) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()));
    let policy_store = lazy_policy_store(core.clone());
    let (refill_service, review_service, budget_repo, reset_scheduler) =
        lazy_refill_and_review_services(core.clone(), &policy_store);
    lightbridge_authz_rest::build_api_router(
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
        lazy_cratestack_db(),
        core,
        lazy_idempotency(),
        lazy_rate_limit(),
        false,
        rpc_base_path,
    )
}

/// A single-identity admin bearer, token string `"admin"`.
fn admin_bearer() -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(MapBearer::new().with("admin", token_info("admin-subject", admin_perms())))
}

/// admin + viewer identities on one router.
fn admin_and_viewer_bearer() -> Arc<dyn BearerTokenServiceTrait> {
    Arc::new(
        MapBearer::new()
            .with("admin", token_info("admin-subject", admin_perms()))
            .with("viewer", token_info("viewer-subject", viewer_perms())),
    )
}

async fn get(router: Router, uri: &str) -> StatusCode {
    router
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn health_probes_report_ok() {
    for uri in ["/", "/healthz", "/healthz/startup"] {
        let router = build_router(admin_bearer(), false);
        assert_eq!(get(router, uri).await, StatusCode::OK, "probe {uri}");
    }
}

#[tokio::test]
async fn dev_cors_preflight_is_answered_with_permissive_headers() {
    let router = build_router(admin_bearer(), true);
    let response = router
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/rpc/model.Account.list")
                .header("origin", "http://example.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("*"),
        "permissive CORS must echo an allow-origin on preflight"
    );
}

#[tokio::test]
async fn dev_cors_adds_allow_origin_header_to_normal_responses() {
    let router = build_router(admin_bearer(), true);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("origin", "http://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .contains_key("access-control-allow-origin"),
        "dev CORS should attach an allow-origin header to normal responses"
    );
}

#[tokio::test]
async fn no_dev_cors_means_no_allow_origin_header() {
    let router = build_router(admin_bearer(), false);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("origin", "http://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin"),
        "CORS headers must be absent when dev CORS is off"
    );
}

/// `build_api_router` no longer mounts `well_known_router`/`token_exchange_router` at all — that
/// surface moved exclusively to `authz-idp` once the `auth.ai.camer.digital` ingress was
/// repointed there (see `build_api_router`'s doc comment in `lib.rs`). Replaces
/// `well_known_discovery_is_merged_only_for_self_signed_oauth2` and the two
/// `token_exchange_route_*` tests, whose premise (that either route is ever reachable here under
/// some config) is now false unconditionally, not just for `external` oauth2. None of these paths
/// are a public route on this router anymore, so each falls through to the RPC router's fallback,
/// which the outermost `rpc_authorize` gate fail-closes to `403` for an unmapped op-id — no
/// bearer token required, since `op_id_from_path` extracts `""` for any path with no `/rpc/`
/// segment and the fail-closed set denies that unconditionally (see `rpc_authorize`'s doc
/// comment). Never the `200`/merged-4xx these paths used to return when self-signed/token-exchange
/// config was present.
#[tokio::test]
async fn well_known_and_token_exchange_paths_are_never_served_by_api_router() {
    let router = build_router(admin_bearer(), false);
    assert_eq!(
        get(router, "/.well-known/openid-configuration").await,
        StatusCode::FORBIDDEN,
        "authz-api must never serve OIDC discovery"
    );

    let router = build_router(admin_bearer(), false);
    assert_eq!(
        get(router, "/.well-known/jwks.json").await,
        StatusCode::FORBIDDEN,
        "authz-api must never serve JWKS"
    );

    let router = build_router(admin_bearer(), false);
    let status = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "authz-api must never mount /oauth2/token"
    );

    let router = build_router(admin_bearer(), false);
    let status = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/revoke")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "authz-api must never mount /oauth2/revoke"
    );
}

/// The security-critical fail-closed half of the RBAC gate: a read-only viewer is rejected on every
/// mutating op-id *before* the request reaches cratestack dispatch (so this needs no DB).
#[tokio::test]
async fn rbac_gate_denies_viewer_on_every_mutating_op() {
    for op in [
        "model.Account.delete",
        "procedure.createAccount",
        "procedure.disableAccount",
        "procedure.enableAccount",
        "procedure.addProjectMember",
        "procedure.removeProjectMember",
        "model.Project.create",
        "model.Project.update",
        "model.Project.delete",
        "procedure.disableProject",
        "procedure.enableProject",
        "procedure.createApiKey",
        "model.ApiKey.update",
        "model.ApiKey.delete",
        "procedure.revokeApiKey",
        "procedure.rotateApiKey",
    ] {
        let router = build_router(admin_and_viewer_bearer(), false);
        let (status, _) = rpc_call(router, op, Wire::Cbor, &json!({}), Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer must be denied `{op}` by the RBAC gate"
        );
    }
}

/// #647's negative half: the three estate-wide identity-resolution op-ids are refused for a caller
/// holding EVERY other permission but not `user:read`. Stated as "admin minus one" rather than
/// "viewer" deliberately — the interesting failure would be `user:read` being implied by some
/// broader grant (`account:read`, say), and a viewer token could not tell that apart from an
/// ordinary read-only denial. The gate runs before dispatch, so this needs no DB: nothing is
/// returned, not even an empty result set.
#[tokio::test]
async fn rbac_gate_denies_identity_resolution_without_user_read() {
    let almost_admin: PermissionSet = Permission::ALL
        .into_iter()
        .filter(|p| *p != Permission::UserRead)
        .collect();
    for op in [
        "procedure.resolveUserProfiles",
        "procedure.resolveActorLabels",
        "procedure.searchUsers",
    ] {
        let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
            MapBearer::new().with("almost", token_info("almost-subject", almost_admin.clone())),
        );
        let router = build_router(bearer, false);
        let (status, _) = rpc_call(router, op, Wire::Cbor, &json!({}), Some("almost")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "`{op}` must require user:read, and no other permission may stand in for it"
        );
    }
}

/// ADR-0033's negative half: the three `platform_role_grants` op-ids are refused for a caller
/// holding EVERY other permission but not `rbac:manage`. Stated as "admin minus one" rather than
/// "viewer" deliberately — the interesting failure would be `rbac:manage` being implied by some
/// broader grant (`user:read`, `account:update`), and a viewer token could not tell that apart from
/// an ordinary read-only denial. This is the single most important refusal in the schema: a caller
/// who can write this table can make themselves `lightbridge-admin`.
#[tokio::test]
async fn rbac_gate_denies_platform_role_management_without_rbac_manage() {
    let almost_admin: PermissionSet = Permission::ALL
        .into_iter()
        .filter(|p| *p != Permission::RbacManage)
        .collect();
    for op in [
        "procedure.listPlatformRoleGrants",
        "procedure.grantPlatformRole",
        "procedure.revokePlatformRole",
    ] {
        let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
            MapBearer::new().with("almost", token_info("almost-subject", almost_admin.clone())),
        );
        let router = build_router(bearer, false);
        let (status, _) = rpc_call(router, op, Wire::Cbor, &json!({}), Some("almost")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "`{op}` must require rbac:manage, and no other permission may stand in for it"
        );
    }
}

/// The other side of the same coin: `getMyAccess` is the ONE op-id served to any authenticated
/// caller, so it must NOT be refused for a caller holding zero permissions at all -- otherwise the
/// console cannot ask what it may render. It reaches dispatch (which then fails on the lazy pool
/// this router is built over), so the assertion is "not 401/403", not "200".
///
/// Still fail-closed for an UNAUTHENTICATED caller: no bearer is a clean 401, not an anonymous
/// answer.
#[tokio::test]
async fn get_my_access_is_served_to_any_authenticated_caller_but_never_to_none() {
    let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(
        MapBearer::new().with("nobody", token_info("nobody-subject", PermissionSet::new())),
    );
    let router = build_router(bearer, false);
    let (status, body) = rpc_call(
        router.clone(),
        "procedure.getMyAccess",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("nobody"),
    )
    .await;
    assert!(
        status != StatusCode::FORBIDDEN && status != StatusCode::UNAUTHORIZED,
        "a caller with zero permissions must still be able to ask what they may do; got {status}:          {}",
        String::from_utf8_lossy(&body)
    );

    let (status, _) = rpc_call(
        router,
        "procedure.getMyAccess",
        Wire::Cbor,
        &json!({ "args": {} }),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "`authenticated only` still means authenticated"
    );
}

/// Deliberately-unmapped and defense-in-depth op-ids are denied unconditionally, even for an admin
/// holding every permission (fail closed — the map, not the token, is the gate here).
#[tokio::test]
async fn rbac_gate_denies_unmapped_and_locked_ops_even_for_admin() {
    for op in [
        "model.Account.create",
        // #398: #379 left `Account.defaultQuota` (the verb's only settable field) `@readonly`,
        // so `model.Account.update` had zero writable fields left and 422ed unconditionally for
        // every caller. The schema's `@@allow("update")` and this op-id's permission mapping were
        // both removed rather than leaving a verb that could only ever fail — the assertion below
        // proves it now denies with 403, not the old 422.
        "model.Account.update",
        "model.ApiKey.create",
        "model.ProjectMember.list",
        "model.ProjectMember.create",
        "model.Account.frobnicate",
        "procedure.unknown",
        "",
    ] {
        let router = build_router(admin_bearer(), false);
        let (status, _) = rpc_call(router, op, Wire::Cbor, &json!({}), Some("admin")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "unmapped/locked op `{op}` must be denied unconditionally"
        );
    }
}

/// `/rpc/batch` bundles multiple ops in its frame body, so the gate can't check a single op-id's
/// permission the way it does for unary calls — but it still requires *some* valid, active caller up
/// front (a wholly unauthenticated batch call gets a clean top-level 401 here, rather than a `200`
/// envelope full of per-frame errors). This file's routers are wired to unreachable Postgres/Redis on
/// purpose (see module docs), so a request the gate *allows through* necessarily fails later, once
/// `RateLimitLayer` tries to reach the dead Redis — the point of these two assertions is only that the
/// RBAC gate itself stops rejecting with 401 as soon as the token is valid; per-frame permission
/// enforcement against real ops (and a real 200 with mixed frame outcomes) needs a live DB/Redis and
/// lives in `rpc_it_tests.rs` (`batch_rpc_frames_enforce_permission_per_frame`).
#[tokio::test]
async fn rbac_gate_on_the_batch_endpoint_requires_a_valid_token_then_forwards() {
    async fn batch_request(token: Option<&str>) -> StatusCode {
        let router = build_router(admin_bearer(), false);
        let mut builder = Request::builder()
            .method("POST")
            .uri("/rpc/batch")
            .header("content-type", "application/cbor");
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        router
            .oneshot(builder.body(Body::from("[]")).unwrap())
            .await
            .unwrap()
            .status()
    }

    assert_eq!(
        batch_request(None).await,
        StatusCode::UNAUTHORIZED,
        "batch with no bearer token must be rejected before dispatch"
    );
    assert_eq!(
        batch_request(Some("bogus-token")).await,
        StatusCode::UNAUTHORIZED,
        "batch with an invalid token must be rejected before dispatch"
    );
    let status = batch_request(Some("admin")).await;
    assert!(
        status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
        "batch with a valid, active token must not be rejected by the RBAC gate itself (got \
         {status}); it now reaches the rate-limit layer instead, which fails against this file's \
         intentionally dead Redis — a real 200 is proven live in rpc_it_tests.rs"
    );
}

/// The RPC surface honours `server.api.rpc_base_path`. With `/api` configured, a mapped op is
/// reachable — and gate-resolved — at `/api/rpc/<op_id>`; an unauthenticated call gets 401
/// (missing bearer), which proves the op-id resolved (an unmapped op would be a 403 *before* the
/// bearer check). Meanwhile the old root path `/rpc/<op_id>` is gone (404). Status codes alone
/// distinguish the cases (401 resolved-but-unauthenticated vs 404 no-route), so this needs no
/// bearer, body, or DB.
#[tokio::test]
async fn rpc_surface_honours_configured_base_path() {
    let req = |uri: &str| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/cbor")
            .body(Body::from("{}"))
            .unwrap()
    };

    // Mapped op at the configured prefix: op-id resolves, then 401 for the missing bearer.
    let router = build_router_at(admin_bearer(), Some("/api"));
    let resolved = router
        .oneshot(req("/api/rpc/model.Account.list"))
        .await
        .unwrap();
    assert_eq!(
        resolved.status(),
        StatusCode::UNAUTHORIZED,
        "a mapped op under the base path must resolve then require a bearer (401), not read as unmapped"
    );

    // The surface no longer answers at the root when a base path is configured.
    let router = build_router_at(admin_bearer(), Some("/api"));
    let moved = router
        .oneshot(req("/rpc/model.Account.list"))
        .await
        .unwrap();
    assert_eq!(
        moved.status(),
        StatusCode::NOT_FOUND,
        "the RPC surface must not stay mounted at the root when rpc_base_path is set"
    );

    // Default (no base path) keeps serving at the root.
    let router = build_router_at(admin_bearer(), None);
    let default_root = router
        .oneshot(req("/rpc/model.Account.list"))
        .await
        .unwrap();
    assert_eq!(
        default_root.status(),
        StatusCode::UNAUTHORIZED,
        "with no base path the op stays at the root and resolves (401 for the missing bearer)"
    );
}

/// A mapped op with no bearer → 401 (missing token); with an unknown/invalid token → 401.
#[tokio::test]
async fn rbac_gate_requires_a_valid_token_on_mapped_ops() {
    let router = build_router(admin_bearer(), false);
    let (status, _) = rpc_call(router, "model.Account.list", Wire::Cbor, &json!({}), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing token → 401");

    let router = build_router(admin_bearer(), false);
    let (status, _) = rpc_call(
        router,
        "model.Account.list",
        Wire::Cbor,
        &json!({}),
        Some("bogus-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "invalid token → 401");
}

/// `listBillingPlans` is gated at the same `apikey:create` permission as `createApiKey` (not a
/// new, looser one) -- a viewer (`account:read`/`project:read`/`apikey:read` only, no
/// `apikey:create`) must be refused exactly like on `createApiKey` itself.
#[tokio::test]
async fn list_billing_plans_denied_for_caller_without_apikey_create() {
    let router = build_router(admin_and_viewer_bearer(), false);
    let (status, _) = rpc_call(
        router,
        "procedure.listBillingPlans",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("viewer"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be denied listBillingPlans by the RBAC gate"
    );
}

/// End-to-end proof that `listBillingPlans` reaches dispatch and answers from the router's actual
/// configured `Billing` catalogue -- not a placeholder, not `Billing::default()` (which is empty
/// and would make this assert an empty array instead). No DB access happens (this file's stores
/// are all lazily wired to unreachable Postgres/Redis, see the module docs), because
/// `AuthzStoreImpl::billing_plans` is a plain in-memory accessor.
#[tokio::test]
async fn list_billing_plans_returns_the_configured_catalogue_over_rpc() {
    let billing = Billing {
        plans: vec![
            lightbridge_authz_core::config::BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: Some(lightbridge_authz_core::config::BillingLimits {
                    requests_per_second: Some(5),
                    requests_per_day: Some(5000),
                    requests_per_month: None,
                    concurrent_requests: Some(5),
                }),
            },
            lightbridge_authz_core::config::BillingPlan {
                id: "enterprise".to_string(),
                name: "Enterprise".to_string(),
                limits: None,
            },
        ],
    };
    let router = build_router_with_billing(admin_bearer(), billing);
    let (status, body) = rpc_call(
        router,
        "procedure.listBillingPlans",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin must reach dispatch");
    let plans = as_json(Wire::Cbor, &body);
    assert_eq!(
        plans,
        json!([
            {"id": "free", "name": "Free", "limits": {"requestsPerSecond": 5, "requestsPerDay": 5000, "requestsPerMonth": null, "concurrentRequests": 5}},
            {"id": "enterprise", "name": "Enterprise", "limits": null},
        ]),
        "listBillingPlans must echo the router's configured catalogue verbatim"
    );
}

/// `listModelCatalog` is gated at `project:update` (not `apikey:create` like `listBillingPlans`
/// above -- see the schema doc comment on `listModelCatalog` for why it reuses `updateProject`'s
/// permission instead) -- a viewer (`account:read`/`project:read`/`apikey:read` only, no
/// `project:update`) must be refused.
#[tokio::test]
async fn list_model_catalog_denied_for_caller_without_project_update() {
    let router = build_router(admin_and_viewer_bearer(), false);
    let (status, _) = rpc_call(
        router,
        "procedure.listModelCatalog",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("viewer"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "viewer must be denied listModelCatalog by the RBAC gate"
    );
}

/// End-to-end proof that `listModelCatalog` reaches dispatch and answers from the router's actual
/// configured `ModelCatalog` -- not a placeholder, not `ModelCatalog::default()` (which is empty
/// and would make this assert an empty array instead). No DB access happens (this file's stores
/// are all lazily wired to unreachable Postgres/Redis, see the module docs), because
/// `AuthzStoreImpl::model_catalog` is a plain in-memory accessor. Mirrors
/// `list_billing_plans_returns_the_configured_catalogue_over_rpc` above.
#[tokio::test]
async fn list_model_catalog_returns_the_configured_catalogue_over_rpc() {
    let models = ModelCatalog {
        models: vec![
            lightbridge_authz_core::config::ModelCatalogEntry {
                id: "dev-model-a".to_string(),
                name: "Dev Model A".to_string(),
            },
            lightbridge_authz_core::config::ModelCatalogEntry {
                id: "dev-model-b".to_string(),
                name: "Dev Model B".to_string(),
            },
        ],
    };
    let router = build_router_with_models(admin_bearer(), models);
    let (status, body) = rpc_call(
        router,
        "procedure.listModelCatalog",
        Wire::Cbor,
        &json!({ "args": {} }),
        Some("admin"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admin must reach dispatch");
    let entries = as_json(Wire::Cbor, &body);
    assert_eq!(
        entries,
        json!([
            {"id": "dev-model-a", "name": "Dev Model A"},
            {"id": "dev-model-b", "name": "Dev Model B"},
        ]),
        "listModelCatalog must echo the router's configured catalogue verbatim"
    );
}

/// The budget-domain microservice split (see `docs/architecture/budget.md`, "Service boundary")
/// moved every `budget:*`-gated op-id off `authz-api` onto `authz-budget` as a HARD cutover --
/// `authz-api` no longer serves any of them, for any caller, permission included. This used to be
/// `editor_role_can_self_refill_but_not_review`, proving the self/review permission split
/// against `build_api_router` (#294); that behavioral coverage moved with the procedures onto
/// `budget_router_tests.rs::editor_role_can_self_refill_but_not_review`, exercised against
/// `build_budget_router` instead. What stays here is the cutover proof: an admin token -- every
/// permission that map could possibly require, including every `budget:*` one -- still gets
/// `404`, because scope, not permission, is what refuses these on `authz-api` now.
#[tokio::test]
async fn budget_gated_op_ids_are_unreachable_on_authz_api_regardless_of_permission() {
    let op_ids = [
        "procedure.activateBudgetPolicy",
        "procedure.getBudgetPolicyStatus",
        "procedure.simulateBudgetPolicy",
        "procedure.requestBudgetRefill",
        "procedure.listPendingAugmentationRequests",
        "procedure.approveAugmentationRequest",
        "procedure.rejectAugmentationRequest",
        "procedure.getMyBudgetBalance",
        "procedure.listMyBudgetGrants",
        "procedure.listMyAugmentationRequests",
        "procedure.getBudgetBalance",
        "procedure.listBudgetGrants",
        "procedure.grantBudget",
        "procedure.revokeBudgetGrant",
        "procedure.createBudgetPolicyRevision",
    ];
    for op in op_ids {
        let router = build_router(admin_bearer(), false);
        let (status, body) = rpc_call(router, op, Wire::Cbor, &json!({}), Some("admin")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{op} must be unreachable on authz-api (moved to authz-budget), even for an admin \
             holding every permission: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

/// The real, effective permission set for `role` as configured in the shipped
/// `config/default.yaml`, loaded and compiled through the exact same `Rbac::compile()` path a
/// running server takes at startup. Mirrors `editor_perms_from_shipped_config` above, generalized
/// to any role name so it also covers `lightbridge-viewer`.
fn perms_from_shipped_config(role: &str) -> lightbridge_authz_core::authz::PermissionSet {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/default.yaml");
    let config = lightbridge_authz_core::config::load_from_path(path)
        .expect("shipped config/default.yaml must parse");
    config
        .oauth2
        .rbac
        .compile()
        .roles
        .get(role)
        .cloned()
        .unwrap_or_else(|| panic!("config/default.yaml must configure role `{role}`"))
}

/// A first-time `lightbridge-viewer`/`lightbridge-editor` caller must be able to self-provision
/// their own account (`procedure.createAccount`, gated by `account:create`) -- without it,
/// `project_members.account_id`'s FK to `accounts` can never be satisfied for them, so no project
/// lead can ever add them to a roster (discovered diagnosing FK-violation test failures, #219).
/// Loads the grant from the *shipped* `config/default.yaml` (like
/// `editor_role_can_self_refill_but_not_review` above) so this fails for the right reason -- a
/// `permission_denied` 403 -- if the grant is ever reverted, instead of silently passing against a
/// stale, hand-copied permission set.
#[tokio::test]
async fn viewer_and_editor_roles_are_granted_account_create_by_shipped_config() {
    for role in ["lightbridge-viewer", "lightbridge-editor"] {
        let bearer: Arc<dyn BearerTokenServiceTrait> = Arc::new(MapBearer::new().with(
            "caller",
            token_info(&format!("{role}-subject"), perms_from_shipped_config(role)),
        ));
        let router = build_router(bearer, false);
        let (status, body) = rpc_call(
            router,
            "procedure.createAccount",
            Wire::Cbor,
            &json!({ "args": {} }),
            Some("caller"),
        )
        .await;
        assert!(
            status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
            "{role} must be granted procedure.createAccount by the RBAC gate, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

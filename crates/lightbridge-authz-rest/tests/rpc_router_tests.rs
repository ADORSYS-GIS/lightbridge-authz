//! Hermetic tests for the assembled authz-api RPC router (`build_api_router`), re-porting the
//! route-shape coverage the deleted `router_tests.rs`/`controllers_tests.rs` had (health probes,
//! dev-CORS, the well-known / token-exchange merges) onto the cratestack RPC surface, plus the
//! **fail-closed half** of the RBAC gate (`docs/rbac.md`, `rpc_authorize.rs`).
//!
//! Everything here is offline: the cratestack CRUD client / idempotency store / rate-limit store are
//! lazily connected to an unreachable address and never queried, because every request either
//!   * hits a non-RPC route (`/healthz*`, `/.well-known/*`, `/oauth2/token`, CORS preflight), or
//!   * is rejected by the outermost `rpc_authorize` gate (403/401) **before** dispatch, idempotency,
//!     or rate-limiting run.
//!
//! The *allow* half of the gate (viewer reads → 200, admin → 200 on every mapped op) reaches
//! dispatch and therefore needs a live DB + Redis; it lives in `rpc_it_tests.rs`.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{MapBearer, Wire, admin_perms, external_oauth2, rpc_call, token_info, viewer_perms};
use cratestack::SqlxIdempotencyStore;
use cratestack::ratelimit::RateLimitStore;
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::config::{JwtSigning, Oauth2, Oauth2TokenExchange, Oauth2Type};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;
use lightbridge_authz_rest::signing::ApiKeyJwtSigner;
use lightbridge_authz_rest::token_exchange::TokenExchangeState;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const DEAD_PG: &str = "postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz";
const DEAD_REDIS: &str = "redis://127.0.0.1:6379";

fn lazy_core_pool() -> Arc<dyn DbPoolTrait> {
    let pool = PgPoolOptions::new()
        .connect_lazy(DEAD_PG)
        .expect("lazy core pool");
    Arc::new(DbPool::from_pool(pool))
}

fn lazy_store_repo() -> Arc<StoreRepo> {
    Arc::new(StoreRepo::new(lazy_core_pool()))
}

fn lazy_cratestack_db() -> schema::Cratestack {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    schema::Cratestack::builder(pool).build()
}

fn lazy_idempotency() -> Arc<SqlxIdempotencyStore> {
    let pool = cratestack::sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(DEAD_PG)
        .expect("lazy cratestack pool");
    Arc::new(SqlxIdempotencyStore::new(pool))
}

fn lazy_rate_limit() -> Arc<dyn RateLimitStore> {
    build_redis_rate_limit_store(DEAD_REDIS, "authz-api-test").expect("rate limit store")
}

fn signing_cfg() -> JwtSigning {
    JwtSigning {
        issuer: "https://authz.example.test".to_string(),
        audience: None,
        ttl_seconds: 7_776_000,
        max_key_age_days: 30,
    }
}

fn self_signed_oauth2() -> Oauth2 {
    let mut oauth2 = external_oauth2();
    oauth2.oauth2_type = Oauth2Type::SelfSigned;
    oauth2.signing = Some(signing_cfg());
    oauth2
}

fn exchange_cfg() -> Oauth2TokenExchange {
    Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec!["openid".to_string()],
    }
}

/// Assemble the full API router with a caller-supplied bearer and (optional) token-exchange state,
/// everything else lazily wired to unreachable backends.
fn build_router(
    bearer: Arc<dyn BearerTokenServiceTrait>,
    oauth2: &Oauth2,
    token_exchange: Option<TokenExchangeState>,
    dev_cors: bool,
) -> Router {
    let core = lazy_core_pool();
    let issuer = Arc::new(AuthzStoreImpl::with_pool(core.clone()));
    lightbridge_authz_rest::build_api_router(
        oauth2,
        bearer,
        issuer,
        lazy_cratestack_db(),
        core,
        lazy_store_repo(),
        token_exchange,
        lazy_idempotency(),
        lazy_rate_limit(),
        dev_cors,
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
        let router = build_router(admin_bearer(), &external_oauth2(), None, false);
        assert_eq!(get(router, uri).await, StatusCode::OK, "probe {uri}");
    }
}

#[tokio::test]
async fn dev_cors_preflight_is_answered_with_permissive_headers() {
    let router = build_router(admin_bearer(), &external_oauth2(), None, true);
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
    let router = build_router(admin_bearer(), &external_oauth2(), None, true);
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
    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
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

#[tokio::test]
async fn well_known_discovery_is_merged_only_for_self_signed_oauth2() {
    // self-signed → well-known router merged, discovery served (static, no DB).
    let router = build_router(admin_bearer(), &self_signed_oauth2(), None, false);
    assert_eq!(
        get(router, "/.well-known/openid-configuration").await,
        StatusCode::OK,
        "self-signed oauth2 must publish OIDC discovery"
    );

    // external → not merged. The path is not a public route, so it falls through to the RPC
    // router's fallback, which the outermost `rpc_authorize` gate wraps — an unknown op-id is
    // fail-closed to 403 (never 200, i.e. the discovery document is decidedly not served).
    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
    assert_eq!(
        get(router, "/.well-known/openid-configuration").await,
        StatusCode::FORBIDDEN,
        "external oauth2 must not publish the self-signed discovery document"
    );
}

#[tokio::test]
async fn token_exchange_route_is_merged_when_configured() {
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(), lazy_store_repo())
        .expect("signer builds from config");
    let te = TokenExchangeState {
        repo: lazy_store_repo(),
        signer,
        bearer: admin_bearer(),
        cfg: exchange_cfg(),
    };
    let router = build_router(admin_bearer(), &self_signed_oauth2(), Some(te), false);

    // The route is merged: a POST reaches the handler (Form extraction fails on an empty body →
    // 4xx), which is decisively *not* the 404 an unmerged route would give.
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
    // Merged → the request reaches the token handler (Form extraction fails on the empty body →
    // a 4xx that is neither the 404 of an absent route nor the 403 the gate gives unmatched paths).
    assert_ne!(status, StatusCode::NOT_FOUND, "route should be merged");
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "merged route reaches the handler, not the gate fallback (got {status})"
    );
}

#[tokio::test]
async fn token_exchange_route_absent_when_not_configured() {
    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
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
    // Not merged → swallowed by the RPC fallback + `rpc_authorize` gate → fail-closed 403 (the
    // merged case above instead reaches the handler and returns a non-403 4xx).
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The security-critical fail-closed half of the RBAC gate: a read-only viewer is rejected on every
/// mutating op-id *before* the request reaches cratestack dispatch (so this needs no DB).
#[tokio::test]
async fn rbac_gate_denies_viewer_on_every_mutating_op() {
    for op in [
        "model.Account.update",
        "model.Account.delete",
        "procedure.createAccount",
        "procedure.disableAccount",
        "procedure.enableAccount",
        "procedure.addAccountMember",
        "procedure.removeAccountMember",
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
        let router = build_router(admin_and_viewer_bearer(), &external_oauth2(), None, false);
        let (status, _) = rpc_call(router, op, Wire::Json, &json!({}), Some("viewer")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer must be denied `{op}` by the RBAC gate"
        );
    }
}

/// Deliberately-unmapped and defense-in-depth op-ids are denied unconditionally, even for an admin
/// holding every permission (fail closed — the map, not the token, is the gate here).
#[tokio::test]
async fn rbac_gate_denies_unmapped_and_locked_ops_even_for_admin() {
    for op in [
        "model.Account.create",
        "model.ApiKey.create",
        "model.AccountMembership.list",
        "model.AccountMembership.create",
        "model.Account.frobnicate",
        "procedure.unknown",
        "",
    ] {
        let router = build_router(admin_bearer(), &external_oauth2(), None, false);
        let (status, _) = rpc_call(router, op, Wire::Json, &json!({}), Some("admin")).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "unmapped/locked op `{op}` must be denied unconditionally"
        );
    }
}

/// `/rpc/batch` is denied wholesale by the gate — a single URL-derived op-id can't represent the
/// per-frame permissions, so even an admin is refused (`docs/rbac.md`, `rpc_authorize.rs`).
#[tokio::test]
async fn rbac_gate_denies_the_batch_endpoint_for_admin() {
    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rpc/batch")
                .header("content-type", "application/json")
                .header("authorization", "Bearer admin")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the batch fan-out endpoint must be denied by the RBAC gate"
    );
}

/// A mapped op with no bearer → 401 (missing token); with an unknown/invalid token → 401.
#[tokio::test]
async fn rbac_gate_requires_a_valid_token_on_mapped_ops() {
    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
    let (status, _) = rpc_call(router, "model.Account.list", Wire::Json, &json!({}), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing token → 401");

    let router = build_router(admin_bearer(), &external_oauth2(), None, false);
    let (status, _) = rpc_call(
        router,
        "model.Account.list",
        Wire::Json,
        &json!({}),
        Some("bogus-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "invalid token → 401");
}

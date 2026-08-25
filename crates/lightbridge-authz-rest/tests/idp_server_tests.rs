// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! ADR-0012, ADR-0023: `authz-idp` carries `/oauth2/token`, `/oauth2/revoke`,
//! `/oauth2/device_authorization`, `.well-known/*`, `/authorize`, `/device/verify`, and
//! `/idp/callback` on a dedicated `idp` subcommand/server. The `auth.ai.camer.digital` ingress
//! routes directly to `authz-idp`, and `authz-api`'s own copy of this surface has been removed
//! (see `build_api_router`'s doc comment in `lib.rs`) -- `authz-idp` is the sole owner. Since
//! ADR-0023, `authz-idp` is a full IdP: `oauth2.relying_party` and an enabled
//! `oauth2.token_exchange` are both MANDATORY, and every flow route this file exercises is
//! mounted unconditionally -- there is no longer a "the RP-leg isn't configured" or "token
//! exchange is disabled" state for `build_idp_router` itself to represent (those are
//! `start_idp_server`-only startup-refusal states now, covered in `mod db` below). This file
//! proves what that now depends on:
//! 1. `build_idp_router` serves discovery + JWKS with real content, and `build_api_router` no
//!    longer serves either at all (`api_router_no_longer_serves_well_known_idp_still_does`).
//! 2. `build_idp_router` serves `/oauth2/token`, `/oauth2/revoke`, `/authorize`,
//!    `/device/verify`, and `/idp/callback` -- ALL unconditionally
//!    (`build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally` is the test
//!    that would have caught the production defect ADR-0023 closes: PR #473 (468084a) made
//!    `relying_party` mount-conditional, which let a live deployment advertise `device_code` in
//!    discovery while `/device/verify` 404'd).
//! 3. Its probes behave like every other server's, DB-unavailable readiness failure included.
//! 4. The signing-key ownership decision (`authz-idp` bootstraps, like `authz-api`/
//!    `lightbridge-mcp`) is safe under concurrent bootstraps.
//!
//! `build_idp_router_omits_well_known_when_oauth2_is_external` was DELETED: its premise (a
//! deployment can reach `build_idp_router` with `oauth2.type: external`) no longer holds --
//! `start_idp_server_rejects_external_oauth2` (below) already proves that startup path refuses to
//! start, and `build_idp_router_always_serves_discovery_and_jwks` (below) proves the surface is
//! now unconditional for every deployment that DOES start.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{IdpServer, JwtSigning, Oauth2, Oauth2Type, Tls};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::{build_idp_router, start_idp_server};
use tower::ServiceExt;

/// `build_idp_router` requires a real, already-validated `Arc<KeycloakRelyingParty>` and
/// `TokenExchangeState` now (ADR-0023) -- there is no `None`/unmounted state left for a call site
/// to pass. `offline_idp_router`/`full_idp_oauth2`/`offline_relying_party` below assemble those
/// fully offline (no live database or Redis touched), mirroring how `start_idp_server` assembles
/// the real ones in production. `lazy_pool` itself stays unreachable-but-well-formed, same as
/// before -- only `probe_router`'s `/healthz/ready` DB-unavailable test relies on it actually
/// failing to connect.
fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

/// A nonexistent directory is fine here: the tests that use this constant don't exercise the
/// static build's actual file-serving behavior (that's `static_assets_tests.rs`'s job for the
/// service in isolation, and this file's own `ui_static_dir`-based tests below for it mounted at
/// `/ui`) -- they only assert that existing protocol routes still resolve correctly with the
/// `/ui`-scoped static mount present, per ADR-0021's path-scoping property (#442): protocol
/// routes and `/ui` occupy disjoint path spaces, so a real static build vs. this nonexistent one
/// makes no difference to whether `.well-known/*`/`/oauth2/*`/the probe router still work.
const TEST_STATIC_DIR: &str = "/nonexistent/idp-server-tests/static";

fn bad_tls() -> Tls {
    Tls {
        cert_path: "/nonexistent/idp-server-tests/cert.pem".to_string(),
        key_path: "/nonexistent/idp-server-tests/key.pem".to_string(),
        client_ca_bundle_path: None,
    }
}

fn signing_cfg() -> JwtSigning {
    JwtSigning {
        issuer: "https://authz-idp.example.test".to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: 7_776_000,
        max_key_age_days: 30,
    }
}

fn external_oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url: "http://jwks".to_string(),
        oauth2_url: None,
        issuer_url: None,
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        issuance: None,
        audience: None,
        signing: None,
        token_exchange: None,
        relying_party: None,
        rbac: Default::default(),
        clients: Vec::new(),
        // Matches `working_relying_party()`'s own `issuer` below, so `full_idp_oauth2()` (which
        // sets `relying_party = Some(working_relying_party())`) satisfies `start_idp_server`'s
        // `federation.issuer == relying_party.issuer` check by default -- tests that need a
        // mismatch override this field explicitly.
        federation: Some(lightbridge_authz_core::config::Federation {
            issuer: "https://keycloak.example.test".to_string(),
        }),
    }
}

fn self_signed_oauth2() -> Oauth2 {
    let mut oauth2 = external_oauth2();
    oauth2.oauth2_type = Oauth2Type::SelfSigned;
    oauth2.signing = Some(signing_cfg());
    oauth2
}

/// `probe_router`'s `/healthz`/`/healthz/startup` never touch the database; `/healthz/ready` does
/// (`is_database_ready`). A `lazy_pool()` pointed at an unreachable address exercises the real
/// failure branch without needing Docker -- mirrors `build_api_router`/`build_opa_router`'s own
/// probe wiring exactly (`lib.rs`'s `probe_router` helper both now share).
#[tokio::test]
async fn build_idp_router_probes_behave_like_the_other_servers_including_db_unavailable() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    for path in ["/", "/healthz", "/healthz/startup"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri("/healthz/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must report unavailable when the database is unreachable, exactly like \
         build_api_router/build_opa_router"
    );
}

/// A real temp directory for the `/ui`-mounting tests below, mirroring
/// `static_assets_tests.rs::build_dir` -- `ServeDir`/`ServeFile` do real filesystem I/O, so the
/// behavior worth proving (which file gets served under `/ui`, and that nothing outside `/ui` is
/// reachable at all) only means something against actual files on disk. Unique per call
/// (nanosecond suffix) so parallel `#[tokio::test]` functions never collide.
fn ui_static_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-idp-ui-mount-test-{name}-{nanos}"
    ));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        b"<!doctype html><title>hosted-login placeholder</title>",
    )
    .unwrap();
    std::fs::write(
        dir.join("assets/index-deadbeef.js"),
        b"console.log('placeholder');",
    )
    .unwrap();
    dir
}

/// Builds a fully-mounted offline `authz-idp` router for the `/ui`-mounting tests. Since
/// ADR-0023 there is no reduced-surface router left to build (every flow route is
/// unconditional), so this is a thin wrapper over `offline_idp_router` -- kept under its own name
/// because these tests are about where `static_dir` is reachable from, not about the rest of the
/// surface, and a real static build directory (not `TEST_STATIC_DIR`'s nonexistent path) is the
/// one thing they need that `offline_idp_router`'s other call sites don't.
fn ui_mount_router(static_dir: &std::path::Path) -> axum::Router {
    offline_idp_router(static_dir)
}

/// ADR-0021 Decision 10's follow-up (#442): the hosted login build is mounted at `/ui`, not the
/// router root, specifically so bare `GET /ui` (no trailing slash) is never a `404` -- the exact
/// wrinkle the owner called out ("I hate the /index.html -> 200 but / is api only"). Both the
/// bare and trailing-slash forms must resolve to the same `index.html`.
#[tokio::test]
async fn ui_bare_and_trailing_slash_both_serve_index_html() {
    let dir = ui_static_dir("bare-and-slash");
    let router = ui_mount_router(&dir);

    for path in ["/ui", "/ui/"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"<!doctype html><title>hosted-login placeholder</title>",
            "GET {path} must serve index.html"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Client-side routing under `/ui`: any path under the prefix that isn't a real static file must
/// still resolve to `index.html` with a `200`, exactly like the pre-`/ui` fallback behavior did,
/// just scoped to the prefix now.
#[tokio::test]
async fn ui_unknown_spa_route_falls_back_to_index_html() {
    let dir = ui_static_dir("spa-route");
    let router = ui_mount_router(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/ui/some/spa/route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        &body[..],
        b"<!doctype html><title>hosted-login placeholder</title>"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A real hashed asset must still be served, with Decision 10's immutable cache header, once
/// nested under `/ui` -- proves `nest_service` strips the `/ui` prefix correctly before the
/// request reaches `static_assets_fallback`'s own `/assets/` prefix check.
#[tokio::test]
async fn ui_serves_hashed_asset_with_immutable_cache_control() {
    let dir = ui_static_dir("asset");
    let router = ui_mount_router(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/ui/assets/index-deadbeef.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .unwrap(),
        "public, max-age=31536000, immutable"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"console.log('placeholder');");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The acceptance-criteria case this whole change exists for: `GET /` must keep returning
/// `authz-idp`'s own API-welcome-JSON `root_handler` response, never the SPA -- even with a real,
/// fully-populated static build mounted at `/ui`. Asserts real JSON content, not just status, so
/// a regression that accidentally routed `/` through the static fallback (getting `index.html`'s
/// HTML back with a `200`, same status code) would still be caught.
///
/// Prove-fail-first (recorded verbatim, then reverted): temporarily deleted the
/// `.route("/", get(root_handler))` line from `probe_router` in `lib.rs` and reran just this
/// test. It failed with `assertion failed: left == right` on the status-code check --
/// `StatusCode::NOT_FOUND` (404) vs the expected `StatusCode::OK` -- because with no `/` route
/// registered, and no root-level fallback configured any more (the whole point of this PR:
/// `/ui`-nesting replaced the old root `.fallback_service`), an unmatched `/` now correctly falls
/// through to axum's default 404, proving this test actually depends on `root_handler` being
/// mounted rather than trivially passing regardless. Restored the line; the test passes again.
#[tokio::test]
async fn root_path_stays_api_welcome_json_not_the_spa() {
    let dir = ui_static_dir("root-not-spa");
    let router = ui_mount_router(&dir);

    let response = router
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("GET / must return the API welcome JSON, not HTML: {e}"));
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["message"], "Welcome to Lightbridge Authz API");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the acceptance criteria: a path that is neither a protocol route nor under
/// `/ui` must be a normal `404` -- the static build must not be a whole-server catch-all any
/// more, unlike the pre-`/ui` root-level `.fallback_service` mount it replaces.
///
/// Prove-fail-first (recorded verbatim, then reverted): temporarily reverted
/// `build_idp_router`'s last line from `router.nest_service("/ui", static_assets::
/// static_assets_fallback(static_dir))` back to the pre-PR
/// `router.fallback_service(static_assets::static_assets_fallback(static_dir))` and reran just
/// this test. It failed with `assertion failed: left == right` -- `StatusCode::OK` (200) vs the
/// expected `StatusCode::NOT_FOUND` -- because the old root-level fallback answers *every*
/// unmatched path with the SPA's `index.html`, exactly the "split personality" behavior this PR
/// removes. Restored the `nest_service` line; the test passes again.
#[tokio::test]
async fn unknown_path_outside_ui_prefix_returns_plain_404() {
    let dir = ui_static_dir("outside-ui-404");
    let router = ui_mount_router(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/some/unknown/path")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a path outside /ui that matches no protocol route must be a plain 404, not the SPA"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

struct UnreachableBearer;

#[async_trait]
impl lightbridge_authz_bearer::BearerTokenServiceTrait for UnreachableBearer {
    async fn validate_bearer_token(
        &self,
        _token: &str,
    ) -> anyhow::Result<lightbridge_authz_bearer::TokenInfo> {
        unreachable!("neither test below reaches a subject_token/bearer validation call")
    }
}

/// ADR-0015 Decision 6: `TokenExchangeOpStore::new` now requires a `PolicyEngine` for
/// `resolve_budget_tier`'s fail-closed fallback. Neither test in this file mints a token (both
/// exercise `/oauth2/revoke`'s pre-store request validation, or router wiring only), so this
/// double panics if actually consulted -- same "fully offline, unreachable if ever called"
/// contract as [`UnreachableBearer`] above.
#[derive(Debug)]
struct UnreachablePolicyEngine;

#[async_trait]
impl lightbridge_authz_budget::PolicyEngine for UnreachablePolicyEngine {
    async fn evaluate(
        &self,
        _facts: &lightbridge_authz_budget::Facts,
        _requested_amount_micros: i64,
    ) -> Result<lightbridge_authz_budget::Decision, lightbridge_authz_budget::BudgetError> {
        unreachable!("neither test below reaches a refill policy evaluation")
    }

    fn allowed_amounts_micros(&self) -> Vec<i64> {
        unreachable!("neither test below reaches a refill ladder read")
    }

    fn starting_amount_micros(&self) -> i64 {
        unreachable!("neither test below reaches a starting-amount read")
    }

    fn fail_closed_floor_micros(&self) -> i64 {
        unreachable!("neither test below reaches resolve_budget_tier's fail-closed fallback")
    }
}

/// Builds a fully offline `TokenExchangeState`: `ApiKeyJwtSigner::from_config` and
/// `RedisClientAssertionStore::connect` are both lazy (never dial out at construction time -- see
/// `signing::ApiKeyJwtSigner`'s and `RedisClientAssertionStore::connect`'s own doc comments), so
/// this never touches a database or Redis instance. Mirrors the private `build_token_exchange_state`
/// in `lib.rs` closely enough to prove `/oauth2/token`/`/oauth2/revoke` are reachable, without
/// needing that function to be `pub`.
fn offline_token_exchange_state(
    oauth2: &Oauth2,
    repo: Arc<StoreRepo>,
) -> lightbridge_authz_rest::token_exchange::TokenExchangeState {
    use lightbridge_authz_rest::oauth2_op::client_assertion_store::RedisClientAssertionStore;
    use lightbridge_authz_rest::oauth2_op::client_store::ConfigClientStore;
    use lightbridge_authz_rest::oauth2_op::store::TokenExchangeOpStore;
    use lightbridge_authz_rest::signing::ApiKeyJwtSigner;
    use lightbridge_authz_rest::token_exchange::TokenExchangeState;

    let cfg = oauth2
        .token_exchange
        .clone()
        .expect("caller supplies a self-signed oauth2 with token_exchange configured");
    let signer = ApiKeyJwtSigner::from_config(oauth2.signing.as_ref().unwrap(), repo.clone())
        .expect("valid signing config");
    let client_store = ConfigClientStore::from_config(&oauth2.clients);
    let assertions =
        RedisClientAssertionStore::connect("redis://127.0.0.1:1", None, "test:idp-server-tests:")
            .expect("lazy redis connection manager always builds");
    let bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
        Arc::new(UnreachableBearer);
    // Built off the SAME (lazy, never-dialed) pool `repo` already wraps -- `StoreRepo.pool` is
    // public precisely so callers like this can share one pool across repos without a second
    // connection config. Keeps this helper "fully offline" per its own doc comment above.
    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        repo.pool.clone(),
    ));
    let op_config = authkestra_op::config::OpConfig {
        issuer: oauth2.signing.as_ref().unwrap().issuer.clone(),
        scopes_supported: cfg.allowed_scopes.clone(),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "refresh_token".to_string(),
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: cfg.authorization_code_ttl_seconds,
        access_token_ttl_secs: cfg.access_ttl_seconds.max(0) as u64,
        device_code_ttl_secs: cfg.device_code_ttl_seconds as u64,
        token_exchange_enabled: cfg.enabled,
    };
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> =
        Arc::new(UnreachablePolicyEngine);
    let op_store = Arc::new(TokenExchangeOpStore::new(
        client_store,
        assertions,
        repo.clone(),
        repo,
        budget_repo,
        policy_engine,
        bearer,
        cfg,
        oauth2
            .federation
            .as_ref()
            .expect("caller supplies oauth2.federation")
            .issuer
            .clone(),
    ));
    TokenExchangeState::new(
        signer,
        op_config,
        op_store,
        "https://authz.example.test/device/verify".to_string(),
        600,
        5,
    )
}

fn token_exchange_oauth2() -> Oauth2 {
    let mut oauth2 = self_signed_oauth2();
    oauth2.token_exchange = Some(lightbridge_authz_core::config::Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        authorization_code_ttl_seconds: 300,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec!["openid".to_string(), "offline_access".to_string()],
        refresh_absolute_ttl_seconds: 7_776_000,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
    });
    oauth2
}

/// Offline-constructible `oauth2.relying_party` -- `KeycloakRelyingParty::new` only validates its
/// shape synchronously (timeout, TTL, base64url state key, callback URL/path), it never dials
/// out, so this is enough to satisfy `build_idp_router`'s now-mandatory `relying_party` parameter
/// without a live Keycloak. Shared by both the file-scope offline fixtures below and `mod db`'s
/// DB-backed startup tests that need a VALID relying-party block (`invalid_relying_party_cfg` in
/// `mod db` covers the deliberately-broken case).
fn working_relying_party() -> lightbridge_authz_core::config::OidcRelyingParty {
    lightbridge_authz_core::config::OidcRelyingParty {
        issuer: "https://keycloak.example.test".to_string(),
        client_id: "authz-idp-rp".to_string(),
        callback_url: "https://authz-idp.example.test/idp/callback".to_string(),
        client_secret: None,
        state_encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        token_encryption_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".to_string(),
        timeout_ms: 500,
        browser_session_ttl_seconds: 28_800,
    }
}

/// Builds a real, already-validated `Arc<KeycloakRelyingParty>` fully offline -- mirrors
/// `token_exchange_tests.rs`'s own `relying_party` helper. `build_idp_router` (ADR-0023) now
/// requires this parameter unconditionally, so every offline test in this file that builds a
/// router needs one; `InMemoryRateLimitStore` keeps the whole thing free of a real Redis, exactly
/// like `device_code_store_tests.rs`/`relying_party_tests.rs` already do for their own offline
/// router-building tests.
fn offline_relying_party(
    repo: Arc<StoreRepo>,
) -> Arc<lightbridge_authz_rest::relying_party::KeycloakRelyingParty> {
    Arc::new(
        lightbridge_authz_rest::relying_party::KeycloakRelyingParty::new(
            working_relying_party(),
            "https://keycloak.example.test/jwks".to_string(),
            repo,
            Arc::new(cratestack_axum::ratelimit::InMemoryRateLimitStore::new()),
        )
        .expect("working_relying_party() is a valid offline config"),
    )
}

/// The full-surface `oauth2` fixture: `token_exchange_oauth2()` plus a valid `relying_party`
/// block. Since ADR-0023 both are mandatory for `authz-idp`, so this (not `token_exchange_oauth2`
/// alone) is what every offline test in this file that builds a router through
/// `offline_idp_router` should use.
fn full_idp_oauth2() -> Oauth2 {
    let mut oauth2 = token_exchange_oauth2();
    oauth2.relying_party = Some(working_relying_party());
    oauth2
}

/// The shared offline `authz-idp` router fixture: every parameter `build_idp_router` now requires
/// (ADR-0023) -- a valid `signing` block, a `TokenExchangeState`, and a real
/// `Arc<KeycloakRelyingParty>` -- assembled fully offline from `full_idp_oauth2()`, mirroring how
/// `start_idp_server` assembles the real ones in production. Every call site in this file that
/// used to pass `None` for `token_exchange`/`relying_party` now goes through this helper instead.
fn offline_idp_router(static_dir: impl AsRef<std::path::Path>) -> axum::Router {
    let pool = lazy_pool();
    let oauth2 = full_idp_oauth2();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let token_exchange = offline_token_exchange_state(&oauth2, signing_repo.clone());
    let relying_party = offline_relying_party(signing_repo.clone());
    build_idp_router(
        &oauth2,
        oauth2.signing.as_ref().unwrap(),
        signing_repo,
        token_exchange,
        pool,
        static_dir,
        relying_party,
    )
}

/// RFC 7009 §2.2: `/oauth2/revoke` returns its client-authentication-failure/malformed-request
/// errors before ever consulting the store, so a request missing the required `token` field
/// proves the route is mounted and dispatching without needing a live database or Redis.
#[tokio::test]
async fn build_idp_router_serves_oauth2_revoke_without_touching_the_database() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "the route must be mounted and reach the handler, not 404"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "invalid_request");
}

/// Since ADR-0023 `authz-idp` always mounts the browser `/authorize` route alongside the token
/// surface, so discovery must always advertise the full 4-grant set plus the PKCE/authorize
/// metadata -- there is no longer a "device routes live, authorization-code metadata absent"
/// state to prove (that was PR #473's mount-conditional behavior, reversed by ADR-0023).
/// `response_modes_supported: ["query"]`/`code_challenge_methods_supported: ["S256"]` in
/// particular closed a real interop bug (#471: PKCE S256 is the only method this server actually
/// supports, and `query` is the only response mode `/authorize` returns).
///
/// Prove-fail-first (recorded verbatim in the PR body): temporarily swapped
/// `DiscoveryCapabilities::full_idp()` in `build_idp_router` for
/// `DiscoveryCapabilities::token_surface().with_device_authorization()` and reran just this test.
#[tokio::test]
async fn path_issuer_metadata_advertises_root_jwks_and_token_paths() {
    let pool = lazy_pool();
    let mut oauth2 = full_idp_oauth2();
    oauth2.signing.as_mut().unwrap().issuer = "https://authz.example.test/issuer/acme".to_string();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let state = offline_token_exchange_state(&oauth2, signing_repo.clone());
    let relying_party = offline_relying_party(signing_repo.clone());
    let router = build_idp_router(
        &oauth2,
        oauth2.signing.as_ref().unwrap(),
        signing_repo,
        state,
        pool,
        TEST_STATIC_DIR,
        relying_party,
    );

    let metadata = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/issuer/acme/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metadata.status(), StatusCode::OK);
    let body = to_bytes(metadata.into_body(), usize::MAX).await.unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        metadata["jwks_uri"],
        "https://authz.example.test/.well-known/jwks.json"
    );
    assert_eq!(
        metadata["token_endpoint"],
        "https://authz.example.test/oauth2/token"
    );
    assert_eq!(
        metadata["revocation_endpoint"],
        "https://authz.example.test/oauth2/revoke"
    );
    assert_eq!(
        metadata["device_authorization_endpoint"],
        "https://authz.example.test/oauth2/device_authorization",
        "the device endpoint is mounted with the token router and must be advertised at its real root route"
    );
    assert_eq!(
        metadata["grant_types_supported"],
        serde_json::json!([
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
            "authorization_code"
        ]),
        "authz-idp is a full IdP (ADR-0023): the authorization_code grant is always advertised \
         alongside the device grant, never conditionally"
    );
    assert_eq!(
        metadata["authorization_endpoint"],
        "https://authz.example.test/authorize"
    );
    assert_eq!(
        metadata["response_types_supported"],
        serde_json::json!(["code"])
    );
    assert_eq!(
        metadata["response_modes_supported"],
        serde_json::json!(["query"])
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        serde_json::json!(["S256"]),
        "PKCE S256 is the only method authz-idp supports (#471)"
    );
    for field in [
        "token_endpoint_auth_methods_supported",
        "token_endpoint_auth_signing_alg_values_supported",
        "revocation_endpoint_auth_methods_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
    ] {
        assert!(
            metadata.get(field).is_none(),
            "an empty client registry must not advertise {field}: {metadata}"
        );
    }

    let jwks = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let token = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let revoke = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/revoke")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke.status(), StatusCode::BAD_REQUEST);
}

/// `/oauth2/token`'s `Form<RawTokenRequest>` extractor requires `grant_type` -- an empty body
/// fails extraction before the handler runs, which axum reports as `422`, not `404`. That is
/// still proof the route is mounted (a truly unmounted path returns `404`), without requiring a
/// reachable signing key/database for a request this malformed.
#[tokio::test]
async fn build_idp_router_serves_oauth2_token_route() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(""))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "/oauth2/token must be mounted on the idp router"
    );
}

/// ADR-0023: since `oauth2.relying_party` and an enabled `oauth2.token_exchange` are both
/// mandatory for `authz-idp`, `build_idp_router` mounts `/authorize`, `/device/verify`, and
/// `/idp/callback` unconditionally -- there is no config shape left that reaches this function
/// without them. THIS is the test that would have caught the production defect ADR-0023 closes:
/// PR #473 (468084a) made `relying_party` mount-conditional, so a live deployment could advertise
/// `device_code` in discovery (gated only on `token_exchange`) while `/device/verify` and
/// `/idp/callback` 404'd -- "optional" and "half-broken" were the same state for that field. None
/// of the three routes needs a live database or Redis to prove it's mounted: `/authorize` and
/// `/idp/callback` both fail query-extraction before touching any store (`422`, not `404`), and
/// `verify_page` (`GET /device/verify`) is `Query`-only -- no `ConnectInfo`, no store lookup --
/// so it answers `200` unconditionally.
///
/// Prove-fail-first (recorded verbatim in the PR body): deleted the `relying_party::router`
/// merge from `build_idp_router` and reran -- `/device/verify` and `/idp/callback` both returned
/// `404`. Restored it, then separately deleted the `authorize::router` merge and reran --
/// `/authorize` returned `404`. Restored both.
#[tokio::test]
async fn build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let authorize = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        authorize.status(),
        StatusCode::NOT_FOUND,
        "/authorize must be mounted unconditionally"
    );

    let device_verify = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/device/verify?user_code=WDJB-MJHT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        device_verify.status(),
        StatusCode::OK,
        "/device/verify must be mounted unconditionally"
    );

    let callback = router
        .oneshot(
            Request::builder()
                .uri("/idp/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        callback.status(),
        StatusCode::NOT_FOUND,
        "/idp/callback must be mounted unconditionally"
    );
}

/// Mutation-testing regression guard (external review finding): every fixture in this file goes
/// through `full_idp_oauth2()`, which always sets `token_exchange.enabled = true`. That is a
/// fixture monoculture -- a mutant that reintroduces a conditional mount in `build_idp_router`
/// keyed on `oauth2.token_exchange.as_ref().map(|t| t.enabled).unwrap_or(false)` (re-inspecting
/// raw config instead of the already-assembled `TokenExchangeState`/`relying_party` parameters)
/// survives the entire suite, because every offline test's `oauth2.token_exchange` agrees with
/// what was actually assembled. It is an equivalent mutant TODAY only because
/// `start_idp_server` independently refuses `enabled: false` at startup (ADR-0023) -- but that
/// startup check has nothing to do with whether `build_idp_router` itself is honest about what it
/// mounts, and a future refactor could easily reintroduce a real gap between the two.
///
/// This test kills that whole mutant class structurally: it deliberately constructs an `oauth2`
/// whose `token_exchange` field is `None` -- incoherent with the real `TokenExchangeState`
/// separately passed to `build_idp_router` -- and asserts the router mounts everything anyway.
/// The incoherence is the point: `build_idp_router`'s mounting decision must derive from the
/// ASSEMBLED `token_exchange`/`relying_party` parameters it was actually given, never from
/// re-inspecting `oauth2`'s raw config (which, in production, `start_idp_server` only ever reads
/// before assembly, not after). Any conditional mount keyed off `oauth2.token_exchange` directly
/// -- present or not, `enabled` or not -- fails this test immediately, regardless of what any
/// other fixture in this file happens to set that field to.
///
/// Prove-fail-first (recorded verbatim in the PR body): reintroduced exactly this shape of mutant
/// -- gated the `relying_party::router` merge in `build_idp_router` on
/// `oauth2.token_exchange.as_ref().map(|t| t.enabled).unwrap_or(false)` -- and reran. This test
/// failed on `/device/verify` (404); the rest of the suite (including
/// `build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally` above, which
/// uses the same `enabled: true` fixture the mutant preserves) stayed green, confirming the old
/// suite alone would have missed it. Reverted.
#[tokio::test]
async fn build_idp_router_mount_does_not_consult_raw_token_exchange_config() {
    let pool = lazy_pool();
    let mut oauth2 = full_idp_oauth2();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let token_exchange = offline_token_exchange_state(&oauth2, signing_repo.clone());
    let relying_party = offline_relying_party(signing_repo.clone());
    // Deliberately incoherent with `token_exchange`/`relying_party` above: a real
    // TokenExchangeState was assembled from `oauth2` BEFORE this mutation, so a mount decision
    // that (wrongly) re-reads `oauth2.token_exchange` after the fact sees `None` here instead.
    oauth2.token_exchange = None;
    let router = build_idp_router(
        &oauth2,
        oauth2.signing.as_ref().unwrap(),
        signing_repo,
        token_exchange,
        pool,
        TEST_STATIC_DIR,
        relying_party,
    );

    let authorize = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/authorize")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        authorize.status(),
        StatusCode::NOT_FOUND,
        "/authorize must be mounted regardless of oauth2.token_exchange's raw config"
    );

    let device_verify = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/device/verify?user_code=WDJB-MJHT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        device_verify.status(),
        StatusCode::OK,
        "/device/verify must be mounted regardless of oauth2.token_exchange's raw config"
    );

    let callback = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/idp/callback")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        callback.status(),
        StatusCode::NOT_FOUND,
        "/idp/callback must be mounted regardless of oauth2.token_exchange's raw config"
    );

    let discovery = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    let body = to_bytes(discovery.into_body(), usize::MAX).await.unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        metadata["authorization_endpoint"], "https://authz-idp.example.test/authorize",
        "discovery must still advertise authorization_endpoint regardless of oauth2.token_exchange's raw config: {metadata}"
    );
}

/// The discovery/JWKS half of the same unconditional-surface property: since ADR-0023 there is no
/// deployment shape (`oauth2.type: self` having reached `build_idp_router` at all -- `type:
/// external` is refused by `start_idp_server` before this function is ever called, see
/// `start_idp_server_rejects_external_oauth2`) that leaves `.well-known/*` unmounted. The JWKS
/// `500` (not `200`) is deliberate and matches every other offline test in this file that hits
/// `/.well-known/jwks.json`: there is no bootstrapped signing key to serialize outside a real
/// database, per this crate's own established convention (see
/// `path_issuer_metadata_advertises_root_jwks_and_token_paths` above).
///
/// Prove-fail-first (recorded verbatim in the PR body): deleted the `signing::well_known_router`
/// merge from `build_idp_router` and reran -- both discovery paths returned `404` and `jwks.json`
/// returned `404` instead of `500`. Restored it.
#[tokio::test]
async fn build_idp_router_always_serves_discovery_and_jwks() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let oidc = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oidc.status(), StatusCode::OK);
    let body = to_bytes(oidc.into_body(), usize::MAX).await.unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(metadata["issuer"], "https://authz-idp.example.test");

    let oauth_metadata = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-authorization-server")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oauth_metadata.status(), StatusCode::OK);

    let jwks = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(
        jwks.status(),
        StatusCode::NOT_FOUND,
        "/.well-known/jwks.json must be mounted unconditionally"
    );
}

/// OIDC Discovery 1.0 §3 and RFC 8414 §2 both require these keys once the corresponding surface is
/// live; #471 is the interop bug that made `code_challenge_methods_supported` matter in the first
/// place (a client that trusts an absent field to mean "PKCE not required" is wrong). Since
/// ADR-0023 all three are unconditional for every `authz-idp` deployment, not just ones that
/// happen to configure `relying_party`.
///
/// Prove-fail-first (recorded verbatim in the PR body): swapped `DiscoveryCapabilities::full_idp()`
/// for `DiscoveryCapabilities::token_surface().with_device_authorization()` (i.e. `full_idp()`
/// minus `with_authorization_code()`) and reran -- all three keys were `Null`. Restored it.
#[tokio::test]
async fn discovery_always_carries_the_three_spec_required_keys() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(metadata["issuer"], "https://authz-idp.example.test");
    assert_eq!(
        metadata["authorization_endpoint"],
        "https://authz-idp.example.test/authorize"
    );
    assert_eq!(
        metadata["response_types_supported"],
        serde_json::json!(["code"])
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
}

/// `oauth2.type: external` has no signing key material for this service to serve discovery/JWKS
/// or dispatch a token-exchange grant from -- `authz-idp` exists only to serve the self-signed
/// surface, so it must refuse to start rather than come up half-configured. Offline: the check
/// happens before `start_idp_server` ever touches `pool`.
#[tokio::test]
async fn start_idp_server_rejects_external_oauth2() {
    let idp = IdpServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        static_dir: TEST_STATIC_DIR.to_string(),
    };
    let result = start_idp_server(&idp, lazy_pool(), &external_oauth2(), &None).await;
    let err = result.expect_err("authz-idp must reject oauth2.type: external");
    assert!(format!("{err}").contains("oauth2.type: self"), "got: {err}");
}

/// Mirrors `start_api_server_rejects_self_signed_oauth2_without_signing_block`
/// (`tests/lib_tests.rs`): `oauth2.type: self` with no `signing` block must fail before ever
/// touching the database, same short-circuit `authz-api` already has.
#[tokio::test]
async fn start_idp_server_rejects_self_signed_oauth2_without_signing_block() {
    let mut oauth2 = external_oauth2();
    oauth2.oauth2_type = Oauth2Type::SelfSigned;
    let idp = IdpServer {
        address: "127.0.0.1".to_string(),
        port: 0,
        tls: bad_tls(),
        static_dir: TEST_STATIC_DIR.to_string(),
    };
    let result = start_idp_server(&idp, lazy_pool(), &oauth2, &None).await;
    assert!(
        result.is_err(),
        "self-signed oauth2 without a signing block must be rejected"
    );
}

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    // OauthClient/OauthClientType are consumed only in this it-tests-gated module (the PKCE
    // client-registration tests near the bottom of this file) -- kept out of the file-scope
    // import so a default-features `cargo test` on this binary (mod db compiled out) doesn't
    // warn `unused_imports` for them.
    use lightbridge_authz_core::config::{OauthClient, OauthClientType, Redis};
    use lightbridge_authz_core::identity::AccountId;
    use lightbridge_authz_rest::auth_provider::SubjectResolver;
    use lightbridge_authz_rest::build_api_router;
    use sqlx::PgPool;

    fn repo(pool: PgPool) -> Arc<StoreRepo> {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
    }

    /// A trust-everything [`SubjectResolver`] test double: this file's `build_api_router` fixture
    /// never actually dispatches an authenticated request through it (every test here is rejected
    /// by the `rpc_authorize` gate before dispatch -- see `api_router_no_longer_serves_well_known`
    /// and friends), so it only needs to construct, never resolve for real.
    struct UnreachableResolver;

    #[lightbridge_authz_core::async_trait]
    impl SubjectResolver for UnreachableResolver {
        async fn resolve(
            &self,
            _iss: &str,
            sub: &str,
        ) -> lightbridge_authz_core::error::Result<AccountId> {
            Ok(AccountId::assert_already_resolved(sub))
        }
    }

    /// Unreachable but syntactically valid -- `start_idp_server`'s mandatory-redis check is
    /// presence-only (AGENTS.md's "Redis is a mandatory dependency" house rule): it only requires
    /// `redis.url` to be set, never that a live Redis already be reachable at process startup.
    /// Every constructor this URL eventually reaches (`RedisClientAssertionStore::connect`) is
    /// lazy and never dials out at construction time, so this never actually connects.
    fn unreachable_redis_cfg() -> Option<Redis> {
        Some(Redis {
            url: "redis://127.0.0.1:1".to_string(),
            ca_bundle_path: None,
        })
    }

    /// Proves the signing-key-ownership decision documented on
    /// `lightbridge_authz_rest::signing::bootstrap_signing_key`: `authz-idp` bootstraps its own
    /// active key rather than depending on `authz-api`/`lightbridge-mcp` to have done so first.
    /// Uses `full_idp_oauth2()` (not `self_signed_oauth2()`): since ADR-0023 `relying_party` is
    /// checked before signing-key bootstrap runs, so a fixture missing it would die on that check
    /// first and never reach bootstrap at all. Supplies a (deliberately unreachable, but
    /// well-formed) redis config so the mandatory-redis check further down `start_idp_server`
    /// doesn't intercept this before it reaches TLS load -- TLS cert paths are bogus, so
    /// `serve_tls` fails right after bootstrap without binding a socket -- same shape as
    /// `start_api_server_bootstraps_signing_key_for_self_signed_oauth2` in `tests/lib_tests.rs`.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_bootstraps_its_own_signing_key(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
        assert!(
            repo(pool.clone())
                .get_active_signing_key()
                .await
                .unwrap()
                .is_none(),
            "precondition: no active key yet"
        );

        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let result =
            start_idp_server(&idp, db_pool, &full_idp_oauth2(), &unreachable_redis_cfg()).await;
        let err = result.expect_err("missing TLS cert paths must surface as an error");
        assert!(
            !format!("{err}").to_lowercase().contains("redis"),
            "must fail on TLS load, not on the redis check, given a well-formed redis config: \
             got {err}"
        );

        assert!(
            repo(pool).get_active_signing_key().await.unwrap().is_some(),
            "start_idp_server must bootstrap an active signing key on its own before failing on \
             TLS load, exactly like start_api_server"
        );
    }

    /// Renamed from `start_idp_server_requires_redis_when_token_exchange_is_enabled`: since
    /// ADR-0023 `token_exchange` is mandatory (not conditionally enabled) for every `authz-idp`
    /// deployment, so "when token exchange is enabled" is no longer a distinguishing condition --
    /// this is simply the mandatory-redis check, exercised with the full mandatory surface
    /// configured (`full_idp_oauth2()`, which also configures `relying_party`).
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_requires_redis(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &full_idp_oauth2(), &None)
            .await
            .expect_err("no redis config must be rejected");
        assert!(format!("{err}").contains("redis"), "got: {err}");
    }

    /// Repurposed from `start_idp_server_requires_redis_without_token_exchange`: the unconditional
    /// half of the "Redis is a mandatory dependency" house rule (AGENTS.md), now proven against a
    /// fixture (`self_signed_oauth2()`) that configures NEITHER `relying_party` NOR
    /// `token_exchange` -- both of which are themselves now-mandatory checks that run AFTER the
    /// redis check (AGENTS.md:571-574's do-not-reintroduce-the-conditional guard, extended: redis
    /// must be checked, and must fail with its own message, before `relying_party`/
    /// `token_exchange` assembly is ever attempted, regardless of whether those blocks are
    /// present). The message must name `authz-idp` and `redis`, and must NOT mention
    /// `relying_party` -- if it did, that would mean the relying_party check ran first and
    /// produced a different error, silently reordering the documented check order (① type:self →
    /// ② signing → ③ redis → ④ relying_party → ⑤ token_exchange). The redis message's own
    /// long-standing text ("mandatory ... not only when oauth2.token_exchange is enabled",
    /// pre-dating ADR-0023) mentions `token_exchange` descriptively, so this deliberately does NOT
    /// assert its absence -- that phrase is about the redis rule's own history, not about which
    /// check actually ran.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_requires_redis_before_token_exchange_assembly(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &self_signed_oauth2(), &None)
            .await
            .expect_err(
                "authz-idp must refuse to start with no redis config even before relying_party/\
                 token_exchange are assembled",
            );
        let message = format!("{err}");
        assert!(message.contains("authz-idp"), "got: {message}");
        assert!(message.to_lowercase().contains("redis"), "got: {message}");
        assert!(
            !message.to_lowercase().contains("relying_party"),
            "redis must be checked before relying_party -- got: {message}"
        );
    }

    /// Enforcement is presence-only, not a startup-time reachability check (AGENTS.md's "Redis is
    /// a mandatory dependency" house rule): a syntactically valid but unreachable `redis.url` must
    /// NOT be rejected by the mandatory-redis check. Uses `full_idp_oauth2()` (not
    /// `token_exchange_oauth2()`): since ADR-0023 `relying_party` is mandatory too, so a fixture
    /// missing it would die on that check instead of reaching TLS load. With `token_exchange`
    /// enabled, this actually exercises `RedisClientAssertionStore::connect` (lazy, per its own
    /// doc comment), so the unreachable address never surfaces as an error here either -- the only
    /// failure is the deliberately-bogus TLS cert path further down.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_does_not_require_redis_to_be_reachable(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let result =
            start_idp_server(&idp, db_pool, &full_idp_oauth2(), &unreachable_redis_cfg()).await;
        let err = result.expect_err("missing TLS cert paths must surface as an error");
        assert!(
            !format!("{err}").to_lowercase().contains("redis"),
            "an unreachable-but-well-formed redis.url must not fail the mandatory-redis check: \
             got {err}"
        );
    }

    /// An `oauth2.relying_party` block that fails `KeycloakRelyingParty::new`'s own validation
    /// (here: a `state_encryption_key` that isn't 32 bytes once base64url-decoded).
    fn invalid_relying_party_cfg() -> lightbridge_authz_core::config::OidcRelyingParty {
        lightbridge_authz_core::config::OidcRelyingParty {
            // Must MATCH the fixture default's `federation.issuer` -- ADR-0025's
            // startup equality check runs before `KeycloakRelyingParty::new`, and this
            // fixture exists to reach new()'s own state-key validation, not the
            // federation check (which has its own dedicated mismatch test).
            issuer: "https://keycloak.example.test".to_string(),
            client_id: "authz-idp".to_string(),
            callback_url: "https://authz.example.test/oauth2/callback".to_string(),
            client_secret: None,
            state_encryption_key: "not-32-bytes-of-key-material".to_string(),
            token_encryption_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".to_string(),
            timeout_ms: 5_000,
            browser_session_ttl_seconds: 28_800,
        }
    }

    /// DELETES + REPLACES `start_idp_server_does_not_require_relying_party_when_rp_leg_is_not_
    /// configured`: that test's premise -- that an `authz-idp` deployment may legitimately omit
    /// `oauth2.relying_party` and still start -- is exactly what ADR-0023 reverses. It was itself
    /// the regression test for PR #463 (`9e0ef4d`), which PR #473 (468084a) then "fixed" by making
    /// `relying_party` mount-conditional -- reintroducing the "optional" reading that ADR-0023
    /// closes for good, owner's own words verbatim: "Let's not make something from the IdP
    /// optional anymore. It's a full IDP now." This test proves the opposite of the deleted one:
    /// a config that leaves `oauth2.relying_party` unset must be a hard startup failure, not a
    /// silent skip that reaches TLS load.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_refuses_to_start_without_relying_party(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = token_exchange_oauth2();
        assert!(
            oauth2.relying_party.is_none(),
            "precondition: this fixture must not configure relying_party"
        );
        oauth2.relying_party = None;
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "authz-idp is a full IdP (ADR-0023): a deployment that omits oauth2.relying_party \
                 must be refused at startup, not silently skip the RP-leg",
            );
        let message = format!("{err}");
        assert!(message.contains("oauth2.relying_party"), "got: {message}");
        assert!(message.contains("authz-idp"), "got: {message}");
    }

    /// Renamed from `start_idp_server_rejects_invalid_relying_party_when_configured`: since
    /// ADR-0023 `relying_party` is always configured for a deployment that reaches this point (the
    /// sibling test above now covers the "absent" case as a hard failure), so "when configured" is
    /// no longer a distinguishing condition -- `oauth2.relying_party` being mandatory must not
    /// degrade into accepting a garbage block either. Uses `unreachable_redis_cfg` so the
    /// mandatory-redis check doesn't intercept this first, isolating the assertion to the
    /// relying_party validation itself.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_rejects_invalid_relying_party(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = self_signed_oauth2();
        oauth2.relying_party = Some(invalid_relying_party_cfg());
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "an invalid oauth2.relying_party block must still be a hard startup failure",
            );
        let message = format!("{err}");
        assert!(
            message.contains("state_encryption_key"),
            "expected KeycloakRelyingParty::new's own validation error, got: {message}"
        );
    }

    /// ADR-0024: `token_encryption_key` gets the SAME offline shape validation as
    /// `state_encryption_key` (base64url, exactly 32 bytes) -- this exercises that half via the
    /// full `start_idp_server` startup path, mirroring `start_idp_server_rejects_invalid_relying_party`
    /// immediately above for the sibling key.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_refuses_a_malformed_token_encryption_key(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = self_signed_oauth2();
        let mut relying_party = working_relying_party();
        relying_party.token_encryption_key = "not-32-bytes-of-key-material".to_string();
        oauth2.relying_party = Some(relying_party);
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "a malformed oauth2.relying_party.token_encryption_key must be a hard startup \
                 failure",
            );
        let message = format!("{err}");
        assert!(
            message.contains("token_encryption_key"),
            "expected KeycloakRelyingParty::new's own validation error, got: {message}"
        );
    }

    /// ADR-0024: `token_encryption_key` must differ from `state_encryption_key` -- the two
    /// protect very different things (a short-lived browser-held cookie vs. a token set that can
    /// sit at rest for a session's full lifetime) and must never share a key.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_refuses_a_token_encryption_key_equal_to_the_state_key(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = self_signed_oauth2();
        let mut relying_party = working_relying_party();
        relying_party.token_encryption_key = relying_party.state_encryption_key.clone();
        oauth2.relying_party = Some(relying_party);
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "a token_encryption_key equal to state_encryption_key must be a hard startup \
                 failure",
            );
        let message = format!("{err}");
        assert!(
            message.contains("token_encryption_key"),
            "expected KeycloakRelyingParty::new's own validation error, got: {message}"
        );
        assert!(
            message.contains("state_encryption_key"),
            "the error must name both keys so an operator can see the conflict, got: {message}"
        );
    }

    /// ADR-0023's other mandatory half: `oauth2.token_exchange` entirely absent (`None`, the
    /// deployment never configured the block at all) must be a hard startup failure -- there is no
    /// `/oauth2/token`, no `/oauth2/device_authorization`, and the always-mounted
    /// `authorization_code` grant `authorize::router` serves cannot issue a redeemable token
    /// without it. Uses `working_relying_party()` so the (now-earlier) relying_party check doesn't
    /// intercept this first, isolating the assertion to the token_exchange requirement.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_refuses_to_start_without_token_exchange(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = self_signed_oauth2();
        oauth2.relying_party = Some(working_relying_party());
        assert!(
            oauth2.token_exchange.is_none(),
            "precondition: this fixture must not configure token_exchange"
        );
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "authz-idp is a full IdP (ADR-0023): a deployment that omits \
                 oauth2.token_exchange entirely must be refused at startup",
            );
        let message = format!("{err}");
        assert!(message.contains("oauth2.token_exchange"), "got: {message}");
        assert!(message.contains("authz-idp"), "got: {message}");
    }

    /// The other config shape for the same requirement: `oauth2.token_exchange` present but
    /// `enabled: false`. `build_token_exchange_state` itself still no-ops to `Ok(None)` for this
    /// shape (its own unit tests, `build_token_exchange_state_is_none_when_disabled`, cover that
    /// directly) -- this proves `start_idp_server` treats that `None` as fatal too, the same as
    /// the block being absent entirely.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_refuses_to_start_when_token_exchange_is_disabled(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = token_exchange_oauth2();
        oauth2.relying_party = Some(working_relying_party());
        oauth2.token_exchange.as_mut().unwrap().enabled = false;
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "authz-idp is a full IdP (ADR-0023): oauth2.token_exchange.enabled: false must \
                 be refused at startup, exactly like the block being absent",
            );
        let message = format!("{err}");
        assert!(message.contains("oauth2.token_exchange"), "got: {message}");
        assert!(
            message.contains("enabled: true"),
            "expected the message to name the fix, got: {message}"
        );
    }

    /// ADR-0025 Stage 1: every serving component this crate starts refuses to start without
    /// `oauth2.federation.issuer` -- the same shape as AGENTS.md's "Redis is a mandatory
    /// dependency" house rule (`start_api_server_requires_redis`/`start_budget_server_requires_redis`
    /// in `tests/lib_tests.rs`), applied to the new federation requirement across all four
    /// servers `lightbridge-authz-rest` starts. `self_signed_oauth2()` deliberately lacks
    /// `relying_party`/`token_exchange` (this file's own minimal fixture); that is fine here
    /// because `require_federation` runs before either of those checks in every one of the four
    /// `start_*_server` functions (verified by each assertion below naming ONLY the federation
    /// field, never a downstream requirement) -- see each function's own call site in `lib.rs`.
    #[tokio::test]
    async fn each_server_refuses_to_start_without_oauth2_federation_issuer() {
        use lightbridge_authz_core::config::{
            ApiKeyExpiry, ApiServer, BasicAuth, Billing, BillingPlan, BudgetServer, ModelCatalog,
            OpaServer, QuotaTiers,
        };
        use lightbridge_authz_rest::{start_api_server, start_budget_server, start_opa_server};

        let mut oauth2 = self_signed_oauth2();
        oauth2.federation = None;
        let billing = Billing {
            plans: vec![BillingPlan {
                id: "free".to_string(),
                name: "Free".to_string(),
                limits: None,
            }],
        };
        let quota_tiers = QuotaTiers::default();
        let models = ModelCatalog::default();
        let api_key_expiry = ApiKeyExpiry::default();

        let api = ApiServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            allowed_hosts: None,
            rpc_base_path: None,
        };
        let err = start_api_server(
            &api,
            lazy_pool(),
            &oauth2,
            &billing,
            &quota_tiers,
            &models,
            &api_key_expiry,
            &None,
            &None,
        )
        .await
        .expect_err("authz-api must refuse to start with no oauth2.federation.issuer");
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(message.contains("authz-api"), "got: {message}");

        let opa = OpaServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            basic_auth: BasicAuth {
                username: "opa-user".to_string(),
                password: "opa-pass".to_string(),
            },
        };
        let err = start_opa_server(&opa, lazy_pool(), &billing, &oauth2)
            .await
            .expect_err("authz-opa must refuse to start with no oauth2.federation.issuer");
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(message.contains("authz-opa"), "got: {message}");

        let budget = BudgetServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
        };
        let err = start_budget_server(
            &budget,
            lazy_pool(),
            &oauth2,
            &billing,
            &quota_tiers,
            &models,
            &api_key_expiry,
            &None,
            &None,
        )
        .await
        .expect_err("authz-budget must refuse to start with no oauth2.federation.issuer");
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(message.contains("authz-budget"), "got: {message}");

        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, lazy_pool(), &oauth2, &None)
            .await
            .expect_err("authz-idp must refuse to start with no oauth2.federation.issuer");
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(message.contains("authz-idp"), "got: {message}");
    }

    /// ADR-0025 Stage 1: `authz-idp` seals `federated_identities` rows under
    /// `oauth2.relying_party.issuer` (the browser-SSO login callback), but
    /// `resolve_account_for_federated_subject` grandfathers against `oauth2.federation.issuer`.
    /// A deployment where the two drift would mint federated identity rows this service can
    /// never resolve back through the ADR-0025 seam -- proves `start_idp_server` refuses to
    /// start in that state rather than silently running with an unreachable identity.
    #[sqlx::test(migrations = "../../migrations")]
    async fn idp_refuses_when_federation_issuer_differs_from_relying_party_issuer(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = full_idp_oauth2();
        assert_eq!(
            oauth2.federation.as_ref().map(|f| f.issuer.as_str()),
            oauth2.relying_party.as_ref().map(|rp| rp.issuer.as_str()),
            "precondition: full_idp_oauth2()'s federation and relying_party issuers must agree \
             before this test deliberately breaks that agreement"
        );
        oauth2.federation = Some(lightbridge_authz_core::config::Federation {
            issuer: "https://a-different-issuer.example.test".to_string(),
        });
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "a federation.issuer that disagrees with relying_party.issuer must be a hard \
                 startup failure for authz-idp",
            );
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(
            message.contains("oauth2.relying_party.issuer"),
            "got: {message}"
        );
    }

    /// OIDC Discovery 1.0 §3: `scopes_supported` MUST include `openid` for an OpenID Provider.
    /// `authz-idp` always mounts the `/authorize` browser-SSO flow and advertises
    /// `authorization_endpoint`, so it is always an OpenID Provider, not a bare OAuth2
    /// authorization server -- a deployment whose `oauth2.token_exchange.allowed_scopes` omits
    /// `openid` must be refused at startup rather than silently serve a spec-noncompliant
    /// discovery document.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_requires_openid_in_allowed_scopes(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = token_exchange_oauth2();
        oauth2.relying_party = Some(working_relying_party());
        oauth2.token_exchange.as_mut().unwrap().allowed_scopes = vec!["profile".to_string()];
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "oauth2.token_exchange.allowed_scopes without openid must be refused at startup",
            );
        let message = format!("{err}");
        assert!(message.contains("allowed_scopes"), "got: {message}");
        assert!(message.contains("openid"), "got: {message}");
    }

    /// Replaces `idp_and_api_routers_serve_byte_identical_discovery_and_jwks`, whose premise --
    /// that `authz-api` and `authz-idp` serve byte-identical discovery/JWKS -- is now deliberately
    /// false: `authz-api`'s own `well_known_router`/`token_exchange_router` merges were removed
    /// once the `auth.ai.camer.digital` ingress was repointed at `authz-idp` (see
    /// `build_api_router`'s doc comment in `lib.rs`). This proves the intended split instead:
    /// `authz-idp` still serves both paths with real content, and `authz-api`'s RPC router treats
    /// them as an unmapped op-id and fail-closes to `403` with no token required --
    /// `op_id_from_path` extracts `""` for any path with no `/rpc/` segment, which
    /// `rpc_authorize`'s fail-closed set denies unconditionally regardless of authentication (see
    /// that module's doc comment) -- never the `200` the two routers used to agree on.
    #[sqlx::test(migrations = "../../migrations")]
    async fn api_router_no_longer_serves_well_known_idp_still_does(pool: PgPool) {
        use cratestack::SqlxIdempotencyStore;
        use lightbridge_authz_api::schema;
        use lightbridge_authz_rest::handlers::AuthzStoreImpl;
        use lightbridge_authz_rest::ratelimit_redis::build_redis_rate_limit_store;

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
        let oauth2 = full_idp_oauth2();
        let signing_repo = repo(pool);
        lightbridge_authz_rest::signing::bootstrap_signing_key(
            &signing_repo,
            oauth2.signing.as_ref().unwrap(),
        )
        .await
        .unwrap();

        // authz-idp's router: thin, no cratestack/idempotency/rate-limit scaffolding needed.
        let idp_state = offline_token_exchange_state(&oauth2, signing_repo.clone());
        let idp_relying_party = offline_relying_party(signing_repo.clone());
        let idp_router = build_idp_router(
            &oauth2,
            oauth2.signing.as_ref().unwrap(),
            signing_repo,
            idp_state,
            db_pool.clone(),
            TEST_STATIC_DIR,
            idp_relying_party,
        );

        // authz-api's router: no oauth2/signing_repo/token_exchange params anymore (it mounts
        // neither well-known nor token-exchange), so the cratestack CRUD client / idempotency
        // store / rate-limit store just need to construct -- they're never touched, since both
        // paths this test drives are rejected by the `rpc_authorize` gate before dispatch.
        let lazy_cratestack_pool = cratestack::sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
            .expect("lazy cratestack pool should be constructible");
        let cratestack_db = schema::Cratestack::builder(lazy_cratestack_pool.clone()).build();
        let idempotency_store = Arc::new(SqlxIdempotencyStore::new(lazy_cratestack_pool));
        let rate_limit_store =
            build_redis_rate_limit_store("redis://127.0.0.1:1", None, "idp-test")
                .expect("well-formed redis url constructs a store without connecting");
        let bearer: Arc<dyn lightbridge_authz_bearer::BearerTokenServiceTrait> =
            Arc::new(UnreachableBearer);
        let issuer = Arc::new(AuthzStoreImpl::with_pool(db_pool.clone()));
        let policy_store = Arc::new(
            lightbridge_authz_budget::PolicyStore::load_active_from_db(
                db_pool.clone(),
                "budget-refill",
                10_000,
            )
            .await
            .expect("migration seeds an active budget-refill revision"),
        );
        let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
            db_pool.clone(),
        ));
        let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
            db_pool.clone(),
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
        let api_router = build_api_router(
            bearer,
            Arc::new(UnreachableResolver),
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
            cratestack_db,
            db_pool,
            idempotency_store,
            rate_limit_store,
            false,
            None,
        );

        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
        ] {
            let idp_response = idp_router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                idp_response.status(),
                StatusCode::OK,
                "authz-idp must still serve {path}"
            );
            let idp_body = to_bytes(idp_response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(
                !idp_body.is_empty(),
                "authz-idp's {path} response must carry real content"
            );

            let api_response = api_router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                api_response.status(),
                StatusCode::FORBIDDEN,
                "authz-api must no longer serve {path} -- expected the RPC gate's fail-closed \
                 unmapped-op-id response (403), got {}",
                api_response.status()
            );
        }
    }

    /// ADR-0021's highest-risk property (#442, "Risks" table in issue #442), updated for the
    /// follow-up that scoped the static build under `/ui`: the `/ui`-nested static mount must
    /// never shadow an existing protocol route, AND (the new half, since this used to be a
    /// whole-server catch-all) the static build must never answer for a path outside `/ui`
    /// either. Needs the DB-backed setup (a real bootstrapped signing key) so
    /// `/.well-known/jwks.json` actually succeeds -- offline it 500s for its own unrelated reason
    /// (no key to serialize), which would make a coarse status-code assertion here meaningless.
    /// Builds the idp router with a REAL, on-disk static build directory (not `TEST_STATIC_DIR`'s
    /// nonexistent path, so `/ui` is actually capable of answering every request under it) and
    /// proves three things: every existing protocol route still resolves to its own handler with
    /// real content; a genuinely unmatched path *under* `/ui` reaches the static build's SPA
    /// fallback (`index.html`, `200`, never a bare `404`); and that exact same path *without* the
    /// `/ui` prefix is a plain `404` -- proving the static build is scoped to `/ui`, not a
    /// catch-all for the whole server any more.
    #[sqlx::test(migrations = "../../migrations")]
    async fn static_fallback_never_shadows_an_existing_protocol_route(pool: PgPool) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let static_dir =
            std::env::temp_dir().join(format!("lightbridge-authz-idp-server-tests-static-{nanos}"));
        std::fs::create_dir_all(&static_dir).unwrap();
        std::fs::write(
            static_dir.join("index.html"),
            b"<!doctype html><title>hosted-login placeholder</title>",
        )
        .unwrap();

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool.clone()));
        let oauth2 = full_idp_oauth2();
        let signing_repo = repo(pool);
        lightbridge_authz_rest::signing::bootstrap_signing_key(
            &signing_repo,
            oauth2.signing.as_ref().unwrap(),
        )
        .await
        .unwrap();

        let idp_state = offline_token_exchange_state(&oauth2, signing_repo.clone());
        let relying_party = offline_relying_party(signing_repo.clone());
        let router = build_idp_router(
            &oauth2,
            oauth2.signing.as_ref().unwrap(),
            signing_repo,
            idp_state,
            db_pool,
            &static_dir,
            relying_party,
        );

        // A bare status-code check is not enough to prove non-shadowing: the SPA fallback also
        // answers every unmatched path with a 200. Each protocol route below is asserted against
        // its own real, non-placeholder body too, so a router bug that accidentally routes one of
        // these through the static fallback fails on content, not just status.
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/jwks.json",
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "GET {path} must still resolve to its protocol handler, not the static \
                 fallback, with a real static_dir mounted"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|e| {
                panic!(
                    "GET {path} must return real JSON discovery/JWKS content, not the static \
                     fallback's HTML placeholder: {e}, got {body:?}"
                )
            });
        }

        for path in ["/healthz", "/healthz/startup"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "GET {path} must still resolve to its protocol handler, not the static \
                 fallback, with a real static_dir mounted"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert!(
                body.is_empty(),
                "GET {path} must return the probe handler's empty body, not the static \
                 fallback's HTML placeholder: got {body:?}"
            );
        }

        for (path, expected) in [
            ("/oauth2/token", StatusCode::UNPROCESSABLE_ENTITY),
            ("/oauth2/revoke", StatusCode::BAD_REQUEST),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("content-type", "application/x-www-form-urlencoded")
                        .body(Body::from(""))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                expected,
                "POST {path} must still be dispatched to its own handler (a malformed-request \
                 status), not fall through to the static fallback (which would answer 200)"
            );
        }

        // ADR-0023: /authorize, /device/verify and /idp/callback are mounted unconditionally now
        // too, and must resolve to their own protocol handlers just like every route above --
        // never a bare 404, and never the /ui static fallback's placeholder body.
        for path in ["/authorize", "/device/verify", "/idp/callback"] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "GET {path} must still resolve to its own protocol handler, not a bare 404"
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            assert_ne!(
                &body[..],
                b"<!doctype html><title>hosted-login placeholder</title>",
                "GET {path} must not be shadowed by the /ui static fallback"
            );
        }

        let fallback_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/some/spa/route/that/is/not/a/protocol/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            fallback_response.status(),
            StatusCode::OK,
            "a genuinely unmatched path under /ui must reach the static build's SPA fallback and \
             get index.html back, never a bare 404"
        );
        let body = to_bytes(fallback_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            b"<!doctype html><title>hosted-login placeholder</title>"
        );

        // The other half of the path-scoping property (#442 follow-up): the exact same
        // unmatched path WITHOUT the /ui prefix must be a plain 404 -- the static build is no
        // longer a catch-all for the whole server. This is the assertion that would have caught
        // the pre-follow-up bug: under the old root-level `.fallback_service(..)` mount, this
        // same path answered 200 with the SPA's index.html instead.
        let outside_ui_response = router
            .oneshot(
                Request::builder()
                    .uri("/some/spa/route/that/is/not/a/protocol/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            outside_ui_response.status(),
            StatusCode::NOT_FOUND,
            "an unmatched path outside /ui must be a plain 404, not the static build's SPA \
             fallback"
        );

        let _ = std::fs::remove_dir_all(&static_dir);
    }

    fn authorization_code_client(
        client_id: &str,
        client_type: OauthClientType,
        require_pkce: bool,
    ) -> OauthClient {
        OauthClient {
            client_id: client_id.to_string(),
            client_type,
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            allowed_audiences: vec![client_id.to_string()],
            jwks: None,
            redirect_uris: vec!["https://cb.example.test/callback".to_string()],
            require_pkce,
        }
    }

    /// Follow-up to PR #466's review finding: `validate_authorization_code_clients` (`lib.rs`)
    /// used to gate the PKCE+redirect_uri requirement on `client_type == OauthClientType::Public`
    /// alone, so a Confidential client configured with the `authorization_code` grant and
    /// `require_pkce: false` started up cleanly -- and could then complete a full non-PKCE
    /// authorization_code flow end to end (`/authorize` enforced PKCE off `client.require_pkce`
    /// alone too, and the upstream `authkestra-op` token handler only verifies PKCE when a
    /// `code_challenge` was actually stored). OAuth 2.1 and RFC 9700 (OAuth Security BCP) recommend
    /// PKCE for every client type, not only public ones, to close authorization-code-injection
    /// attacks. This proves the startup gate now rejects a Confidential client exactly like it
    /// always rejected a Public one.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_rejects_confidential_authorization_code_client_without_pkce(
        pool: PgPool,
    ) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = token_exchange_oauth2();
        oauth2.relying_party = Some(working_relying_party());
        oauth2.clients = vec![authorization_code_client(
            "confidential-no-pkce",
            OauthClientType::Confidential,
            false,
        )];
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err(
                "a Confidential authorization_code client with require_pkce: false must be \
                 rejected at startup, not only a Public one",
            );
        let message = format!("{err}");
        assert!(message.contains("authorization_code"), "got: {message}");
        assert!(message.to_lowercase().contains("pkce"), "got: {message}");
    }

    /// The compliant half: a client with `require_pkce: true` and at least one `redirect_uri`
    /// still passes startup validation regardless of `client_type` -- Public and Confidential
    /// alike. `start_idp_server` proceeds past `validate_authorization_code_clients` and fails
    /// only on the deliberately-bogus TLS cert path further down, same shape as every other
    /// `start_idp_server_*` TLS-failure test in this module.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_accepts_pkce_compliant_authorization_code_clients_of_any_type(
        pool: PgPool,
    ) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = token_exchange_oauth2();
        oauth2.relying_party = Some(working_relying_party());
        oauth2.clients = vec![
            authorization_code_client("public-pkce", OauthClientType::Public, true),
            authorization_code_client("confidential-pkce", OauthClientType::Confidential, true),
        ];
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg())
            .await
            .expect_err("missing TLS cert paths must surface as an error");
        let message = format!("{err}").to_lowercase();
        assert!(
            !message.contains("pkce") && !message.contains("redirect_uri"),
            "PKCE-compliant clients of any client_type must pass \
             validate_authorization_code_clients and fail only on TLS load: got {message}"
        );
    }
}

// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! ADR-0012: `authz-idp` carries `/oauth2/token`, `/oauth2/revoke`, and `.well-known/*` on a
//! dedicated `idp` subcommand/server. The `auth.ai.camer.digital` ingress now routes directly to
//! `authz-idp`, and `authz-api`'s own copy of this surface has been removed (see
//! `build_api_router`'s doc comment in `lib.rs`) -- `authz-idp` is the sole owner. This file
//! proves what that now depends on:
//! 1. `build_idp_router` serves discovery + JWKS with real content, and `build_api_router` no
//!    longer serves either at all (`api_router_no_longer_serves_well_known_idp_still_does`).
//! 2. `build_idp_router` serves `/oauth2/token` and `/oauth2/revoke`.
//! 3. Its probes behave like every other server's, DB-unavailable readiness failure included.
//! 4. The signing-key ownership decision (`authz-idp` bootstraps, like `authz-api`/
//!    `lightbridge-mcp`) is safe under concurrent bootstraps.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::{IdpServer, JwtSigning, Oauth2, Oauth2Type, Tls};
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::{build_idp_router, start_idp_server};
use tower::ServiceExt;

fn lazy_pool() -> Arc<dyn DbPoolTrait> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool should be constructible");
    Arc::new(DbPool::from_pool(pool))
}

/// A nonexistent directory is fine here: none of the tests in this file exercise the static
/// fallback's actual file-serving behavior (that's `static_assets_tests.rs`'s job) -- they only
/// assert that existing protocol routes still resolve with the fallback mounted, per ADR-0021's
/// mount-order requirement (#442).
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
        rbac: Default::default(),
        clients: Vec::new(),
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
    let pool = lazy_pool();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let router = build_idp_router(
        &self_signed_oauth2(),
        signing_repo,
        None,
        pool,
        TEST_STATIC_DIR,
    );

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

/// `well_known_router` only mounts under `oauth2.type: self` + `oauth2.signing` (see
/// `build_idp_router`'s own gating, mirroring `build_api_router`'s). An `external` deployment
/// must not serve `.well-known/*` from `authz-idp` at all -- matching the same non-mount on
/// `authz-api` today.
#[tokio::test]
async fn build_idp_router_omits_well_known_when_oauth2_is_external() {
    let pool = lazy_pool();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let router = build_idp_router(
        &external_oauth2(),
        signing_repo,
        None,
        pool,
        TEST_STATIC_DIR,
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Protocol namespaces belong to the authorization server even when a particular endpoint is not
/// mounted. The hosted SPA must therefore not make a typo such as `/oauth2/future-grant` appear
/// to be a successful browser page.
#[tokio::test]
async fn static_fallback_refuses_unknown_protocol_namespace_paths() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let static_dir =
        std::env::temp_dir().join(format!("lightbridge-authz-idp-protocol-namespace-{nanos}"));
    std::fs::create_dir_all(&static_dir).unwrap();
    std::fs::write(static_dir.join("index.html"), b"hosted-login-placeholder").unwrap();

    let pool = lazy_pool();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let router = build_idp_router(&external_oauth2(), signing_repo, None, pool, &static_dir);

    for path in [
        "/.well-known/future-document",
        "/oauth2/future-grant",
        "/authorize",
        "/authorize/future-handler",
        "/userinfo",
        "/device_authorization",
        "/idp/callback",
        // Percent-encoded `/`: `http::Uri::path()` never decodes it, so a naive raw-string
        // `strip_prefix("/authorize")`/`starts_with(".../")` check sees a suffix that starts
        // with `%2F`, not `/`, and lets the request fall through to the SPA fallback as if it
        // were an unreserved path.
        "/authorize%2Ffuture-handler",
        "/oauth2%2Ftoken",
        "/.well-known%2Fjwks.json",
        // Mixed case: a byte-exact comparison against the lowercase reserved roots also lets
        // these fall through to the SPA fallback.
        "/OAuth2/token",
        "/AUTHORIZE",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must not fall through to index.html"
        );
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri("/device/verify")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        b"hosted-login-placeholder"
    );

    std::fs::remove_dir_all(static_dir).unwrap();
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
        response_types_supported: vec!["token".to_string()],
        grant_types_supported: vec![
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            "refresh_token".to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 0,
        access_token_ttl_secs: cfg.access_ttl_seconds.max(0) as u64,
        device_code_ttl_secs: 0,
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
    ));
    TokenExchangeState::new(signer, op_config, op_store)
}

fn token_exchange_oauth2() -> Oauth2 {
    let mut oauth2 = self_signed_oauth2();
    oauth2.token_exchange = Some(lightbridge_authz_core::config::Oauth2TokenExchange {
        enabled: true,
        access_ttl_seconds: 900,
        refresh_ttl_seconds: 2_592_000,
        allowed_scopes: vec!["openid".to_string(), "offline_access".to_string()],
        refresh_absolute_ttl_seconds: 7_776_000,
    });
    oauth2
}

/// RFC 7009 §2.2: `/oauth2/revoke` returns its client-authentication-failure/malformed-request
/// errors before ever consulting the store, so a request missing the required `token` field
/// proves the route is mounted and dispatching without needing a live database or Redis.
#[tokio::test]
async fn build_idp_router_serves_oauth2_revoke_without_touching_the_database() {
    let pool = lazy_pool();
    let oauth2 = token_exchange_oauth2();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let state = offline_token_exchange_state(&oauth2, signing_repo.clone());
    let router = build_idp_router(&oauth2, signing_repo, Some(state), pool, TEST_STATIC_DIR);

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

/// `/oauth2/token`'s `Form<RawTokenRequest>` extractor requires `grant_type` -- an empty body
/// fails extraction before the handler runs, which axum reports as `422`, not `404`. That is
/// still proof the route is mounted (a truly unmounted path returns `404`), without requiring a
/// reachable signing key/database for a request this malformed.
#[tokio::test]
async fn build_idp_router_serves_oauth2_token_route() {
    let pool = lazy_pool();
    let oauth2 = token_exchange_oauth2();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let state = offline_token_exchange_state(&oauth2, signing_repo.clone());
    let router = build_idp_router(&oauth2, signing_repo, Some(state), pool, TEST_STATIC_DIR);

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
    use lightbridge_authz_core::config::Redis;
    use lightbridge_authz_rest::build_api_router;
    use sqlx::PgPool;

    fn repo(pool: PgPool) -> Arc<StoreRepo> {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
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
    /// Supplies a (deliberately unreachable, but well-formed) redis config so the mandatory-redis
    /// check further down `start_idp_server` doesn't intercept this before it reaches TLS load --
    /// TLS cert paths are bogus, so `serve_tls` fails right after bootstrap without binding a
    /// socket -- same shape as `start_api_server_bootstraps_signing_key_for_self_signed_oauth2`
    /// in `tests/lib_tests.rs`.
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
        let result = start_idp_server(
            &idp,
            db_pool,
            &self_signed_oauth2(),
            &unreachable_redis_cfg(),
        )
        .await;
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

    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_requires_redis_when_token_exchange_is_enabled(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(&idp, db_pool, &token_exchange_oauth2(), &None)
            .await
            .expect_err("token_exchange enabled with no redis config must be rejected");
        assert!(format!("{err}").contains("redis"), "got: {err}");
    }

    /// The unconditional half of the "Redis is a mandatory dependency" house rule (AGENTS.md):
    /// `authz-idp` must refuse to start with no `redis.url` configured even when
    /// `oauth2.token_exchange` is disabled -- this used to be the one case that tolerated a
    /// missing redis config (the check lived inside the `token_exchange.enabled` branch); it no
    /// longer does.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_requires_redis_without_token_exchange(pool: PgPool) {
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
                "authz-idp must refuse to start with no redis config even without token_exchange",
            );
        let message = format!("{err}");
        assert!(message.contains("authz-idp"), "got: {message}");
        assert!(message.to_lowercase().contains("redis"), "got: {message}");
    }

    /// Enforcement is presence-only, not a startup-time reachability check (AGENTS.md's "Redis is
    /// a mandatory dependency" house rule): a syntactically valid but unreachable `redis.url` must
    /// NOT be rejected by the mandatory-redis check. With `token_exchange` enabled, this actually
    /// exercises `RedisClientAssertionStore::connect` (lazy, per its own doc comment), so the
    /// unreachable address never surfaces as an error here either -- the only failure is the
    /// deliberately-bogus TLS cert path further down.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_does_not_require_redis_to_be_reachable(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let result = start_idp_server(
            &idp,
            db_pool,
            &token_exchange_oauth2(),
            &unreachable_redis_cfg(),
        )
        .await;
        let err = result.expect_err("missing TLS cert paths must surface as an error");
        assert!(
            !format!("{err}").to_lowercase().contains("redis"),
            "an unreachable-but-well-formed redis.url must not fail the mandatory-redis check: \
             got {err}"
        );
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
        let oauth2 = token_exchange_oauth2();
        let signing_repo = repo(pool);
        lightbridge_authz_rest::signing::bootstrap_signing_key(
            &signing_repo,
            oauth2.signing.as_ref().unwrap(),
        )
        .await
        .unwrap();

        // authz-idp's router: thin, no cratestack/idempotency/rate-limit scaffolding needed.
        let idp_state = offline_token_exchange_state(&oauth2, signing_repo.clone());
        let idp_router = build_idp_router(
            &oauth2,
            signing_repo,
            Some(idp_state),
            db_pool.clone(),
            TEST_STATIC_DIR,
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

    /// ADR-0021's highest-risk property (#442, "Risks" table in issue #442): mounting the static
    /// fallback must never shadow an existing protocol route. Needs the DB-backed setup (a real
    /// bootstrapped signing key) so `/.well-known/jwks.json` actually succeeds -- offline it
    /// 500s for its own unrelated reason (no key to serialize), which would make a coarse
    /// status-code assertion here meaningless. Builds the idp router with a REAL, on-disk static
    /// build directory (not `TEST_STATIC_DIR`'s nonexistent path, so the fallback is actually
    /// capable of answering every request) and proves both directions: every existing protocol
    /// route still resolves to its own handler with real content, and only a genuinely unmatched
    /// path reaches the static fallback (getting `index.html` back with a `200`, never a bare
    /// `404`).
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
        let oauth2 = token_exchange_oauth2();
        let signing_repo = repo(pool);
        lightbridge_authz_rest::signing::bootstrap_signing_key(
            &signing_repo,
            oauth2.signing.as_ref().unwrap(),
        )
        .await
        .unwrap();

        let idp_state = offline_token_exchange_state(&oauth2, signing_repo.clone());
        let router = build_idp_router(&oauth2, signing_repo, Some(idp_state), db_pool, &static_dir);

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

        let fallback_response = router
            .oneshot(
                Request::builder()
                    .uri("/some/spa/route/that/is/not/a/protocol/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            fallback_response.status(),
            StatusCode::OK,
            "a genuinely unmatched path must reach the static fallback and get index.html back, \
             never a bare 404"
        );
        let body = to_bytes(fallback_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            b"<!doctype html><title>hosted-login placeholder</title>"
        );

        let _ = std::fs::remove_dir_all(&static_dir);
    }
}

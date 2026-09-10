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
use axum::http::{Request, StatusCode, header};
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

/// A claim-redeem state for router-shape tests. The pool is lazy, so nothing dials a database
/// unless a test actually exercises redemption -- these tests only assert what is mounted.
fn test_claim_redeem() -> lightbridge_authz_rest::claim_redeem::ClaimRedeemState {
    let repo = std::sync::Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(lazy_pool()));
    lightbridge_authz_rest::claim_redeem::ClaimRedeemState {
        claims: Some(std::sync::Arc::new(
            lightbridge_authz_rest::secret_claim::SecretClaimStore::new(
                repo.clone(),
                [7u8; 32],
                300,
            ),
        )),
        repo,
    }
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

/// The single issuer identity every offline fixture in this file agrees on -- `external_oauth2()`'s
/// `federation.issuer` and `offline_relying_party()`'s issuer argument both use this constant, so
/// there is exactly one place to change it (no more hand-kept-in-sync `relying_party.issuer` field
/// to drift from `federation.issuer`, now that the config-level equality trap is gone).
const WORKING_ISSUER: &str = "https://keycloak.example.test";

fn signing_cfg() -> JwtSigning {
    JwtSigning {
        issuer: "https://authz-idp.example.test".to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: 7_776_000,
        max_key_age_days: 30,
        claim_mappers: Vec::new(),
    }
}

fn external_oauth2() -> Oauth2 {
    Oauth2 {
        oauth2_type: Oauth2Type::External,
        jwks_url: "http://jwks".to_string(),
        jwks_ca_bundle_path: None,
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
        // Matches `offline_relying_party()`'s issuer argument, so `full_idp_oauth2()` builds a
        // consistent identity across `federation.issuer` and the offline `KeycloakRelyingParty` --
        // there is no longer a `relying_party.issuer` field for this to drift against; the config
        // trap that check used to guard against is gone along with the duplicated field.
        federation: Some(lightbridge_authz_core::config::Federation {
            issuer: WORKING_ISSUER.to_string(),
            discovery_url: None,
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
    // #598: the route allowlist manifest every test using this fixture now needs -- without it,
    // every test below silently degrades to `load_route_manifest`'s `{"/"}` fallback and several
    // would pass for the wrong reason.
    std::fs::write(
        dir.join("routes.json"),
        br#"{"version":1,"basename":"/ui","routes":["/","/device","/device/confirm"]}"#,
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

/// #598: `/ui` is a route ALLOWLIST now, not a catch-all -- any path under the prefix that is not
/// one of the manifest's entries must be a bare `404`, not `index.html`.
///
/// Prove-fail-first (recorded verbatim against unfixed code, pre-B4): with `static_assets_fallback`
/// still `ServeDir::new(dir).fallback(ServeFile::new(index))` (the old whole-subtree catch-all),
/// this test failed with:
/// ```text
/// thread 'ui_unknown_spa_route_returns_404' (3774949) panicked at
/// crates/lightbridge-authz-rest/tests/idp_server_tests.rs:280:5:
/// assertion `left == right` failed
///   left: 200
///  right: 404
/// ```
#[tokio::test]
async fn ui_unknown_spa_route_returns_404() {
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
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The positive counterpart to [`ui_unknown_spa_route_returns_404`]: a path the manifest DOES
/// list must still resolve to `index.html` with a `200`, once nested under `/ui`.
///
/// Not a prove-fail-first case, same as its `static_assets_tests.rs` twin
/// (`allowlisted_client_route_serves_index_html`): run against unfixed code (pre-B4, the old
/// whole-subtree `.fallback(ServeFile::new(index))` catch-all), this test PASSES already -- for
/// the wrong reason, since that catch-all answers every path with `index.html` regardless of any
/// manifest. `ui_unknown_spa_route_returns_404` right above is what actually falsifies the old
/// behavior; this test only starts passing for the RIGHT reason once the manifest-driven allowlist
/// lands.
#[tokio::test]
async fn ui_allowlisted_route_serves_index_html() {
    let dir = ui_static_dir("allowlisted-route");
    let router = ui_mount_router(&dir);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/ui/device")
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

/// A DRIFT GUARD AGAINST THE RUST LOADER, NOT AGAINST THE SHIPPED ARTIFACT (#598's own Risks
/// section, made mechanical, corrected by the consolidated review): every SPA route
/// `relying_party.rs`'s `UI_*` constants redirect into must appear in `dist/routes.json`, or the
/// redirect lands on a path `static_assets` 404s. This builds the router with a `routes.json` that
/// is a VERBATIM copy of `apps/authz-ui`'s manifest shape (the same six-route shape
/// converse-frontends' `vite.config.ts` route-manifest emitter produces, plan A15) and proves every
/// one of the five `/ui/device*`/`/ui/error` redirect targets resolves against `load_route_manifest`
/// -- **but this is a FIXTURE, copied by hand into this test, not the artifact this repo actually
/// ships.** It guards `load_route_manifest`'s parsing/registration logic against a manifest shaped
/// like the real one; it cannot catch the real `apps/authz-ui` build drifting from this fixture.
/// That artifact-level guard lives in two other places instead: `.docker/it/idp_it.py`'s
/// `section_root_and_spa` (asserts the pinned, running artifact's actual routes over real HTTP) and
/// `.github/actions/stage-authz-ui`'s post-pull `grep` of the five non-root routes against the
/// staged `dist/static/routes.json` (fails CI before a container is even built if one is missing).
///
/// Not a prove-fail-first case: against unfixed code (pre-B4) this passes already, trivially --
/// the old whole-subtree catch-all answers every `/ui/*` path with `200` regardless of any
/// manifest, so this assertion is vacuous until B4's per-route allowlist loop makes `200` mean
/// "this route is actually allowlisted." Kept here (not deferred) because it is the guard B1's
/// `UI_*` constants' own doc comment names by name.
#[tokio::test]
async fn redirect_targets_are_all_allowlisted() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "lightbridge-authz-idp-redirect-targets-allowlisted-{nanos}"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("index.html"),
        b"<!doctype html><title>hosted-login placeholder</title>",
    )
    .unwrap();
    // Verbatim copy of apps/authz-ui's dist/routes.json (converse-frontends#409's
    // vite.config.ts manifest emitter, plan A15) -- NOT hand-trimmed, so this test fails the
    // moment either side's route set drifts from the other.
    std::fs::write(
        dir.join("routes.json"),
        br#"{
  "version": 1,
  "basename": "/ui",
  "routes": ["/", "/device", "/device/invalid", "/device/confirm", "/device/success", "/error"]
}
"#,
    )
    .unwrap();
    let router = ui_mount_router(&dir);

    for path in [
        "/ui/device",
        "/ui/device/invalid",
        "/ui/device/confirm",
        "/ui/device/success",
        "/ui/error",
    ] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
    }

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
    let client_store = ConfigClientStore::from_config(&oauth2.clients, &cfg);
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
            "client_credentials".to_string(),
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
        repo.clone(),
        repo,
        budget_repo,
        policy_engine,
        bearer,
        std::sync::Arc::new(Vec::new()),
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
        refresh_reuse_grace_seconds: 30,
        device_code_ttl_seconds: 600,
        device_poll_interval_seconds: 5,
        device_verification_uri: "https://authz.example.test/device/verify".to_string(),
        client_credentials_ttl_seconds: 900,
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
            WORKING_ISSUER.to_string(),
            WORKING_ISSUER.to_string(),
            repo,
            Arc::new(cratestack_axum::ratelimit::InMemoryRateLimitStore::new()),
            None,
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
        test_claim_redeem(),
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
        test_claim_redeem(),
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
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "authorization_code"
        ]),
        "authz-idp is a full IdP (ADR-0023): the authorization_code grant is always advertised \
         alongside the device grant, never conditionally -- and since #534, client_credentials is \
         advertised unconditionally too, regardless of whether any oauth2.clients entry is \
         actually configured for it"
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
/// so it answers unconditionally (a `303` handoff to the SPA since lightbridge-authz#598, `200`
/// HTML before it; either way, never a `404`).
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
    // #598: `verify_page` is a 303 handoff into the SPA now, not a 200 HTML page -- assert the
    // actual response shape (a mount-presence-only `assert_ne!(.., NOT_FOUND)` would also pass for
    // a route that answered something other than the real handoff).
    assert_eq!(
        device_verify.status(),
        StatusCode::SEE_OTHER,
        "/device/verify must be mounted unconditionally and answer with the SPA handoff"
    );
    // Pins the sanitiser end-to-end, not just via its own unit tests: `sanitize_user_code_for_display`
    // keeps `-`, so it survives into the handoff target, then `utf8_percent_encode`'s
    // `NON_ALPHANUMERIC` set (which percent-encodes every non-alphanumeric ASCII byte, `-`
    // included) turns it into `%2D` in the `Location` header the browser actually receives.
    assert_eq!(
        device_verify.headers().get(header::LOCATION).unwrap(),
        "/ui/device?user_code=WDJB%2DMJHT"
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
        test_claim_redeem(),
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
    // #598: same "assert the actual response shape" correction as
    // build_idp_router_mounts_authorize_device_verify_and_callback_unconditionally above --
    // verify_page is a 303 handoff now, not a 200 HTML page.
    assert_eq!(
        device_verify.status(),
        StatusCode::SEE_OTHER,
        "/device/verify must be mounted regardless of oauth2.token_exchange's raw config, and \
         answer with the SPA handoff"
    );
    assert_eq!(
        device_verify.headers().get(header::LOCATION).unwrap(),
        "/ui/device?user_code=WDJB%2DMJHT"
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

/// A router built off a custom `Oauth2` block, mirroring `offline_idp_router` exactly (same
/// fully-offline `TokenExchangeState`/`KeycloakRelyingParty` assembly) but for tests below that
/// need a non-default `oauth2` -- specifically, a registered client, which `full_idp_oauth2()`
/// carries none of, so `offline_idp_router` alone cannot exercise "does discovery mirror a
/// non-empty client registry" or "does a registered client reach the token lookup" cases.
fn offline_idp_router_with_oauth2(
    oauth2: &Oauth2,
    static_dir: impl AsRef<std::path::Path>,
) -> axum::Router {
    let pool = lazy_pool();
    let signing_repo = Arc::new(StoreRepo::new(pool.clone()));
    let token_exchange = offline_token_exchange_state(oauth2, signing_repo.clone());
    let relying_party = offline_relying_party(signing_repo.clone());
    build_idp_router(
        oauth2,
        oauth2.signing.as_ref().unwrap(),
        signing_repo,
        token_exchange,
        pool,
        static_dir,
        relying_party,
        test_claim_redeem(),
    )
}

/// A minimal Public, `NoAuth`-authenticating client -- enough for `ClientAuthenticationMetadata::
/// from_oauth2` to populate `methods: ["none"]`, and enough for `/oauth2/introspect`'s client
/// lookup + `authenticate_presented_client` to succeed offline (both are in-memory/config-only,
/// never touch the database). Fully qualified rather than imported at file scope: `OauthClient`/
/// `OauthClientType` are otherwise only used inside `mod db` below, and adding a duplicate
/// top-level `use` would make that module's own import dead code under `-D warnings`.
fn offline_public_client(client_id: &str) -> lightbridge_authz_core::config::OauthClient {
    lightbridge_authz_core::config::OauthClient {
        client_id: client_id.to_string(),
        client_type: lightbridge_authz_core::config::OauthClientType::Public,
        scopes: vec!["openid".to_string()],
        grant_types: Vec::new(),
        allowed_audiences: vec![client_id.to_string()],
        jwks: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        require_pkce: false,
        refresh_ttl_seconds: None,
        refresh_absolute_ttl_seconds: None,
    }
}

/// RFC 7662's `introspection_endpoint` and OIDC Session Management 1.0's `check_session_iframe`/
/// `claims_parameter_supported` -- the discovery additions commit f45cc9c made. `scopes_supported`
/// containing `openid` is already-served, pre-existing behavior (`token_exchange_oauth2()`'s
/// `allowed_scopes`), pinned here per the task's explicit ask so a future change silently
/// dropping it fails a test rather than only a docs mismatch.
///
/// Prove-fail-first (recorded verbatim, then reverted): changed `signing.rs`'s
/// `introspection_endpoint: token_endpoint_mounted.then(...)` to always evaluate to `None` and
/// reran just this test. It failed on `.expect("introspection_endpoint must be advertised...")`
/// with `metadata["introspection_endpoint"]` being `Null`, not a string. Restored the line.
#[tokio::test]
async fn discovery_advertises_introspection_and_session_management_additions() {
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

    let introspection_endpoint = metadata["introspection_endpoint"]
        .as_str()
        .expect("introspection_endpoint must be advertised once the token surface is mounted");
    assert!(
        introspection_endpoint.ends_with("/oauth2/introspect"),
        "got: {introspection_endpoint}"
    );

    let check_session_iframe = metadata["check_session_iframe"]
        .as_str()
        .expect("check_session_iframe must be advertised once authorization_code is mounted");
    assert!(
        check_session_iframe.ends_with("/oauth2/check_session_iframe"),
        "got: {check_session_iframe}"
    );

    assert_eq!(metadata["claims_parameter_supported"], false);

    let scopes = metadata["scopes_supported"]
        .as_array()
        .expect("scopes_supported must be a non-empty array");
    assert!(
        scopes.iter().any(|scope| scope == "openid"),
        "scopes_supported must include openid: {scopes:?}"
    );
}

/// `introspection_endpoint_auth_methods_supported`/`_auth_signing_alg_values_supported` are
/// documented as mirroring revocation's own -- both derived from the same
/// `ClientAuthenticationMetadata` value in `signing.rs`'s `discovery_document`. A single
/// registered Public client is enough to move both fields off their (equal, but degenerate)
/// omitted-when-empty default, proving the mirror against real, non-empty content rather than two
/// absent fields trivially comparing equal.
///
/// Prove-fail-first (recorded verbatim, then reverted): temporarily changed
/// `introspection_endpoint_auth_methods_supported: client_auth_methods` in `signing.rs`'s
/// `discovery_document` to `Vec::new()`, reran just this test. It failed: `revocation_endpoint_
/// auth_methods_supported` was `["none"]` but `introspection_endpoint_auth_methods_supported` was
/// absent (`Null`) -- the assert_eq on the two fields failed with a type mismatch. Restored.
#[tokio::test]
async fn discovery_mirrors_introspection_and_revocation_auth_methods() {
    let mut oauth2 = full_idp_oauth2();
    oauth2.clients = vec![offline_public_client("offline-public-client")];
    let router = offline_idp_router_with_oauth2(&oauth2, TEST_STATIC_DIR);

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

    assert_eq!(
        metadata["revocation_endpoint_auth_methods_supported"],
        serde_json::json!(["none"]),
        "sanity check: a registered Public client must move the field off its omitted default"
    );
    assert_eq!(
        metadata["introspection_endpoint_auth_methods_supported"],
        metadata["revocation_endpoint_auth_methods_supported"]
    );
}

/// `GET /oauth2/check_session_iframe` (OIDC Session Management 1.0): serves the static HTML page
/// verbatim, `no-store` (never cached -- every RP embed must poll live), and the body must
/// actually carry the OP browser-state cookie name and the `postMessage` call the RP-embedded
/// script uses to answer polls -- proving the real inline script shipped, not just any HTML.
///
/// Prove-fail-first (recorded verbatim, then reverted): temporarily changed
/// `session_management.rs`'s `check_session_iframe` handler's `Cache-Control` header value from
/// `"no-store"` to `"no-cache"` and reran just this test. It failed:
/// `assertion `left == right` failed` -- `"no-cache"` vs the expected `"no-store"`. Restored.
#[tokio::test]
async fn check_session_iframe_serves_static_html_with_no_store_and_op_cookie_script() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth2/check_session_iframe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"),
        "must be served as HTML"
    );
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CACHE_CONTROL)
            .unwrap(),
        "no-store"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        html.contains("__Host-authz_op_state"),
        "the inline script must reference the OP browser-state cookie name"
    );
    assert!(
        html.contains("postMessage"),
        "the inline script must actually answer RP polls via postMessage"
    );
}

/// `POST /oauth2/introspect`, RFC 7662 §2.1: `token` is a REQUIRED form field, and its absence is
/// a malformed *request* (400 `invalid_request`), never the uniform bare-inactive response --
/// mirrors `revoke_with_missing_token_field_is_invalid_request`'s already-established polarity
/// for the sibling `/oauth2/revoke` endpoint.
#[tokio::test]
async fn introspect_with_missing_token_field_is_invalid_request() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("client_id=whatever"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "invalid_request");
}

/// `POST /oauth2/introspect` with an unregistered `client_id`: client-authentication failure is
/// the ONE case RFC 7662 §2.1's anti-oracle posture does not cover -- it must be `401
/// invalid_client`, resolved entirely before the token itself is ever looked up (this offline
/// router's DB pool is unreachable, so a client-lookup-before-token-lookup ordering is exactly
/// what makes this test possible without a real database at all).
#[tokio::test]
async fn introspect_with_unknown_client_is_rejected() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("token=whatever&client_id=never-registered"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "invalid_client");
}

/// Pins this OFFLINE harness's own behavior for a registered client presenting a garbage token --
/// deliberately NOT RFC 7662's `{"active": false}` contract. This router's pool
/// (`lazy_pool()`) never actually connects, so `TokenExchangeOpStore::
/// find_active_refresh_token_for_client`'s DB lookup errors before `introspect_endpoint` can ever
/// reach the "not found -> inactive" branch, and the handler correctly reports that as `500
/// server_error` rather than papering over it as `{"active": false}` (a real storage failure and
/// a genuinely-inactive token are different facts; collapsing them would hide an outage as a
/// mundane "no such token"). The true RFC 7662 `{"active": false}` case for a garbage/unknown
/// token, proven against a real reachable Postgres, lives in `token_exchange_tests.rs`.
#[tokio::test]
async fn introspect_with_garbage_token_against_unreachable_db_returns_server_error() {
    let mut oauth2 = full_idp_oauth2();
    oauth2.clients = vec![offline_public_client("offline-public-client")];
    let router = offline_idp_router_with_oauth2(&oauth2, TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/introspect")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "token=totally-made-up-garbage&client_id=offline-public-client",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "server_error");
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
    let result = start_idp_server(&idp, lazy_pool(), &external_oauth2(), &None, &None).await;
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
    let result = start_idp_server(&idp, lazy_pool(), &oauth2, &None, &None).await;
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
        let result = start_idp_server(
            &idp,
            db_pool,
            &full_idp_oauth2(),
            &unreachable_redis_cfg(),
            &None,
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
        let err = start_idp_server(&idp, db_pool, &full_idp_oauth2(), &None, &None)
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
        let err = start_idp_server(&idp, db_pool, &self_signed_oauth2(), &None, &None)
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
        let result = start_idp_server(
            &idp,
            db_pool,
            &full_idp_oauth2(),
            &unreachable_redis_cfg(),
            &None,
        )
        .await;
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
            .await
            .expect_err(
                "authz-idp is a full IdP (ADR-0023): a deployment that omits oauth2.relying_party \
                 must be refused at startup, not silently skip the RP-leg",
            );
        let message = format!("{err}");
        assert!(message.contains("oauth2.relying_party"), "got: {message}");
        assert!(message.contains("authz-idp"), "got: {message}");
    }

    /// GHSA-9pc6-965v-2c44: `secret_claim` is deliberately NOT a startup mandate for authz-idp.
    ///
    /// authz-idp is the sole server of this deployment's issuer, and every in-circulation API-key
    /// JWT names it in `iss`. Refusing to boot over a missing claim-redemption key would take the
    /// whole issuer down in order to disable one page -- a far worse failure than that page
    /// answering 503. This asserts the absent block is tolerated, by checking that startup gets
    /// PAST this point and fails later on the deliberately-bad TLS instead.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_tolerates_absent_secret_claim(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let err = start_idp_server(
            &idp,
            db_pool,
            &full_idp_oauth2(),
            &unreachable_redis_cfg(),
            &None,
        )
        .await
        .expect_err("bad_tls() guarantees this cannot bind, whatever else happens");
        let message = format!("{err}");
        assert!(
            !message.contains("secret_claim"),
            "an ABSENT secret_claim must not stop authz-idp starting -- it degrades to a 503 on \
             /api-keys/claim. Got: {message}"
        );
    }

    /// The other half of the contract: absent is tolerated, but PRESENT-but-malformed is still a
    /// hard startup failure. Tolerating a bad key would leave every claim URL silently broken with
    /// no signal, which is the failure mode the offline validation exists to prevent.
    #[sqlx::test(migrations = "../../migrations")]
    async fn start_idp_server_rejects_a_malformed_secret_claim_key(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let bad = Some(lightbridge_authz_core::config::SecretClaim {
            encryption_key: "not-32-bytes".to_string(),
            ttl_seconds: 300,
            redeem_base_url: "https://auth.example.test".to_string(),
        });
        let err = start_idp_server(
            &idp,
            db_pool,
            &full_idp_oauth2(),
            &unreachable_redis_cfg(),
            &bad,
        )
        .await
        .expect_err("a malformed secret_claim.encryption_key must refuse at startup");
        let message = format!("{err}");
        assert!(message.contains("secret_claim"), "got: {message}");
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
            snapshot_refresh_seconds: 15,
            snapshot_active_window_minutes: 1440,
            snapshot_slow_lane_minutes: 10,
            snapshot_seed_lookback_days: 30,
            snapshot_batch: 500,
            snapshot_concurrency: 8,
        };
        let err = start_budget_server(
            &budget,
            None,
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
        let err = start_idp_server(&idp, lazy_pool(), &oauth2, &None, &None)
            .await
            .expect_err("authz-idp must refuse to start with no oauth2.federation.issuer");
        let message = format!("{err}");
        assert!(
            message.contains("oauth2.federation.issuer"),
            "got: {message}"
        );
        assert!(message.contains("authz-idp"), "got: {message}");
    }

    /// Identity-vs-location split (this branch): `oauth2.relying_party.issuer` was deleted --
    /// `oauth2.federation.issuer` is now the ONE issuer field, and `oauth2.federation.discovery_url`
    /// is a separate, optional LOCATION override for where `authz-idp` dials OIDC discovery from.
    /// Before this change, the analogous scenario -- the deployment's two issuer-shaped config
    /// values disagreeing -- was a hard startup failure (`idp_refuses_when_federation_issuer_
    /// differs_from_relying_party_issuer`, deleted by this same change). That failure mode no
    /// longer exists: a `federation.discovery_url` that names a different URL than
    /// `federation.issuer` is now the INTENDED shape for a deployment where the two network planes
    /// diverge (see `Federation::discovery_url`'s doc comment), so `start_idp_server` must start
    /// successfully rather than refuse.
    #[sqlx::test(migrations = "../../migrations")]
    async fn idp_starts_when_federation_discovery_url_differs_from_issuer(pool: PgPool) {
        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let mut oauth2 = full_idp_oauth2();
        oauth2.federation = Some(lightbridge_authz_core::config::Federation {
            issuer: WORKING_ISSUER.to_string(),
            discovery_url: Some("https://internal-keycloak.example.test".to_string()),
        });
        let idp = IdpServer {
            address: "127.0.0.1".to_string(),
            port: 0,
            tls: bad_tls(),
            static_dir: TEST_STATIC_DIR.to_string(),
        };
        let result =
            start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None).await;
        let err = result.expect_err(
            "bad TLS cert paths still fail startup after the relying-party/federation checks \
             pass -- this proves the discovery_url-vs-issuer divergence itself was NOT the cause",
        );
        let message = format!("{err}");
        assert!(
            !message.to_lowercase().contains("issuer"),
            "a federation.discovery_url that differs from federation.issuer must not be treated \
             as an error anymore: got {message}"
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
            test_claim_redeem(),
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
        let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
            db_pool.clone(),
            budget_repo.clone(),
            Arc::new(lightbridge_authz_budget::UnavailableSpendReader),
        ));
        let api_router = build_api_router(
            bearer,
            Arc::new(UnreachableResolver),
            issuer,
            policy_store,
            refill_service,
            review_service,
            budget_repo,
            reset_scheduler,
            std::sync::Arc::new(lightbridge_authz_core::platform_role::known_platform_roles(
                &lightbridge_authz_core::authz::Rbac::default(),
            )),
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
    /// follow-up that scoped the static build under `/ui`, and updated again for #598's route
    /// allowlist: the `/ui`-nested static mount must never shadow an existing protocol route, AND
    /// (the new half, since this used to be a whole-server catch-all) the static build must never
    /// answer for a path outside `/ui` either. Needs the DB-backed setup (a real bootstrapped
    /// signing key) so `/.well-known/jwks.json` actually succeeds -- offline it 500s for its own
    /// unrelated reason (no key to serialize), which would make a coarse status-code assertion
    /// here meaningless. Builds the idp router with a REAL, on-disk static build directory (not
    /// `TEST_STATIC_DIR`'s nonexistent path, so `/ui` is actually capable of answering every
    /// request under it) and proves three things: every existing protocol route still resolves to
    /// its own handler with real content; a genuinely unmatched path *under* `/ui` -- one that is
    /// not in the manifest -- is a bare `404` (inverted by #598: this used to prove the opposite,
    /// that an unmatched path fell back to `index.html`); and that exact same path *without* the
    /// `/ui` prefix is ALSO a plain `404` -- so both shapes now agree, rather than one being a
    /// `200` SPA-shell and the other a `404`.
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
        // #598: without a manifest here, this fixture degrades to the `{"/"}` fallback and the
        // `/authorize`/`/device/verify`/`/idp/callback` non-404 assertions below would still pass,
        // but for reasons unrelated to what this test proves. Not adding "/device"/etc: this
        // test is about protocol-route shadowing, not the allowlist's own contents.
        std::fs::write(
            static_dir.join("routes.json"),
            br#"{"version":1,"basename":"/ui","routes":["/"]}"#,
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
            test_claim_redeem(),
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

        // #598: a genuinely unmatched path under /ui -- one the manifest does not list -- is now
        // a bare 404, never the SPA shell. Inverted from the pre-#598 assertion this test made
        // (200 + index.html) -- see the surrounding doc comment.
        //
        // Prove-fail-first (recorded verbatim against unfixed code, pre-B4): with
        // `static_assets_fallback` still the old whole-subtree catch-all, this failed with:
        // ```text
        // thread 'db::static_fallback_never_shadows_an_existing_protocol_route' (3776699)
        // panicked at crates/lightbridge-authz-rest/tests/idp_server_tests.rs:2434:9:
        // assertion `left == right` failed: a genuinely unmatched path under /ui -- outside the
        // route allowlist -- must be a bare 404, never the SPA shell
        //   left: 200
        //  right: 404
        // ```
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
            StatusCode::NOT_FOUND,
            "a genuinely unmatched path under /ui -- outside the route allowlist -- must be a \
             bare 404, never the SPA shell"
        );

        // The other half of the path-scoping property (#442 follow-up, now also #598's "both
        // shapes agree" property): the exact same unmatched path WITHOUT the /ui prefix must ALSO
        // be a plain 404 -- the static build is no longer a catch-all for the whole server, and
        // since #598 it isn't a catch-all for its own /ui subtree either.
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

    /// A `Confidential`/`Service` client needs a real, parseable `jwks` since #534/ADR-0030's
    /// `validate_client_credentials_and_service_clients` startup check -- a `None` jwks used to
    /// start cleanly (the exact discovery-vs-store disagreement that check now closes) and would
    /// now be refused before this function's own PKCE assertion is ever reached. `Public` clients
    /// authenticate with no credential at all, so they stay `jwks: None` unchanged.
    fn authorization_code_client(
        client_id: &str,
        client_type: OauthClientType,
        require_pkce: bool,
    ) -> OauthClient {
        let jwks = match client_type {
            OauthClientType::Public => None,
            OauthClientType::Confidential | OauthClientType::Service => {
                let key = lightbridge_authz_rest::signing::generate_rs256_key()
                    .expect("rsa keypair generation");
                Some(serde_json::json!({ "keys": [key.public_jwk] }))
            }
        };
        OauthClient {
            client_id: client_id.to_string(),
            client_type,
            scopes: vec!["openid".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            allowed_audiences: vec![client_id.to_string()],
            jwks,
            redirect_uris: vec!["https://cb.example.test/callback".to_string()],
            post_logout_redirect_uris: Vec::new(),
            require_pkce,
            refresh_ttl_seconds: None,
            refresh_absolute_ttl_seconds: None,
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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
        let err = start_idp_server(&idp, db_pool, &oauth2, &unreachable_redis_cfg(), &None)
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

// --- OIDC RP-Initiated Logout 1.0 + OIDC Core §5.3 UserInfo -----------------------------------
//
// ADR-0023's rule, applied to the two routes added alongside it: a route that discovery
// advertises MUST be mounted. #473 shipped the inverse (discovery advertised `device_code` while
// `/device/verify` 404'd) and it reached production, so each new endpoint gets both halves
// asserted -- advertised, and actually answering -- rather than one standing in for the other.
//
// Both requests below are fully offline. `/oauth2/end_session` without a session cookie never
// reaches the repository (`revoke_current_session` returns early), and `/oauth2/userinfo` with no
// `Authorization` header is refused before any JWKS lookup, so the lazy, never-dialed pool is
// never touched.

/// Prove-fail-first (recorded verbatim, then reverted): changed `signing.rs`'s
/// `end_session_endpoint: authorization_code_mounted.then(...)` to `None` and reran this test. It
/// failed with `metadata["end_session_endpoint"]` being `Null`. Same for `userinfo_endpoint`.
/// Restored both lines.
#[tokio::test]
async fn discovery_advertises_end_session_and_userinfo() {
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

    assert_eq!(
        metadata["end_session_endpoint"].as_str(),
        Some("https://authz-idp.example.test/oauth2/end_session"),
        "RP-Initiated Logout 1.0 §3 -- an RP discovers logout here or not at all"
    );
    assert_eq!(
        metadata["userinfo_endpoint"].as_str(),
        Some("https://authz-idp.example.test/oauth2/userinfo")
    );
    // Neither logout channel is implemented, so neither may be advertised -- the omission
    // discipline `signing::discovery_document` exists to enforce.
    assert!(
        metadata.get("frontchannel_logout_supported").is_none()
            && metadata.get("backchannel_logout_supported").is_none(),
        "advertising a logout channel with no handler is exactly the ADR-0023 failure"
    );
}

/// Logout with no session is a success, not an error: it is idempotent, and a user who is already
/// signed out asked for the state they are in. The cookie is cleared regardless, so a browser
/// holding a stale cookie for an already-dead session stops sending it.
#[tokio::test]
async fn end_session_without_a_session_succeeds_and_clears_the_cookie() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth2/end_session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("logout must clear the session cookie even when there was nothing to end")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        set_cookie.starts_with("__Host-authz_session="),
        "the removal must name the same cookie, got {set_cookie}"
    );
    assert!(
        set_cookie.contains("Max-Age=0"),
        "the removal must expire the cookie, got {set_cookie}"
    );
    // `__Host-` conformance: a browser rejects the removal outright if these drift from
    // `build_session_cookie`'s attributes, silently leaving the live cookie in place.
    assert!(
        set_cookie.contains("Secure") && set_cookie.contains("Path=/"),
        "the removal must keep the __Host- attribute set, got {set_cookie}"
    );
    assert!(
        !set_cookie.contains("Domain="),
        "a Domain attribute makes the cookie non-__Host- and the removal a no-op, got {set_cookie}"
    );
}

/// An unregistered `post_logout_redirect_uri` must not become a `Location`. Asserted at the route
/// level as well as in `end_session_tests.rs` because the failure mode being guarded against is a
/// handler that resolves the redirect correctly and then emits it anyway.
#[tokio::test]
async fn end_session_never_redirects_to_an_unregistered_uri() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri(
                    "/oauth2/end_session?client_id=lightbridge-console\
                     &post_logout_redirect_uri=https://attacker.example/steal",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an unregistered redirect is refused by rendering the OP's own page, not by erroring"
    );
    assert!(
        response.headers().get("location").is_none(),
        "an unregistered post_logout_redirect_uri must never reach a Location header"
    );
}

/// RFC 6750 §3.1: no credential gets the bare challenge, not `invalid_token` -- an RP library
/// keys its refresh-and-retry decision on that error code.
#[tokio::test]
async fn userinfo_without_a_bearer_challenges_without_an_error_code() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth2/userinfo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .expect("RFC 6750 §3 requires a challenge on a 401")
        .to_str()
        .unwrap();
    assert_eq!(challenge, "Bearer");
}

/// A syntactically-invalid token fails at `decode_header`, before any JWKS lookup -- which is what
/// keeps this test offline, and is also why the response can be `invalid_token` without the
/// service having consulted anything.
#[tokio::test]
async fn userinfo_with_a_malformed_bearer_is_invalid_token() {
    let router = offline_idp_router(TEST_STATIC_DIR);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/oauth2/userinfo")
                .header("authorization", "Bearer not-a-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        challenge.contains("error=\"invalid_token\""),
        "got {challenge}"
    );
}

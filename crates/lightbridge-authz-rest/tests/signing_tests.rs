// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, capped_expiry, generate_rs256_key};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

const ISSUER: &str = "https://authz.example.test";

fn signing_cfg(ttl: i64) -> JwtSigning {
    JwtSigning {
        issuer: ISSUER.to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: ttl,
        max_key_age_days: 30,
    }
}

fn lazy_repo() -> Arc<lightbridge_authz_api_key::repo::StoreRepo> {
    let pool = PgPoolOptions::new()
        // Bounded so a deliberately-dead pool fails fast: sqlx's default
        // `acquire_timeout` is 30s, and every test that touches one paid it in full.
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/lightbridge_authz")
        .expect("lazy pool");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(lightbridge_authz_api_key::repo::StoreRepo::new(pool))
}

#[derive(Serialize, Deserialize)]
struct Probe {
    sub: String,
    exp: i64,
}

/// Verifies the generated keypair is matched and its JWK is usable: sign with the PEM, verify
/// with the JWK's RSA components.
#[test]
fn keygen_produces_matched_keypair_and_jwk() {
    let key = generate_rs256_key().expect("keygen");
    assert_eq!(key.public_jwk["kid"], key.kid);
    assert_eq!(key.public_jwk["alg"], "RS256");

    let encoding = EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).expect("encoding key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let token = encode(
        &header,
        &Probe {
            sub: "s".to_string(),
            exp: 4102444800,
        },
        &encoding,
    )
    .expect("sign");

    let decoding = DecodingKey::from_rsa_components(
        key.public_jwk["n"].as_str().unwrap(),
        key.public_jwk["e"].as_str().unwrap(),
    )
    .expect("decoding key");
    let data = decode::<Probe>(&token, &decoding, &Validation::new(Algorithm::RS256))
        .expect("verify against jwk");
    assert_eq!(data.claims.sub, "s");
}

#[tokio::test]
async fn from_config_builds_signer_for_valid_config() {
    assert!(ApiKeyJwtSigner::from_config(&signing_cfg(3600), lazy_repo()).is_ok());
}

#[tokio::test]
async fn debug_impl_omits_private_key_material() {
    let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), lazy_repo()).unwrap();
    let debug = format!("{signer:?}");
    assert!(debug.contains(ISSUER));
    assert!(
        !debug.to_lowercase().contains("private"),
        "Debug output must not expose private key material: {debug}"
    );
}

#[tokio::test]
async fn from_config_rejects_empty_issuer() {
    let mut cfg = signing_cfg(3600);
    cfg.issuer = "   ".to_string();
    let err = ApiKeyJwtSigner::from_config(&cfg, lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("issuer is required"));
}

#[tokio::test]
async fn from_config_rejects_non_positive_ttl() {
    let err = ApiKeyJwtSigner::from_config(&signing_cfg(0), lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("ttl_seconds must be positive"));
}

#[tokio::test]
async fn well_known_serves_cors_headers() {
    use axum::body::Body;
    use axum::http::{Request, header};
    use lightbridge_authz_rest::signing::well_known_router;
    use tower::ServiceExt;

    let response = well_known_router::<()>(ISSUER, lazy_repo(), None, false)
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .header(header::ORIGIN, "https://example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("well-known responses must carry a CORS allow-origin header"),
        "*"
    );
}

#[tokio::test]
async fn jwks_endpoint_returns_server_error_when_repo_is_unreachable() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::Value;
    use tower::ServiceExt;

    let response = well_known_router::<()>(ISSUER, lazy_repo(), None, false)
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["keys"].as_array().unwrap().len(), 0);
}

const CAP_TTL_SECONDS: i64 = 7_776_000;

#[test]
fn capped_expiry_honors_requested_within_cap() {
    let now = chrono::Utc::now();
    let requested = now + chrono::Duration::days(30);
    assert_eq!(
        capped_expiry(now, CAP_TTL_SECONDS, Some(requested)),
        requested
    );
}

#[test]
fn capped_expiry_clamps_requested_beyond_cap() {
    let now = chrono::Utc::now();
    let requested = now + chrono::Duration::days(365);
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, Some(requested)), cap);
}

#[test]
fn capped_expiry_defaults_to_ttl_when_unrequested() {
    let now = chrono::Utc::now();
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, None), cap);
}

#[test]
fn capped_expiry_ignores_past_request_to_avoid_dead_token() {
    let now = chrono::Utc::now();
    let cap = now + chrono::Duration::seconds(CAP_TTL_SECONDS);
    let past = now - chrono::Duration::days(1);
    assert_eq!(capped_expiry(now, CAP_TTL_SECONDS, Some(past)), cap);
}

/// OIDC Core §3.1.3.6 `at_hash`: SHA-256 the access token octets, take the left-most half, base64url
/// (no padding) encode it. Independently computed via Python (NOT this crate's implementation) so
/// this is a real known-vector test, not a self-check:
///
/// ```python
/// import hashlib, base64
/// d = hashlib.sha256(b"hello-world-access-token").digest()
/// base64.urlsafe_b64encode(d[:16]).rstrip(b"=").decode()
/// # => "7bwQYIKkMUJvb0oGYN1JlA"
/// ```
#[test]
fn at_hash_matches_independently_computed_vector() {
    use lightbridge_authz_rest::signing::compute_at_hash;
    assert_eq!(
        compute_at_hash("hello-world-access-token"),
        "7bwQYIKkMUJvb0oGYN1JlA"
    );
}

#[test]
fn at_hash_changes_with_the_access_token() {
    use lightbridge_authz_rest::signing::compute_at_hash;
    assert_ne!(
        compute_at_hash("token-a"),
        compute_at_hash("token-b"),
        "at_hash must actually bind to the access token, not return a constant"
    );
}

/// Regression test for the empty-`grant_types_supported`/`scopes_supported` discovery document
/// served in production (`https://auth.ai.camer.digital/.well-known/openid-configuration`). Does
/// NOT need `it-tests` -- `well_known_router`'s discovery route never touches the DB (only
/// `/.well-known/jwks.json` does), so this runs in the default `cargo test -p
/// lightbridge-authz-rest`.
///
/// Asserts the exact set `discovery_document` promises when token-exchange is enabled -- these
/// values must stay in lockstep with what `token_exchange::TOKEN_EXCHANGE_GRANT`/
/// `REFRESH_TOKEN_GRANT` and `handle_token`'s real dispatch accept (see `token_exchange.rs`), not
/// just "non-empty". `response_types_supported` is asserted empty here too, not merely omitted
/// from this list -- see `discovery_never_advertises_response_types_or_modes` below for why that
/// must hold regardless of the token-exchange gate, and for the regression this guards (this
/// service served `["token", "id_token", "id_token token"]` here in production once token-exchange
/// was enabled, claiming an authorization endpoint that has never existed).
#[tokio::test]
async fn discovery_advertises_exact_token_exchange_metadata_when_enabled() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    let scopes = vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ];
    let discovery = well_known_router::<()>(ISSUER, lazy_repo(), Some(scopes), false)
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
    let payload: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        payload["grant_types_supported"],
        json!([
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "refresh_token",
        ]),
        "grant_types_supported must exactly match what handle_token dispatches: {payload}"
    );
    assert_eq!(
        payload["scopes_supported"],
        json!(["openid", "profile", "email", "offline_access"]),
        "scopes_supported must exactly match oauth2.token_exchange.allowed_scopes: {payload}"
    );
    assert_eq!(
        payload["response_types_supported"],
        json!([]),
        "response_types_supported describes the AUTHORIZATION endpoint (OIDC Discovery 1.0 §3), \
         which this service never serves, on or off -- token-exchange is a direct token-endpoint \
         grant (RFC 8693), not a redirect-based response_type negotiation: {payload}"
    );
    assert_eq!(
        payload["token_endpoint"],
        format!("{ISSUER}/oauth2/token"),
        "token_endpoint must be advertised once token-exchange is actually mounted: {payload}"
    );
    assert_eq!(
        payload["token_endpoint_auth_methods_supported"],
        json!(["none"]),
        "must never advertise client_secret_basic/client_secret_post (ADR-0011 Decision 6): {payload}"
    );
}

/// Companion to the "enabled" case above: when token-exchange is off (`token_exchange_scopes` is
/// `None` -- either `oauth2.token_exchange.enabled: false`, or the block is absent from config
/// entirely, as in the live regression), the document must not claim capabilities the server
/// doesn't have. Empty arrays for grant/response/scope metadata are the honest RFC 8414 way to say
/// "no grants offered"; they are deliberately NOT hardcoded to non-empty regardless of config --
/// see `discovery_document`'s doc comment for why that would be inventing a capability.
///
/// Also proves the other half of the same design point: `well_known_router` is only mounted at all
/// when `oauth2.type: self` + `oauth2.signing` are configured (see call site in `lib.rs`), which
/// makes this service an OIDC *issuer* independent of whether the token-exchange grant is enabled
/// -- `ApiKeyJwtSigner` mints self-signed API-key JWTs through that path regardless. So the
/// issuer-identity fields (`issuer`, `jwks_uri`, `subject_types_supported`,
/// `id_token_signing_alg_values_supported`) must stay populated even with token-exchange disabled;
/// only the grant-surface fields (`grant_types_supported`, `scopes_supported`, `token_endpoint`)
/// go empty/absent. Two independent gates, not one flag driving everything.
#[tokio::test]
async fn discovery_advertises_no_grants_when_exchange_disabled() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::Value;
    use tower::ServiceExt;

    let discovery = well_known_router::<()>(ISSUER, lazy_repo(), None, false)
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
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload["grant_types_supported"]
            .as_array()
            .unwrap()
            .is_empty(),
        "no grants must be advertised when token-exchange is disabled: {payload}"
    );
    assert!(
        payload["response_types_supported"]
            .as_array()
            .unwrap()
            .is_empty(),
        "no response types must be advertised when token-exchange is disabled: {payload}"
    );
    assert!(
        payload["scopes_supported"].as_array().unwrap().is_empty(),
        "no scopes must be advertised when token-exchange is disabled: {payload}"
    );
    assert!(
        payload.get("token_endpoint").is_none(),
        "token_endpoint must stay absent when token-exchange is disabled: {payload}"
    );

    assert_eq!(
        payload["issuer"], ISSUER,
        "issuer identity is true independent of the token-exchange grant: {payload}"
    );
    assert_eq!(
        payload["jwks_uri"],
        format!("{ISSUER}/.well-known/jwks.json"),
        "JWKS is served whenever signing is configured, whether or not token-exchange is enabled \
         -- ApiKeyJwtSigner mints self-signed API-key JWTs through this path regardless: {payload}"
    );
    assert_eq!(
        payload["subject_types_supported"],
        serde_json::json!(["public"]),
        "subject type is an issuer property, not a token-exchange one: {payload}"
    );
    assert_eq!(
        payload["id_token_signing_alg_values_supported"],
        serde_json::json!(["RS256"]),
        "the signing algorithm is fixed by this deployment's key material, not by whether \
         token-exchange is enabled: {payload}"
    );
}

/// Regression test, restored: this exact test (`discovery_omits_token_endpoint_when_exchange_disabled`)
/// existed against the pre-ADR-0011 hand-built discovery document (added in #95) and was deleted
/// during the authkestra swap (#286/#288) on the belief that `OidcDiscovery`'s required (non-`Option`)
/// `token_endpoint` field made omitting it "impossible to preserve" -- see the now-removed doc
/// comment this replaced. That was wrong: `discovery_document` already had the pattern for exactly
/// this (`authorization_endpoint` is dropped from the serialized JSON post-hoc, for the identical
/// reason), it just was not applied to `token_endpoint`. This is the live bug behind
/// `https://auth.ai.camer.digital/.well-known/openid-configuration` serving a `token_endpoint` URL
/// alongside empty `grant_types_supported` -- a spec-reading client sees an endpoint that accepts
/// nothing. Run against unmodified code (before the `obj.remove("token_endpoint")` fix in
/// `discovery_document`), this test fails: `token_endpoint` is present. Restoring the fix passes it.
#[tokio::test]
async fn discovery_omits_token_endpoint_when_exchange_disabled() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::Value;
    use tower::ServiceExt;

    let discovery = well_known_router::<()>(ISSUER, lazy_repo(), None, false)
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
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        payload.get("token_endpoint").is_none(),
        "token_endpoint must be absent when token-exchange is disabled -- \
         a live token_endpoint URL advertising zero grants is worse than none: {payload}"
    );
    assert!(
        payload.get("authorization_endpoint").is_none(),
        "authorization_endpoint must always be absent -- this service never serves /authorize: {payload}"
    );
}

/// ADR-0011 Decision 6: a `confidential` client authenticates via `private_key_jwt` only, never
/// `client_secret_basic`/`client_secret_post`. This must hold with or without token-exchange being
/// enabled -- confidentiality of client auth is independent of whether the grant itself is live.
#[tokio::test]
async fn discovery_advertises_private_key_jwt_only_when_a_confidential_client_is_registered() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    let discovery = well_known_router::<()>(ISSUER, lazy_repo(), None, true)
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
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let methods = payload["token_endpoint_auth_methods_supported"]
        .as_array()
        .unwrap();
    assert!(methods.contains(&json!("none")));
    assert!(methods.contains(&json!("private_key_jwt")));
    assert!(
        !methods.contains(&json!("client_secret_basic"))
            && !methods.contains(&json!("client_secret_post")),
        "must never advertise secret-based client auth, confidential clients or not: {payload}"
    );
}

/// This service never serves `/authorize` (ADR-0011, Context) regardless of whether
/// `oauth2.token_exchange.enabled` is on: token-exchange is a direct token-endpoint grant
/// (RFC 8693), not a redirect-based authorization flow. `response_types_supported` and
/// `response_modes_supported` describe the authorization endpoint (OIDC Discovery 1.0 §3 --
/// `response_types_supported` is REQUIRED to be present as a JSON array, but the spec's
/// "MUST support code/id_token/id_token token" clause binds only "Dynamic OpenID Providers",
/// meaning ones that also advertise a `registration_endpoint`; this deployment has none, so an
/// empty array is spec-compliant, not merely tidy). So both must stay empty/absent on *both*
/// sides of the token-exchange gate -- unlike `grant_types_supported`/`scopes_supported`/
/// `token_endpoint`, which correctly describe the token-endpoint grant surface and are gated on
/// it. Checked against both states in one test specifically because the enabled/disabled tests
/// above each only prove one side; a gate wired to the wrong field (as `response_types_supported`
/// was before this test was added -- it flipped to `["token", "id_token", "id_token token"]`
/// purely because `oauth2.token_exchange.enabled` went from `false` to `true` in production) would
/// still pass a test that only checks one state.
#[tokio::test]
async fn discovery_never_advertises_response_types_or_modes() {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use lightbridge_authz_rest::signing::well_known_router;
    use serde_json::Value;
    use tower::ServiceExt;

    for (label, scopes) in [
        ("disabled", None),
        (
            "enabled",
            Some(vec!["openid".to_string(), "offline_access".to_string()]),
        ),
    ] {
        let discovery = well_known_router::<()>(ISSUER, lazy_repo(), scopes, false)
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
        let payload: Value = serde_json::from_slice(&body).unwrap();

        assert!(
            payload["response_types_supported"]
                .as_array()
                .unwrap()
                .is_empty(),
            "[{label}] no authorization endpoint exists in this deployment -- \
             response_types_supported must stay empty: {payload}"
        );
        assert!(
            payload["response_modes_supported"]
                .as_array()
                .unwrap()
                .is_empty(),
            "[{label}] no redirect-based flow is ever served -- response_modes_supported must \
             stay empty: {payload}"
        );
        assert!(
            payload.get("authorization_endpoint").is_none(),
            "[{label}] authorization_endpoint must stay absent: {payload}"
        );
    }
}

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    use chrono::{Duration, Utc};
    use lightbridge_authz_api_key::repo::StoreRepo;
    // `Billing`/`BillingPlan` are imported HERE, not at file scope: they are used only by this
    // `it-tests`-gated module, so a file-level import reads as unused on a build without the
    // feature (which is what `cargo fix` acted on) while being required with it.
    use lightbridge_authz_core::config::{Billing, BillingPlan, Oauth2};
    use lightbridge_authz_core::cuid::cuid2;
    use lightbridge_authz_core::{CreateAccount, CreateApiKey, CreateProject};
    use lightbridge_authz_rest::handlers::AuthzStoreImpl;
    use lightbridge_authz_rest::signing::{KeyOwner, bootstrap_signing_key};
    use serde_json::Value;
    use sqlx::PgPool;

    #[derive(Debug, Deserialize)]
    struct ApiKeyClaims {
        iss: String,
        sub: String,
        api_key_id: String,
        project_id: String,
        account_id: String,
        allowed_models: Option<Vec<String>>,
        email: Option<String>,
        email_verified: Option<bool>,
        typ: Option<String>,
        scope: Option<String>,
        #[serde(rename = "lightbridge_caller_kind")]
        caller_kind: Option<String>,
    }

    fn repo(pool: PgPool) -> Arc<StoreRepo> {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        Arc::new(StoreRepo::new(pool))
    }

    fn verify_against(jwk: &Value, token: &str) -> ApiKeyClaims {
        let decoding = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["lightbridge-api-key"]);
        validation.set_issuer(&[ISSUER]);
        decode::<ApiKeyClaims>(token, &decoding, &validation)
            .expect("verify")
            .claims
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn bootstrap_creates_active_key_and_is_idempotent(pool: PgPool) {
        let repo = repo(pool);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());

        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let first = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active");

        // Second boot must not create a second active key.
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let second = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active");
        assert_eq!(first.kid, second.kid, "boot should be idempotent");
        assert_eq!(repo.list_verification_jwks().await.unwrap().len(), 1);
    }

    /// ADR-0012 Phase 1's signing-key ownership decision: `authz-idp` bootstraps its own active
    /// key at startup, exactly as `authz-api` and `lightbridge-mcp` already do, making this the
    /// *third* concurrent bootstrapper against the shared `signing_keys` table. Simulates all
    /// three cold-starting against an empty table at the same instant -- `bootstrap_signing_key`'s
    /// own doc comment argues this is safe because every caller serializes on the same
    /// transaction-scoped `pg_advisory_xact_lock` (`StoreRepo::ensure_active_signing_key`)
    /// regardless of caller count; this test is the proof against a real database rather than
    /// just the argument. `tokio::join!` polls all three futures concurrently on one task, so
    /// each one's `BEGIN; SELECT pg_advisory_xact_lock(...)` genuinely races the others at the
    /// database, which is exactly the interleaving three real services cold-starting at once
    /// would produce.
    #[sqlx::test(migrations = "../../migrations")]
    async fn concurrent_bootstraps_from_multiple_services_produce_exactly_one_active_key(
        pool: PgPool,
    ) {
        let repo = repo(pool);
        let cfg = signing_cfg(3600);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());

        let (authz_api, lightbridge_mcp, authz_idp) = tokio::join!(
            bootstrap_signing_key(&repo, &cfg),
            bootstrap_signing_key(&repo, &cfg),
            bootstrap_signing_key(&repo, &cfg),
        );
        authz_api.unwrap();
        lightbridge_mcp.unwrap();
        authz_idp.unwrap();

        let jwks = repo.list_verification_jwks().await.unwrap();
        assert_eq!(
            jwks.len(),
            1,
            "three concurrent bootstraps (authz-api, lightbridge-mcp, authz-idp) must produce \
             exactly one signing key, never one per caller"
        );
        assert!(
            repo.get_active_signing_key().await.unwrap().is_some(),
            "exactly one key must be active after the race settles"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_stales_old_key_and_publishes_both(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let old = repo.get_active_signing_key().await.unwrap().unwrap();

        // Force rotation: cutoff after the current key's creation.
        let candidate = generate_rs256_key().unwrap();
        let new = repo
            .ensure_active_signing_key(
                lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey {
                    kid: candidate.kid,
                    algorithm: "RS256".to_string(),
                    private_key_pem: candidate.private_key_pem,
                    public_jwk: candidate.public_jwk,
                    created_at: Utc::now(),
                },
                Utc::now() + Duration::minutes(1),
            )
            .await
            .unwrap();

        assert_ne!(old.kid, new.kid);
        assert_eq!(new.status, "active");
        // Both keys remain published so tokens from the old key still verify.
        assert_eq!(repo.list_verification_jwks().await.unwrap().len(), 2);
        assert_eq!(
            repo.get_active_signing_key().await.unwrap().unwrap().kid,
            new.kid
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn signer_signs_verifiable_against_active_jwk(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let owner = KeyOwner {
            subject: "kc-user-123".to_string(),
            email: Some("dev@example.test".to_string()),
            email_verified: Some(true),
        };
        let signed = signer
            .sign(
                &owner,
                "key_1",
                "proj_1",
                "acct_1",
                Some(vec!["gpt-4.1-mini".to_string()]),
                Utc::now(),
                None,
            )
            .await
            .unwrap();

        let claims = verify_against(&active.public_jwk, &signed.token);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.sub, "kc-user-123");
        assert_eq!(claims.api_key_id, "key_1");
        assert_eq!(claims.project_id, "proj_1");
        assert_eq!(claims.account_id, "acct_1");
        assert_eq!(claims.email.as_deref(), Some("dev@example.test"));
        assert_eq!(claims.email_verified, Some(true));
        assert_eq!(claims.typ.as_deref(), Some("Bearer"));
        assert_eq!(claims.scope.as_deref(), Some("profile email"));
        assert_eq!(
            claims.allowed_models,
            Some(vec!["gpt-4.1-mini".to_string()])
        );
        // #191/#216: every self-signed API-key JWT must carry this claim so
        // `requestBudgetRefill` can refuse API-key-derived callers by a real, intentional
        // signal rather than by JWKS separation happening to reject the token first.
        assert_eq!(
            claims.caller_kind.as_deref(),
            Some(lightbridge_authz_bearer::API_KEY_CALLER_KIND)
        );
    }

    /// The exact claim shape `signing.rs`'s hand-rolled `jsonwebtoken::encode` produced before
    /// ADR-0011 replaced it with `TokenManager` -- reconstructed here (not imported: the real
    /// struct is gone) so this test is a genuine diff against the old wire contract, not a
    /// description of it written after the fact.
    #[derive(serde::Serialize)]
    struct OldApiKeyClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        jti: String,
        iat: i64,
        exp: i64,
        typ: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        azp: Option<&'a str>,
        #[serde(rename = "lightbridge_caller_kind")]
        caller_kind: &'static str,
        sid: String,
        scope: &'static str,
        api_key_id: &'a str,
        project_id: &'a str,
        account_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email_verified: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        allowed_models: Option<Vec<String>>,
    }

    #[allow(clippy::too_many_arguments)]
    fn old_signer_token(
        active_key_pem: &str,
        kid: &str,
        owner: &KeyOwner,
        api_key_id: &str,
        project_id: &str,
        account_id: &str,
        allowed_models: Option<Vec<String>>,
        now: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
    ) -> String {
        let encoding_key = EncodingKey::from_rsa_pem(active_key_pem.as_bytes()).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let claims = OldApiKeyClaims {
            iss: ISSUER,
            sub: &owner.subject,
            jti: format!("lgbr:{}", cuid2()),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            typ: "Bearer",
            aud: Some("lightbridge-api-key"),
            azp: Some("lightbridge-api-key"),
            caller_kind: lightbridge_authz_bearer::API_KEY_CALLER_KIND,
            sid: cuid2(),
            scope: "profile email",
            api_key_id,
            project_id,
            account_id,
            email: owner.email.as_deref(),
            email_verified: owner.email_verified,
            allowed_models,
        };
        encode(&header, &claims, &encoding_key).unwrap()
    }

    /// Decodes a JWT's full claim set into an untyped `serde_json::Value`, verifying its
    /// signature against `jwk` -- unlike the typed `ApiKeyClaims` test helper above, this sees
    /// every key on the wire, not just the ones a fixed struct happens to declare.
    fn decode_untyped(jwk: &Value, token: &str) -> Value {
        let decoding = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["lightbridge-api-key"]);
        validation.set_issuer(&[ISSUER]);
        decode::<Value>(token, &decoding, &validation)
            .expect("verify")
            .claims
    }

    /// ADR-0011 Decision 2 non-regression requirement: the access token's claim set produced
    /// through the new `TokenManager` path must be EQUIVALENT to the old hand-rolled
    /// `jsonwebtoken::encode` path -- same claim names, same values, same omissions -- with any
    /// deviation stated explicitly rather than silently shipped.
    ///
    /// `TokenManager::issue_user_token_with_extra` is not a drop-in replacement at the wire level:
    /// it unconditionally adds one claim this signer never emitted before (a nested `identity`
    /// object duplicating `sub`/`email`) plus `nbf`. `jti` used to be a third, similar deviation --
    /// authkestra minted it as a UUIDv4 with no clean way to override it, since an `extra["jti"]`
    /// entry collided with `Claims`' own top-level `jti` field and produced a JWT payload with a
    /// duplicate `jti` key on the wire. authkestra 0.5.0 (PR #215) closed that gap:
    /// `TokenManager::take_jti` now removes a string-valued `extra["jti"]` and uses it verbatim,
    /// so `signing.rs`'s `access_token_extra` supplies this repo's own `lgbr:`-prefixed CUID2
    /// through it -- this test now asserts `jti` is back to matching the old signer's format, not
    /// diverging from it.
    #[sqlx::test(migrations = "../../migrations")]
    async fn new_signer_claim_set_is_a_documented_superset_of_the_old_signer(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let owner = KeyOwner {
            subject: "kc-user-old-vs-new".to_string(),
            email: Some("dev@example.test".to_string()),
            email_verified: Some(true),
        };
        let allowed_models = Some(vec!["gpt-4.1-mini".to_string()]);
        let now = Utc::now();
        let expires_at = now + Duration::seconds(3600);

        let old_token = old_signer_token(
            &active.private_key_pem,
            &active.kid,
            &owner,
            "key_1",
            "proj_1",
            "acct_1",
            allowed_models.clone(),
            now,
            expires_at,
        );
        let old_claims = decode_untyped(&active.public_jwk, &old_token);

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(3600), repo.clone()).unwrap();
        let signed = signer
            .sign(
                &owner,
                "key_1",
                "proj_1",
                "acct_1",
                allowed_models,
                now,
                None,
            )
            .await
            .unwrap();
        let new_claims = decode_untyped(&active.public_jwk, &signed.token);

        let old_obj = old_claims.as_object().unwrap();
        let new_obj = new_claims.as_object().unwrap();

        for (key, value) in old_obj {
            // `jti`/`sid` are freshly random per call by design (a session identifier and a
            // token identifier respectively), so an exact-value comparison across two independent
            // signing calls would always fail regardless of this signer swap; `iat`/`exp` differ
            // because `TokenManager` stamps its own internal `now()` (documented above).
            if matches!(key.as_str(), "jti" | "sid" | "iat" | "exp") {
                continue;
            }
            assert_eq!(
                new_obj.get(key),
                Some(value),
                "claim `{key}` regressed: old={value:?} new={:?}",
                new_obj.get(key)
            );
        }

        let old_keys: std::collections::BTreeSet<&str> =
            old_obj.keys().map(String::as_str).collect();
        let new_keys: std::collections::BTreeSet<&str> =
            new_obj.keys().map(String::as_str).collect();
        let added: std::collections::BTreeSet<&str> =
            new_keys.difference(&old_keys).copied().collect();
        assert_eq!(
            added,
            std::collections::BTreeSet::from(["identity", "nbf"]),
            "the new signer must add exactly `identity` + `nbf` and nothing else beyond the old \
             claim set -- any other addition/removal is an undocumented wire-contract change"
        );

        assert!(
            new_obj["sid"].is_string() && !new_obj["sid"].as_str().unwrap().is_empty(),
            "sid must still be present and non-empty on the new signer"
        );

        let old_jti = old_obj["jti"].as_str().unwrap();
        let new_jti = new_obj["jti"].as_str().unwrap();
        assert!(
            old_jti.starts_with("lgbr:"),
            "sanity check on the reconstructed old shape"
        );
        assert!(
            new_jti.starts_with("lgbr:") && new_jti != old_jti,
            "new jti must use this repo's own `lgbr:`-prefixed CUID2 format, now that authkestra \
             0.5.0 (#215) honors `extra[\"jti\"]` as an override instead of always generating a \
             UUIDv4 (see the doc comment on this test) -- and must still be freshly minted per \
             call, not a fixed/reused value: {new_jti}"
        );

        // The nested `identity` object mirrors `sub`/`email`, not new authority.
        assert_eq!(new_obj["identity"]["external_id"], "kc-user-old-vs-new");
        assert_eq!(new_obj["identity"]["email"], "dev@example.test");
    }

    // `sign_id_token` was removed from `ApiKeyJwtSigner` in ADR-0011 phase 2: id_token minting for
    // the token-exchange grant now lives in `oauth2_op::store` (per-client `azp`/`aud`, via
    // `TokenManager::issue_id_token_with_extra` directly), not on the plain CRUD signer, which has
    // no id_token concept of its own. The claim-shape assertions this file used to make here
    // (`sub`/`email`/`email_verified`/`auth_time`/`nonce`/`azp`/`at_hash` present, tenant context
    // absent; `auth_time`/`nonce` omitted-not-fabricated when absent upstream) now live in
    // `token_exchange_tests.rs`'s `exchange_issues_id_token_when_openid_granted`,
    // `exchange_id_token_propagates_auth_time_and_nonce_when_present`, and
    // `exchange_id_token_omits_auth_time_and_nonce_when_absent`, exercised end to end through the
    // real `/oauth2/token` endpoint rather than the deleted method directly. The third deleted
    // test (refusing to mint when `oauth2.signing.audience` is unset) has no replacement: `azp`/
    // `aud` on the new path is always the authenticated client's `client_id`, which is guaranteed
    // present by the time id_token minting runs (client authentication already resolved it), so
    // the "no audience configured" failure mode this test covered no longer exists.

    fn signing_oauth2() -> Oauth2 {
        Oauth2 {
            oauth2_type: lightbridge_authz_core::config::Oauth2Type::SelfSigned,
            jwks_url: "http://unused".to_string(),
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: None,
            audience: None,
            signing: Some(signing_cfg(3600)),
            token_exchange: None,
            rbac: Default::default(),
            clients: Vec::new(),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_api_key_emits_verifiable_signed_jwt(pool: PgPool) {
        let key_repo = repo(pool.clone());
        bootstrap_signing_key(&key_repo, &signing_cfg(3600))
            .await
            .unwrap();
        let active = key_repo.get_active_signing_key().await.unwrap().unwrap();

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let store = AuthzStoreImpl::with_pool_and_oauth2(
            db_pool,
            &signing_oauth2(),
            &Billing {
                plans: vec![BillingPlan {
                    id: "free".to_string(),
                    name: "Free".to_string(),
                    limits: None,
                }],
            },
        )
        .unwrap();
        let subject = "owner-sign";

        let account = store
            .create_account(
                subject,
                CreateAccount {
                    default_quota: None,
                },
            )
            .await
            .unwrap();
        // Project creation left `AuthzStoreImpl` in the cratestack migration (the CRUD verbs now run
        // through the generated client). Seed the project row directly via the surviving
        // hand-written `StoreRepo::create_project` (membership already seeded by `create_account`);
        // this test only needs a project to exist so `create_api_key` can sign against it.
        let project = key_repo
            .create_project(
                subject,
                &account.id,
                CreateProject {
                    name: "p".to_string(),
                    allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                    default_limits: None,
                    billing_plan: "free".to_string(),
                    billing_identity: format!("bill-{}", cuid2()),
                    project_quota: None,
                },
                cuid2(),
            )
            .await
            .unwrap();
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"email":"owner@example.test","email_verified":true}"#);
        let bearer = format!("h.{payload}.s");
        let created = store
            .create_api_key(
                subject,
                Some(&bearer),
                &project.id,
                CreateApiKey {
                    name: "k".to_string(),
                    expires_at: None,
                    billing_plan: "free".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(created.secret.split('.').count(), 3, "must be a JWT");
        let claims = verify_against(&active.public_jwk, &created.secret);
        assert_eq!(claims.sub, subject);
        assert_eq!(claims.api_key_id, created.api_key.id);
        assert_eq!(claims.project_id, project.id);
        assert_eq!(claims.account_id, account.id);
        assert_eq!(claims.email.as_deref(), Some("owner@example.test"));
        assert_eq!(claims.email_verified, Some(true));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn jwks_and_discovery_endpoints_serve_db_keys(pool: PgPool) {
        use axum::body::{Body, to_bytes};
        use axum::http::{Request, StatusCode};
        use lightbridge_authz_rest::signing::well_known_router;
        use tower::ServiceExt;

        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(3600))
            .await
            .unwrap();
        // Rotate so both an active and a stale key are published.
        let candidate = generate_rs256_key().unwrap();
        repo.ensure_active_signing_key(
            lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey {
                kid: candidate.kid,
                algorithm: "RS256".to_string(),
                private_key_pem: candidate.private_key_pem,
                public_jwk: candidate.public_jwk,
                created_at: Utc::now(),
            },
            Utc::now() + Duration::minutes(1),
        )
        .await
        .unwrap();

        let jwks = well_known_router::<()>(ISSUER, repo.clone(), None, false)
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(jwks.status(), StatusCode::OK);
        let body = to_bytes(jwks.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            payload["keys"].as_array().unwrap().len(),
            2,
            "active + stale keys should both be published"
        );
        assert_eq!(payload["keys"][0]["alg"], "RS256");

        let scopes = vec!["openid".to_string(), "offline_access".to_string()];
        let discovery = well_known_router::<()>(ISSUER, repo, Some(scopes), false)
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
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["issuer"], ISSUER);
        assert_eq!(
            payload["jwks_uri"],
            format!("{ISSUER}/.well-known/jwks.json")
        );
        assert_eq!(
            payload["token_endpoint"],
            format!("{ISSUER}/oauth2/token"),
            "token_endpoint must be advertised when token-exchange is enabled"
        );
        let grants = payload["grant_types_supported"].as_array().unwrap();
        assert!(
            grants
                .iter()
                .any(|g| g == "urn:ietf:params:oauth:grant-type:token-exchange"),
            "discovery must advertise the token-exchange grant"
        );
        let scopes_supported = payload["scopes_supported"].as_array().unwrap();
        assert!(scopes_supported.iter().any(|s| s == "openid"));
        assert!(scopes_supported.iter().any(|s| s == "offline_access"));
        let auth_methods = payload["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap();
        assert_eq!(
            auth_methods,
            &[Value::String("none".to_string())],
            "must never advertise client_secret_basic/client_secret_post -- \
             this service never accepts secret-based client auth"
        );
        let claims_supported = payload["claims_supported"].as_array().unwrap();
        for claim in ["sub", "email", "email_verified", "auth_time", "at_hash"] {
            assert!(
                claims_supported.iter().any(|c| c == claim),
                "claims_supported must list {claim}: {claims_supported:?}"
            );
        }
    }
}

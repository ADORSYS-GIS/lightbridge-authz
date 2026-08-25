#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

use std::net::SocketAddr;
use std::sync::Arc;

use authkestra_engine::auth::state::OAuth2State;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use chrono::{Duration, Utc};
use cratestack_axum::ratelimit::{InMemoryRateLimitStore, RateLimitStore};
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::crypto::open;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{
    config::OidcRelyingParty,
    dto::{CreateAccount, CreateProject, ResourceStatus},
};
use lightbridge_authz_rest::oauth2_op::device_store::DbDeviceCodeStore;
use lightbridge_authz_rest::relying_party::{
    BrowserLoginTarget, KeycloakRelyingParty, KeycloakTokenSet, router,
};
use lightbridge_authz_rest::session_management::OP_BROWSER_STATE_COOKIE;
use lightbridge_authz_rest::signing::{GeneratedKey, generate_rs256_key};
use serde::Serialize;
use sqlx::PgPool;
use tower::ServiceExt;

const STATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// Deliberately distinct from [`STATE_KEY`] -- `KeycloakRelyingParty::new` rejects a config
/// where `token_encryption_key == state_encryption_key` (ADR-0024).
const TOKEN_KEY: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

fn rate_limiter() -> Arc<dyn RateLimitStore> {
    Arc::new(InMemoryRateLimitStore::new())
}

/// Fixed caller address injected into every request built below, standing in for the real
/// `ConnectInfo<SocketAddr>` `axum-server` normally populates from the live TCP connection --
/// `.oneshot()` bypasses that entirely, so tests insert it themselves via
/// `http::request::Builder::extension`.
fn test_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 4242))
}

fn rp_config(server: &MockServer) -> OidcRelyingParty {
    OidcRelyingParty {
        issuer: server.base_url(),
        client_id: "authz-idp-rp".to_string(),
        callback_url: "https://authz.example.test/idp/callback".to_string(),
        client_secret: None,
        state_encryption_key: STATE_KEY.to_string(),
        token_encryption_key: TOKEN_KEY.to_string(),
        timeout_ms: 500,
        browser_session_ttl_seconds: 28_800,
    }
}

fn discovery_body(server: &MockServer) -> serde_json::Value {
    serde_json::json!({
        "issuer": server.base_url(),
        "authorization_endpoint": server.url("/authorize"),
        "token_endpoint": server.url("/token"),
        "jwks_uri": server.url("/jwks")
    })
}

fn session() -> DeviceCodeSession {
    DeviceCodeSession {
        device_code: "device-code".to_string(),
        user_code: "PAIR1234".to_string(),
        client_id: "cli".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::minutes(10),
        status: DeviceCodeStatus::Pending,
        last_polled_at: None,
    }
}

fn state_from_redirect(response: &axum::response::Response) -> String {
    let location = response
        .headers()
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    reqwest::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap()
}

fn rp_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

fn callback_uri(state: &str) -> String {
    callback_uri_with_code(state, "code")
}

fn callback_uri_with_code(state: &str, code: &str) -> String {
    let mut url = reqwest::Url::parse("http://authz.test/idp/callback").unwrap();
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    format!(
        "{}{}",
        url.path(),
        url.query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default()
    )
}

#[derive(Serialize)]
struct IdToken<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    nonce: &'a str,
    exp: i64,
    iat: i64,
}

async fn begin_pairing(router: axum::Router) -> (axum::Router, String, String) {
    let confirmation = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .extension(ConnectInfo(test_addr()))
                .body(Body::from("user_code=pair-1234"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmation.status(), StatusCode::OK);
    // The CSRF-binding cookie `verify_submit` sets for this `user_code` -- `verify_continue`
    // below requires it (proof this same caller was shown the confirmation page), so a real
    // browser client forwards it exactly like this on the "Continue" form submission.
    let confirm_cookie = rp_cookie(&confirmation);
    let confirmation_body = to_bytes(confirmation.into_body(), usize::MAX)
        .await
        .unwrap();
    let confirmation_body = String::from_utf8(confirmation_body.to_vec()).unwrap();
    assert!(confirmation_body.contains("Requesting client: <strong>cli</strong>"));
    assert!(confirmation_body.contains("Code: <strong>PAIR1234</strong>"));
    assert!(confirmation_body.contains("name=\"user_code\" value=\"PAIR1234\""));
    assert!(!confirmation_body.contains("device-code"));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device/verify/continue")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, confirm_cookie)
                .extension(ConnectInfo(test_addr()))
                .body(Body::from("user_code=PAIR1234"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let state = state_from_redirect(&response);
    let cookie = rp_cookie(&response);
    (router, state, cookie)
}

#[sqlx::test(migrations = "../../migrations")]
async fn verified_keycloak_callback_transitions_pending_device_code_to_approved(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool);
    // ADR-0024 Correction (2026-08-25): upsert_federated_identity now refuses a subject with no
    // pre-existing account, so this callback's identity must have one to adopt.
    repo.create_account(
        "keycloak-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let mut config = rp_config(&keycloak);
    config.client_secret = Some("confidential-secret".to_string());
    let rp = Arc::new(
        KeycloakRelyingParty::new(config, keycloak.url("/jwks"), repo.clone(), rate_limiter())
            .unwrap(),
    );
    let router = router(rp);
    let (router, state, cookie) = begin_pairing(router).await;
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "keycloak-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("grant_type=authorization_code")
                .body_includes("code=code")
                .body_includes("code_verifier=")
                .body_includes("client_secret=confidential-secret");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fetched = store.get_device_code("device-code").await.unwrap().unwrap();
    match fetched.status {
        DeviceCodeStatus::Approved(identity) => {
            assert_eq!(identity.external_id, "keycloak-subject")
        }
        status => panic!("expected approved device code, got {status:?}"),
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn keycloak_token_failure_leaves_device_code_pending(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token");
            then.status(503).body("unavailable");
        })
        .await;
    let repo = repo(pool);
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (router, state, cookie) = begin_pairing(router(rp)).await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let fetched = store.get_device_code("device-code").await.unwrap().unwrap();
    assert!(matches!(fetched.status, DeviceCodeStatus::Pending));
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_device_codes_have_one_uniform_response_and_frame_protection(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let mut invalid_callback = rp_config(&keycloak);
    invalid_callback.callback_url = "https://authz.example.test/attacker-controlled".to_string();
    assert!(
        KeycloakRelyingParty::new(
            invalid_callback,
            keycloak.url("/jwks"),
            repo(pool.clone()),
            rate_limiter(),
        )
        .is_err()
    );
    let repo = repo(pool);
    let store = DbDeviceCodeStore::new(repo.clone());
    let mut expired = session();
    expired.device_code = "expired-device-code".to_string();
    expired.user_code = "EXPIRED1".to_string();
    expired.expires_at = Utc::now() - Duration::minutes(1);
    store.store_device_code(expired).await.unwrap();

    let mut consumed = session();
    consumed.device_code = "consumed-device-code".to_string();
    consumed.user_code = "CONSUMED1".to_string();
    store.store_device_code(consumed).await.unwrap();
    assert!(
        store
            .approve_pending("consumed-device-code", "keycloak-subject")
            .await
            .unwrap()
    );
    assert!(
        store
            .consume_device_code("consumed-device-code")
            .await
            .unwrap()
            .is_some()
    );

    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo,
            rate_limiter(),
        )
        .unwrap(),
    );
    let router = router(rp);
    let request = |code: &'static str| {
        Request::builder()
            .method("POST")
            .uri("/device/verify")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .extension(ConnectInfo(test_addr()))
            .body(Body::from(format!("user_code={code}")))
            .unwrap()
    };
    let unknown = router.clone().oneshot(request("missing")).await.unwrap();
    let expired = router.clone().oneshot(request("EXPIRED1")).await.unwrap();
    let consumed = router.oneshot(request("CONSUMED1")).await.unwrap();
    for response in [&unknown, &expired, &consumed] {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::X_FRAME_OPTIONS).unwrap(),
            "DENY"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .unwrap(),
            "default-src 'self'; frame-ancestors 'none'"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }
    let unknown_body = to_bytes(unknown.into_body(), usize::MAX).await.unwrap();
    let expired_body = to_bytes(expired.into_body(), usize::MAX).await.unwrap();
    let consumed_body = to_bytes(consumed.into_body(), usize::MAX).await.unwrap();
    assert_eq!(unknown_body, expired_body);
    assert_eq!(unknown_body, consumed_body);
}

/// CSRF regression coverage for `POST /device/verify/continue`: without the mechanism this test
/// pins down, an attacker starts their own device-code flow, then serves a page with a hidden
/// auto-submitting form `POST`ing this route with the attacker's own `user_code`. A victim with
/// an active Keycloak SSO session who merely visits that page would silently pair the attacker's
/// device to the victim's identity -- the victim never sees the real confirmation screen.
///
/// (a) a same-site `POST` naming a real, live, pending `user_code` but carrying NO
/// `__Host-authz_device_confirm` cookie must be refused, not approved -- this is exactly the
/// shape of the cross-site auto-submitting form's request (the confirmation cookie itself is
/// `SameSite=Strict`, so a genuinely cross-site request could never carry it even if the attacker
/// somehow learned its value).
/// (b) a confirmation cookie minted for a DIFFERENT `user_code` must not authorize this one.
/// (c) the legitimate flow -- visit the confirmation page first, then submit with the cookie it
/// set -- still succeeds; every `begin_pairing`-based test above already exercises this path end
/// to end (each asserts `StatusCode::SEE_OTHER`), so it is not re-asserted standalone here.
#[sqlx::test(migrations = "../../migrations")]
async fn verify_continue_requires_the_confirmation_cookie_from_verify_submit(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let repo = repo(pool);
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let mut other = session();
    other.device_code = "other-device-code".to_string();
    other.user_code = "OTHER1234".to_string();
    store.store_device_code(other).await.unwrap();

    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo,
            rate_limiter(),
        )
        .unwrap(),
    );
    let router = router(rp);

    let continue_request = |cookie: Option<String>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/device/verify/continue")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .extension(ConnectInfo(test_addr()));
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder.body(Body::from("user_code=PAIR1234")).unwrap()
    };

    // (a) No confirmation cookie at all.
    let no_cookie = router
        .clone()
        .oneshot(continue_request(None))
        .await
        .unwrap();
    assert_eq!(
        no_cookie.status(),
        StatusCode::FORBIDDEN,
        "a bare POST with no confirmation cookie must never pair a device"
    );

    // (b) A confirmation cookie minted for a *different* user_code (obtained by visiting the
    // confirmation page for "OTHER1234") must not authorize approving "PAIR1234".
    let other_confirmation = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/device/verify")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .extension(ConnectInfo(test_addr()))
                .body(Body::from("user_code=OTHER1234"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_confirmation.status(), StatusCode::OK);
    let mismatched_cookie = rp_cookie(&other_confirmation);
    let mismatched = router
        .clone()
        .oneshot(continue_request(Some(mismatched_cookie)))
        .await
        .unwrap();
    assert_eq!(
        mismatched.status(),
        StatusCode::FORBIDDEN,
        "a confirmation cookie bound to a different user_code must not authorize this one"
    );

    // Neither rejected attempt actually approved the device.
    let still_pending = store.get_device_code("device-code").await.unwrap().unwrap();
    assert!(matches!(still_pending.status, DeviceCodeStatus::Pending));
}

#[sqlx::test(migrations = "../../migrations")]
async fn relying_party_rejects_non_positive_runtime_limits(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let mut zero_timeout = rp_config(&keycloak);
    zero_timeout.timeout_ms = 0;
    assert!(
        KeycloakRelyingParty::new(
            zero_timeout,
            keycloak.url("/jwks"),
            repo(pool.clone()),
            rate_limiter(),
        )
        .is_err()
    );

    let mut zero_browser_ttl = rp_config(&keycloak);
    zero_browser_ttl.browser_session_ttl_seconds = 0;
    assert!(
        KeycloakRelyingParty::new(
            zero_browser_ttl,
            keycloak.url("/jwks"),
            repo(pool),
            rate_limiter(),
        )
        .is_err()
    );
}

/// Open-redirect regression coverage for `begin_browser`'s `resume_path` guard. Blocking only a
/// bare leading `//` is not enough on its own: WHATWG URL parsing (what every real browser
/// implements) treats `\` identically to `/` when resolving a relative reference against an
/// http(s) base, so `/\evil.com` and `/\/evil.com` both normalize to the same off-origin redirect
/// as `//evil.com` even though a plain `starts_with("//")` check does not see them as such.
#[sqlx::test(migrations = "../../migrations")]
async fn begin_browser_rejects_backslash_open_redirect_variants(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let rp = KeycloakRelyingParty::new(
        rp_config(&keycloak),
        keycloak.url("/jwks"),
        repo(pool),
        rate_limiter(),
    )
    .unwrap();

    for resume_path in ["/\\evil.com", "/\\/evil.com", "//evil.com"] {
        assert!(
            rp.begin_browser(BrowserLoginTarget {
                project_id: Some("some-project".to_string()),
                resume_path: resume_path.to_string(),
            })
            .await
            .is_err(),
            "resume_path {resume_path:?} must be rejected as an open-redirect bypass"
        );
    }

    // Sanity check the guard is not simply rejecting every path: a real same-origin path passes.
    assert!(
        rp.begin_browser(BrowserLoginTarget {
            project_id: Some("some-project".to_string()),
            resume_path: "/browser".to_string(),
        })
        .await
        .is_ok()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn callback_rejects_state_cookie_mismatch_before_contacting_keycloak(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo(pool),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp.begin_device("device-code".to_string()).await.unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let response = router(rp.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri("different-state"))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_ne!(state, "different-state");
}

#[sqlx::test(migrations = "../../migrations")]
async fn invalid_id_token_profiles_fail_closed(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo(pool),
            rate_limiter(),
        )
        .unwrap(),
    );
    let now = Utc::now();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid.clone());

    for profile in [
        "wrong-nonce",
        "missing-nonce",
        "wrong-issuer",
        "wrong-audience",
        "missing-iat",
        "multiple-aud-without-azp",
        "wrong-signature",
    ] {
        let (location, cookie) = rp.begin_device(format!("device-{profile}")).await.unwrap();
        let state = reqwest::Url::parse(&location)
            .unwrap()
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .unwrap();
        let decoded = OAuth2State::decrypt(
            &state,
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(STATE_KEY)
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let mut claims = serde_json::json!({
            "sub": "keycloak-subject",
            "iss": keycloak.base_url(),
            "aud": "authz-idp-rp",
            "nonce": decoded.nonce.as_deref().unwrap(),
            "exp": (now + Duration::minutes(5)).timestamp(),
            "iat": now.timestamp(),
        });
        let signing_key = if profile == "wrong-signature" {
            generate_rs256_key().unwrap().private_key_pem
        } else {
            key.private_key_pem.clone()
        };
        match profile {
            "wrong-nonce" => claims["nonce"] = serde_json::json!("wrong"),
            "missing-nonce" => {
                claims.as_object_mut().unwrap().remove("nonce");
            }
            "wrong-issuer" => claims["iss"] = serde_json::json!("https://wrong.example.test"),
            "wrong-audience" => claims["aud"] = serde_json::json!("wrong-client"),
            "missing-iat" => {
                claims.as_object_mut().unwrap().remove("iat");
            }
            "multiple-aud-without-azp" => {
                claims["aud"] = serde_json::json!(["authz-idp-rp", "other-client"]);
            }
            "wrong-signature" => {}
            _ => unreachable!(),
        }
        let token = encode(
            &jwt_header,
            &claims,
            &EncodingKey::from_rsa_pem(signing_key.as_bytes()).unwrap(),
        )
        .unwrap();
        let code = format!("code-{profile}");
        let _token = keycloak
            .mock_async(|when, then| {
                when.method(POST)
                    .path("/token")
                    .body_includes(format!("code={code}"));
                then.status(200)
                    .json_body(serde_json::json!({ "id_token": token }));
            })
            .await;
        let response = router(rp.clone())
            .oneshot(
                Request::builder()
                    .uri(callback_uri_with_code(&state, &code))
                    .header(header::COOKIE, cookie.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{profile}");
        assert_eq!(_token.calls_async().await, 1, "{profile}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn browser_session_is_bound_to_the_verified_subject_context(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool.clone());
    repo.create_account(
        "keycloak-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("keycloak-subject"),
        "keycloak-subject",
        CreateProject {
            name: "browser project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "browser-binding".to_string(),
            project_quota: None,
        },
        "browser-project".to_string(),
    )
    .await
    .unwrap();
    let default_project_id = repo
        .find_default_project_id(
            &lightbridge_authz_core::identity::AccountId::assert_already_resolved(
                "keycloak-subject",
            ),
        )
        .await
        .unwrap()
        .unwrap();
    repo.create_account(
        "other-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("other-subject"),
        "other-subject",
        CreateProject {
            name: "other browser project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "other-browser-binding".to_string(),
            project_quota: None,
        },
        "other-browser-project".to_string(),
    )
    .await
    .unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "keycloak-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(header::LOCATION).unwrap(),
        "/browser"
    );
    // The `Completion::Browser` arm sets a second `Set-Cookie` beside `__Host-authz_session`:
    // the OIDC Session Management OP browser-state cookie. `axum::http::HeaderMap::get` only
    // ever returns the FIRST `Set-Cookie` value, so this reads all of them via `get_all` --
    // otherwise a regression that stopped setting the op-state cookie entirely could hide behind
    // whichever cookie happens to serialize first.
    let set_cookies: Vec<String> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    let op_state_cookie = set_cookies
        .iter()
        .find(|value| value.starts_with(&format!("{OP_BROWSER_STATE_COOKIE}=")))
        .unwrap_or_else(|| {
            panic!("no {OP_BROWSER_STATE_COOKIE} Set-Cookie header among: {set_cookies:?}")
        });
    assert!(
        !op_state_cookie.contains("HttpOnly"),
        "the OP browser-state cookie must be JS-readable by the check-session iframe, never \
         HttpOnly -- unlike its __Host-authz_session sibling: {op_state_cookie}"
    );
    let row: (String, String) =
        sqlx::query_as("SELECT account_id, project_id FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, ("keycloak-subject".to_string(), default_project_id));

    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: Some("other-browser-project".to_string()),
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "keycloak-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("code=unbound");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp)
        .oneshot(
            Request::builder()
                .uri(callback_uri_with_code(&state, "unbound"))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let browser_sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(browser_sessions, 1);
}

/// Code-review follow-up to #463/#466/#467 (Finding A): `resolve_context` only checks
/// ownership/membership, never `status` -- before this fix, `KeycloakRelyingParty::complete`'s
/// `PendingFlow::Browser` arm called it and then `create_session` with no Active-status gate at
/// all, so a SUSPENDED account still got handed a live browser SSO session. Proof this test
/// catches the regression: reverting the `resolve_active_context` status checks in
/// `relying_party.rs` back to a bare `self.repo.resolve_context(...).await?` makes this test
/// fail with `left: 0, right: 1` (a session row IS created) instead of passing.
#[sqlx::test(migrations = "../../migrations")]
async fn suspended_account_is_refused_a_browser_session(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool.clone());
    repo.create_account(
        "suspended-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("suspended-subject"),
        "suspended-subject",
        CreateProject {
            name: "suspended account project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "suspended-account-binding".to_string(),
            project_quota: None,
        },
        "suspended-account-project".to_string(),
    )
    .await
    .unwrap();
    repo.set_account_status(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("suspended-subject"),
        "suspended-subject",
        ResourceStatus::Suspended,
    )
    .await
    .expect("suspend the account");
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "suspended-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp)
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "a suspended account must not complete browser SSO"
    );
    let browser_sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        browser_sessions, 0,
        "a suspended account must never get a live browser session"
    );
}

/// Code-review follow-up to #463/#466/#467 (Finding A, project half): same gap as
/// `suspended_account_is_refused_a_browser_session`, but for an INACTIVE project rather than a
/// suspended account -- `resolve_context` resolves the project regardless of its own `status`.
#[sqlx::test(migrations = "../../migrations")]
async fn inactive_project_is_refused_a_browser_session(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool.clone());
    repo.create_account(
        "inactive-project-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(
            "inactive-project-subject",
        ),
        "inactive-project-subject",
        CreateProject {
            name: "inactive project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "inactive-project-binding".to_string(),
            project_quota: None,
        },
        "inactive-project".to_string(),
    )
    .await
    .unwrap();
    repo.set_project_status(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(
            "inactive-project-subject",
        ),
        "inactive-project",
        ResourceStatus::Suspended,
    )
    .await
    .expect("suspend the project");
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: Some("inactive-project".to_string()),
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "inactive-project-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp)
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "an inactive project must not complete browser SSO"
    );
    let browser_sessions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        browser_sessions, 0,
        "an inactive project must never get a live browser session"
    );
}

/// Code-review follow-up to #463/#466/#467 (Finding B, groundwork): the browser session row must
/// persist the REAL authenticated subject (`sessions.subject`), not just the resolved
/// `account_id` -- which `resolve_context` sets to the project's OWNING account even when the
/// caller only holds a `project_members` roster row. Proof this test catches the regression:
/// before `migrations/20260824000003_sessions_add_subject.sql` and the `NewSession { subject:
/// Some(claims.sub), .. }` change in `relying_party.rs`, `sessions` had no `subject` column at
/// all, and `claims.sub` was discarded once `resolve_context` returned -- there would be no way
/// to distinguish `member-subject` from `owner-subject` after this call.
#[sqlx::test(migrations = "../../migrations")]
async fn browser_session_persists_the_real_authenticated_member_subject(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool.clone());
    repo.create_account(
        "owner-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_account(
        "member-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("owner-subject"),
        "owner-subject",
        CreateProject {
            name: "owner project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "member-binding".to_string(),
            project_quota: None,
        },
        "member-scope-project".to_string(),
    )
    .await
    .unwrap();
    repo.add_project_member(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved("owner-subject"),
        "member-scope-project",
        "member-subject",
        Some("member"),
    )
    .await
    .expect("add member-subject as a roster member");
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: Some("member-scope-project".to_string()),
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: "member-subject",
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp)
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT account_id, project_id, subject FROM sessions WHERE kind = 'browser'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            "owner-subject".to_string(),
            "member-scope-project".to_string(),
            Some("member-subject".to_string())
        ),
        "account_id resolves to the project OWNER, but subject must be the real authenticated \
         member -- these must never collapse to the same value for a non-owner member"
    );
}

/// ADR-0025 Stage 2: `sessions.subject` must be the FEDERATED account id
/// (`persist_federated_identity`'s returned row) -- never the raw Keycloak `sub` claim off the
/// ID token directly -- once a `federated_identities` row already links that raw subject to a
/// DIFFERENT id than itself. `browser_session_persists_the_real_authenticated_member_subject`
/// above is the grandfathered-account sibling of this test (where the raw subject and the
/// resolved account id happen to be byte-identical, proving wire-invariance); this test
/// deliberately makes them differ, proving the general translation, not merely coincidence.
#[sqlx::test(migrations = "../../migrations")]
async fn browser_session_subject_is_the_acting_account_not_the_keycloak_sub(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let _discovery = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(&keycloak));
        })
        .await;
    let key = generate_rs256_key().unwrap();
    let _jwks = keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk] }));
        })
        .await;
    let repo = repo(pool.clone());
    let account_id = "federated-target-account";
    let raw_keycloak_sub = "kc-raw-sub-differs-from-account";
    repo.create_account(
        account_id,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    // Pre-seeds a federated_identities row where subject != account_id -- not producible by this
    // repo's own write paths in Stage 1-3 (the self-healing grandfather branch always adopts
    // subject == account_id), but a legitimate general shape `upsert_federated_identity`'s UPDATE
    // branch (an already-existing row) must still resolve correctly through.
    sqlx::query(
        "INSERT INTO federated_identities (id, issuer, subject, account_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(lightbridge_authz_core::cuid::cuid2())
    .bind(keycloak.base_url())
    .bind(raw_keycloak_sub)
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("seeding the federated_identities row must succeed");
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(account_id),
        account_id,
        CreateProject {
            name: "federated project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "federated-binding".to_string(),
            project_quota: None,
        },
        "federated-project".to_string(),
    )
    .await
    .unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: Some("federated-project".to_string()),
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(
        &state,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(STATE_KEY)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid);
    let token = encode(
        &jwt_header,
        &IdToken {
            sub: raw_keycloak_sub,
            iss: &keycloak.base_url(),
            aud: "authz-idp-rp",
            nonce: decoded.nonce.as_deref().unwrap(),
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    let _token = keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(serde_json::json!({ "id_token": token }));
        })
        .await;
    let response = router(rp)
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let row: (Option<String>,) =
        sqlx::query_as("SELECT subject FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row.0.as_deref(),
        Some(account_id),
        "sessions.subject must be the federated account id, never the raw Keycloak sub claim"
    );
}

// ---------------------------------------------------------------------------------------------
// ADR-0024: the Keycloak token set is persisted (sealed) as a federated identity on every
// successful callback, for both flows sharing `complete`'s single funnel.
// ---------------------------------------------------------------------------------------------

fn token_key_bytes() -> [u8; 32] {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(TOKEN_KEY)
        .unwrap()
        .try_into()
        .unwrap()
}

fn state_key_bytes() -> [u8; 32] {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(STATE_KEY)
        .unwrap()
        .try_into()
        .unwrap()
}

fn sign_id_token(key: &GeneratedKey, sub: &str, iss: &str, nonce: &str) -> String {
    let mut jwt_header = Header::new(Algorithm::RS256);
    jwt_header.kid = Some(key.kid.clone());
    encode(
        &jwt_header,
        &IdToken {
            sub,
            iss,
            aud: "authz-idp-rp",
            nonce,
            exp: (Utc::now() + Duration::minutes(5)).timestamp(),
            iat: Utc::now().timestamp(),
        },
        &EncodingKey::from_rsa_pem(key.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// A `/token` response carrying a full Keycloak token set -- refresh token, expiries, scope,
/// `session_state` -- so the ADR-0024 persistence tests below can assert on every sealed field,
/// not just `id_token`.
fn rich_token_response(id_token: &str, refresh_token: &str) -> serde_json::Value {
    serde_json::json!({
        "id_token": id_token,
        "access_token": "should-never-be-persisted-access-token",
        "refresh_token": refresh_token,
        "expires_in": 300,
        "refresh_expires_in": 1800,
        "token_type": "Bearer",
        "scope": "openid profile email",
        "session_state": "session-state-value",
    })
}

async fn mock_discovery_and_jwks(keycloak: &MockServer, key: &GeneratedKey) {
    keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(discovery_body(keycloak));
        })
        .await;
    keycloak
        .mock_async(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200)
                .json_body(serde_json::json!({ "keys": [key.public_jwk.clone()] }));
        })
        .await;
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_pairing_callback_persists_a_federated_identity_for_an_existing_account(
    pool: PgPool,
) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    repo.create_account(
        "keycloak-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (router, state, cookie) = begin_pairing(router(rp)).await;
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        "keycloak-subject",
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "device-pairing-refresh"));
        })
        .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let federation = repo
        .find_federated_identity(&keycloak.base_url(), "keycloak-subject")
        .await
        .unwrap()
        .expect("a federated identity row must exist after a successful device-pairing callback");
    assert_eq!(federation.issuer, keycloak.base_url());
    assert_eq!(federation.subject, "keycloak-subject");
    assert_eq!(
        federation.account_id, "keycloak-subject",
        "the pre-existing account sharing this subject's id must be adopted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn device_pairing_callback_is_refused_for_a_subject_with_no_account(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    // Deliberately no repo.create_account() call -- this subject has no pre-existing account.
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (router, state, cookie) = begin_pairing(router(rp)).await;
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        "accountless-device-subject",
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "accountless-device-refresh"));
        })
        .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "a subject with no pre-existing account must be refused, not paired"
    );

    let federation = repo
        .find_federated_identity(&keycloak.base_url(), "accountless-device-subject")
        .await
        .unwrap();
    assert!(
        federation.is_none(),
        "the refused login must leave no federated_identities row behind"
    );

    let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        user_count, 0,
        "the refused login must never mint a users row -- there is no mint-a-user branch any more"
    );

    let store = DbDeviceCodeStore::new(repo);
    let fetched = store.get_device_code("device-code").await.unwrap().unwrap();
    assert!(
        matches!(fetched.status, DeviceCodeStatus::Pending),
        "the gate precedes the flow arm's own side effect -- the device code must remain Pending, \
         never Approved, expected Pending got {:?}",
        fetched.status
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn browser_sso_callback_persists_the_same_federated_identity(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    let subject = "browser-federation-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(subject),
        subject,
        CreateProject {
            name: "browser federation project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "browser-federation-binding".to_string(),
            project_quota: None,
        },
        "browser-federation-project".to_string(),
    )
    .await
    .unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        subject,
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "browser-refresh"));
        })
        .await;
    let response = router(rp.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let federation = repo
        .find_federated_identity(&keycloak.base_url(), subject)
        .await
        .unwrap()
        .expect("a federated identity row must exist after a successful browser SSO callback");
    assert_eq!(federation.issuer, keycloak.base_url());
    assert_eq!(federation.subject, subject);
    assert_eq!(
        federation.account_id,
        subject.to_string(),
        "a pre-existing account whose id equals the subject must be adopted"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn stored_token_envelope_is_not_plaintext_at_rest(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    repo.create_account(
        "keycloak-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (router, state, cookie) = begin_pairing(router(rp)).await;
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        "keycloak-subject",
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "super-secret-refresh-value"));
        })
        .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let raw_envelope: Option<String> = sqlx::query_scalar(
        "SELECT token_envelope FROM federated_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(keycloak.base_url())
    .bind("keycloak-subject")
    .fetch_one(&pool)
    .await
    .unwrap();
    let raw_envelope = raw_envelope.expect("a sealed envelope must be stored");
    assert!(
        !raw_envelope.contains("super-secret-refresh-value"),
        "the raw column value must never contain the plaintext refresh token: {raw_envelope}"
    );
    assert!(
        raw_envelope.starts_with("v1."),
        "the envelope must carry the v1. version prefix: got {raw_envelope}"
    );

    let aad = format!("{}\u{1f}keycloak-subject", keycloak.base_url());
    let opened = open(&token_key_bytes(), &aad, &raw_envelope)
        .expect("opening under the real token_encryption_key and matching AAD must succeed");
    let token_set: KeycloakTokenSet = serde_json::from_slice(&opened).unwrap();
    assert_eq!(
        token_set.refresh_token.as_deref(),
        Some("super-secret-refresh-value")
    );
    assert_eq!(token_set.id_token_claims.sub, "keycloak-subject");
}

#[sqlx::test(migrations = "../../migrations")]
async fn token_envelope_does_not_open_under_the_state_encryption_key(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    repo.create_account(
        "keycloak-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let (router, state, cookie) = begin_pairing(router(rp)).await;
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        "keycloak-subject",
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "super-secret-refresh-value"));
        })
        .await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let raw_envelope: String = sqlx::query_scalar::<_, Option<String>>(
        "SELECT token_envelope FROM federated_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(keycloak.base_url())
    .bind("keycloak-subject")
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap();

    let aad = format!("{}\u{1f}keycloak-subject", keycloak.base_url());
    let opened_under_state_key = open(&state_key_bytes(), &aad, &raw_envelope);
    assert!(
        opened_under_state_key.is_err(),
        "a token envelope sealed under token_encryption_key must not open under the separate \
         state_encryption_key"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_second_login_updates_the_same_federated_identity_row_and_reseals(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let key = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak, &key).await;
    let repo = repo(pool.clone());
    let subject = "reseal-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(subject),
        subject,
        CreateProject {
            name: "reseal project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "reseal-binding".to_string(),
            project_quota: None,
        },
        "reseal-project".to_string(),
    )
    .await
    .unwrap();
    let rp = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak),
            keycloak.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );

    // First login.
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        subject,
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("code=first-code");
            then.status(200)
                .json_body(rich_token_response(&token, "first-refresh-value"));
        })
        .await;
    let response = router(rp.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri_with_code(&state, "first-code"))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let first = repo
        .find_federated_identity(&keycloak.base_url(), subject)
        .await
        .unwrap()
        .expect("first login must persist a federated identity");

    // Second login for the SAME (issuer, subject).
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key,
        subject,
        &keycloak.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak
        .mock_async(|when, then| {
            when.method(POST)
                .path("/token")
                .body_includes("code=second-code");
            then.status(200)
                .json_body(rich_token_response(&token, "second-refresh-value"));
        })
        .await;
    let response = router(rp.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri_with_code(&state, "second-code"))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let row_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM federated_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(keycloak.base_url())
    .bind(subject)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row_count, 1,
        "a second login for the same (issuer, subject) must update the existing row, never insert \
         a second one"
    );

    let second = repo
        .find_federated_identity(&keycloak.base_url(), subject)
        .await
        .unwrap()
        .expect("the row must still exist after the second login");
    assert_eq!(
        second.id, first.id,
        "the second login must update the SAME row by id, not replace it"
    );

    let aad = format!("{}\u{1f}{}", keycloak.base_url(), subject);
    let opened = open(
        &token_key_bytes(),
        &aad,
        &second
            .token_envelope
            .expect("the resealed envelope must be present"),
    )
    .unwrap();
    let token_set: KeycloakTokenSet = serde_json::from_slice(&opened).unwrap();
    assert_eq!(
        token_set.refresh_token.as_deref(),
        Some("second-refresh-value"),
        "the resealed envelope must reflect the second login's refresh token, not the first"
    );
}

/// End-to-end (real HTTP callback, two independently-configured `KeycloakRelyingParty`
/// instances) proof that a second issuer never silently merges into an account issuer_a already
/// adopted. In THIS two-independent-RP shape the refusal still comes from
/// `federated_identities_account_uidx` (each RP's own `config.issuer` self-satisfies ADR-0025's
/// new `upsert_federated_identity` issuer pin, since `validate_id_token` already enforces
/// `claims.iss == self.config.issuer` before the pin is ever reached) -- that DB-level backstop
/// was already sufficient once an adoption exists to collide with, and remains exercised here.
/// The pin's own, stronger guarantee -- refusing a non-grandfather issuer's FIRST adoption
/// attempt, before anything exists to race against -- is order-independent and cannot be proven
/// with two self-consistent RPs (a real deployment only ever runs one), so it is proven directly
/// against the repo seam instead:
/// `upsert_federated_identity_refuses_adoption_from_a_non_grandfather_issuer` in
/// `crates/lightbridge-authz-api-key/tests/federated_identity_account_link_tests.rs` runs the
/// non-grandfather issuer FIRST, against a freshly-created, never-adopted account, and asserts
/// `Error::Forbidden` -- proving the refusal is the issuer pin itself, not a race lost to a prior
/// adoption.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_issuer_with_a_colliding_subject_is_refused_not_merged(pool: PgPool) {
    let keycloak_a = MockServer::start_async().await;
    let key_a = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak_a, &key_a).await;
    let keycloak_b = MockServer::start_async().await;
    let key_b = generate_rs256_key().unwrap();
    mock_discovery_and_jwks(&keycloak_b, &key_b).await;

    let repo = repo(pool.clone());
    let subject = "colliding-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(subject),
        subject,
        CreateProject {
            name: "colliding project".to_string(),
            allowed_models: None,
            default_limits: None,
            billing_plan: "free".to_string(),
            billing_identity: "colliding-binding".to_string(),
            project_quota: None,
        },
        "colliding-project".to_string(),
    )
    .await
    .unwrap();

    let rp_a = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak_a),
            keycloak_a.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );
    let rp_b = Arc::new(
        KeycloakRelyingParty::new(
            rp_config(&keycloak_b),
            keycloak_b.url("/jwks"),
            repo.clone(),
            rate_limiter(),
        )
        .unwrap(),
    );

    // First login: issuer_a adopts the pre-existing account.
    let (location, cookie) = rp_a
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key_a,
        subject,
        &keycloak_a.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak_a
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "issuer-a-refresh"));
        })
        .await;
    let response = router(rp_a.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let issuer_a_before = repo
        .find_federated_identity(&keycloak_a.base_url(), subject)
        .await
        .unwrap()
        .expect("issuer_a's login must adopt the pre-existing account");
    // ADR-0024 Correction (2026-08-25): account_id is a plain, NOT NULL String now -- the refusal
    // exercised below still comes from the adopt-path's 23505 (issuer_b's subject already adopted
    // an account via issuer_a), not the accountless-subject refusal this correction adds; that
    // distinction matters because both now map to `Error::Forbidden`/`Error::Conflict` and the same
    // uniform BAD_GATEWAY, so this test is what pins "refused, not merged" specifically for the
    // already-has-an-account collision case.
    assert_eq!(issuer_a_before.account_id, subject.to_string());

    // Second login: issuer_b presents the SAME subject. Must be refused, not merged.
    let (location, cookie) = rp_b
        .begin_browser(BrowserLoginTarget {
            project_id: None,
            resume_path: "/browser".to_string(),
        })
        .await
        .unwrap();
    let state = reqwest::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .unwrap();
    let decoded = OAuth2State::decrypt(&state, &state_key_bytes()).unwrap();
    let token = sign_id_token(
        &key_b,
        subject,
        &keycloak_b.base_url(),
        decoded.nonce.as_deref().unwrap(),
    );
    keycloak_b
        .mock_async(|when, then| {
            when.method(POST).path("/token").body_includes("code=code");
            then.status(200)
                .json_body(rich_token_response(&token, "issuer-b-refresh"));
        })
        .await;
    let response = router(rp_b.clone())
        .oneshot(
            Request::builder()
                .uri(callback_uri(&state))
                .header(header::COOKIE, cookie.to_string())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "a second issuer presenting a subject that already adopted an account must be refused \
         (complete()'s Err maps to a generic BAD_GATEWAY failure), never silently merged"
    );

    let issuer_b_row = repo
        .find_federated_identity(&keycloak_b.base_url(), subject)
        .await
        .unwrap();
    assert!(
        issuer_b_row.is_none(),
        "the refused attempt must leave no federated_identities row behind for issuer_b"
    );

    let issuer_a_after = repo
        .find_federated_identity(&keycloak_a.base_url(), subject)
        .await
        .unwrap()
        .expect("issuer_a's row must still exist");
    assert_eq!(
        issuer_a_after.account_id, issuer_a_before.account_id,
        "issuer_a's own row must be completely untouched by issuer_b's refused attempt"
    );
    assert_eq!(issuer_a_after.id, issuer_a_before.id);
}

#[test]
fn token_response_debug_never_leaks_the_refresh_token() {
    use lightbridge_authz_rest::relying_party::TokenResponse;

    let response: TokenResponse = serde_json::from_value(serde_json::json!({
        "id_token": "eyJ.super-secret-id-token.value",
        "access_token": "super-secret-access-token-value",
        "refresh_token": "super-secret-refresh-token-value",
        "expires_in": 300,
        "refresh_expires_in": 1800,
        "token_type": "Bearer",
        "scope": "openid",
        "session_state": "state-value",
    }))
    .unwrap();

    let rendered = format!("{response:?}");

    assert!(!rendered.contains("super-secret-id-token"));
    assert!(!rendered.contains("super-secret-access-token-value"));
    assert!(!rendered.contains("super-secret-refresh-token-value"));
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("openid"));
}

#[test]
fn keycloak_token_set_debug_never_leaks_the_refresh_token() {
    use lightbridge_authz_rest::relying_party::IdTokenClaimsSnapshot;

    let token_set = KeycloakTokenSet {
        refresh_token: Some("super-secret-refresh-token-value".to_string()),
        id_token_claims: IdTokenClaimsSnapshot {
            sub: "user-sub".to_string(),
            iss: "https://keycloak.example.test".to_string(),
            email: None,
            email_verified: None,
            preferred_username: None,
            name: None,
            auth_time: None,
            sid: None,
            exp: 42,
            iat: 1,
        },
        token_type: Some("Bearer".to_string()),
        session_state: None,
    };

    let rendered = format!("{token_set:?}");

    assert!(!rendered.contains("super-secret-refresh-token-value"));
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("user-sub"));
}

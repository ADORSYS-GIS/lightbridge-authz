#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

use std::sync::Arc;

use authkestra_engine::auth::state::OAuth2State;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use chrono::{Duration, Utc};
use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{
    config::OidcRelyingParty,
    dto::{CreateAccount, CreateProject},
};
use lightbridge_authz_rest::oauth2_op::device_store::DbDeviceCodeStore;
use lightbridge_authz_rest::relying_party::{BrowserLoginTarget, KeycloakRelyingParty, router};
use lightbridge_authz_rest::signing::generate_rs256_key;
use serde::Serialize;
use sqlx::PgPool;
use tower::ServiceExt;

const STATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn repo(pool: PgPool) -> Arc<StoreRepo> {
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    Arc::new(StoreRepo::new(pool))
}

fn rp_config(server: &MockServer) -> OidcRelyingParty {
    OidcRelyingParty {
        issuer: server.base_url(),
        client_id: "authz-idp-rp".to_string(),
        callback_url: "https://authz.example.test/idp/callback".to_string(),
        client_secret: None,
        state_encryption_key: STATE_KEY.to_string(),
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
                .body(Body::from("user_code=pair-1234"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(confirmation.status(), StatusCode::OK);
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
    let store = DbDeviceCodeStore::new(repo.clone());
    store.store_device_code(session()).await.unwrap();
    let mut config = rp_config(&keycloak);
    config.client_secret = Some("confidential-secret".to_string());
    let rp =
        Arc::new(KeycloakRelyingParty::new(config, keycloak.url("/jwks"), repo.clone()).unwrap());
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
        KeycloakRelyingParty::new(rp_config(&keycloak), keycloak.url("/jwks"), repo.clone())
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
        KeycloakRelyingParty::new(invalid_callback, keycloak.url("/jwks"), repo(pool.clone()))
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
        KeycloakRelyingParty::new(rp_config(&keycloak), keycloak.url("/jwks"), repo).unwrap(),
    );
    let router = router(rp);
    let request = |code: &'static str| {
        Request::builder()
            .method("POST")
            .uri("/device/verify")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
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

#[sqlx::test(migrations = "../../migrations")]
async fn relying_party_rejects_non_positive_runtime_limits(pool: PgPool) {
    let keycloak = MockServer::start_async().await;
    let mut zero_timeout = rp_config(&keycloak);
    zero_timeout.timeout_ms = 0;
    assert!(
        KeycloakRelyingParty::new(zero_timeout, keycloak.url("/jwks"), repo(pool.clone())).is_err()
    );

    let mut zero_browser_ttl = rp_config(&keycloak);
    zero_browser_ttl.browser_session_ttl_seconds = 0;
    assert!(
        KeycloakRelyingParty::new(zero_browser_ttl, keycloak.url("/jwks"), repo(pool)).is_err()
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
        KeycloakRelyingParty::new(rp_config(&keycloak), keycloak.url("/jwks"), repo(pool)).unwrap(),
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
        KeycloakRelyingParty::new(rp_config(&keycloak), keycloak.url("/jwks"), repo(pool)).unwrap(),
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
        "keycloak-subject",
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
    repo.create_account(
        "other-subject",
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .unwrap();
    repo.create_project(
        "other-subject",
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
        KeycloakRelyingParty::new(rp_config(&keycloak), keycloak.url("/jwks"), repo.clone())
            .unwrap(),
    );
    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: "browser-project".to_string(),
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
    let row: (String, String) =
        sqlx::query_as("SELECT account_id, project_id FROM sessions WHERE kind = 'browser'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            "keycloak-subject".to_string(),
            "browser-project".to_string()
        )
    );

    let (location, cookie) = rp
        .begin_browser(BrowserLoginTarget {
            project_id: "other-browser-project".to_string(),
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

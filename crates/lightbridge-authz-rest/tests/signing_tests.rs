use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::signing::{
    ApiKeyJwtSigner, KeyOwner, capped_expiry, generate_rs256_key,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

const ISSUER: &str = "https://authz.example.test";

fn signing_cfg(enabled: bool, ttl: i64) -> JwtSigning {
    JwtSigning {
        enabled,
        issuer: ISSUER.to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: ttl,
        max_key_age_days: 30,
    }
}

fn lazy_repo() -> Arc<lightbridge_authz_api_key::repo::StoreRepo> {
    let pool = PgPoolOptions::new()
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
async fn from_config_disabled_returns_none() {
    assert!(
        ApiKeyJwtSigner::from_config(&signing_cfg(false, 3600), lazy_repo())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn from_config_rejects_empty_issuer() {
    let mut cfg = signing_cfg(true, 3600);
    cfg.issuer = "   ".to_string();
    let err = ApiKeyJwtSigner::from_config(&cfg, lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("issuer is empty"));
}

#[tokio::test]
async fn from_config_rejects_non_positive_ttl() {
    let err = ApiKeyJwtSigner::from_config(&signing_cfg(true, 0), lazy_repo()).unwrap_err();
    assert!(format!("{err}").contains("ttl_seconds must be positive"));
}

#[tokio::test]
async fn well_known_serves_cors_headers() {
    use axum::body::Body;
    use axum::http::{Request, header};
    use lightbridge_authz_rest::signing::well_known_router;
    use tower::ServiceExt;

    let response = well_known_router::<()>(ISSUER, lazy_repo())
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

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    use chrono::{Duration, Utc};
    use lightbridge_authz_api::contract::AuthzStore;
    use lightbridge_authz_api_key::repo::StoreRepo;
    use lightbridge_authz_core::config::Oauth2;
    use lightbridge_authz_core::{CreateAccount, CreateApiKey, CreateProject};
    use lightbridge_authz_rest::handlers::AuthzStoreImpl;
    use lightbridge_authz_rest::signing::bootstrap_signing_key;
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

        bootstrap_signing_key(&repo, &signing_cfg(true, 3600))
            .await
            .unwrap();
        let first = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active");

        // Second boot must not create a second active key.
        bootstrap_signing_key(&repo, &signing_cfg(true, 3600))
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

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_stales_old_key_and_publishes_both(pool: PgPool) {
        let repo = repo(pool);
        bootstrap_signing_key(&repo, &signing_cfg(true, 3600))
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
        bootstrap_signing_key(&repo, &signing_cfg(true, 3600))
            .await
            .unwrap();
        let active = repo.get_active_signing_key().await.unwrap().unwrap();

        let signer = ApiKeyJwtSigner::from_config(&signing_cfg(true, 3600), repo.clone())
            .unwrap()
            .unwrap();
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
    }

    fn signing_oauth2() -> Oauth2 {
        Oauth2 {
            jwks_url: "http://unused".to_string(),
            oauth2_url: None,
            issuer_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            issuance: None,
            audience: None,
            signing: Some(signing_cfg(true, 3600)),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_api_key_emits_verifiable_signed_jwt(pool: PgPool) {
        let key_repo = repo(pool.clone());
        bootstrap_signing_key(&key_repo, &signing_cfg(true, 3600))
            .await
            .unwrap();
        let active = key_repo.get_active_signing_key().await.unwrap().unwrap();

        let db_pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let store = AuthzStoreImpl::with_pool_and_oauth2(db_pool, &signing_oauth2()).unwrap();
        let subject = "owner-sign";

        let account = store
            .create_account(
                subject,
                CreateAccount {
                    billing_identity: "t".to_string(),
                },
            )
            .await
            .unwrap();
        let project = store
            .create_project(
                subject,
                &account.id,
                CreateProject {
                    name: "p".to_string(),
                    allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                    default_limits: None,
                    billing_plan: "free".to_string(),
                },
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
        bootstrap_signing_key(&repo, &signing_cfg(true, 3600))
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

        let jwks = well_known_router::<()>(ISSUER, repo.clone())
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

        let discovery = well_known_router::<()>(ISSUER, repo)
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
    }
}

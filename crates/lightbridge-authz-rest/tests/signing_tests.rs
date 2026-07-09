use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_rest::signing::{ApiKeyJwtSigner, well_known_router};
use rand_core::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;
use std::sync::OnceLock;
use tower::ServiceExt;

const KID: &str = "authz-apikey-test";
const ISSUER: &str = "https://authz.example.test";

/// An ephemeral RSA keypair generated at test time (once) — nothing sensitive is committed.
/// Returns `(private_key_pem, jwks_json)`.
fn material() -> &'static (String, String) {
    static MATERIAL: OnceLock<(String, String)> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string();
        let public = RsaPublicKey::from(&private);
        let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let n = b64(public.n().to_bytes_be());
        let e = b64(public.e().to_bytes_be());
        let jwks = format!(
            r#"{{"keys":[{{"kty":"RSA","use":"sig","alg":"RS256","kid":"{KID}","n":"{n}","e":"{e}"}}]}}"#
        );
        (pem, jwks)
    })
}

fn private_key_pem() -> &'static str {
    &material().0
}

fn jwks() -> &'static str {
    &material().1
}

fn signing_config(enabled: bool, key: &str) -> JwtSigning {
    JwtSigning {
        enabled,
        issuer: ISSUER.to_string(),
        kid: KID.to_string(),
        private_key_pem: key.to_string(),
        jwks: jwks().to_string(),
        audience: Some("lightbridge-api-key".to_string()),
        ttl_seconds: 3600,
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: i64,
    api_key_id: String,
    project_id: String,
    account_id: String,
    allowed_models: Option<Vec<String>>,
}

#[test]
fn signer_mints_verifiable_jwt_with_api_key_claims() {
    let signer = ApiKeyJwtSigner::from_config(&signing_config(true, private_key_pem()))
        .expect("valid config")
        .expect("signer enabled");

    let signed = signer
        .sign(
            "key_123",
            "proj_456",
            "acct_789",
            Some(vec!["gpt-4.1-mini".to_string()]),
            Utc::now(),
        )
        .expect("sign");

    assert_eq!(signed.token.split('.').count(), 3, "must be a JWT");

    // Verify the signature with the published JWKS public key.
    let jwks_doc: Value = serde_json::from_str(jwks()).unwrap();
    let jwk = &jwks_doc["keys"][0];
    let key =
        DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["lightbridge-api-key"]);
    validation.set_issuer(&[ISSUER]);
    let data = decode::<Claims>(&signed.token, &key, &validation).expect("verify");

    assert_eq!(data.claims.iss, ISSUER);
    assert_eq!(data.claims.sub, "key_123");
    assert_eq!(data.claims.api_key_id, "key_123");
    assert_eq!(data.claims.project_id, "proj_456");
    assert_eq!(data.claims.account_id, "acct_789");
    assert_eq!(
        data.claims.allowed_models,
        Some(vec!["gpt-4.1-mini".to_string()])
    );
    assert_eq!(data.claims.exp, signed.expires_at.timestamp());
}

#[test]
fn signer_disabled_returns_none() {
    let signer = ApiKeyJwtSigner::from_config(&signing_config(false, private_key_pem())).unwrap();
    assert!(signer.is_none());
}

#[test]
fn signer_rejects_invalid_private_key() {
    let err = ApiKeyJwtSigner::from_config(&signing_config(true, "not-a-pem")).unwrap_err();
    assert!(format!("{err}").contains("invalid api-key signing key"));
}

#[test]
fn signer_rejects_empty_private_key_with_clear_error() {
    let err = ApiKeyJwtSigner::from_config(&signing_config(true, "")).unwrap_err();
    assert!(format!("{err}").contains("private_key_pem is empty"));
}

#[test]
fn signer_rejects_non_positive_ttl() {
    let mut cfg = signing_config(true, private_key_pem());
    cfg.ttl_seconds = -1;
    let err = ApiKeyJwtSigner::from_config(&cfg).unwrap_err();
    assert!(format!("{err}").contains("ttl_seconds must be positive"));
}

#[tokio::test]
async fn jwks_endpoint_serves_configured_keys() {
    let router = well_known_router::<()>(ISSUER, jwks());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["keys"][0]["kid"], KID);
    assert_eq!(payload["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn discovery_endpoint_points_at_jwks() {
    let router = well_known_router::<()>(ISSUER, jwks());
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
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["issuer"], ISSUER);
    assert_eq!(
        payload["jwks_uri"],
        format!("{ISSUER}/.well-known/jwks.json")
    );
    assert_eq!(payload["id_token_signing_alg_values_supported"][0], "RS256");
}

#[cfg(feature = "it-tests")]
mod db {
    use super::{Claims, ISSUER, KID, jwks, private_key_pem};
    use lightbridge_authz_api::contract::AuthzStore;
    use lightbridge_authz_core::config::{JwtSigning, Oauth2};
    use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
    use lightbridge_authz_core::{CreateAccount, CreateApiKey, CreateProject};
    use lightbridge_authz_rest::handlers::AuthzStoreImpl;
    use sqlx::PgPool;
    use std::sync::Arc;

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
            signing: Some(JwtSigning {
                enabled: true,
                issuer: ISSUER.to_string(),
                kid: KID.to_string(),
                private_key_pem: private_key_pem().to_string(),
                jwks: jwks().to_string(),
                audience: Some("lightbridge-api-key".to_string()),
                ttl_seconds: 3600,
            }),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn create_api_key_emits_verifiable_signed_jwt(pool: PgPool) {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        let store = AuthzStoreImpl::with_pool_and_oauth2(pool, &signing_oauth2()).unwrap();
        let subject = "owner-sign";

        let account = store
            .create_account(
                subject,
                CreateAccount {
                    billing_identity: "tenant-sign".to_string(),
                },
            )
            .await
            .unwrap();
        let project = store
            .create_project(
                subject,
                &account.id,
                CreateProject {
                    name: "proj-sign".to_string(),
                    allowed_models: Some(vec!["gpt-4.1-mini".to_string()]),
                    default_limits: None,
                    billing_plan: "free".to_string(),
                },
            )
            .await
            .unwrap();

        let created = store
            .create_api_key(
                subject,
                None,
                &project.id,
                CreateApiKey {
                    name: "signed-key".to_string(),
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            created.secret.split('.').count(),
            3,
            "issued secret must be a JWT"
        );

        let jwks_doc: serde_json::Value = serde_json::from_str(jwks()).unwrap();
        let jwk = &jwks_doc["keys"][0];
        let key = jsonwebtoken::DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&["lightbridge-api-key"]);
        validation.set_issuer(&[ISSUER]);
        let data =
            jsonwebtoken::decode::<Claims>(&created.secret, &key, &validation).expect("verify");

        assert_eq!(data.claims.api_key_id, created.api_key.id);
        assert_eq!(data.claims.project_id, project.id);
        assert_eq!(data.claims.account_id, account.id);
        assert_eq!(
            data.claims.allowed_models,
            Some(vec!["gpt-4.1-mini".to_string()])
        );
    }
}

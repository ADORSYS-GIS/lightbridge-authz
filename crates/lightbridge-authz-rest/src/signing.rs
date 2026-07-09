use std::sync::Arc;

use axum::{Json, Router, http::StatusCode, routing::get};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use rand_core::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;

const RSA_KEY_BITS: usize = 2048;
const ALGORITHM: &str = "RS256";

/// A freshly generated RS256 signing key: PKCS#8 private PEM + the public JWK to publish.
pub struct GeneratedKey {
    pub kid: String,
    pub private_key_pem: String,
    pub public_jwk: serde_json::Value,
}

/// Generates an RS256 signing keypair with a unique `kid`.
pub fn generate_rs256_key() -> Result<GeneratedKey> {
    let private = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
        .map_err(|e| Error::Server(format!("rsa key generation failed: {e}")))?;
    let pem = private
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| Error::Server(format!("private key encoding failed: {e}")))?
        .to_string();
    let public = RsaPublicKey::from(&private);
    let kid = cuid2();
    let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let public_jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": ALGORITHM,
        "kid": kid,
        "n": b64(public.n().to_bytes_be()),
        "e": b64(public.e().to_bytes_be()),
    });
    Ok(GeneratedKey {
        kid,
        private_key_pem: pem,
        public_jwk,
    })
}

impl GeneratedKey {
    fn into_candidate(self, created_at: DateTime<Utc>) -> NewSigningKey {
        NewSigningKey {
            kid: self.kid,
            algorithm: ALGORITHM.to_string(),
            private_key_pem: self.private_key_pem,
            public_jwk: self.public_jwk,
            created_at,
        }
    }
}

/// Ensures an active signing key exists, generating one on first boot and auto-rotating when
/// the active key is older than `max_key_age_days`. Idempotent and safe across replicas.
pub async fn bootstrap_signing_key(repo: &StoreRepo, cfg: &JwtSigning) -> Result<()> {
    if !cfg.enabled {
        return Ok(());
    }
    let now = Utc::now();
    let cutoff = now - Duration::days(cfg.max_key_age_days.max(1));
    let candidate = generate_rs256_key()?.into_candidate(now);
    let active = repo.ensure_active_signing_key(candidate, cutoff).await?;
    tracing::info!(kid = %active.kid, "active api-key signing key ready");
    Ok(())
}

/// Signs issued API keys as RS256 JWTs using the active signing key from the DB. Rotation is
/// picked up automatically (the active key is read per issuance); revocation still flows through
/// the introspection endpoint.
#[derive(Clone)]
pub struct ApiKeyJwtSigner {
    repo: Arc<StoreRepo>,
    issuer: String,
    audience: Option<String>,
    ttl_seconds: i64,
}

impl std::fmt::Debug for ApiKeyJwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyJwtSigner")
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct ApiKeyClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    jti: String,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    api_key_id: &'a str,
    project_id: &'a str,
    account_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_models: Option<Vec<String>>,
}

/// A freshly signed API-key JWT and the expiry stamped into it.
pub struct SignedApiKey {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

impl ApiKeyJwtSigner {
    /// Builds a signer from config. Returns `Ok(None)` when signing is disabled, and an error
    /// for invalid config (fail-fast at startup). Key material lives in the DB, not config.
    pub fn from_config(cfg: &JwtSigning, repo: Arc<StoreRepo>) -> Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.issuer.trim().is_empty() {
            return Err(Error::Server(
                "jwt signing is enabled but issuer is empty".to_string(),
            ));
        }
        if cfg.ttl_seconds <= 0 {
            return Err(Error::Server(format!(
                "jwt signing ttl_seconds must be positive, got {}",
                cfg.ttl_seconds
            )));
        }
        Ok(Some(Self {
            repo,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            ttl_seconds: cfg.ttl_seconds,
        }))
    }

    /// Signs an API-key JWT with the current active key for the given key/project/account.
    pub async fn sign(
        &self,
        api_key_id: &str,
        project_id: &str,
        account_id: &str,
        allowed_models: Option<Vec<String>>,
        now: DateTime<Utc>,
    ) -> Result<SignedApiKey> {
        let active = self
            .repo
            .get_active_signing_key()
            .await?
            .ok_or_else(|| Error::Server("no active api-key signing key".to_string()))?;
        let encoding_key = EncodingKey::from_rsa_pem(active.private_key_pem.as_bytes())
            .map_err(|e| Error::Server(format!("invalid stored signing key: {e}")))?;
        let expires_at = now + Duration::seconds(self.ttl_seconds);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(active.kid);
        let claims = ApiKeyClaims {
            iss: &self.issuer,
            sub: api_key_id,
            jti: cuid2(),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            aud: self.audience.as_deref(),
            api_key_id,
            project_id,
            account_id,
            allowed_models,
        };
        let token = encode(&header, &claims, &encoding_key)
            .map_err(|e| Error::Server(format!("api-key signing failed: {e}")))?;
        Ok(SignedApiKey { token, expires_at })
    }
}

/// Public OIDC discovery + JWKS routes for Authorino's `jwt` identity. JWKS is served live from
/// the DB (active + stale keys) so tokens signed by a rotated-out key keep verifying until they
/// expire. Stateless w.r.t. axum state, so it merges into any router.
pub fn well_known_router<S>(issuer: &str, repo: Arc<StoreRepo>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let discovery_issuer = issuer.to_string();
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let issuer = discovery_issuer.clone();
                async move {
                    Json(serde_json::json!({
                        "issuer": issuer,
                        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "response_types_supported": ["token"],
                        "subject_types_supported": ["public"],
                    }))
                }
            }),
        )
        .route(
            "/.well-known/jwks.json",
            get(move || {
                let repo = repo.clone();
                async move {
                    match repo.list_verification_jwks().await {
                        Ok(keys) => (StatusCode::OK, Json(serde_json::json!({ "keys": keys }))),
                        Err(_) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "keys": [] })),
                        ),
                    }
                }
            }),
        )
}

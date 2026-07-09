use axum::{Json, Router, http::header, routing::get};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use serde::Serialize;

/// Public, unauthenticated OIDC discovery + JWKS routes so Authorino's `jwt` identity can
/// verify API-key JWT signatures via `issuerUrl` discovery. Stateless, so it merges into any
/// router regardless of its state type.
pub fn well_known_router<S>(issuer: &str, jwks: &str) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let discovery_issuer = issuer.to_string();
    let jwks_body = jwks.to_string();
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
                let jwks = jwks_body.clone();
                async move { ([(header::CONTENT_TYPE, "application/json")], jwks) }
            }),
        )
}

/// Signs issued API keys as RS256 JWTs carrying their own identity/scope claims. The public
/// half is published as JWKS so Authorino can verify signatures; revocation still flows through
/// the introspection endpoint (the `api_keys` row remains the source of truth).
#[derive(Clone)]
pub struct ApiKeyJwtSigner {
    encoding_key: EncodingKey,
    kid: String,
    issuer: String,
    audience: Option<String>,
    ttl_seconds: i64,
    jwks: String,
}

impl std::fmt::Debug for ApiKeyJwtSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyJwtSigner")
            .field("kid", &self.kid)
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
    /// when it is enabled but the private key cannot be parsed (fail-fast at startup).
    pub fn from_config(cfg: &JwtSigning) -> Result<Option<Self>> {
        if !cfg.enabled {
            return Ok(None);
        }
        if cfg.private_key_pem.trim().is_empty() {
            return Err(Error::Server(
                "jwt signing is enabled but private_key_pem is empty".to_string(),
            ));
        }
        if cfg.jwks.trim().is_empty() {
            return Err(Error::Server(
                "jwt signing is enabled but jwks is empty".to_string(),
            ));
        }
        if cfg.ttl_seconds <= 0 {
            return Err(Error::Server(format!(
                "jwt signing ttl_seconds must be positive, got {}",
                cfg.ttl_seconds
            )));
        }
        let encoding_key = EncodingKey::from_rsa_pem(cfg.private_key_pem.as_bytes())
            .map_err(|e| Error::Server(format!("invalid api-key signing key: {e}")))?;
        Ok(Some(Self {
            encoding_key,
            kid: cfg.kid.clone(),
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            ttl_seconds: cfg.ttl_seconds,
            jwks: cfg.jwks.clone(),
        }))
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn jwks(&self) -> &str {
        &self.jwks
    }

    /// Signs an API-key JWT for the given key/project/account context.
    pub fn sign(
        &self,
        api_key_id: &str,
        project_id: &str,
        account_id: &str,
        allowed_models: Option<Vec<String>>,
        now: DateTime<Utc>,
    ) -> Result<SignedApiKey> {
        let expires_at = now + Duration::seconds(self.ttl_seconds);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
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
        let token = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| Error::Server(format!("api-key signing failed: {e}")))?;
        Ok(SignedApiKey { token, expires_at })
    }
}

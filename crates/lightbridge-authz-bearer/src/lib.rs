use anyhow::anyhow;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use jwks::Jwks;
use lightbridge_authz_core::config::Oauth2;
use serde::Deserialize;

/// Token information returned by JWT validation.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub sub: Option<String>,
    pub exp: Option<u64>,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: Option<String>,
    exp: Option<u64>,
    client_id: Option<String>,
}

/// Service responsible for validating bearer tokens.
pub struct BearerTokenService {
    config: Oauth2,
}

impl BearerTokenService {
    /// Create a new instance of the BearerTokenService.
    pub fn new(config: Oauth2) -> Self {
        BearerTokenService { config }
    }

    /// Validate a bearer token string by validating it as a JWT using the configured JWKS.
    ///
    /// If JWKS validation fails (including missing jwks_url), this function returns an error
    /// which should be translated to HTTP 401 by the caller.
    pub async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo> {
        if token.trim().is_empty() {
            return Ok(TokenInfo {
                active: false,
                sub: None,
                exp: None,
                client_id: None,
            });
        }

        // Require JWKS URL to be configured.
        let jwks_url = self.config.jwks_url.as_str();

        // Decode JWT header and extract kid
        let header = decode_header(token).map_err(|_| anyhow!("unauthorized"))?;
        let kid = header.kid.as_ref().ok_or_else(|| anyhow!("unauthorized"))?;

        // Load JWKS and find JWK by kid
        let jwks: Jwks = Jwks::from_jwks_url(jwks_url).await.map_err(|e| {
            tracing::error!("Some error {e}");
            anyhow!("unauthorized")
        })?;
        let jwk = jwks.keys.get(kid).ok_or_else(|| anyhow!("unauthorized"))?;

        // Validate the token using the JWK decoding key.
        let validation = Validation::new(Algorithm::RS256);
        let token_data = decode::<Claims>(token, &jwk.decoding_key, &validation).map_err(|e| {
            tracing::error!("Some error {e}");
            anyhow!("unauthorized")
        })?;
        let claims = token_data.claims;

        Ok(TokenInfo {
            active: true,
            sub: claims.sub,
            exp: claims.exp,
            client_id: claims.client_id,
        })
    }
}

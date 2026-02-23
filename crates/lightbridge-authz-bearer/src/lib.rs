use anyhow::{anyhow, ensure};
use jsonwebtoken::{Validation, decode, decode_header};
use jwks::{Jwk, Jwks};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::config::Oauth2;
use serde::Deserialize;
use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Token information returned by JWT validation.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub sub: String,
    pub exp: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
}

const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
struct JwksCache {
    url: String,
    ttl: Duration,
    inner: Arc<RwLock<Option<CachedJwks>>>,
}

struct CachedJwks {
    jwks: Jwks,
    expires_at: Instant,
}

impl JwksCache {
    fn new(url: String) -> Self {
        Self::with_ttl(url, DEFAULT_JWKS_CACHE_TTL)
    }

    fn with_ttl(url: String, ttl: Duration) -> Self {
        Self {
            url,
            ttl,
            inner: Arc::new(RwLock::new(None)),
        }
    }

    async fn get(&self, kid: &str) -> Result<Option<Jwk>, jwks::JwksError> {
        self.ensure_fresh().await?;
        if let Some(key) = self.lookup(kid).await {
            return Ok(Some(key));
        }

        self.refresh().await?;
        Ok(self.lookup(kid).await)
    }

    async fn lookup(&self, kid: &str) -> Option<Jwk> {
        let guard = self.inner.read().await;
        guard
            .as_ref()
            .and_then(|cached| cached.jwks.keys.get(kid).cloned())
    }

    async fn ensure_fresh(&self) -> Result<(), jwks::JwksError> {
        let now = Instant::now();
        {
            let guard = self.inner.read().await;
            if guard
                .as_ref()
                .map(|cached| cached.expires_at > now)
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        self.refresh().await
    }

    async fn refresh(&self) -> Result<(), jwks::JwksError> {
        let jwks = Jwks::from_jwks_url(&self.url).await?;
        let mut guard = self.inner.write().await;
        *guard = Some(CachedJwks {
            jwks,
            expires_at: Instant::now() + self.ttl,
        });
        Ok(())
    }
}

/// Trait for validating bearer tokens.
#[async_trait]
pub trait BearerTokenServiceTrait: Send + Sync {
    /// Validate a bearer token string by validating it as a JWT using the configured JWKS.
    ///
    /// If JWKS validation fails (including missing jwks_url), this function returns an error
    /// which should be translated to HTTP 401 by the caller.
    async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo>;
}

/// Service responsible for validating bearer tokens.
#[derive(Clone)]
pub struct BearerTokenService {
    config: Oauth2,
    cache: JwksCache,
}

impl fmt::Debug for BearerTokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerTokenService")
            .field("jwks_url", &self.config.jwks_url)
            .finish()
    }
}

impl BearerTokenService {
    /// Create a new instance of the BearerTokenService.
    pub fn new(config: Oauth2) -> Self {
        let cache = JwksCache::new(config.jwks_url.clone());
        BearerTokenService { config, cache }
    }
}

#[async_trait]
impl BearerTokenServiceTrait for BearerTokenService {
    /// Validate a bearer token string by validating it as a JWT using the configured JWKS.
    ///
    /// If JWKS validation fails (including missing jwks_url), this function returns an error
    /// which should be translated to HTTP 401 by the caller.
    async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo> {
        ensure!(!token.trim().is_empty(), anyhow!("empty token"));

        // Decode JWT header and extract kid
        let header = decode_header(token).map_err(|_| anyhow!("unauthorized"))?;
        let kid = header.kid.as_ref().ok_or_else(|| anyhow!("unauthorized"))?;

        // Load JWKS (cached) and find JWK by kid.
        let jwk = match self.cache.get(kid).await {
            Ok(Some(key)) => key,
            Ok(None) => return Err(anyhow!("unauthorized")),
            Err(err) => {
                tracing::error!("Some error {err}");
                return Err(anyhow!("unauthorized"));
            }
        };

        // Validate the token using the JWK decoding key.
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false;

        let token_data = decode::<Claims>(token, &jwk.decoding_key, &validation).map_err(|e| {
            tracing::error!("Some error {e}");
            anyhow!("unauthorized")
        })?;
        let claims = token_data.claims;

        Ok(TokenInfo {
            active: true,
            sub: claims.sub,
            exp: claims.exp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use serde_json::json;
    use std::time::Duration;

    const TEST_KID: &str = "91413cf4fa0cb92a3c3f5a054509132c47660937";

    fn jwks_body() -> String {
        json!({
            "keys": [
                {
                    "use": "sig",
                    "alg": "RS256",
                    "kid": TEST_KID,
                    "kty": "RSA",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB"
                }
            ]
        })
        .to_string()
    }

    #[tokio::test]
    async fn cache_reuses_jwks_within_ttl() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.header("content-type", "application/json")
                .status(200)
                .body(jwks_body());
        });

        let cache = JwksCache::with_ttl(server.url("/jwks"), Duration::from_secs(60));
        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.hits(), 1);

        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.hits(), 1);
    }

    #[tokio::test]
    async fn cache_refreshes_when_expired() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.header("content-type", "application/json")
                .status(200)
                .body(jwks_body());
        });

        let cache = JwksCache::with_ttl(server.url("/jwks"), Duration::from_secs(0));
        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.hits(), 1);

        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.hits(), 2);
    }
}

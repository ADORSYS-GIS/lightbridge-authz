use anyhow::{anyhow, ensure};
use jsonwebtoken::{Validation, decode, decode_header};
use jwks::{Jwk, Jwks};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::{PermissionSet, permissions_for_roles};
use lightbridge_authz_core::config::Oauth2;
use lightbridge_authz_core::{Error, Permission};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Token information returned by JWT validation.
#[derive(Clone, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub sub: String,
    pub exp: u64,
    /// The audience claim from the JWT, if present.
    #[serde(default)]
    pub aud: Vec<String>,
    /// Raw role strings extracted from the configured roles claim.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Permissions derived from `roles` via the configured RBAC mapping.
    #[serde(default)]
    pub permissions: PermissionSet,
    #[serde(default)]
    pub access_token: String,
}

impl std::fmt::Debug for TokenInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenInfo")
            .field("active", &self.active)
            .field("sub", &self.sub)
            .field("exp", &self.exp)
            .field("aud", &self.aud)
            .field("roles", &self.roles)
            .field("permissions", &self.permissions)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

impl TokenInfo {
    /// Whether the caller holds `permission`.
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// Returns `Ok(())` when the caller holds `permission`, otherwise [`Error::Forbidden`]
    /// (HTTP 403). Handlers call this before performing a gated operation.
    pub fn require(&self, permission: Permission) -> Result<(), Error> {
        self.permissions.require(permission)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: String,
    exp: u64,
    /// Audience claim - can be a single string or array of strings
    #[serde(default)]
    aud: Option<Audience>,
    /// All remaining claims, so the configurable roles claim can be read by name at runtime.
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

/// Extract role strings from a JWT claim value. Accepts a JSON array of strings or a single
/// space-delimited string (Keycloak emits either shape depending on the mapper).
fn roles_from_claim(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// Audience claim can be either a single string or an array of strings.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn to_vec(&self) -> Vec<String> {
        match self {
            Audience::Single(s) => vec![s.clone()],
            Audience::Multiple(v) => v.clone(),
        }
    }
}

impl Default for Audience {
    fn default() -> Self {
        Audience::Multiple(Vec::new())
    }
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
    /// JWT claim carrying the caller's roles.
    roles_claim: String,
    /// Precompiled role → permission map (wildcards already expanded).
    role_permissions: HashMap<String, PermissionSet>,
}

impl fmt::Debug for BearerTokenService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BearerTokenService")
            .field("jwks_url", &self.config.jwks_url)
            .field("roles_claim", &self.roles_claim)
            .finish()
    }
}

impl BearerTokenService {
    /// Create a new instance of the BearerTokenService.
    pub fn new(config: Oauth2) -> Self {
        tracing::info!(
            "Initializing BearerTokenService with audience config: {:?}, roles_claim: {:?}",
            config.audience,
            config.rbac.roles_claim
        );
        let cache = JwksCache::new(config.jwks_url.clone());
        let roles_claim = config.rbac.roles_claim.clone();
        let role_permissions = config.rbac.compile();
        BearerTokenService {
            config,
            cache,
            roles_claim,
            role_permissions,
        }
    }
}

#[async_trait]
impl BearerTokenServiceTrait for BearerTokenService {
    /// Validate a bearer token string by validating it as a JWT using the configured JWKS.
    ///
    /// If JWKS validation fails (including missing jwks_url), this function returns an error
    /// which should be translated to HTTP 401 by the caller.
    ///
    /// If `audience` is configured in the Oauth2 config, the JWT's `aud` claim must contain
    /// at least one of the configured audience values.
    async fn validate_bearer_token(&self, token: &str) -> anyhow::Result<TokenInfo> {
        ensure!(!token.trim().is_empty(), anyhow!("unauthorized"));

        // Decode JWT header and extract kid
        let header = decode_header(token).map_err(|e| {
            tracing::debug!("Failed to decode JWT header: {}", e);
            anyhow!("unauthorized")
        })?;
        let kid = header.kid.as_ref().ok_or_else(|| {
            tracing::debug!("JWT missing kid header");
            anyhow!("unauthorized")
        })?;

        // Load JWKS (cached) and find JWK by kid.
        let jwk = match self.cache.get(kid).await {
            Ok(Some(key)) => key,
            Ok(None) => {
                tracing::debug!("JWK not found for kid: {}", kid);
                return Err(anyhow!("unauthorized"));
            }
            Err(err) => {
                tracing::error!("JWKS retrieval error: {}", err);
                return Err(anyhow!("unauthorized"));
            }
        };

        // Validate the token using the JWK decoding key.
        let mut validation = Validation::new(header.alg);
        if let Some(expected_audiences) = &self.config.audience {
            tracing::debug!(
                "Validating JWT with expected audiences: {:?}",
                expected_audiences
            );
            if !expected_audiences.is_empty() {
                validation.set_audience(expected_audiences);
                validation.validate_aud = true;
            } else {
                validation.validate_aud = false;
            }
        } else {
            validation.validate_aud = false;
        }

        let token_data = decode::<Claims>(token, &jwk.decoding_key, &validation).map_err(|e| {
            tracing::error!("JWT validation failed: {}", e);
            anyhow!("unauthorized")
        })?;
        let claims = token_data.claims;

        // Extract audience from claims
        let token_audience: Vec<String> = claims.aud.map(|a| a.to_vec()).unwrap_or_default();

        // Explicit check: If we have expected audiences, verify that the token actually has one.
        // Some JWT libraries might allow a missing 'aud' claim even when validate_aud=true if no required audiences are set.
        if let Some(expected) = &self.config.audience {
            if !expected.is_empty() && token_audience.is_empty() {
                tracing::error!("JWT validation failed: missing mandatory 'aud' claim");
                return Err(anyhow!("unauthorized"));
            }

            // Check that at least one of the configured expected audiences is present in the token.
            // This ensures tokens are explicitly issued for this service.
            let has_matching_audience = token_audience.iter().any(|token_aud| {
                expected
                    .iter()
                    .any(|expected_aud| token_aud == expected_aud)
            });

            if !has_matching_audience {
                tracing::error!(
                    "JWT validation failed: no matching audience found. Expected one of {:?}, got {:?}",
                    expected,
                    token_audience
                );
                return Err(anyhow!("unauthorized"));
            }

            tracing::debug!(
                "JWT audience validation passed. Expected: {:?}, Token: {:?}",
                expected,
                token_audience
            );
        }

        let roles = roles_from_claim(claims.extra.get(&self.roles_claim));
        let permissions = permissions_for_roles(&roles, &self.role_permissions);

        tracing::debug!(
            "JWT claims validated. Subject: {}, Audience: {:?}, Roles: {:?}, Permissions: {}",
            claims.sub,
            token_audience,
            roles,
            permissions.len()
        );

        Ok(TokenInfo {
            active: true,
            sub: claims.sub,
            exp: claims.exp,
            aud: token_audience,
            roles,
            permissions,
            access_token: token.to_string(),
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

    #[test]
    fn roles_from_array_claim() {
        let value = json!(["lightbridge-admin", "offline_access"]);
        assert_eq!(
            roles_from_claim(Some(&value)),
            vec![
                "lightbridge-admin".to_string(),
                "offline_access".to_string()
            ]
        );
    }

    #[test]
    fn roles_from_space_delimited_string_claim() {
        let value = json!("lightbridge-admin lightbridge-viewer");
        assert_eq!(
            roles_from_claim(Some(&value)),
            vec![
                "lightbridge-admin".to_string(),
                "lightbridge-viewer".to_string()
            ]
        );
    }

    #[test]
    fn roles_from_missing_or_wrong_type_claim_is_empty() {
        assert!(roles_from_claim(None).is_empty());
        assert!(roles_from_claim(Some(&json!(42))).is_empty());
        assert!(roles_from_claim(Some(&json!({"a": 1}))).is_empty());
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
        assert_eq!(mock.calls(), 1);

        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.calls(), 1);
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
        assert_eq!(mock.calls(), 1);

        assert!(cache.get(TEST_KID).await.unwrap().is_some());
        assert_eq!(mock.calls(), 2);
    }
}

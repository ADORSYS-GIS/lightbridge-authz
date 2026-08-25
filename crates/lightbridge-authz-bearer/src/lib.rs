use anyhow::{anyhow, ensure};
use authkestra_resource::jwt::{JwksCache, ValidationConfig, validate_jwt_generic};
use jsonwebtoken::{Algorithm, Validation, decode_header};
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::authz::{CompiledRbac, PermissionSet, permissions_for_roles};
use lightbridge_authz_core::config::Oauth2;
use lightbridge_authz_core::{Error, Permission};
use serde::Deserialize;
use serde_json::Value;
use std::{fmt, sync::Arc, time::Duration};

/// Claim name carrying the caller-kind signal (see [`API_KEY_CALLER_KIND`]). Custom (not a
/// standard OIDC claim) and namespaced like the existing `lightbridge_api_roles` roles claim, so
/// it cannot collide with an IdP's own claims.
pub const CALLER_KIND_CLAIM: &str = "lightbridge_caller_kind";

/// The [`CALLER_KIND_CLAIM`] value stamped onto a token minted for an API key, as opposed to a
/// human OIDC login. Under `oauth2.type: self` this repo's own [`ApiKeyJwtSigner`]
/// (`lightbridge-authz-rest::signing`) mints it unconditionally on every self-signed API-key JWT.
/// Under `oauth2.type: external` it must be minted by whatever IdP-side flow performs the API-key
/// token exchange (see `docs/rbac.md`'s "Self-service refill and the admin review queue" section)
/// -- this repo cannot mint it on the IdP's behalf, so callers authenticated under `external` do
/// not carry it until that flow is updated to stamp it.
pub const API_KEY_CALLER_KIND: &str = "api_key";

/// Token information returned by JWT validation.
#[derive(Clone, Deserialize)]
pub struct TokenInfo {
    pub active: bool,
    pub sub: String,
    /// The token's `iss` claim (ADR-0025 Stage 2). Extraction only, deliberately NOT enforced
    /// here: `BearerTokenService` is one shared instance per component, validating every bearer
    /// token that component ever sees regardless of which plane minted it -- a Keycloak-issued
    /// human OIDC token (`oauth2.type: external`, or the token-exchange grant's `subject_token`
    /// check under `type: self`) and a self-signed API-key JWT this service minted itself
    /// (`ApiKeyJwtSigner`, `oauth2.signing.issuer` -- deliberately OUR OWN issuer, not
    /// `oauth2.federation.issuer`) both flow through the SAME `validate_bearer_token` call site,
    /// keyed off the SAME `oauth2.jwks_url`. Enforcing `iss == oauth2.federation.issuer` here
    /// would refuse every self-signed-JWT deployment outright. Scoping enforcement to only the
    /// Keycloak-validated plane needs a caller-side signal this trait does not carry today (which
    /// `oauth2.type` produced the config this instance was built with, and/or which call site is
    /// asking) -- tracked as a follow-up; see ADR-0025's own "amends ADR-0011" section.
    pub iss: String,
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
    /// The [`CALLER_KIND_CLAIM`] value, if the token carries one. `None` means "unknown" -- most
    /// tokens today (every human OIDC login, and every `external`-mode token until the IdP-side
    /// exchange flow is updated) carry no such claim at all, so `None` must not be read as "not an
    /// API key"; it only means this signal is unavailable for this token. Callers that need to
    /// exclude API-key-derived tokens should compare against [`API_KEY_CALLER_KIND`] explicitly.
    #[serde(default)]
    pub caller_kind: Option<String>,
    #[serde(default)]
    pub access_token: String,
}

impl std::fmt::Debug for TokenInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenInfo")
            .field("active", &self.active)
            .field("sub", &self.sub)
            .field("iss", &self.iss)
            .field("exp", &self.exp)
            .field("aud", &self.aud)
            .field("roles", &self.roles)
            .field("permissions", &self.permissions)
            .field("caller_kind", &self.caller_kind)
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

    /// Whether this token was minted for an API key rather than a human OIDC login, per the
    /// [`CALLER_KIND_CLAIM`] claim. See that constant's docs for why the absence of the claim
    /// (the common case today) means "unknown", not "human".
    pub fn is_api_key_derived(&self) -> bool {
        self.caller_kind.as_deref() == Some(API_KEY_CALLER_KIND)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    sub: String,
    /// ADR-0025 Stage 2: extracted so [`TokenInfo::iss`] can carry it -- see that field's doc
    /// comment for why this codebase does not enforce it inside this service. Deliberately
    /// required (no `#[serde(default)]`), not `Option<String>`: every real token this service
    /// ever validates -- Keycloak-issued or self-signed -- carries an `iss` claim, so a token
    /// missing one is not a legitimate degraded case to tolerate. AGENTS.md's fail-closed rule
    /// applies here too: a missing claim is "unknown", and unknown routes to the strictest
    /// branch, which for a required field means deserialization itself fails the whole token,
    /// not a permissive default. See `missing_iss_is_rejected` in `token_validation_tests.rs` for
    /// the dedicated regression test.
    iss: String,
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

/// Default JWKS cache refresh interval, matching the previous hand-written cache's TTL.
///
/// `authkestra_resource::jwt::ValidationConfigBuilder` defaults to one hour when unset; we keep the
/// tighter five-minute interval this service shipped with so key rotation propagates promptly.
const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// JWT signing algorithms this service accepts. Fixed (rather than trusting the `alg` the
/// presented token's header claims, as the previous implementation did via
/// `Validation::new(header.alg)`) to avoid algorithm-confusion: an attacker-controlled header
/// must never select which verification algorithm is used. Keycloak (and every JWKS-backed RSA
/// issuer this service targets) signs with RS256.
const ACCEPTED_ALGORITHMS: [Algorithm; 1] = [Algorithm::RS256];

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
///
/// JWKS fetch/cache and JWT decode/verify are delegated to `authkestra_resource::jwt` (crate
/// `authkestra-resource`, published separately on crates.io — see the module docs below for why).
/// This service still owns: the `kid`-presence check (`authkestra`'s key lookup falls back to the
/// JWKS's first key when a token omits `kid`, which this service intentionally does not allow),
/// the accepted-algorithm allowlist, and the multi-value audience match (`authkestra`'s
/// `ValidationConfig::audience` only accepts a single expected value, but `oauth2.audience` here
/// is a list — see [`ValidationConfig`] docs upstream).
#[derive(Clone)]
pub struct BearerTokenService {
    config: Oauth2,
    cache: Arc<JwksCache>,
    /// JWT claim carrying the caller's roles.
    roles_claim: String,
    /// Precompiled role → permission map (wildcards already expanded), plus the compiled
    /// `default_grants` fallback applied to roles that match none of it.
    role_permissions: CompiledRbac,
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
        // `ValidationConfig` also exposes `.issuer()`/`.audience()` builder methods, but neither
        // is wired here: this service has never enforced `iss` (the JWKS URL itself is
        // realm-scoped), and `.audience()` only accepts a single expected value while
        // `oauth2.audience` is a list — so audience matching is done manually below, against
        // jsonwebtoken's own multi-value `set_audience`, exactly as before this migration.
        let validation_config = ValidationConfig::builder()
            .jwks_url(config.jwks_url.clone())
            .refresh_interval(DEFAULT_JWKS_CACHE_TTL)
            .algorithms(ACCEPTED_ALGORITHMS.to_vec())
            .build();
        let cache = Arc::new(JwksCache::new(
            validation_config.jwks_url,
            validation_config.refresh_interval,
        ));
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

        // Decode the JWT header ourselves first, purely to require a `kid`: authkestra_resource's
        // key lookup (`Jwks::find_key`) falls back to the JWKS's first key when `kid` is absent,
        // which this service does not allow (JWKS here may hold multiple keys during rotation).
        let header = decode_header(token).map_err(|e| {
            tracing::debug!("Failed to decode JWT header: {}", e);
            anyhow!("unauthorized")
        })?;
        if header.kid.is_none() {
            tracing::debug!("JWT missing kid header");
            return Err(anyhow!("unauthorized"));
        }

        let mut validation = Validation::new(ACCEPTED_ALGORITHMS[0]);
        validation.algorithms = ACCEPTED_ALGORITHMS.to_vec();
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

        // JWKS fetch/cache + kid lookup + signature/exp verification, delegated to
        // authkestra_resource::jwt::validate_jwt_generic. Any failure (network, missing key,
        // signature, expiry) is folded into a uniform "unauthorized" so callers never see which
        // step failed, matching this service's existing security posture.
        let claims: Claims = validate_jwt_generic(token, &self.cache, &validation)
            .await
            .map_err(|e| {
                tracing::error!("JWT validation failed: {}", e);
                anyhow!("unauthorized")
            })?;

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
        let caller_kind = claims
            .extra
            .get(CALLER_KIND_CLAIM)
            .and_then(Value::as_str)
            .map(str::to_owned);

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
            iss: claims.iss,
            exp: claims.exp,
            aud: token_audience,
            roles,
            permissions,
            caller_kind,
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

    #[test]
    fn audience_default_is_empty() {
        assert!(Audience::default().to_vec().is_empty());
    }

    #[test]
    fn audience_to_vec_variants() {
        assert_eq!(
            Audience::Single("a".to_string()).to_vec(),
            vec!["a".to_string()]
        );
        assert_eq!(
            Audience::Multiple(vec!["a".to_string(), "b".to_string()]).to_vec(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    /// Exercises the real `authkestra_resource::jwt::JwksCache` (this crate no longer hand-rolls
    /// its own cache), preserving the coverage the previous hand-written cache had.
    #[tokio::test]
    async fn cache_reuses_jwks_within_ttl() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.header("content-type", "application/json")
                .status(200)
                .body(jwks_body());
        });

        let cache = JwksCache::new(server.url("/jwks"), Duration::from_secs(60));
        assert!(cache.get_key(Some(TEST_KID)).await.unwrap().is_some());
        assert_eq!(mock.calls(), 1);

        assert!(cache.get_key(Some(TEST_KID)).await.unwrap().is_some());
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

        let cache = JwksCache::new(server.url("/jwks"), Duration::from_secs(0));
        assert!(cache.get_key(Some(TEST_KID)).await.unwrap().is_some());
        assert_eq!(mock.calls(), 1);

        assert!(cache.get_key(Some(TEST_KID)).await.unwrap().is_some());
        assert_eq!(mock.calls(), 2);
    }

    /// The service must reject tokens with no `kid` header before ever consulting the JWKS
    /// cache, because `authkestra_resource`'s own key lookup falls back to the JWKS's first key
    /// when `kid` is absent (see `Jwks::find_key`) rather than rejecting outright.
    #[tokio::test]
    async fn missing_kid_falls_back_to_first_key_in_authkestra_but_this_service_rejects_it() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.header("content-type", "application/json")
                .status(200)
                .body(jwks_body());
        });

        let cache = JwksCache::new(server.url("/jwks"), Duration::from_secs(60));
        // Demonstrates the upstream fallback this service's explicit kid check guards against.
        assert!(cache.get_key(None).await.unwrap().is_some());
        assert_eq!(mock.calls(), 1);
    }
}

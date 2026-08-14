use std::collections::HashMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::token::TokenManager;
use authkestra_op::config::OpConfig;
use authkestra_op::handlers::discovery::OidcDiscovery;
use authkestra_op::handlers::jwks::JwksResponse;
use axum::{
    Json, Router,
    http::{Method, StatusCode},
    routing::get,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::JwtSigning;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use rand_core::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower_http::cors::{Any, CorsLayer};

const RSA_KEY_BITS: usize = 2048;
const ALGORITHM: &str = "RS256";
const TOKEN_TYP: &str = "Bearer";
const TOKEN_SCOPE: &str = "profile email";

/// [`Identity::provider_id`] stamped on every derived identity this signer mints. This service
/// never authenticates anyone itself (ADR-0011, Context) -- every identity here is a snapshot of
/// an upstream Keycloak login, so the provider is always Keycloak regardless of `oauth2.type`.
const IDENTITY_PROVIDER_ID: &str = "keycloak";

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
    let now = Utc::now();
    let cutoff = now - Duration::days(cfg.max_key_age_days.max(1));
    let candidate = generate_rs256_key()?.into_candidate(now);
    let active = repo.ensure_active_signing_key(candidate, cutoff).await?;
    tracing::info!(kid = %active.kid, "active api-key signing key ready");
    Ok(())
}

/// Computes the OIDC Core §3.1.3.6 `at_hash`: SHA-256 the access token's ASCII octets (SHA-256
/// because the signing algorithm here is always RS256), take the left-most half of the digest,
/// base64url-encode it without padding. Binds an `id_token` to the `access_token` minted
/// alongside it in the same response -- `authkestra_engine::token::TokenManager` does not compute
/// this itself (ADR-0011, Decision 7), so it is supplied via `extra`.
pub fn compute_at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    let half = &digest[..digest.len() / 2];
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half)
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

/// Identity of the human who created or rotated the key, snapshotted into the issued JWT so the
/// token mirrors a Keycloak access token. Captured at issuance from the creator's bearer token;
/// frozen for the token's TTL and refreshed on rotation.
#[derive(Debug, Clone, Default)]
pub struct KeyOwner {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
}

/// A freshly signed API-key JWT and the expiry stamped into it.
pub struct SignedApiKey {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Resolves the JWT `exp` for an issued key. `ttl_seconds` is both the default lifetime (when the
/// frontend requests no expiry) and the hard cap: a requested expiry beyond `now + ttl_seconds` is
/// clamped down to it. A requested expiry at or before `now` is ignored (defaults to the cap) so a
/// malformed request can never mint a dead-on-arrival token.
pub fn capped_expiry(
    now: DateTime<Utc>,
    ttl_seconds: i64,
    requested: Option<DateTime<Utc>>,
) -> DateTime<Utc> {
    let cap = now + Duration::seconds(ttl_seconds);
    match requested {
        Some(requested) if requested > now => requested.min(cap),
        _ => cap,
    }
}

/// Builds the `Identity` every derived token (access or id) is minted for. `sub`/`email` are
/// upstream snapshots -- never re-minted (ADR-0011, Context and Decision 7).
fn identity_for(owner: &KeyOwner) -> Identity {
    Identity {
        provider_id: IDENTITY_PROVIDER_ID.to_string(),
        external_id: owner.subject.clone(),
        email: owner.email.clone(),
        username: None,
        attributes: HashMap::new(),
    }
}

impl ApiKeyJwtSigner {
    /// Builds a signer from the `signing` config (only reached under `oauth2.type: self`). Errors
    /// on invalid config (fail-fast at startup). Key material lives in the DB, not config.
    pub fn from_config(cfg: &JwtSigning, repo: Arc<StoreRepo>) -> Result<Self> {
        if cfg.issuer.trim().is_empty() {
            return Err(Error::Server(
                "oauth2.signing.issuer is required for oauth2.type: self".to_string(),
            ));
        }
        if cfg.ttl_seconds <= 0 {
            return Err(Error::Server(format!(
                "oauth2.signing.ttl_seconds must be positive, got {}",
                cfg.ttl_seconds
            )));
        }
        Ok(Self {
            repo,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            ttl_seconds: cfg.ttl_seconds,
        })
    }

    /// Fetches the active signing key and builds a `TokenManager` from it. Shared by both
    /// `sign` and `sign_id_token` so both tokens in a token-exchange response are always signed
    /// by the same key, and so key rotation is picked up per-call exactly as the previous
    /// hand-rolled `jsonwebtoken::encode` path did.
    async fn token_manager(&self) -> Result<TokenManager> {
        let active = self
            .repo
            .get_active_signing_key()
            .await?
            .ok_or_else(|| Error::Server("no active api-key signing key".to_string()))?;
        TokenManager::new_asymmetric(
            active.private_key_pem.as_bytes(),
            Some(self.issuer.clone()),
            Some(active.kid),
        )
        .map_err(|e| Error::Server(format!("invalid stored signing key: {e}")))
    }

    /// Signs an API-key JWT with the current active key for the given key/project/account. `owner`
    /// supplies the creator's Keycloak `sub` and (optionally) email, mirroring a Keycloak token.
    /// `requested_expires_at` is the frontend-requested expiry; the stamped `exp` is
    /// `min(now + ttl_seconds, requested_expires_at)`, defaulting to `now + ttl_seconds`.
    ///
    /// Signing itself goes through `authkestra_engine::token::TokenManager::issue_user_token_with_extra`
    /// (ADR-0011, Decision 2) rather than hand-rolled `jsonwebtoken::encode`. Every claim this
    /// service minted before (`typ`, `azp`, `lightbridge_caller_kind`, `sid`, `api_key_id`,
    /// `project_id`, `account_id`, `email`, `email_verified`, `allowed_models`) is preserved
    /// byte-for-byte via `extra`, with the same `skip_serializing_if`-style omission (simply not
    /// inserting the key when the value is absent). `TokenManager` itself unconditionally adds two
    /// claims this signer never emitted before -- `nbf` and a nested `identity` object mirroring
    /// `sub`/`email` -- and mints `jti` as a UUIDv4 rather than this repo's `lgbr:`-prefixed
    /// CUID2. Both are documented, deliberate consequences of adopting `TokenManager` as ADR-0011
    /// Decision 2 mandates; see `crates/lightbridge-authz-rest/tests/signing_tests.rs`'s
    /// `new_signer_claim_set_is_a_documented_superset_of_the_old_signer` for the exact diff this
    /// was verified against, and the ADR-0011 phase-1 PR description for why `jti` could not be
    /// held to the AGENTS.md "every minted id is CUID2" rule here (`extra` cannot cleanly override
    /// `jti`: it collides with `Claims`' own top-level field and produces a JWT payload with a
    /// duplicate `jti` key, which is technically-malformed JSON even though `serde_json` happens
    /// to take last-wins on decode).
    #[allow(clippy::too_many_arguments)]
    pub async fn sign(
        &self,
        owner: &KeyOwner,
        api_key_id: &str,
        project_id: &str,
        account_id: &str,
        allowed_models: Option<Vec<String>>,
        now: DateTime<Utc>,
        requested_expires_at: Option<DateTime<Utc>>,
    ) -> Result<SignedApiKey> {
        let manager = self.token_manager().await?;
        let expires_at = capped_expiry(now, self.ttl_seconds, requested_expires_at);
        // `TokenManager` computes `iat`/`nbf`/`exp` from its own internal `chrono::Utc::now()`
        // call rather than accepting an injected `now`, so only the duration survives the crossing
        // -- `exp` on the wire will be a few microseconds later than `expires_at` below, which is
        // still computed from our own `now` for the response's `expires_in` and for callers that
        // persist it. Functionally immaterial (no test here asserts `exp` to sub-second precision),
        // called out because it is a real, if tiny, behavior change from the previous
        // single-`now`-for-everything implementation.
        let expires_in_secs = (expires_at - now).num_seconds().max(0) as u64;

        let mut extra = HashMap::new();
        extra.insert("typ".to_string(), Value::String(TOKEN_TYP.to_string()));
        if let Some(azp) = self.audience.as_deref() {
            extra.insert("azp".to_string(), Value::String(azp.to_string()));
        }
        extra.insert(
            "lightbridge_caller_kind".to_string(),
            Value::String(lightbridge_authz_bearer::API_KEY_CALLER_KIND.to_string()),
        );
        extra.insert("sid".to_string(), Value::String(cuid2()));
        extra.insert(
            "api_key_id".to_string(),
            Value::String(api_key_id.to_string()),
        );
        extra.insert(
            "project_id".to_string(),
            Value::String(project_id.to_string()),
        );
        extra.insert(
            "account_id".to_string(),
            Value::String(account_id.to_string()),
        );
        if let Some(email) = owner.email.as_deref() {
            extra.insert("email".to_string(), Value::String(email.to_string()));
        }
        if let Some(verified) = owner.email_verified {
            extra.insert("email_verified".to_string(), Value::Bool(verified));
        }
        if let Some(models) = allowed_models {
            extra.insert(
                "allowed_models".to_string(),
                Value::Array(models.into_iter().map(Value::String).collect()),
            );
        }

        let token = manager
            .issue_user_token_with_extra(
                identity_for(owner),
                expires_in_secs,
                Some(TOKEN_SCOPE.to_string()),
                self.audience.clone(),
                extra,
            )
            .map_err(|e| Error::Server(format!("api-key signing failed: {e}")))?;
        tracing::info!(
            api_key_id = %api_key_id,
            project_id = %project_id,
            account_id = %account_id,
            exp = expires_at.timestamp(),
            "issued api-key jwt"
        );
        Ok(SignedApiKey { token, expires_at })
    }

    /// Issues a derived `id_token` (ADR-0011, Decisions 1 and 7) via
    /// `TokenManager::issue_id_token_with_extra`. Only ever called from the token-exchange grant
    /// when the granted scope set includes `openid` -- never from the CRUD API-key issuance path,
    /// which has no OIDC `id_token` concept.
    ///
    /// Claim-by-claim provenance, matching ADR-0011 Decision 7 exactly:
    /// - `iss`/`sub`/`aud`/`exp`/`iat` are set by `TokenManager` itself. `sub` is `owner.subject`,
    ///   the upstream `subject_token`'s own `sub` -- never re-minted.
    /// - `nonce` is the dedicated parameter, merged by `TokenManager` only when `Some`; pass `None`
    ///   to omit it. Callers must not synthesize one.
    /// - `auth_time` is supplied via `extra` only when `Some`, so it is omitted (never defaulted to
    ///   "now") when the upstream token carried none.
    /// - `email`/`email_verified` are upstream snapshots, mirroring the access token.
    /// - `at_hash` is computed by the caller (see `compute_at_hash`) over the access token minted
    ///   alongside this id_token in the same response, and passed in via `extra`.
    /// - `azp` is `self.audience` -- the only "client" concept this phase has (ADR-0011 Decision 5,
    ///   a real per-client audience, is out of scope until phase 2).
    ///
    /// Tenant context (`api_key_id`/`project_id`/`account_id`) and role/quota data never appear on
    /// the id_token, matching ADR-0011 Decision 7's "not a second home for authorization data".
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_id_token(
        &self,
        owner: &KeyOwner,
        access_token: &str,
        auth_time: Option<i64>,
        nonce: Option<String>,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<String> {
        let client_id = self.audience.as_deref().ok_or_else(|| {
            Error::Server("oauth2.signing.audience is required to issue an id_token".to_string())
        })?;
        let manager = self.token_manager().await?;
        let expires_in_secs = (expires_at - now).num_seconds().max(0) as u64;

        let mut extra = HashMap::new();
        if let Some(email) = owner.email.as_deref() {
            extra.insert("email".to_string(), Value::String(email.to_string()));
        }
        if let Some(verified) = owner.email_verified {
            extra.insert("email_verified".to_string(), Value::Bool(verified));
        }
        if let Some(auth_time) = auth_time {
            extra.insert("auth_time".to_string(), Value::from(auth_time));
        }
        extra.insert("azp".to_string(), Value::String(client_id.to_string()));
        extra.insert(
            "at_hash".to_string(),
            Value::String(compute_at_hash(access_token)),
        );

        manager
            .issue_id_token_with_extra(
                identity_for(owner),
                client_id,
                nonce,
                expires_in_secs,
                extra,
            )
            .map_err(|e| Error::Server(format!("id token signing failed: {e}")))
    }
}

/// Converts the raw JSON JWKs this service stores (`signing_keys.public_jwk`) into
/// `authkestra_engine::token::jwk::Jwk` for `JwksResponse`. Deliberately tolerant of a key that
/// fails to parse (skips it rather than failing the whole response) -- every key here was minted
/// by `generate_rs256_key` in this same process, so a parse failure would indicate stored-data
/// corruption, not a normal runtime condition worth a hard 500 on every other, still-good key.
fn to_jwks(raw: Vec<Value>) -> Vec<authkestra_engine::token::jwk::Jwk> {
    raw.into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect()
}

/// Builds the OIDC discovery document via `authkestra_op::handlers::discovery::OidcDiscovery`
/// (ADR-0011, Decision 9) rather than the previous hand-built `serde_json::json!`. `OidcDiscovery`
/// models a full OP (authorization_code + device flows included), which this service structurally
/// never runs (ADR-0011, Context -- no user store, no login flow) -- `authorization_endpoint`
/// is therefore a required-but-unreachable URL (the type has no way to omit it), mitigated by
/// `response_types_supported` never advertising `"code"`, so no spec-compliant client has a reason
/// to call it. `userinfo_endpoint` is genuinely optional on the type and is nulled out below,
/// since this service does not serve one.
///
/// `token_endpoint_auth_methods_supported` is set explicitly to `["none"]`, not
/// `OidcDiscovery::from_config`'s default (`client_secret_basic`/`client_secret_post`/`none`) --
/// this service never accepts secret-based client auth, and phase 1 (this ADR) does not yet
/// authenticate clients at all (that is Decision 6/Decision 3, phase 2).
fn discovery_document(issuer: &str, token_exchange_scopes: Option<&[String]>) -> serde_json::Value {
    let enabled = token_exchange_scopes.is_some();
    let scopes_supported = token_exchange_scopes
        .map(<[String]>::to_vec)
        .unwrap_or_default();
    let (response_types_supported, grant_types_supported) = if enabled {
        (
            vec![
                "token".to_string(),
                "id_token".to_string(),
                "id_token token".to_string(),
            ],
            vec![
                crate::token_exchange::TOKEN_EXCHANGE_GRANT.to_string(),
                crate::token_exchange::REFRESH_TOKEN_GRANT.to_string(),
            ],
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let op_config = OpConfig {
        issuer: issuer.to_string(),
        scopes_supported,
        response_types_supported,
        grant_types_supported,
        id_token_signing_alg: ALGORITHM.to_string(),
        authorization_code_ttl_secs: 0,
        access_token_ttl_secs: 0,
        device_code_ttl_secs: 0,
        token_exchange_enabled: enabled,
    };

    let mut doc = OidcDiscovery::from_config(&op_config);
    doc.jwks_uri = format!("{issuer}/.well-known/jwks.json");
    doc.token_endpoint = format!("{issuer}/oauth2/token");
    doc.userinfo_endpoint = None;
    doc.response_modes_supported = Vec::new();
    doc.token_endpoint_auth_methods_supported = vec!["none".to_string()];
    doc.claims_supported = [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "typ",
        "azp",
        "lightbridge_caller_kind",
        "sid",
        "scope",
        "api_key_id",
        "project_id",
        "account_id",
        "email",
        "email_verified",
        "allowed_models",
        "identity",
        "nonce",
        "auth_time",
        "at_hash",
    ]
    .into_iter()
    .map(String::from)
    .collect();

    serde_json::to_value(&doc).unwrap_or_else(|_| serde_json::json!({ "issuer": issuer }))
}

/// Public OIDC discovery + JWKS routes for Authorino's `jwt` identity. JWKS is served live from
/// the DB (active + stale keys) so tokens signed by a rotated-out key keep verifying until they
/// expire. Stateless w.r.t. axum state, so it merges into any router. CORS is wide-open (any
/// origin, GET) because these are public, non-secret discovery documents — browser-based OIDC
/// clients must be able to fetch them cross-origin, as any standard OIDC provider allows.
///
/// `token_exchange_scopes` is `Some(allowed_scopes)` when the token-exchange grant is enabled
/// (`oauth2.token_exchange.enabled`), `None` when it is off. Because `OidcDiscovery`'s
/// `token_endpoint`/`grant_types_supported`/`response_types_supported` fields are not all
/// `Option` (unlike the previous hand-built document, which omitted `token_endpoint` entirely when
/// disabled), the disabled case now advertises a `token_endpoint` URL with empty
/// `grant_types_supported`/`response_types_supported` instead of omitting the field -- see
/// `discovery_document`'s doc comment.
pub fn well_known_router<S>(
    issuer: &str,
    repo: Arc<StoreRepo>,
    token_exchange_scopes: Option<Vec<String>>,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let discovery_issuer = issuer.to_string();
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET]);
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let issuer = discovery_issuer.clone();
                let scopes = token_exchange_scopes.clone();
                async move { Json(discovery_document(&issuer, scopes.as_deref())) }
            }),
        )
        .route(
            "/.well-known/jwks.json",
            get(move || {
                let repo = repo.clone();
                async move {
                    match repo.list_verification_jwks().await {
                        Ok(keys) => (
                            StatusCode::OK,
                            Json(
                                serde_json::to_value(JwksResponse::new(to_jwks(keys)))
                                    .unwrap_or_else(|_| serde_json::json!({ "keys": [] })),
                            ),
                        ),
                        Err(_) => (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({ "keys": [] })),
                        ),
                    }
                }
            }),
        )
        .layer(cors)
}

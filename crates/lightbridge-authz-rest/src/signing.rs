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
/// upstream snapshots -- never re-minted (ADR-0011, Context and Decision 7). `attributes` starts
/// empty here; `oauth2_op`'s refresh-token store uses it as the only extension point
/// `authkestra_op::refresh::RefreshToken` offers to round-trip `account_id`/`project_id` (which
/// have no dedicated field on `Identity`) through the `RefreshTokenStore` trait boundary -- see
/// that module for the full round trip.
pub(crate) fn identity_for(owner: &KeyOwner) -> Identity {
    Identity {
        provider_id: IDENTITY_PROVIDER_ID.to_string(),
        external_id: owner.subject.clone(),
        email: owner.email.clone(),
        username: None,
        attributes: HashMap::new(),
    }
}

/// Builds the `extra` claim map every minted *access* token carries, shared between the plain
/// CRUD API-key signer ([`ApiKeyJwtSigner::sign`]) and the token-exchange grant
/// (`oauth2_op::store`) -- the two differ only in `azp` (a fixed `oauth2.signing.audience` for the
/// former, the authenticated client's `client_id` for the latter) and in the `api_key_id`/`sid`
/// values each supplies. See [`ApiKeyJwtSigner::sign`]'s doc comment for the full claim-by-claim
/// provenance; this is that same set, factored out so it is defined exactly once.
pub(crate) fn access_token_extra(
    owner: &KeyOwner,
    api_key_id: &str,
    project_id: &str,
    account_id: &str,
    allowed_models: Option<Vec<String>>,
    azp: Option<&str>,
) -> HashMap<String, Value> {
    let mut extra = HashMap::new();
    extra.insert("typ".to_string(), Value::String(TOKEN_TYP.to_string()));
    if let Some(azp) = azp {
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
    extra
}

/// Builds the `extra` claim map every derived `id_token` carries (ADR-0011, Decision 7):
/// `email`/`email_verified` upstream snapshots, `auth_time` propagated only when the upstream
/// token carried one (never defaulted to "now"), `azp` naming the client the tokens were issued
/// to, and `at_hash` binding this `id_token` to the `access_token` minted alongside it in the same
/// response. Tenant context (`api_key_id`/`project_id`/`account_id`) and role/quota data never
/// appear here -- see [`compute_at_hash`].
pub(crate) fn id_token_extra(
    owner: &KeyOwner,
    access_token: &str,
    auth_time: Option<i64>,
    azp: &str,
) -> HashMap<String, Value> {
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
    extra.insert("azp".to_string(), Value::String(azp.to_string()));
    extra.insert(
        "at_hash".to_string(),
        Value::String(compute_at_hash(access_token)),
    );
    extra
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

    /// Fetches the active signing key and builds a `TokenManager` from it. Used by `sign` for the
    /// plain CRUD API-key issuance path, and by `oauth2_op`'s axum handler (via
    /// `TokenExchangeState::token_manager`) to build the single `TokenManager` a whole
    /// token-exchange request shares -- `authkestra_op::handlers::token::handle_token` takes one
    /// `&TokenManager` per call, and the exchange/refresh grant overrides mint both the access and
    /// id token from it, so both tokens in a response are always signed by the same key. Key
    /// rotation is picked up per-call exactly as the previous hand-rolled `jsonwebtoken::encode`
    /// path did. `pub(crate)` rather than private: `oauth2_op` lives in this crate but a different
    /// module.
    pub(crate) async fn token_manager(&self) -> Result<TokenManager> {
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

        let extra = access_token_extra(
            owner,
            api_key_id,
            project_id,
            account_id,
            allowed_models,
            self.audience.as_deref(),
        );

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
/// `token_endpoint_auth_methods_supported` is set explicitly to `["none"]`, plus `private_key_jwt`
/// when `private_key_jwt_supported` (at least one registered client is `confidential` -- ADR-0011
/// Decision 6/9) -- never `OidcDiscovery::from_config`'s default (`client_secret_basic`/
/// `client_secret_post`/`none`), since this service never accepts secret-based client auth at all.
///
/// `authorization_endpoint` is dropped from the serialized document entirely (ADR-0011 Decision 9,
/// item 8): `OidcDiscovery`'s field is a required `String` with no way to omit it via the type
/// itself, but this service never serves `/authorize` (no authorization_code flow -- ADR-0011
/// Context) and `response_types_supported` never advertises `"code"`, so publishing a URL for it
/// would promise a capability nothing here provides.
///
/// `token_endpoint` is dropped the same way when `token_exchange_scopes` is `None`
/// (`oauth2.token_exchange.enabled` is off, or the deployment's config never wired the block at
/// all -- both collapse to the same "no grants served" state upstream, since
/// `build_token_exchange_state` never mounts `POST /oauth2/token` in that case either). Advertising
/// a live-looking `token_endpoint` next to empty `grant_types_supported`/`scopes_supported` is
/// exactly what the hand-built document this replaced (ADR-0011, Decision 9) never did -- it
/// omitted `token_endpoint` outright when the feature was off, and a spec-reading client seeing a
/// URL with nothing behind it is worse than seeing no URL at all. Restored here.
///
/// `grant_types_supported`/`response_types_supported`/`scopes_supported` themselves stay legitimately
/// empty arrays (not also dropped) in the disabled case -- OIDC discovery treats these as always-
/// present metadata (RFC 8414 §2), and an empty array is the honest way to say "no grants offered",
/// same as any OP that structurally serves none. They are **not** hardcoded to advertise
/// token-exchange support regardless of config: this service genuinely does not accept any grant at
/// `/oauth2/token` when `token_exchange_scopes` is `None`, since the route is not mounted at all
/// (see `build_token_exchange_state`) -- advertising the grant anyway would be inventing a
/// capability this deployment does not have.
fn discovery_document(
    issuer: &str,
    token_exchange_scopes: Option<&[String]>,
    private_key_jwt_supported: bool,
) -> serde_json::Value {
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
    // `response_modes_supported` is unconditionally empty regardless of `enabled`: response modes
    // (`query`/`fragment`/`form_post`) describe how an authorization *response* is delivered back
    // to a browser redirect URI. This service never redirects a user-agent at all -- the
    // token-exchange grant is a direct machine-to-machine POST/response, not a redirect flow -- so
    // no response mode ever applies, on or off. `from_config` defaults this to `["query"]`
    // (appropriate for the authorization_code flow it also models), which would misrepresent a
    // capability this service never had regardless of token-exchange config.
    doc.response_modes_supported = Vec::new();
    doc.token_endpoint_auth_methods_supported = if private_key_jwt_supported {
        vec!["none".to_string(), "private_key_jwt".to_string()]
    } else {
        vec!["none".to_string()]
    };
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

    let mut value =
        serde_json::to_value(&doc).unwrap_or_else(|_| serde_json::json!({ "issuer": issuer }));
    if let Some(obj) = value.as_object_mut() {
        obj.remove("authorization_endpoint");
        if !enabled {
            obj.remove("token_endpoint");
        }
    }
    value
}

/// Public OIDC discovery + JWKS routes for Authorino's `jwt` identity. JWKS is served live from
/// the DB (active + stale keys) so tokens signed by a rotated-out key keep verifying until they
/// expire. Stateless w.r.t. axum state, so it merges into any router. CORS is wide-open (any
/// origin, GET) because these are public, non-secret discovery documents — browser-based OIDC
/// clients must be able to fetch them cross-origin, as any standard OIDC provider allows.
///
/// `token_exchange_scopes` is `Some(allowed_scopes)` when the token-exchange grant is enabled
/// (`oauth2.token_exchange.enabled`), `None` when it is off (including when the whole
/// `oauth2.token_exchange` block is absent from config, which deserializes to `None` the same
/// way). `discovery_document` drops `token_endpoint` from the disabled document entirely, matching
/// the previous hand-built document -- see its doc comment for the full rationale.
pub fn well_known_router<S>(
    issuer: &str,
    repo: Arc<StoreRepo>,
    token_exchange_scopes: Option<Vec<String>>,
    private_key_jwt_supported: bool,
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
                async move {
                    Json(discovery_document(
                        &issuer,
                        scopes.as_deref(),
                        private_key_jwt_supported,
                    ))
                }
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

use std::collections::HashMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_engine::token::TokenManager;
use authkestra_op::attestation::parse_public_jwk;
use authkestra_op::handlers::jwks::JwksResponse;
use axum::{
    Json, Router,
    http::{Method, StatusCode},
    routing::get,
};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
use lightbridge_authz_api_key::entities::signing_key_row::NewSigningKey;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::{JwtSigning, Oauth2, OauthClientType};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use rand_core::OsRng;
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
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

/// Client-authentication capabilities actually accepted by the mounted token and revocation
/// endpoints. This is derived from the static client registry so metadata cannot advertise a
/// method for which no configured client can authenticate.
#[derive(Debug, Clone, Default)]
pub struct ClientAuthenticationMetadata {
    methods: Vec<String>,
    signing_algorithms: Vec<String>,
}

/// Protocol routes mounted alongside the discovery document.
///
/// Discovery is a statement about the router assembled for this process, not about every grant a
/// configured client could theoretically request. Keeping these route facts separate from the
/// client registry prevents a configuration-only change from advertising an unmounted endpoint.
/// authz-idp's production call site always passes [`DiscoveryCapabilities::full_idp`] -- it is a
/// full IdP, so every flow route `build_idp_router` mounts is unconditional, and its discovery
/// document describes all of them unconditionally too. The other named constructors remain because
/// `well_known_router` stays generic over callers that mount less.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscoveryCapabilities {
    token_endpoint: bool,
    device_authorization_endpoint: bool,
    authorization_endpoint: bool,
}

impl DiscoveryCapabilities {
    /// The token and revocation routes are mounted, with no browser-facing flow routes.
    pub const fn token_surface() -> Self {
        Self {
            token_endpoint: true,
            device_authorization_endpoint: false,
            authorization_endpoint: false,
        }
    }

    /// The RFC 8628 device-authorization route is mounted with the token surface.
    pub const fn with_device_authorization(mut self) -> Self {
        self.device_authorization_endpoint = true;
        self
    }

    /// The browser-facing authorization-code route is mounted with the token surface.
    pub const fn with_authorization_code(mut self) -> Self {
        self.authorization_endpoint = true;
        self
    }

    /// Every flow route build_idp_router mounts. authz-idp is a full IdP: the token,
    /// revocation, device-authorization and browser /authorize routes are all mounted
    /// unconditionally, so its discovery document describes all of them unconditionally too.
    /// Kept as a named constructor rather than deleting DiscoveryCapabilities outright: this
    /// type is what keeps the document a statement about the assembled route table instead of
    /// about configuration intent (see the struct's own doc comment), and well_known_router
    /// remains generic over callers that mount less.
    pub const fn full_idp() -> Self {
        Self::token_surface()
            .with_device_authorization()
            .with_authorization_code()
    }
}

impl ClientAuthenticationMetadata {
    /// Derives supported client-authentication methods from the configured client registry.
    pub fn from_oauth2(oauth2: &Oauth2) -> Self {
        let public_client_registered = oauth2
            .clients
            .iter()
            .any(|client| client.client_type == OauthClientType::Public);
        let mut seen_algorithms = std::collections::HashSet::new();
        let signing_algorithms: Vec<String> = oauth2
            .clients
            .iter()
            .filter(|client| client.client_type == OauthClientType::Confidential)
            .filter_map(|client| client.jwks.as_ref())
            .filter_map(|jwks| jwks.get("keys").and_then(Value::as_array))
            .flat_map(|keys| keys.iter())
            .filter_map(|jwk| parse_public_jwk(jwk).ok())
            .flat_map(|jwk| client_assertion_algorithms(&jwk.algorithm))
            .map(str::to_string)
            .filter(|algorithm| seen_algorithms.insert(algorithm.clone()))
            .collect();

        let mut methods = Vec::new();
        if public_client_registered {
            methods.push("none".to_string());
        }
        if !signing_algorithms.is_empty() {
            methods.push("private_key_jwt".to_string());
        }

        Self {
            methods,
            signing_algorithms,
        }
    }

    /// Public-client metadata for route-level discovery tests.
    pub fn public_client() -> Self {
        Self {
            methods: vec!["none".to_string()],
            signing_algorithms: Vec::new(),
        }
    }

    /// Confidential-client metadata for route-level discovery tests.
    pub fn private_key_jwt(signing_algorithms: Vec<String>) -> Self {
        Self {
            methods: vec!["private_key_jwt".to_string()],
            signing_algorithms,
        }
    }
}

fn client_assertion_algorithms(algorithm: &AlgorithmParameters) -> Vec<&'static str> {
    match algorithm {
        AlgorithmParameters::RSA(_) => vec!["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => vec!["ES256"],
            EllipticCurve::P384 => vec!["ES384"],
            _ => Vec::new(),
        },
        AlgorithmParameters::OctetKeyPair(params) => match params.curve {
            EllipticCurve::Ed25519 => vec!["EdDSA"],
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

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
///
/// ## Signing-key ownership (ADR-0012, "signing-key bootstrap")
///
/// Three services now call this function at startup: `authz-api` (`start_api_server`),
/// `lightbridge-mcp`, and, since ADR-0012 Phase 1, `authz-idp` (`start_idp_server`). All three
/// bootstrap rather than only read — deliberately: an `authz-idp` that only ever *read* the
/// active key (via [`StoreRepo::get_active_signing_key`]) would depend on some other service
/// having bootstrapped one first, an implicit startup-ordering dependency this repo does not
/// otherwise have between its services. Bootstrapping independently means `authz-idp` (like
/// `authz-api` and `lightbridge-mcp` today) can cold-start against an empty `signing_keys` table
/// on its own.
///
/// **Why a third concurrent bootstrapper is exactly as safe as the two that already exist.**
/// This function's only DB-mutating call, [`StoreRepo::ensure_active_signing_key`], takes a
/// transaction-scoped `pg_advisory_xact_lock` before it ever reads or writes `signing_keys` (see
/// that function's own doc comment) — every caller serializes on the same lock regardless of how
/// many there are. The first caller to acquire it inserts the key and commits; every other
/// caller, whether it arrived a microsecond later or was already blocked on the lock, observes
/// the just-inserted row as `active`, decides `needs_rotation == false`, and returns it unchanged.
/// This holds identically for two callers or three (or more) — the lock, not the caller count, is
/// what guarantees exactly one active key. See
/// `concurrent_bootstraps_from_multiple_services_produce_exactly_one_active_key`
/// (`tests/signing_tests.rs`) for the proof against a real database with three concurrent callers.
///
/// **What happens if services disagree on `max_key_age_days`.** Each caller computes its own
/// rotation cutoff from its own `cfg.max_key_age_days` before taking the lock (see this
/// function's body). If `authz-idp` is configured with a shorter value than `authz-api`,
/// `authz-idp`'s check can decide `needs_rotation == true` earlier than `authz-api`'s would have
/// on its own — but because rotation itself is still gated by the same advisory lock, this only
/// changes *when* the next rotation happens, never whether more than one key ends up active.
/// Disagreement is a rotation-*cadence* imprecision (a key might retire a few days earlier or
/// later than any single service's own config alone would suggest), not a correctness hazard —
/// there is no interleaving of any number of differently-configured callers that produces two
/// simultaneously active keys. Operationally, this repo's Compose stack sidesteps the question
/// entirely: `authz-api`, `authz-opa`, `authz-mcp`, and `authz-idp` all mount the *same*
/// `.docker/authz/container.yaml` (`compose.yaml`), so `oauth2.signing.max_key_age_days` is
/// always one value, not three. A deployment that ever does split this config per service
/// inherits the cadence-only consequence above, not a safety one.
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
///
/// ADR-0025 Stage 3: `subject` and `account_id` are deliberately BOTH carried, and deliberately
/// NOT the same field -- `subject` is the raw upstream claim, kept only as a log/email-resolution
/// surface (it is never minted into the token itself any more); `account_id` is the already
/// ADR-0025-resolved acting account id, and [`identity_for`] mints the token's `sub` from THAT,
/// never from `subject`. For every existing (grandfathered) account the two are byte-identical
/// today, which is exactly the wire-invariance property Stage 1-3 promises -- see
/// `minted_sub_is_the_acting_account_id_not_the_upstream_subject` and
/// `sub_and_account_id_differ_when_a_roster_member_acts_on_someone_elses_project` in
/// `crates/lightbridge-authz-rest/tests/signing_tests.rs` for both halves proven directly.
#[derive(Debug, Clone, Default)]
pub struct KeyOwner {
    pub subject: String,
    pub account_id: String,
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

/// Builds the `Identity` every derived token (access or id) is minted for. `email` is an upstream
/// snapshot -- never re-minted. `sub` (`external_id`) is DIFFERENT since ADR-0025 Stage 3: it is
/// minted from `owner.account_id` -- the already-resolved acting account id -- never from
/// `owner.subject` (the raw upstream claim, amending ADR-0011's Context/Decision 7 "sub copied
/// from upstream, never re-minted": the upstream-validation posture survives verbatim, but the
/// *value* placed on `sub` is now this service's own resolved account id, not a bare copy of the
/// presented claim). For a grandfathered account (`accounts.id == subject`) this is byte-identical
/// to the pre-Stage-3 behavior -- see [`KeyOwner`]'s own doc comment. `attributes` starts empty
/// here; `oauth2_op`'s refresh-token store uses it as the only extension point
/// `authkestra_op::refresh::RefreshToken` offers to round-trip `account_id`/`project_id` (which
/// have no dedicated field on `Identity`) through the `RefreshTokenStore` trait boundary -- see
/// that module for the full round trip.
pub(crate) fn identity_for(owner: &KeyOwner) -> Identity {
    Identity {
        provider_id: IDENTITY_PROVIDER_ID.to_string(),
        external_id: owner.account_id.clone(),
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
///
/// **`sid` (ADR-0020 Decision 2, #437's scoped-down interpretation):** the caller now supplies
/// `sid` explicitly rather than this function minting one inline. For a token-exchange access
/// token (`oauth2_op::store`), `sid` and `api_key_id` are the SAME real, persisted `sessions.id`
/// (see `oauth2_op::store::TokenExchangeOpStore::handle_token_exchange`/`handle_refresh_token`) --
/// a deliberate, documented narrowing of ADR-0020 Decision 2's full scope: that Decision's own
/// text anticipates `sid`/`api_key_id` eventually being fully separated (tracked by #421,
/// deliberately NOT done in this PR), but Authorino's `"lightbridgeintrospect"` metadata step is
/// gated on `auth.identity.api_key_id != ""` (ADR-0020 Context point 6) -- emptying or
/// repurposing `api_key_id` here would silently stop the gateway from ever calling introspection
/// at all for these tokens, a regression far worse than what this PR fixes. Both claims carrying
/// the same value already fixes the practical symptom #421 describes (a token-exchange session id
/// changing identity on every refresh), even though it does not rename/separate the claims the
/// way #421's full scope eventually will. For the plain self-signed API-key JWT path
/// (`ApiKeyJwtSigner::sign`), `sid` stays an independent, freshly-minted `cuid2()` per call --
/// completely unchanged behavior, since this PR does not touch API-key-JWT session semantics.
///
/// Stamps `extra["jti"]` with this repo's own `lgbr:`-prefixed CUID2 (ADR-0039: every id this
/// service mints is a CUID2). `TokenManager` (authkestra-engine 0.5.0, PR #215) removes a
/// string-valued `extra["jti"]` and uses it verbatim as the token's `jti` claim instead of
/// generating a UUIDv4 -- see `take_jti` in `authkestra_engine::token`. Before 0.5.0 this override
/// was not possible: `extra["jti"]` and `Claims::jti` both serialized under the same flattened
/// key, producing an undecodable duplicate-key JWT.
pub(crate) fn access_token_extra(
    owner: &KeyOwner,
    sid: &str,
    api_key_id: &str,
    project_id: &str,
    account_id: &str,
    allowed_models: Option<Vec<String>>,
    azp: Option<&str>,
) -> HashMap<String, Value> {
    let mut extra = HashMap::new();
    extra.insert(
        "jti".to_string(),
        Value::String(format!("lgbr:{}", cuid2())),
    );
    extra.insert("typ".to_string(), Value::String(TOKEN_TYP.to_string()));
    if let Some(azp) = azp {
        extra.insert("azp".to_string(), Value::String(azp.to_string()));
    }
    extra.insert(
        "lightbridge_caller_kind".to_string(),
        Value::String(lightbridge_authz_bearer::API_KEY_CALLER_KIND.to_string()),
    );
    extra.insert("sid".to_string(), Value::String(sid.to_string()));
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
/// appear here -- see [`compute_at_hash`]. `jti` is stamped as this repo's own `lgbr:`-prefixed
/// CUID2, same as [`access_token_extra`] and for the same ADR-0039 reason.
pub(crate) fn id_token_extra(
    owner: &KeyOwner,
    access_token: &str,
    auth_time: Option<i64>,
    azp: &str,
) -> HashMap<String, Value> {
    let mut extra = HashMap::new();
    extra.insert(
        "jti".to_string(),
        Value::String(format!("lgbr:{}", cuid2())),
    );
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
    /// `project_id`, `account_id`, `email`, `email_verified`, `allowed_models`, and -- since the
    /// authkestra 0.5.0 bump (PR #215) -- `jti` too) is preserved byte-for-byte via `extra`, with
    /// the same `skip_serializing_if`-style omission (simply not inserting the key when the value
    /// is absent). `TokenManager` itself unconditionally adds one claim this signer never emitted
    /// before -- `nbf` and a nested `identity` object mirroring `sub`/`email`; documented,
    /// deliberate consequences of adopting `TokenManager` as ADR-0011 Decision 2 mandates. See
    /// `crates/lightbridge-authz-rest/tests/signing_tests.rs`'s
    /// `new_signer_claim_set_is_a_documented_superset_of_the_old_signer` for the exact diff this
    /// was verified against. `jti` no longer needs an exception to the AGENTS.md "every minted id
    /// is CUID2" rule: before authkestra 0.5.0, `extra["jti"]` collided with `Claims`' own
    /// top-level `jti` field and produced a JWT payload with a duplicate `jti` key (technically
    /// malformed JSON that only happened to decode via `serde_json`'s last-wins behavior); 0.5.0's
    /// `TokenManager::take_jti` now removes a string-valued `extra["jti"]` and uses it verbatim
    /// instead of generating a UUIDv4, so [`access_token_extra`]/[`id_token_extra`] supply this
    /// repo's own `lgbr:`-prefixed CUID2 through that seam.
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

        // Unchanged behavior: this path has no `sessions` table concept, so `sid` stays an
        // independent, freshly-minted `cuid2()` per call -- see `access_token_extra`'s doc
        // comment.
        let extra = access_token_extra(
            owner,
            &cuid2(),
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

/// The common, currently truthful subset of OIDC Discovery and RFC 8414 metadata.
///
/// Authkestra's `OidcDiscovery` cannot represent RFC 8414's revocation metadata and serializes
/// several unsupported endpoints and client-authentication defaults. This explicit, small model
/// makes omission the default: a field appears only when this process mounts the corresponding
/// route. `/authorize` and device authorization are represented by independent route facts;
/// introspection (`/oauth2/introspect`, RFC 7662) and the OIDC Session Management check-session
/// iframe are advertised alongside the surfaces that mount them; UserInfo and logout remain
/// absent until their handlers exist. `claims_parameter_supported` is advertised explicitly as
/// `false` (OIDC Discovery 1.0 §3 -- the `claims` request parameter is not supported) rather
/// than left to the spec's implicit default, so RPs need not guess.
///
/// RFC 8414 requires zero-element arrays to be omitted from an authorization-server metadata
/// response. The shared narrow document applies the same omission discipline to OIDC discovery:
/// the disabled token surface advertises only the issuer and JWKS, not empty grant, scope,
/// response, or client-authentication capabilities.
#[derive(Serialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    scopes_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    grant_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    response_modes_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    code_challenge_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    revocation_endpoint_auth_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    introspection_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    introspection_endpoint_auth_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    introspection_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    check_session_iframe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_session_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claims_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subject_types_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    id_token_signing_alg_values_supported: Vec<String>,
}

fn discovery_document(
    issuer: &str,
    token_exchange_scopes: Option<&[String]>,
    client_authentication: &ClientAuthenticationMetadata,
    capabilities: DiscoveryCapabilities,
) -> DiscoveryDocument {
    let token_endpoint_mounted = capabilities.token_endpoint && token_exchange_scopes.is_some();
    let device_authorization_mounted =
        token_endpoint_mounted && capabilities.device_authorization_endpoint;
    let authorization_code_mounted = token_endpoint_mounted && capabilities.authorization_endpoint;
    let scopes_supported = token_endpoint_mounted
        .then_some(token_exchange_scopes)
        .flatten()
        .map(<[String]>::to_vec)
        .unwrap_or_default();
    let mut grant_types_supported = if token_endpoint_mounted {
        vec![
            crate::token_exchange::TOKEN_EXCHANGE_GRANT.to_string(),
            crate::token_exchange::REFRESH_TOKEN_GRANT.to_string(),
        ]
    } else {
        Vec::new()
    };
    if device_authorization_mounted {
        grant_types_supported.push(crate::token_exchange::DEVICE_CODE_GRANT.to_string());
    }
    if authorization_code_mounted {
        grant_types_supported.push("authorization_code".to_string());
    }
    let oidc_tokens_supported =
        token_endpoint_mounted && scopes_supported.iter().any(|scope| scope == "openid");
    let endpoint_base = issuer_origin(issuer);
    let client_auth_methods = if token_endpoint_mounted {
        client_authentication.methods.clone()
    } else {
        Vec::new()
    };
    let client_auth_signing_algorithms = if token_endpoint_mounted {
        client_authentication.signing_algorithms.clone()
    } else {
        Vec::new()
    };
    let subject_types_supported = if oidc_tokens_supported {
        vec!["public".to_string()]
    } else {
        Vec::new()
    };
    let id_token_signing_alg_values_supported = if oidc_tokens_supported {
        vec![ALGORITHM.to_string()]
    } else {
        Vec::new()
    };

    DiscoveryDocument {
        issuer: issuer.to_string(),
        jwks_uri: format!("{endpoint_base}/.well-known/jwks.json"),
        token_endpoint: token_endpoint_mounted.then(|| format!("{endpoint_base}/oauth2/token")),
        revocation_endpoint: token_endpoint_mounted
            .then(|| format!("{endpoint_base}/oauth2/revoke")),
        device_authorization_endpoint: device_authorization_mounted
            .then(|| format!("{endpoint_base}/oauth2/device_authorization")),
        authorization_endpoint: authorization_code_mounted
            .then(|| format!("{endpoint_base}/authorize")),
        scopes_supported,
        grant_types_supported,
        response_types_supported: if authorization_code_mounted {
            vec!["code".to_string()]
        } else {
            Vec::new()
        },
        response_modes_supported: if authorization_code_mounted {
            vec!["query".to_string()]
        } else {
            Vec::new()
        },
        code_challenge_methods_supported: if authorization_code_mounted {
            vec!["S256".to_string()]
        } else {
            Vec::new()
        },
        token_endpoint_auth_methods_supported: client_auth_methods.clone(),
        token_endpoint_auth_signing_alg_values_supported: client_auth_signing_algorithms.clone(),
        revocation_endpoint_auth_methods_supported: client_auth_methods.clone(),
        revocation_endpoint_auth_signing_alg_values_supported: client_auth_signing_algorithms
            .clone(),
        introspection_endpoint: token_endpoint_mounted
            .then(|| format!("{endpoint_base}/oauth2/introspect")),
        introspection_endpoint_auth_methods_supported: client_auth_methods,
        introspection_endpoint_auth_signing_alg_values_supported: client_auth_signing_algorithms,
        check_session_iframe: authorization_code_mounted
            .then(|| format!("{endpoint_base}/oauth2/check_session_iframe")),
        // OIDC RP-Initiated Logout 1.0 §3. Gated on the authorization-code surface, not on the
        // token surface: logout ends the BROWSER session, and the browser session only exists
        // where `/authorize` is mounted. `frontchannel_logout_supported`/
        // `backchannel_logout_supported` stay absent -- this OP implements neither, and the
        // omission discipline this document follows means never advertising a capability whose
        // handler does not exist (ADR-0023's whole lesson).
        end_session_endpoint: authorization_code_mounted
            .then(|| format!("{endpoint_base}/oauth2/end_session")),
        // OIDC Core §5.3. Gated on `oidc_tokens_supported` rather than the route table alone: the
        // endpoint refuses any token lacking the `openid` scope, so where `openid` is not an
        // issuable scope it would answer nothing but `insufficient_scope`.
        userinfo_endpoint: oidc_tokens_supported
            .then(|| format!("{endpoint_base}/oauth2/userinfo")),
        claims_parameter_supported: oidc_tokens_supported.then_some(false),
        subject_types_supported,
        id_token_signing_alg_values_supported,
    }
}

fn issuer_origin(issuer: &str) -> String {
    reqwest::Url::parse(issuer)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|| issuer.trim_end_matches('/').to_string())
}

fn well_known_paths(issuer: &str) -> (String, String) {
    let parsed = reqwest::Url::parse(issuer);
    let path = parsed
        .as_ref()
        .ok()
        .map_or("", |url| url.path().trim_end_matches('/'));
    let oidc = if path.is_empty() || path == "/" {
        "/.well-known/openid-configuration".to_string()
    } else {
        format!("{path}/.well-known/openid-configuration")
    };
    let oauth = if path.is_empty() || path == "/" {
        "/.well-known/oauth-authorization-server".to_string()
    } else {
        format!("/.well-known/oauth-authorization-server{path}")
    };
    (oidc, oauth)
}

/// Public OIDC discovery, RFC 8414 authorization-server metadata, and JWKS routes. JWKS is
/// served live from the DB (active + stale keys) so tokens signed by a rotated-out key keep
/// verifying until they expire. Stateless w.r.t. axum state, so it merges into any router. CORS
/// is wide-open (any origin, GET) because these are public, non-secret discovery documents.
///
/// `token_exchange_scopes` is populated only when the token surface was successfully assembled;
/// `capabilities` separately records which optional flow routes the enclosing router mounted.
/// `discovery_document` drops every endpoint from the disabled document entirely, matching the
/// actual route table rather than config intent alone.
pub fn well_known_router<S>(
    issuer: &str,
    repo: Arc<StoreRepo>,
    token_exchange_scopes: Option<Vec<String>>,
    client_authentication: ClientAuthenticationMetadata,
    capabilities: DiscoveryCapabilities,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let issuer: Arc<str> = Arc::from(issuer);
    let (openid_configuration_path, authorization_server_metadata_path) = well_known_paths(&issuer);
    let token_exchange_scopes = Arc::new(token_exchange_scopes);
    let client_authentication = Arc::new(client_authentication);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET]);
    Router::new()
        .route(
            &openid_configuration_path,
            get({
                let issuer = Arc::clone(&issuer);
                let scopes = Arc::clone(&token_exchange_scopes);
                let client_authentication = Arc::clone(&client_authentication);
                move || {
                    let issuer = Arc::clone(&issuer);
                    let scopes = Arc::clone(&scopes);
                    let client_authentication = Arc::clone(&client_authentication);
                    async move {
                        Json(discovery_document(
                            &issuer,
                            scopes.as_deref(),
                            &client_authentication,
                            capabilities,
                        ))
                    }
                }
            }),
        )
        .route(
            &authorization_server_metadata_path,
            get({
                let issuer = Arc::clone(&issuer);
                let scopes = Arc::clone(&token_exchange_scopes);
                let client_authentication = Arc::clone(&client_authentication);
                move || {
                    let issuer = Arc::clone(&issuer);
                    let scopes = Arc::clone(&scopes);
                    let client_authentication = Arc::clone(&client_authentication);
                    async move {
                        Json(discovery_document(
                            &issuer,
                            scopes.as_deref(),
                            &client_authentication,
                            capabilities,
                        ))
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::{OctetKeyPairParameters, OctetKeyPairType};

    #[test]
    fn client_assertion_algorithms_reports_eddsa_only_for_the_ed25519_okp_curve() {
        let params = OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: String::new(),
        };
        assert_eq!(
            client_assertion_algorithms(&AlgorithmParameters::OctetKeyPair(params)),
            vec!["EdDSA"]
        );
    }

    #[test]
    fn client_assertion_algorithms_reports_no_algorithm_for_non_ed25519_okp_curves() {
        // `jsonwebtoken`'s `OctetKeyPairParameters::curve` reuses the very same `EllipticCurve`
        // enum as EC keys, so a non-Ed25519 curve value (a malformed key, or the real-world
        // equivalent of an X25519 key-agreement JWK once that variant exists) can legitimately
        // reach this arm. Before this fix, `AlgorithmParameters::OctetKeyPair(_) => vec!["EdDSA"]`
        // matched unconditionally and reported every OKP key as EdDSA-capable regardless of curve.
        for curve in [
            EllipticCurve::P256,
            EllipticCurve::P384,
            EllipticCurve::P521,
        ] {
            let params = OctetKeyPairParameters {
                key_type: OctetKeyPairType::OctetKeyPair,
                curve: curve.clone(),
                x: String::new(),
            };
            assert_eq!(
                client_assertion_algorithms(&AlgorithmParameters::OctetKeyPair(params)),
                Vec::<&'static str>::new(),
                "non-Ed25519 OKP curve {curve:?} must not be reported as EdDSA-capable"
            );
        }
    }
}

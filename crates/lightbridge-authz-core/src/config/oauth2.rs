use crate::error::{Error, Result};
use serde::Deserialize;

/// Credential-issuance mode. REQUIRED and has no default — the operator must state it explicitly,
/// because it decides how every API key is minted. `self` mints self-signed JWTs via
/// `oauth2.signing`; `external` exchanges the credential at an upstream IdP (e.g. Keycloak) via
/// `oauth2.issuance`. The two are mutually exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Oauth2Type {
    #[serde(rename = "self")]
    SelfSigned,
    External,
}

/// ADR-0025 Stage 1: the identity of the ONE issuer this deployment trusts to translate a bearer
/// token's `(iss, sub)` into the acting person's lightbridge account id
/// (`StoreRepo::resolve_account_for_federated_subject`) -- the single seam every ingress now
/// routes remote-subject translation through, instead of trusting `accounts.id == sub` directly
/// (ADR-0006's original property). Mandatory for `authz-api`, `authz-idp`, `authz-opa`,
/// `authz-budget`, and `lightbridge-mcp` -- each refuses to start without it, loudly, naming
/// `oauth2.federation.issuer` and the component (see each `start_*_server` function in
/// `crates/lightbridge-authz-rest/src/lib.rs`, and `app/lightbridge-authz/src/bin/lightbridge-mcp.rs`),
/// the same shape AGENTS.md's "Redis is a mandatory dependency" house rule documents for a
/// different dependency.
#[derive(Debug, Clone, Deserialize)]
pub struct Federation {
    /// The IDENTITY issuer (ADR-0025's "the ONE issuer this deployment trusts"): the `iss` claim
    /// value every ID token must carry, what `authz-idp`'s Keycloak discovery response is checked
    /// against, what the browser is ultimately sent to via the discovered
    /// `authorization_endpoint`, and the issuer URL every ADR-0025 ingress translation
    /// grandfathers a pre-ADR-0024 (`accounts.id == subject`) account against on its first
    /// resolution -- see `StoreRepo::resolve_account_for_federated_subject`'s doc comment for the
    /// self-healing adoption this enables. This is deliberately NOT the address `authz-idp` dials
    /// to fetch OIDC discovery -- see [`Self::discovery_url`] for that, and why the two can
    /// legitimately differ. There is no longer a separate `oauth2.relying_party.issuer` this must
    /// be kept equal to (that field was deleted); this is the one and only issuer field.
    pub issuer: String,
    /// WHERE `authz-idp` dials OIDC discovery from inside this deployment's own network. Defaults
    /// to [`Self::issuer`] when unset -- most deployments don't need this at all, since most
    /// issuers are reachable at the same address internally and externally. Set this only when
    /// they diverge: e.g. a local-dev stack where the browser and host-side tooling reach
    /// Keycloak via `http://localhost:9100/realms/dev` but `authz-idp`'s own container must dial
    /// it via the in-network `http://keycloak:9100/realms/dev` instead. `discover()`
    /// (`KeycloakRelyingParty`) fetches from this URL but still validates the returned
    /// `metadata.issuer` against [`Self::issuer`] -- the identity check is never relaxed to
    /// compare against this LOCATION value instead.
    #[serde(default)]
    pub discovery_url: Option<String>,
}

impl Federation {
    /// Offline validation only (ADR-0025): non-empty, and parses as a URL. No network call, no
    /// discovery fetch against the issuer -- the same "presence PLUS offline validation, not a
    /// live reachability check" posture `oauth2.relying_party`/`KeycloakRelyingParty::new`
    /// already applies to a config-sourced external-IdP URL, for the identical reason
    /// AGENTS.md's "Redis is a mandatory dependency" house rule gives for its own presence-only
    /// enforcement: no startup-ordering dependency on a third party being reachable yet. Applies
    /// the identical shape check to `discovery_url` when set (non-empty, valid URL) -- it is just
    /// as much an offline-checkable deployment value as `issuer` is.
    pub fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(Error::Server(
                "oauth2.federation.issuer must not be empty".to_string(),
            ));
        }
        url::Url::parse(&self.issuer).map_err(|e| {
            Error::Server(format!("oauth2.federation.issuer must be a valid URL: {e}"))
        })?;
        if let Some(discovery_url) = &self.discovery_url {
            if discovery_url.trim().is_empty() {
                return Err(Error::Server(
                    "oauth2.federation.discovery_url must not be empty when set".to_string(),
                ));
            }
            url::Url::parse(discovery_url).map_err(|e| {
                Error::Server(format!(
                    "oauth2.federation.discovery_url must be a valid URL: {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// WHERE to dial OIDC discovery -- [`Self::discovery_url`] when set, otherwise
    /// [`Self::issuer`]. See [`Self::discovery_url`]'s doc comment for the identity-vs-location
    /// split this resolves.
    pub fn effective_discovery_url(&self) -> &str {
        self.discovery_url.as_deref().unwrap_or(&self.issuer)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2 {
    /// REQUIRED credential-issuance mode (`self` or `external`). No default — a missing `type`
    /// fails config load rather than silently picking a mode.
    #[serde(rename = "type")]
    pub oauth2_type: Oauth2Type,
    pub jwks_url: String,
    /// Path to a PEM-encoded CA bundle trusted for `jwks_url`, when it resolves to a private,
    /// in-cluster endpoint whose certificate chains to the cluster's own CA rather than a
    /// publicly-trusted one (lightbridge-authz#625) -- e.g. dialling `authz-idp`'s own in-cluster
    /// Service DNS name for JWKS instead of hairpinning back out through the public ingress.
    /// Scoped to ONLY the JWKS HTTP client (`reqwest::ClientBuilder::add_root_certificate`),
    /// never `SSL_CERT_FILE`, which replaces the trust store for every outbound connection this
    /// process makes, Keycloak discovery included. Optional -- unset (the default, and today's
    /// universal case) is byte-identical to before this field existed: the default client,
    /// platform roots only. An unreadable path or a bundle with no parseable PEM certificate is a
    /// hard construction-time failure naming the path, never a silent fallback to the default
    /// client -- the same fail-closed convention as `Redis::ca_bundle_path` and
    /// `UsageServiceClient::ca_bundle_path` above.
    #[serde(default)]
    pub jwks_ca_bundle_path: Option<String>,
    #[serde(default)]
    pub oauth2_url: Option<String>,
    #[serde(default)]
    pub issuer_url: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub issuance: Option<Oauth2Issuance>,
    /// Expected audience(s) for JWT validation. If set, the JWT's `aud` claim must
    /// contain at least one of these values. Can be a single value or multiple values.
    #[serde(default)]
    pub audience: Option<Vec<String>>,
    /// Optional self-signing config: when enabled, issued API keys are RS256 JWTs signed
    /// by this service (rather than opaque secrets or Keycloak-exchanged tokens).
    #[serde(default)]
    pub signing: Option<JwtSigning>,
    /// Optional native RFC 8693 token-exchange: when enabled, this service exchanges an
    /// upstream IdP access token for a short-lived, project-scoped self-signed JWT (and an
    /// optional refresh token). Requires `type: self` (the exchanged token is signed by this
    /// service). Independent of `issuance`, which proxies exchange to an upstream IdP.
    #[serde(default)]
    pub token_exchange: Option<Oauth2TokenExchange>,
    /// The outbound OIDC relying-party leg to Keycloak used by the hosted device-verification
    /// page and, once `/authorize` lands, browser SSO. It is deliberately separate from
    /// `issuance`: this is an interactive authorization-code client, not the service-account
    /// token-exchange client used to issue API-key credentials.
    #[serde(default)]
    pub relying_party: Option<OidcRelyingParty>,
    /// Role-based access control: which JWT claim carries the caller's roles and how those roles
    /// map to permissions. When omitted, the built-in default mapping is used
    /// (`crate::authz::default_role_permissions`).
    #[serde(default)]
    pub rbac: crate::authz::Rbac,
    /// Real, config-sourced OAuth2/OIDC clients permitted to use the native token-exchange
    /// endpoint (ADR-0011, Decision 5). Sourced from YAML only -- no database table, no
    /// cratestack model (see that decision's revisit trigger: self-service client registration,
    /// not needed today). Empty by default: token-exchange with no registered clients means every
    /// request fails client authentication (`invalid_client`), not that the endpoint is
    /// unprotected. Mapped onto `authkestra_op::client::ClientRegistration` in
    /// `lightbridge_authz_rest::oauth2_op` (kept out of this crate so `core` never depends on
    /// `authkestra-op`).
    #[serde(default)]
    pub clients: Vec<OauthClient>,
    /// ADR-0025 Stage 1: the ONE issuer this deployment trusts for remote-subject-to-account-id
    /// translation. `Option` at the type level ONLY because every other field on this struct
    /// that starts life optional-and-becomes-mandatory-per-component follows that same shape
    /// (`relying_party`, `token_exchange` -- see `start_idp_server`'s doc comment); every
    /// component that actually serves traffic enforces this unconditionally at startup -- see
    /// [`Federation`]'s own doc comment for the full list and the loud-refusal contract.
    #[serde(default)]
    pub federation: Option<Federation>,
}

/// Configuration for `authz-idp` acting as a Keycloak OIDC relying party (ADR-0012, ADR-0021).
#[derive(Debug, Clone, Deserialize)]
pub struct OidcRelyingParty {
    /// Registered Keycloak client ID. The ID-token audience must contain this exact value.
    pub client_id: String,
    /// The one fixed callback Keycloak is allowed to redirect to. This value is deployment
    /// configuration, never derived from a request parameter or client registration.
    pub callback_url: String,
    /// Optional confidential-client credential. Public clients use PKCE with no secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Base64url-without-padding encoding of exactly 32 random bytes, used to encrypt the
    /// short-lived RP state cookie.
    pub state_encryption_key: String,
    /// Base64url-without-padding encoding of exactly 32 random bytes, used with
    /// [`crate::crypto::seal`]/[`crate::crypto::open`] (AES-256-GCM) to protect the Keycloak
    /// token set (refresh token + ID-token claims snapshot, never the access token) persisted at
    /// rest on `federated_identities.token_envelope` (ADR-0024). Deliberately a SEPARATE key from
    /// [`Self::state_encryption_key`] -- `KeycloakRelyingParty::new` rejects a config where the
    /// two are equal, since the state key protects a short-lived (10-minute) cookie the browser
    /// itself holds, a very different exposure/rotation posture from a token set that can sit at
    /// rest for a session's full lifetime. Non-`Option`, no `#[serde(default)]`: a deployment
    /// that omits this field must fail config parsing outright rather than silently start with an
    /// absent key -- see AGENTS.md's "authz-idp surface is mandatory" house rule for the same
    /// shape applied to `oauth2.relying_party` as a whole. Rotation: there is no key history, so
    /// rotating this value makes every previously-sealed `token_envelope` permanently unopenable;
    /// `open()`'s failure is treated as "no stored token", never as a row to delete, and the row
    /// re-seals itself on that identity's next successful login.
    pub token_encryption_key: String,
    /// Bounded timeout for discovery and authorization-code redemption.
    #[serde(default = "default_rp_timeout_ms")]
    pub timeout_ms: u64,
    /// Fixed lifetime of a browser SSO session. Device pairing never creates this session.
    #[serde(default = "default_browser_session_ttl_seconds")]
    pub browser_session_ttl_seconds: i64,
}

fn default_rp_timeout_ms() -> u64 {
    5_000
}

fn default_browser_session_ttl_seconds() -> i64 {
    28_800
}

/// A registered OAuth2/OIDC client (ADR-0011, Decision 5). Mirrors
/// `authkestra_op::client::ClientRegistration`'s 9 fields minus the two this service never needs:
/// `client_secret_hash` (always `None` -- Decision 6 bans secret-based client auth outright) and
/// `redirect_uris` and `require_pkce`, which are relevant to browser authorization-code clients.
#[derive(Debug, Clone, Deserialize)]
pub struct OauthClient {
    pub client_id: String,
    /// `public` (no client authentication beyond the `client_id` itself), `confidential`
    /// (`private_key_jwt` only -- ADR-0011 Decision 6 bans `client_secret_basic`/
    /// `client_secret_post` for every client this service registers), or `service` (also
    /// `private_key_jwt` -- #534/ADR-0030: a `client_credentials` (M2M) client, identical
    /// authentication to `confidential` but a distinct config-level name so a reviewer can see
    /// at a glance which registered clients are machines rather than browser/native RP legs; see
    /// `oauth2_op::client_store::to_registration`, which maps both `confidential` and `service`
    /// onto `TokenEndpointAuthMethod::PrivateKeyJwt`). `start_idp_server`'s startup validation
    /// refuses a `public` client that lists the `client_credentials` grant -- see that check's own
    /// doc comment for why a config-only enable of that combination is a live footgun.
    #[serde(rename = "type")]
    pub client_type: OauthClientType,
    /// Scopes this client may request. For every grant except `client_credentials`, intersected
    /// with `Oauth2TokenExchange.allowed_scopes` (the server-wide ceiling) at exchange/refresh time
    /// -- neither list alone is authoritative. `client_credentials` (#534/ADR-0030) is the ONE
    /// deliberate exception: machine scopes are a separate namespace from the human-plane
    /// `openid`/`profile`/`email`/`offline_access` ceiling, so that grant checks a requested scope
    /// against THIS list alone -- see `token_exchange::client_credentials_scopes`'s own doc
    /// comment.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Grant types this client may use, as raw RFC 8693/OAuth2 grant-type strings (e.g.
    /// `"urn:ietf:params:oauth:grant-type:token-exchange"`, `"refresh_token"`,
    /// `"client_credentials"` -- #534/ADR-0030 added the last of these; before it, only the first
    /// two were ever meaningful here, since this service ran no other machine-facing grant). The
    /// list is not restricted at the config-parsing layer so an operator typo surfaces as "client
    /// not authorized for this grant type" at request time rather than a silent config-load
    /// failure -- `start_idp_server`'s startup validation catches the one combination that would
    /// otherwise be a live footgun (`type: public` + `client_credentials`, see that check's own
    /// doc comment) rather than every possible typo.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Downstream audiences this client may request via the token-exchange `audience` parameter.
    /// Per ADR-0011 Decision 5 the minted access token's `aud`/`azp` default to this client's own
    /// `client_id` when no `audience` is requested; requesting anything else requires it to be
    /// listed here.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Inline JWK Set (`{"keys": [...]}`) -- the public half of a `confidential` client's keypair,
    /// used to verify its `private_key_jwt` client assertions (RFC 7523 §2.2). Required for
    /// `confidential` clients, ignored for `public` ones. Deliberately no `jwks_uri` counterpart
    /// (ADR-0011 Decision 6): this service takes no HTTP-client dependency for client
    /// authentication, so a confidential client's public key is a config value, not a fetch.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// Exact, byte-for-byte callback URLs accepted by `/authorize` for this client. Empty for
    /// non-browser clients.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Exact, byte-for-byte URLs `/oauth2/end_session` will redirect to after ending the session
    /// (OIDC RP-Initiated Logout 1.0 §2, `post_logout_redirect_uri`). Deliberately a SEPARATE list
    /// from `redirect_uris` rather than reusing it: the two are reached under different
    /// conditions, and the logout endpoint accepts a redirect target from an unauthenticated,
    /// CSRF-able GET. Folding them together would silently turn every registered callback into a
    /// logout landing page.
    ///
    /// Empty (the default) means this client gets NO redirect: `/oauth2/end_session` still ends
    /// the session and renders its own confirmation page. An unregistered
    /// `post_logout_redirect_uri` is never honoured -- that is the whole open-redirect boundary
    /// (see `end_session::resolve_post_logout_redirect`).
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Whether the authorization request must carry an S256 PKCE challenge.
    #[serde(default)]
    pub require_pkce: bool,
    /// Per-client override of [`Oauth2TokenExchange::refresh_ttl_seconds`] (the lifetime of one
    /// issued refresh token, in seconds). `None` (the default) falls back to the server-wide
    /// value -- most clients need no override. Resolved once, at startup
    /// (`oauth2_op::client_store::ConfigClientStore::from_config`), not re-read per request.
    /// `start_idp_server` refuses to start when the EFFECTIVE value (this override, or the
    /// global fallback) is not positive, or exceeds the EFFECTIVE
    /// [`Self::refresh_absolute_ttl_seconds`] -- see `oauth2_op::refresh_ttl` for why a longer
    /// per-token TTL than the chain's absolute cap is a config trap, not just a bad value.
    #[serde(default)]
    pub refresh_ttl_seconds: Option<i64>,
    /// Per-client override of [`Oauth2TokenExchange::refresh_absolute_ttl_seconds`] (the hard cap
    /// on a refresh-token chain's total lifetime, set once when the chain is born and inherited
    /// unchanged by every rotation). `None` (the default) falls back to the server-wide value.
    /// Deliberately a SEPARATE override from [`Self::refresh_ttl_seconds`] rather than one
    /// combined knob: a client configured only for a longer per-token TTL, with no matching
    /// absolute-cap override, would otherwise have every one of its tokens silently killed by the
    /// still-global (and likely shorter) chain cap -- `start_idp_server`'s startup validation
    /// refuses exactly that combination instead of letting it ship half-working.
    #[serde(default)]
    pub refresh_absolute_ttl_seconds: Option<i64>,
}

/// A client's authentication method at the token endpoint (ADR-0011, Decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OauthClientType {
    Public,
    Confidential,
    /// A `client_credentials` (M2M) client (#534, ADR-0030). Authenticates identically to
    /// `Confidential` (`private_key_jwt` only -- ADR-0011 Decision 6 draws no exception for
    /// machine clients) -- this is a separate variant purely so config/discovery/startup
    /// validation can name "this registration is a machine client" without overloading
    /// `Confidential`, which predates the `client_credentials` grant entirely and originally meant
    /// only "a browser/native RP leg that happens to hold a keypair".
    Service,
}

impl Oauth2 {
    pub fn is_self_signed(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::SelfSigned)
    }

    pub fn is_external(&self) -> bool {
        matches!(self.oauth2_type, Oauth2Type::External)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtSigning {
    /// `iss` claim and the OIDC issuer URL Authorino discovers the JWKS from.
    pub issuer: String,
    /// Optional `aud` claim stamped on issued tokens.
    #[serde(default)]
    pub audience: Option<String>,
    /// Default token lifetime in seconds and the hard cap on any frontend-requested expiry.
    #[serde(default = "default_signing_ttl_seconds")]
    pub ttl_seconds: i64,
    /// Auto-rotate the active signing key once it is older than this many days (checked at
    /// startup). The rotated-out key is marked stale and kept in the JWKS for verification.
    #[serde(default = "default_max_key_age_days")]
    pub max_key_age_days: i64,
    /// Extra claims stamped onto tokens this deployment signs, declared rather than hard-coded.
    ///
    /// Exists so `authz-idp` can be the sole issuer for the human plane without borrowing claims
    /// from the upstream IdP. Everything a mapper needs is already resolved server-side at mint
    /// time (`resolve_context` gives account/project; `project_members` gives the roster role), so
    /// a claim like the RBAC roles claim is derived from data this service owns -- not copied out
    /// of a Keycloak token.
    ///
    /// Empty by default: a deployment that stamps no extra claims behaves exactly as before.
    #[serde(default)]
    pub claim_mappers: Vec<crate::config::claim_mapper::ClaimMapper>,
}

fn default_signing_ttl_seconds() -> i64 {
    7_776_000
}

fn default_max_key_age_days() -> i64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2Issuance {
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub subject_token_type: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2TokenExchange {
    #[serde(default)]
    pub enabled: bool,
    /// Lifetime of the exchanged access JWT, in seconds. Kept short (session-scoped) because
    /// these tokens are only revocable by expiry; renewal flows through the refresh token.
    #[serde(default = "default_exchange_access_ttl_seconds")]
    pub access_ttl_seconds: i64,
    /// Lifetime of a browser authorization code. Codes are persisted and single-use, so this is
    /// intentionally short and must remain positive whenever the token endpoint is enabled.
    #[serde(default = "default_authorization_code_ttl_seconds")]
    pub authorization_code_ttl_seconds: i64,
    /// Lifetime of an issued refresh token, in seconds. Refresh tokens are stored hashed and are
    /// revocable, so they carry the long-lived session; only minted when `offline_access` is
    /// requested and permitted.
    #[serde(default = "default_exchange_refresh_ttl_seconds")]
    pub refresh_ttl_seconds: i64,
    /// Scopes a client may request on exchange. `offline_access` gates refresh-token issuance.
    #[serde(default = "default_exchange_allowed_scopes")]
    pub allowed_scopes: Vec<String>,
    /// Absolute cap on a refresh-token *chain*'s lifetime, in seconds, independent of
    /// `refresh_ttl_seconds`. Each rotation resets the individual token's own `expires_at` to
    /// `now() + refresh_ttl_seconds`, so without this a session that keeps refreshing before
    /// every expiry never actually ends -- this is the ceiling that stops it. Set once, when a
    /// chain is born (the offline-scope exchange grant), and inherited unchanged by every
    /// rotation thereafter (`exchange_refresh_tokens.chain_expires_at`); a refresh presented
    /// after this deadline is refused with `invalid_grant` regardless of the individual token's
    /// own remaining `expires_at`. Defaults to 90 days -- longer than `refresh_ttl_seconds`'
    /// 30-day default (a session that refreshes at least once a month lives up to 3 rotations
    /// past the individual TTL before hitting the cap), short enough that a forgotten/leaked
    /// session cannot outlive it indefinitely.
    #[serde(default = "default_exchange_refresh_absolute_ttl_seconds")]
    pub refresh_absolute_ttl_seconds: i64,
    /// Bounded idempotent-replay grace window, in seconds, for a refresh token presented AFTER it
    /// was already rotated (RFC 6819 §5.2.2.3 reuse detection). Added after a real production
    /// incident (2026-08-30): the console runs 2 replicas, each with its own in-memory, per-pod
    /// refresh single-flight, and raced its own refresh -- one pod rotated the presented token,
    /// the other replayed the same pre-rotation token seconds later, and the strict reuse cascade
    /// (`TokenExchangeOpStore::classify_replayed_refresh_token`) revoked the WHOLE chain as if the
    /// token had been stolen, killing the user's session with intermittent 401s even though
    /// nothing was actually stolen -- both pods were the same already-authenticated client.
    ///
    /// A replay presented within this many seconds of the ORIGINAL token's own `rotated_at` is
    /// treated as a benign race, not theft: it mints a fresh access+refresh pair (a second live
    /// leaf on the same chain -- see `classify_replayed_refresh_token`'s doc comment for why a
    /// graced replay cannot simply replay the first rotation's response) instead of cascading. A
    /// replay presented after this window still cascades exactly as before -- the grace window
    /// bounds how long a rotated token retains this power, it does not remove reuse detection.
    /// Standard practice for exactly this race: Keycloak's "revoke refresh token: max reuse",
    /// Auth0's reuse interval. Defaults to 30 seconds -- long enough to absorb a same-request-cycle
    /// race between replicas, short enough that a genuinely stolen-and-replayed token is still
    /// caught almost immediately. `0` disables the grace window entirely (today's pre-incident
    /// strict behavior: every post-rotation replay cascades).
    #[serde(default = "default_refresh_reuse_grace_seconds")]
    pub refresh_reuse_grace_seconds: i64,
    /// RFC 8628 device and user-code lifetime. Device authorization is mounted with the native
    /// token endpoint, so this is an operational value rather than a separate feature flag.
    #[serde(default = "default_device_code_ttl_seconds")]
    pub device_code_ttl_seconds: i64,
    /// Minimum RFC 8628 polling interval returned to a device client.
    #[serde(default = "default_device_poll_interval_seconds")]
    pub device_poll_interval_seconds: i32,
    /// Public, absolute HTTPS verification page URL returned to device clients. Credentials,
    /// query parameters, and fragments are rejected at startup so the user code is added only by
    /// the device-authorization response.
    #[serde(default = "default_device_verification_uri")]
    pub device_verification_uri: String,
    /// Lifetime of a `client_credentials` (M2M) access token, in seconds (#534, ADR-0030).
    /// Deliberately its OWN field, not reused from `access_ttl_seconds`: that field is the
    /// human-plane token-exchange access-token lifetime, and the two are allowed to diverge (a
    /// machine token is revoked by removing its `jwks` entry from config and redeploying, per
    /// ADR-0030 -- there is no refresh token to rotate away from, so this TTL doubles as the
    /// window an already-issued token remains usable after that revocation). Defaults to 900
    /// seconds, matching `access_ttl_seconds`' own default.
    #[serde(default = "default_client_credentials_ttl_seconds")]
    pub client_credentials_ttl_seconds: i64,
}

fn default_exchange_access_ttl_seconds() -> i64 {
    900
}

fn default_authorization_code_ttl_seconds() -> i64 {
    300
}

fn default_exchange_refresh_ttl_seconds() -> i64 {
    2_592_000
}

fn default_exchange_refresh_absolute_ttl_seconds() -> i64 {
    7_776_000
}

fn default_refresh_reuse_grace_seconds() -> i64 {
    30
}

fn default_device_code_ttl_seconds() -> i64 {
    600
}

fn default_device_poll_interval_seconds() -> i32 {
    5
}

fn default_device_verification_uri() -> String {
    "https://localhost:13004/device/verify".to_string()
}

fn default_client_credentials_ttl_seconds() -> i64 {
    900
}

fn default_exchange_allowed_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "profile".to_string(),
        "email".to_string(),
        "offline_access".to_string(),
    ]
}

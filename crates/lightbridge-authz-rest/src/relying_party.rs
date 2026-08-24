//! Keycloak OIDC relying-party leg shared by device verification and browser SSO.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use authkestra_engine::{
    auth::{discovery::ProviderMetadata, pkce::Pkce, state::OAuth2State},
    token::Audience,
};
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus};
use authkestra_resource::jwt::{JwksCache, ValidationConfig, validate_jwt_generic};
use axum::{
    Router,
    extract::{ConnectInfo, Form, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{AppendHeaders, Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use cratestack_axum::ratelimit::{RateLimitConfig, RateLimitStore};
use jsonwebtoken::{Algorithm, Validation, decode_header};
use serde::{Deserialize, Serialize};

use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::OidcRelyingParty;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};

use crate::oauth2_op::device_store::{DbDeviceCodeStore, get_by_user_code_rate_limited};
use crate::oauth2_op::random_urlsafe;
use crate::session_cookie::build_session_cookie;
use crate::static_assets::CONTENT_SECURITY_POLICY;

const CALLBACK_PATH: &str = "/idp/callback";
const DEVICE_VERIFY_PATH: &str = "/device/verify";
const RP_STATE_COOKIE_NAME: &str = "__Host-authz_rp_state";
const RP_STATE_TTL_SECONDS: i64 = 600;
const ACCEPTED_ALGORITHMS: [Algorithm; 1] = [Algorithm::RS256];
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// `__Host-`-prefixed cookie binding a rendered `/device/verify` confirmation page to whichever
/// `user_code` it displayed, so `POST /device/verify/continue` can require proof the caller
/// actually visited that page first (see [`verify_continue`]'s doc comment for the CSRF this
/// closes). `__Host-` requires `Secure` + `Path=/` + no `Domain` -- mirrors
/// [`RP_STATE_COOKIE_NAME`]'s own attribute set exactly, just a different name/TTL/`SameSite`.
const DEVICE_CONFIRM_COOKIE_NAME: &str = "__Host-authz_device_confirm";

/// Short-lived: only needs to outlive the human reading the confirmation page and clicking
/// "Continue" -- comfortably shorter than a device code's own TTL (minutes, not the ~10-15
/// minutes `session()`-shaped rows typically carry).
const DEVICE_CONFIRM_TTL_SECONDS: i64 = 300;

/// [`OAuth2State::provider_id`] stamped on every device-confirm envelope. Never "keycloak" --
/// `KeycloakRelyingParty::complete` rejects any non-"keycloak" `provider_id`, so an envelope
/// minted here could never be replayed as if it were a real Keycloak callback state even if it
/// ended up on the wrong cookie by some future bug.
const DEVICE_CONFIRM_PROVIDER_ID: &str = "device-confirm";

/// Rate limit applied to every `user_code` lookup on the public, unauthenticated verification
/// pages (`verify_submit`/`verify_continue`), keyed by caller IP (see [`lookup_pending_session`]).
/// Generous enough that a human retyping a mistyped code a few times never gets throttled, tight
/// enough that scripted brute-forcing of the 8-character `user_code` space
/// (`device_store::USER_CODE_ALPHABET`) is not viable within a device code's short TTL.
const VERIFY_RATE_LIMIT_BURST: u32 = 20;
const VERIFY_RATE_LIMIT_REFILL_PER_SECOND: f64 = 1.0;

#[derive(Clone)]
pub struct KeycloakRelyingParty {
    config: OidcRelyingParty,
    callback_url: String,
    state_key: [u8; 32],
    client: reqwest::Client,
    jwks: Arc<JwksCache>,
    jwks_url: String,
    repo: Arc<StoreRepo>,
    /// Backs [`lookup_pending_session`]'s `get_by_user_code_rate_limited` call -- the SAME
    /// Redis-backed store `authz-api`/`authz-budget` use for HTTP rate limiting in production
    /// (`start_idp_server` builds it via `ratelimit_redis::build_redis_rate_limit_store`), so
    /// throttling state is shared across every `authz-idp` replica rather than per-process.
    rate_limiter: Arc<dyn RateLimitStore>,
}

#[derive(Deserialize)]
struct VerifyQuery {
    user_code: Option<String>,
}

#[derive(Deserialize)]
struct VerifyForm {
    user_code: String,
}

#[derive(Deserialize)]
struct ContinueForm {
    user_code: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[derive(Deserialize)]
struct IdTokenClaims {
    sub: String,
    aud: Audience,
    azp: Option<String>,
    iat: i64,
    nonce: Option<String>,
}

#[derive(Serialize, Deserialize)]
enum PendingFlow {
    Device { device_code: String },
    Browser(BrowserLoginTarget),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BrowserLoginTarget {
    pub project_id: Option<String>,
    pub resume_path: String,
}

impl KeycloakRelyingParty {
    pub fn new(
        config: OidcRelyingParty,
        jwks_url: String,
        repo: Arc<StoreRepo>,
        rate_limiter: Arc<dyn RateLimitStore>,
    ) -> Result<Self> {
        if config.timeout_ms == 0 {
            return Err(Error::Server(
                "oauth2.relying_party.timeout_ms must be positive".to_string(),
            ));
        }
        if config.browser_session_ttl_seconds <= 0 {
            return Err(Error::Server(
                "oauth2.relying_party.browser_session_ttl_seconds must be positive".to_string(),
            ));
        }
        let state_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&config.state_encryption_key)
            .map_err(|_| {
                Error::Server(
                    "oauth2.relying_party.state_encryption_key must be base64url".to_string(),
                )
            })?;
        let state_key: [u8; 32] = state_key_bytes.try_into().map_err(|_| {
            Error::Server(
                "oauth2.relying_party.state_encryption_key must decode to exactly 32 bytes"
                    .to_string(),
            )
        })?;
        let callback_url = config.callback_url.clone();
        let callback = reqwest::Url::parse(&callback_url).map_err(|_| {
            Error::Server("oauth2.relying_party.callback_url must be an absolute URL".to_string())
        })?;
        if callback.scheme() != "https"
            || callback.path() != CALLBACK_PATH
            || callback.query().is_some()
            || callback.fragment().is_some()
        {
            return Err(Error::Server(format!(
                "oauth2.relying_party.callback_url must be the exact fixed HTTPS {CALLBACK_PATH} URL"
            )));
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| Error::Server(format!("failed to build Keycloak RP HTTP client: {e}")))?;
        // `.issuer(..)`/`.audience(..)`/`.algorithms(..)` are deliberately NOT set here: real ID
        // token validation runs through a separately-constructed `Validation` in
        // `validate_id_token` below (which does set issuer/audience/algorithms on that object),
        // never through this `ValidationConfig`. Only `jwks_url`/`refresh_interval`/`require_kid`
        // are read off it (immediately below), so setting the other three would be dead code.
        let validation_config = ValidationConfig::builder()
            .jwks_url(jwks_url.clone())
            .refresh_interval(JWKS_REFRESH_INTERVAL)
            .require_kid(true)
            .build();
        let jwks = Arc::new(
            JwksCache::new(
                validation_config.jwks_url,
                validation_config.refresh_interval,
            )
            .require_kid(validation_config.require_kid),
        );
        Ok(Self {
            config,
            callback_url,
            state_key,
            client,
            jwks,
            jwks_url,
            repo,
            rate_limiter,
        })
    }

    pub async fn begin_device(&self, device_code: String) -> Result<(String, Cookie<'static>)> {
        self.begin(PendingFlow::Device { device_code }).await
    }

    pub async fn begin_browser(
        &self,
        target: BrowserLoginTarget,
    ) -> Result<(String, Cookie<'static>)> {
        if is_unsafe_resume_path(&target.resume_path) {
            return Err(Error::BadRequest(
                "browser resume path must be same-origin".to_string(),
            ));
        }
        self.begin(PendingFlow::Browser(target)).await
    }

    pub async fn find_active_browser_session(
        &self,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<Option<lightbridge_authz_api_key::entities::session_row::BrowserSessionContextRow>>
    {
        self.repo.find_active_browser_session(session_id, now).await
    }

    /// Resolves `{account_id, project_id}` for `subject` + `project_id`, gated by the
    /// Active-status check `StoreRepo::resolve_context` itself deliberately does not apply (see
    /// `StoreRepo::resolve_active_context`'s doc comment -- the single shared implementation every
    /// grant/session path in this codebase now routes through). Used by `authorize.rs` when a
    /// request's `project_id` differs from an already-established browser session's own project --
    /// see that call site's doc comment for why silently issuing for the session's project instead
    /// would be wrong.
    pub async fn resolve_authorized_context(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<lightbridge_authz_core::dto::ResolvedContext> {
        self.repo.resolve_active_context(subject, project_id).await
    }

    async fn begin(&self, flow: PendingFlow) -> Result<(String, Cookie<'static>)> {
        let metadata = self.discover().await?;
        let pkce = Pkce::new();
        let state = OAuth2State {
            state: random_urlsafe(32),
            nonce: Some(random_urlsafe(32)),
            code_verifier: Some(pkce.code_verifier),
            success_url: Some(encode_pending_flow(&flow)?),
            provider_id: "keycloak".to_string(),
            expires_at: (Utc::now() + ChronoDuration::seconds(RP_STATE_TTL_SECONDS)).timestamp(),
        };
        let encrypted_state = state
            .encrypt(&self.state_key)
            .map_err(|e| Error::Server(format!("failed to encrypt Keycloak RP state: {e}")))?;
        let mut url = reqwest::Url::parse(&metadata.authorization_endpoint).map_err(|e| {
            Error::Server(format!(
                "Keycloak discovery returned invalid authorization endpoint: {e}"
            ))
        })?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.callback_url)
            .append_pair("scope", "openid profile email")
            .append_pair("state", &encrypted_state)
            .append_pair("nonce", state.nonce.as_deref().unwrap_or_default())
            .append_pair("code_challenge", &pkce.code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok((url.into(), build_rp_state_cookie(encrypted_state)))
    }

    async fn discover(&self) -> Result<ProviderMetadata> {
        let (metadata, _) = ProviderMetadata::discover(&self.config.issuer, self.client.clone())
            .await
            .map_err(|e| Error::Server(format!("Keycloak discovery unavailable: {e}")))?;
        if metadata.issuer != self.config.issuer {
            return Err(Error::Server(
                "Keycloak discovery issuer mismatch".to_string(),
            ));
        }
        if metadata.jwks_uri != self.jwks_url {
            return Err(Error::Server(
                "Keycloak discovery JWKS URI mismatch".to_string(),
            ));
        }
        Ok(metadata)
    }

    async fn complete(&self, state: OAuth2State, code: &str) -> Result<Completion> {
        if state.provider_id != "keycloak" {
            return Err(Error::Forbidden(
                "invalid Keycloak callback state".to_string(),
            ));
        }
        let flow = decode_pending_flow(state.success_url.as_deref())?;
        let metadata = self.discover().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.callback_url.as_str()),
            ("client_id", self.config.client_id.as_str()),
            (
                "code_verifier",
                state.code_verifier.as_deref().unwrap_or_default(),
            ),
        ];
        if let Some(secret) = self.config.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        let response = self
            .client
            .post(metadata.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|_| Error::Server("Keycloak token endpoint unavailable".to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Server(
                "Keycloak token endpoint refused callback".to_string(),
            ));
        }
        let token = response.json::<TokenResponse>().await.map_err(|_| {
            Error::Server("Keycloak token endpoint returned invalid response".to_string())
        })?;
        let claims = self.validate_id_token(&token.id_token).await?;
        if claims.nonce != state.nonce {
            return Err(Error::Forbidden(
                "Keycloak ID token nonce mismatch".to_string(),
            ));
        }
        match flow {
            PendingFlow::Device { device_code } => {
                let store = DbDeviceCodeStore::new(self.repo.clone());
                let approved = store
                    .approve_pending(&device_code, &claims.sub)
                    .await
                    .map_err(|_| {
                        Error::Server("failed to approve device authorization".to_string())
                    })?;
                if !approved {
                    return Err(Error::Forbidden(
                        "device authorization is no longer pending".to_string(),
                    ));
                }
                Ok(Completion::Device)
            }
            PendingFlow::Browser(target) => {
                let ttl = self.config.browser_session_ttl_seconds;
                let project_id = match target.project_id {
                    Some(project_id) => project_id,
                    None => self
                        .repo
                        .find_default_project_id(&claims.sub)
                        .await?
                        .ok_or(Error::NotFound)?,
                };
                let context = self
                    .repo
                    .resolve_active_context(&claims.sub, &project_id)
                    .await?;
                let session = self
                    .repo
                    .create_session(NewSession {
                        id: cuid2(),
                        account_id: context.account_id,
                        project_id: context.project_id,
                        client_id: None,
                        kind: "browser".to_string(),
                        expires_at: Utc::now() + ChronoDuration::seconds(ttl),
                        subject: Some(claims.sub),
                    })
                    .await?;
                Ok(Completion::Browser {
                    resume_path: target.resume_path,
                    session_cookie: build_session_cookie(session.id, time::Duration::seconds(ttl)),
                })
            }
        }
    }

    async fn validate_id_token(&self, token: &str) -> Result<IdTokenClaims> {
        let header = decode_header(token)
            .map_err(|_| Error::Forbidden("invalid Keycloak ID token".to_string()))?;
        if header.kid.is_none() {
            return Err(Error::Forbidden(
                "Keycloak ID token missing kid".to_string(),
            ));
        }
        let mut validation = Validation::new(ACCEPTED_ALGORITHMS[0]);
        validation.algorithms = ACCEPTED_ALGORITHMS.to_vec();
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        let claims: IdTokenClaims = validate_jwt_generic(token, &self.jwks, &validation)
            .await
            .map_err(|_| Error::Forbidden("invalid Keycloak ID token".to_string()))?;
        if claims.iat <= 0 {
            return Err(Error::Forbidden("invalid Keycloak ID token".to_string()));
        }
        if matches!(&claims.aud, Audience::Multiple(audiences) if audiences.len() > 1)
            && claims.azp.as_deref() != Some(self.config.client_id.as_str())
        {
            return Err(Error::Forbidden("invalid Keycloak ID token".to_string()));
        }
        Ok(claims)
    }
}

enum Completion {
    Device,
    Browser {
        resume_path: String,
        session_cookie: Cookie<'static>,
    },
}

#[derive(Clone)]
struct RpRouteState {
    rp: Arc<KeycloakRelyingParty>,
}

pub fn router(rp: Arc<KeycloakRelyingParty>) -> Router {
    Router::new()
        .route(DEVICE_VERIFY_PATH, get(verify_page).post(verify_submit))
        .route("/device/verify/continue", post(verify_continue))
        .route(CALLBACK_PATH, get(callback))
        .with_state(RpRouteState { rp })
}

async fn verify_page(Query(query): Query<VerifyQuery>) -> Response {
    verification_response(query.user_code.as_deref(), None, None, StatusCode::OK)
}

/// Shared by [`verify_submit`] and [`verify_continue`]: rate-limits (keyed by caller IP -- see
/// [`VERIFY_RATE_LIMIT_BURST`]'s doc comment) and looks up a `user_code`, returning the live
/// `Pending` session or the exact uniform failure response both callers already returned before
/// this helper existed (deliberately identical for "unknown"/"expired"/"consumed"/anything else
/// non-pending, so the response never discloses which case applied).
async fn lookup_pending_session(
    state: &RpRouteState,
    addr: SocketAddr,
    user_code: &str,
) -> std::result::Result<DeviceCodeSession, Box<Response>> {
    let caller_key = addr.ip().to_string();
    let config = RateLimitConfig::new(VERIFY_RATE_LIMIT_BURST, VERIFY_RATE_LIMIT_REFILL_PER_SECOND);
    match get_by_user_code_rate_limited(
        &state.rp.repo,
        state.rp.rate_limiter.as_ref(),
        config,
        &caller_key,
        user_code,
    )
    .await
    {
        Ok(Some(session)) if matches!(session.status, DeviceCodeStatus::Pending) => Ok(session),
        Ok(_) => Err(Box::new(verification_response(
            None,
            None,
            Some("That code cannot be used."),
            StatusCode::NOT_FOUND,
        ))),
        Err(_) => Err(Box::new(generic_failure(StatusCode::SERVICE_UNAVAILABLE))),
    }
}

async fn verify_submit(
    State(state): State<RpRouteState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(form): Form<VerifyForm>,
) -> Response {
    let session = match lookup_pending_session(&state, addr, &form.user_code).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    // Bind this confirmation page to the `user_code` it displayed (CSRF fix): `verify_continue`
    // below requires this exact cookie, proving the caller's browser actually rendered this page
    // -- not merely that some cross-site page auto-submitted a `POST` naming an arbitrary code.
    // See `verify_continue`'s doc comment for the full attack this closes.
    let confirm_cookie = match build_device_confirm_cookie(&session.user_code, &state.rp.state_key)
    {
        Ok(cookie) => cookie,
        Err(_) => return generic_failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    with_cookie(
        verification_response(
            Some(&session.user_code),
            Some(&session.client_id),
            Some("Confirm that this code and requesting client match your application."),
            StatusCode::OK,
        ),
        confirm_cookie,
    )
}

/// Completes device pairing. **CSRF-critical:** requires [`DEVICE_CONFIRM_COOKIE_NAME`], set only
/// by [`verify_submit`] when it rendered a confirmation page for this exact `user_code`.
///
/// Without this binding, an attacker can start their own device-code flow, then serve a page with
/// a hidden auto-submitting form `POST`ing to this route with the attacker's own `user_code`. A
/// victim with an active Keycloak SSO session who merely visits that page would silently pair the
/// attacker's device to the victim's identity -- the victim never sees the real confirmation
/// screen this route exists to require. `SameSite=Strict` on the confirm cookie (stricter than
/// [`RP_STATE_COOKIE_NAME`]'s `Lax`) means it is never attached to that cross-site auto-submit in
/// the first place; requiring it here, and cross-checking its embedded `user_code` against the
/// one freshly looked up, closes the gap even for a same-site replay of an old confirmation.
async fn verify_continue(
    State(state): State<RpRouteState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Form(form): Form<ContinueForm>,
) -> Response {
    let session = match lookup_pending_session(&state, addr, &form.user_code).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if !device_confirm_cookie_matches(&jar, &state.rp.state_key, &session.user_code) {
        return generic_failure(StatusCode::FORBIDDEN);
    }
    match state.rp.begin_device(session.device_code).await {
        Ok((location, cookie)) => with_cookie(
            (
                AppendHeaders([(header::SET_COOKIE, cookie.to_string())]),
                Redirect::to(&location),
            )
                .into_response(),
            clear_device_confirm_cookie(),
        ),
        Err(_) => generic_failure(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn callback(
    State(state): State<RpRouteState>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let clear = clear_rp_state_cookie();
    let Some(cookie) = jar.get(RP_STATE_COOKIE_NAME) else {
        return with_cookie(generic_failure(StatusCode::BAD_REQUEST), clear);
    };
    if cookie.value() != query.state {
        return with_cookie(generic_failure(StatusCode::BAD_REQUEST), clear);
    }
    let pending = match OAuth2State::decrypt(&query.state, &state.rp.state_key) {
        Ok(pending) => pending,
        Err(_) => return with_cookie(generic_failure(StatusCode::BAD_REQUEST), clear),
    };
    match state.rp.complete(pending, &query.code).await {
        Ok(Completion::Device) => with_cookie(
            verification_response(
                None,
                None,
                Some("Device paired. You can return to your application."),
                StatusCode::OK,
            ),
            clear,
        ),
        Ok(Completion::Browser {
            resume_path,
            session_cookie,
        }) => {
            let mut response = Redirect::to(&resume_path).into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&clear.to_string()).expect("cookie is a valid header value"),
            );
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&session_cookie.to_string())
                    .expect("cookie is a valid header value"),
            );
            response
        }
        Err(_) => with_cookie(generic_failure(StatusCode::BAD_GATEWAY), clear),
    }
}

fn verification_response(
    user_code: Option<&str>,
    client_id: Option<&str>,
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    let form_value = escape_html(user_code.unwrap_or_default());
    let message = message.unwrap_or("Enter the code shown by your application.");
    let confirmation = match client_id {
        Some(client_id) => format!(
            "<p>Code: <strong>{}</strong></p><p>Requesting client: <strong>{}</strong></p><form method=\"post\" action=\"/device/verify/continue\"><input type=\"hidden\" name=\"user_code\" value=\"{}\"><button type=\"submit\">Continue to Keycloak</button></form>",
            escape_html(user_code.unwrap_or_default()),
            escape_html(client_id),
            form_value,
        ),
        _ => format!(
            "<form method=\"post\" action=\"{DEVICE_VERIFY_PATH}\"><label>User code <input name=\"user_code\" value=\"{form_value}\" autocomplete=\"one-time-code\" required></label><button type=\"submit\">Continue</button></form>"
        ),
    };
    let body = format!(
        "<!doctype html><html><head><title>Device verification</title></head><body><main><h1>Verify your device</h1><p>{}</p>{confirmation}</main></body></html>",
        escape_html(message),
    );
    (
        status,
        [
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html(body),
    )
        .into_response()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn generic_failure(status: StatusCode) -> Response {
    (
        status,
        [
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Html("<!doctype html><title>Sign-in unavailable</title><p>Unable to complete sign-in. Please try again.</p>"),
    ).into_response()
}

fn with_cookie(mut response: Response, cookie: Cookie<'static>) -> Response {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).expect("cookie is a valid header value"),
    );
    response
}

fn build_rp_state_cookie(value: String) -> Cookie<'static> {
    Cookie::build((RP_STATE_COOKIE_NAME, value))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(RP_STATE_TTL_SECONDS))
        .build()
}

fn clear_rp_state_cookie() -> Cookie<'static> {
    Cookie::build((RP_STATE_COOKIE_NAME, ""))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::ZERO)
        .build()
}

/// Builds the CSRF-binding cookie [`verify_submit`] sets when it renders a confirmation page for
/// `user_code`, and [`verify_continue`] later requires. Reuses [`OAuth2State`]'s existing
/// AES-256-GCM `encrypt`/`decrypt` envelope (same primitive [`encode_pending_flow`]/
/// [`decode_pending_flow`] repurpose `success_url` for -- see their doc comment) rather than
/// introducing a second signing/encryption mechanism: `state` carries the bound `user_code`,
/// `provider_id` is [`DEVICE_CONFIRM_PROVIDER_ID`] (never `"keycloak"`, so this envelope could
/// never be mistaken for a real callback state even if it ended up on the wrong cookie), and
/// `expires_at` gets `OAuth2State::decrypt`'s existing expiry check for free.
fn build_device_confirm_cookie(user_code: &str, state_key: &[u8; 32]) -> Result<Cookie<'static>> {
    let envelope = OAuth2State {
        state: user_code.to_string(),
        nonce: None,
        code_verifier: None,
        success_url: None,
        provider_id: DEVICE_CONFIRM_PROVIDER_ID.to_string(),
        expires_at: (Utc::now() + ChronoDuration::seconds(DEVICE_CONFIRM_TTL_SECONDS)).timestamp(),
    };
    let value = envelope
        .encrypt(state_key)
        .map_err(|e| Error::Server(format!("failed to encrypt device confirmation cookie: {e}")))?;
    Ok(Cookie::build((DEVICE_CONFIRM_COOKIE_NAME, value))
        .secure(true)
        .http_only(true)
        // Stricter than `RP_STATE_COOKIE_NAME`'s `Lax` deliberately: this cookie only needs to
        // travel on a same-origin `POST` from the confirmation page's own form, never on a
        // cross-site top-level navigation the way the Keycloak-redirect-return RP-state cookie
        // does. `Strict` means browsers withhold it on exactly the cross-site auto-submitting-form
        // request this cookie exists to defeat.
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(DEVICE_CONFIRM_TTL_SECONDS))
        .build())
}

fn clear_device_confirm_cookie() -> Cookie<'static> {
    Cookie::build((DEVICE_CONFIRM_COOKIE_NAME, ""))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::ZERO)
        .build()
}

/// True when `jar` carries a live [`DEVICE_CONFIRM_COOKIE_NAME`] cookie whose embedded
/// `user_code` matches `expected_user_code` exactly. Both sides compare the canonical,
/// already-normalized `user_code` off a fresh `DeviceCodeSession` lookup (never the raw form
/// input), so casing/whitespace differences between what the cookie was minted with and what the
/// current request submitted can never cause a false mismatch.
fn device_confirm_cookie_matches(
    jar: &CookieJar,
    state_key: &[u8; 32],
    expected_user_code: &str,
) -> bool {
    let Some(cookie) = jar.get(DEVICE_CONFIRM_COOKIE_NAME) else {
        return false;
    };
    match OAuth2State::decrypt(cookie.value(), state_key) {
        Ok(envelope) => {
            envelope.provider_id == DEVICE_CONFIRM_PROVIDER_ID
                && envelope.state == expected_user_code
        }
        Err(_) => false,
    }
}

/// Encodes the post-authentication continuation (which device code to approve, or which browser
/// session/resume path to mint) into [`OAuth2State::success_url`].
///
/// **This repurposes a field `authkestra_engine` documents as "Optional redirect URL to go back
/// to after flow completion" (a plain URL string) to instead carry an arbitrary JSON
/// [`PendingFlow`] payload.** That works today, safely, only because `success_url` is an
/// unconstrained `Option<String>` inside an already-encrypted, already-integrity-checked envelope
/// (`OAuth2State::encrypt`/`decrypt`, AES-256-GCM) -- `authkestra_engine` itself never inspects or
/// parses `success_url`'s contents, only stores and returns it verbatim, so this crate is the only
/// reader that ever needs the value to mean anything in particular. It is a real design smell
/// (silently violating a dependency-owned field's documented contract), not a fix for this PR:
/// properly resolving it means either forking/patching `authkestra_engine` to add a real
/// "arbitrary continuation payload" field, or replacing `OAuth2State` with a different
/// state-passing mechanism entirely, both larger than this change's scope. Flagged here so a
/// future reader hitting this is not confused about why it works.
fn encode_pending_flow(flow: &PendingFlow) -> Result<String> {
    serde_json::to_string(flow)
        .map_err(|e| Error::Server(format!("failed to serialize pending Keycloak flow: {e}")))
}

/// Inverse of [`encode_pending_flow`] -- see that function's doc comment for the `success_url`
/// repurposing this decodes.
fn decode_pending_flow(value: Option<&str>) -> Result<PendingFlow> {
    value
        .ok_or_else(|| Error::Forbidden("Keycloak callback has no pending flow".to_string()))
        .and_then(|value| {
            serde_json::from_str(value)
                .map_err(|_| Error::Forbidden("invalid Keycloak callback state".to_string()))
        })
}

/// Rejects a browser resume path unless it is a same-origin, absolute path: must start with `/`,
/// and its second character must not be `/` or `\`. Blocking only a bare leading `//` (the
/// "protocol-relative URL" bypass) is not enough on its own -- WHATWG URL parsing (what every
/// browser actually implements) treats `\` identically to `/` when resolving a relative reference
/// against an http(s) base, so `/\evil.com` normalizes to the same off-origin redirect as
/// `//evil.com` even though `starts_with("//")` alone does not catch it. A single leading `\`
/// alone is already rejected by the `starts_with('/')` requirement, so only the second-character
/// case needs an explicit check here.
fn is_unsafe_resume_path(path: &str) -> bool {
    let mut chars = path.chars();
    match chars.next() {
        Some('/') => matches!(chars.next(), Some('/') | Some('\\')),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_origin_absolute_paths_are_safe() {
        assert!(!is_unsafe_resume_path("/browser"));
        assert!(!is_unsafe_resume_path("/"));
        assert!(!is_unsafe_resume_path("/a/b?c=d"));
    }

    #[test]
    fn relative_and_scheme_relative_paths_are_unsafe() {
        assert!(is_unsafe_resume_path("browser"));
        assert!(is_unsafe_resume_path(""));
        assert!(is_unsafe_resume_path("https://evil.com"));
    }

    #[test]
    fn protocol_relative_slash_slash_is_unsafe() {
        assert!(is_unsafe_resume_path("//evil.com"));
    }

    #[test]
    fn backslash_variants_that_browsers_treat_as_slash_are_unsafe() {
        // WHATWG URL parsing treats `\` exactly like `/` when resolving a relative reference
        // against an http(s) base -- these all normalize to an off-origin redirect in a real
        // browser even though a plain `starts_with("//")` check does not see them as such.
        assert!(is_unsafe_resume_path("/\\evil.com"));
        assert!(is_unsafe_resume_path("/\\/evil.com"));
        assert!(is_unsafe_resume_path("\\\\evil.com"));
    }
}

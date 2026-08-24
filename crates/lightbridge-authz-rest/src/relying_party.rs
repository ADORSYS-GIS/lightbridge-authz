//! Keycloak OIDC relying-party leg shared by device verification and browser SSO.

use std::sync::Arc;
use std::time::Duration;

use authkestra_engine::{
    auth::{discovery::ProviderMetadata, pkce::Pkce, state::OAuth2State},
    token::Audience,
};
use authkestra_op::device::DeviceCodeStore;
use authkestra_resource::jwt::{JwksCache, ValidationConfig, validate_jwt_generic};
use axum::extract::{Form, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Router, response::AppendHeaders};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, Validation, decode_header};
use lightbridge_authz_api_key::entities::session_row::NewSession;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::OidcRelyingParty;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::oauth2_op::device_store::DbDeviceCodeStore;
use crate::session_cookie::build_session_cookie;

const CALLBACK_PATH: &str = "/idp/callback";
const DEVICE_VERIFY_PATH: &str = "/device/verify";
const RP_STATE_COOKIE_NAME: &str = "__Host-authz_rp_state";
const RP_STATE_TTL_SECONDS: i64 = 600;
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; frame-ancestors 'none'";
const ACCEPTED_ALGORITHMS: [Algorithm; 1] = [Algorithm::RS256];
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct KeycloakRelyingParty {
    config: OidcRelyingParty,
    callback_url: String,
    state_key: [u8; 32],
    client: reqwest::Client,
    jwks: Arc<JwksCache>,
    jwks_url: String,
    repo: Arc<StoreRepo>,
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
    pub project_id: String,
    pub resume_path: String,
}

impl KeycloakRelyingParty {
    pub fn new(config: OidcRelyingParty, jwks_url: String, repo: Arc<StoreRepo>) -> Result<Self> {
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
        let validation_config = ValidationConfig::builder()
            .jwks_url(jwks_url.clone())
            .refresh_interval(JWKS_REFRESH_INTERVAL)
            .issuer(config.issuer.clone())
            .audience(config.client_id.clone())
            .algorithms(ACCEPTED_ALGORITHMS.to_vec())
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
        })
    }

    pub async fn begin_device(&self, device_code: String) -> Result<(String, Cookie<'static>)> {
        self.begin(PendingFlow::Device { device_code }).await
    }

    pub async fn begin_browser(
        &self,
        target: BrowserLoginTarget,
    ) -> Result<(String, Cookie<'static>)> {
        if !target.resume_path.starts_with('/') || target.resume_path.starts_with("//") {
            return Err(Error::BadRequest(
                "browser resume path must be same-origin".to_string(),
            ));
        }
        self.begin(PendingFlow::Browser(target)).await
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
                let context = self
                    .repo
                    .resolve_context(&claims.sub, &target.project_id)
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

async fn verify_submit(
    State(state): State<RpRouteState>,
    Form(form): Form<VerifyForm>,
) -> Response {
    let store = DbDeviceCodeStore::new(state.rp.repo.clone());
    let session = match store.get_by_user_code(&form.user_code).await {
        Ok(Some(session))
            if matches!(
                session.status,
                authkestra_op::device::DeviceCodeStatus::Pending
            ) =>
        {
            session
        }
        Ok(_) => {
            return verification_response(
                None,
                None,
                Some("That code cannot be used."),
                StatusCode::NOT_FOUND,
            );
        }
        Err(_) => return generic_failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    verification_response(
        Some(&session.user_code),
        Some(&session.client_id),
        Some("Confirm that this code and requesting client match your application."),
        StatusCode::OK,
    )
}

async fn verify_continue(
    State(state): State<RpRouteState>,
    Form(form): Form<ContinueForm>,
) -> Response {
    let store = DbDeviceCodeStore::new(state.rp.repo.clone());
    let session = match store.get_by_user_code(&form.user_code).await {
        Ok(Some(session))
            if matches!(
                session.status,
                authkestra_op::device::DeviceCodeStatus::Pending
            ) =>
        {
            session
        }
        Ok(_) => {
            return verification_response(
                None,
                None,
                Some("That code cannot be used."),
                StatusCode::NOT_FOUND,
            );
        }
        Err(_) => return generic_failure(StatusCode::SERVICE_UNAVAILABLE),
    };
    match state.rp.begin_device(session.device_code).await {
        Ok((location, cookie)) => (
            AppendHeaders([(header::SET_COOKIE, cookie.to_string())]),
            Redirect::to(&location),
        )
            .into_response(),
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

fn encode_pending_flow(flow: &PendingFlow) -> Result<String> {
    serde_json::to_string(flow)
        .map_err(|e| Error::Server(format!("failed to serialize pending Keycloak flow: {e}")))
}

fn decode_pending_flow(value: Option<&str>) -> Result<PendingFlow> {
    value
        .ok_or_else(|| Error::Forbidden("Keycloak callback has no pending flow".to_string()))
        .and_then(|value| {
            serde_json::from_str(value)
                .map_err(|_| Error::Forbidden("invalid Keycloak callback state".to_string()))
        })
}

fn random_urlsafe(bytes: usize) -> String {
    use rand_core::{OsRng, RngCore};
    let mut value = vec![0; bytes];
    OsRng.fill_bytes(&mut value);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

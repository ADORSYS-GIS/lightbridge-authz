//! `POST /oauth2/token` -- ADR-0011 phase 2. Hand-wires
//! `authkestra_op::handlers::token::handle_token` (client authentication, grant dispatch) into
//! axum rather than taking a dependency on `authkestra-axum`: that crate's `FromRef` bounds pull
//! in its own `AxumError` wrapper and `tower_cookies` plus a full slate of handlers this service
//! never routes (`/authorize`, `/device_authorization`, `/userinfo`, enrolment). The handler below
//! is the ~15 lines that setup actually needs.
//!
//! Everything grant-type-specific (client auth already lives in `handle_token` itself; exchange/
//! refresh minting lives in `oauth2_op::store::TokenExchangeOpStore`) -- this module is purely the
//! HTTP boundary: request/response shapes and the `TokenErrorResponse.error` string -> `StatusCode`
//! mapping RFC 6749 §5.2 leaves to the server.

use std::sync::Arc;

use authkestra_op::client::{ClientRegistration, ClientStore, TokenEndpointAuthMethod};
use authkestra_op::client_assertion::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, peek_client_assertion_subject, verify_client_assertion,
};
use authkestra_op::config::OpConfig;
use authkestra_op::handlers::token::{
    TokenErrorResponse as AkTokenErrorResponse, TokenRequest as AkTokenRequest,
    TokenResponse as AkTokenResponse, handle_token,
};
use axum::{
    Form, Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::oauth2_op::store::{RequestScopedOpStore, TokenExchangeOpStore};
use crate::signing::ApiKeyJwtSigner;

/// The exchange and refresh values are also referenced from `crate::signing::discovery_document`.
/// Device authorization remains deliberately undiscoverable until the dedicated discovery work.
pub(crate) const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub(crate) const REFRESH_TOKEN_GRANT: &str = "refresh_token";
pub(crate) const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Everything the native token-exchange endpoint needs: the self-signed-JWT signer (used only to
/// build the per-request `TokenManager` `handle_token` requires), the OP-level config discovery
/// also reads, and the shared `OpStore` implementation.
#[derive(Clone)]
pub struct TokenExchangeState {
    signer: ApiKeyJwtSigner,
    op_config: OpConfig,
    op_store: Arc<TokenExchangeOpStore>,
    device_verification_uri: String,
    device_code_ttl_secs: u64,
    device_poll_interval_secs: u64,
    cors_origins: Arc<Vec<String>>,
}

impl TokenExchangeState {
    pub fn new(
        signer: ApiKeyJwtSigner,
        op_config: OpConfig,
        op_store: Arc<TokenExchangeOpStore>,
        device_verification_uri: String,
        device_code_ttl_secs: u64,
        device_poll_interval_secs: u64,
    ) -> Self {
        Self {
            signer,
            op_config,
            op_store,
            device_verification_uri,
            device_code_ttl_secs,
            device_poll_interval_secs,
            cors_origins: Arc::new(Vec::new()),
        }
    }

    pub fn with_cors_origins(mut self, cors_origins: Vec<String>) -> Self {
        self.cors_origins = Arc::new(cors_origins);
        self
    }

    pub(crate) fn op_config(&self) -> &OpConfig {
        &self.op_config
    }

    pub(crate) fn op_store(&self) -> &TokenExchangeOpStore {
        self.op_store.as_ref()
    }

    fn allows_cors_origin(&self, origin: &str) -> bool {
        self.cors_origins.iter().any(|allowed| allowed == origin)
    }
}

/// Public `/oauth2/token` and `/oauth2/revoke` routes. Public because the presented
/// `subject_token`/`refresh_token`/`client_assertion`/revocation `token` is itself the credential
/// -- no bearer middleware. Provides its own state so it merges into any parent router.
///
/// `/oauth2/revoke` (RFC 7009) is mounted here, not discoverable, and not dormant: it is live and
/// functional the moment this router is merged in, it is simply absent from
/// `/.well-known/openid-configuration` because `authkestra_op::handlers::discovery::OidcDiscovery`
/// has no `revocation_endpoint` field to advertise it in -- see `signing::discovery_document`'s
/// doc comment for the filed upstream issue.
pub fn token_exchange_router<S>(state: TokenExchangeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/oauth2/token",
            post(token_endpoint).layer(middleware::from_fn(apply_token_response_headers)),
        )
        .route("/oauth2/token", axum::routing::options(token_preflight))
        .route(
            "/oauth2/device_authorization",
            post(device_authorization_endpoint),
        )
        .route("/oauth2/revoke", post(revoke_endpoint))
        .route("/oauth2/introspect", post(introspect_endpoint))
        .with_state(state)
}

/// Mirrors `authkestra_op::handlers::token::TokenRequest` field-for-field, plus `project_id`: an
/// extension to the request this service needs (which project's context to seal into the
/// exchanged token) that is not part of RFC 8693 and has no home on the upstream type. See
/// `oauth2_op::store::RequestScopedOpStore` for how it reaches the exchange grant despite that.
#[derive(Debug, Deserialize, Clone)]
struct RawTokenRequest {
    grant_type: String,
    code: Option<String>,
    device_code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
    scope: Option<String>,
    refresh_token: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    actor_token: Option<String>,
    actor_token_type: Option<String>,
    requested_token_type: Option<String>,
    audience: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
    project_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationRequest {
    client_id: Option<String>,
    scope: Option<String>,
    project_id: Option<String>,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}

#[derive(Serialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

impl From<RawTokenRequest> for AkTokenRequest {
    fn from(raw: RawTokenRequest) -> Self {
        AkTokenRequest {
            grant_type: raw.grant_type,
            code: raw.code,
            device_code: raw.device_code,
            redirect_uri: raw.redirect_uri,
            client_id: raw.client_id,
            client_secret: raw.client_secret,
            code_verifier: raw.code_verifier,
            scope: raw.scope,
            refresh_token: raw.refresh_token,
            subject_token: raw.subject_token,
            subject_token_type: raw.subject_token_type,
            actor_token: raw.actor_token,
            actor_token_type: raw.actor_token_type,
            requested_token_type: raw.requested_token_type,
            audience: raw.audience,
            client_assertion: raw.client_assertion,
            client_assertion_type: raw.client_assertion_type,
        }
    }
}

/// Token response. `issued_token_type` is retained only when a grant, such as RFC 8693 token
/// exchange, requires it; RFC 8628 responses must not advertise an exchange-token type.
#[derive(Serialize)]
struct TokenResponseBody {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

async fn token_endpoint(
    State(state): State<TokenExchangeState>,
    headers: HeaderMap,
    Form(raw): Form<RawTokenRequest>,
) -> Response {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if raw.grant_type == DEVICE_CODE_GRANT {
        return cors_response(
            device_token_endpoint(state.clone(), headers, raw).await,
            origin.as_deref(),
            &state,
        );
    }
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let project_id = raw.project_id.clone();
    let req: AkTokenRequest = raw.into();

    let tokens = match state.signer.token_manager().await {
        Ok(tokens) => tokens,
        Err(_) => {
            return cors_response(
                oauth_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "signing key unavailable",
                ),
                origin.as_deref(),
                &state,
            );
        }
    };

    let scoped = RequestScopedOpStore {
        inner: state.op_store.as_ref(),
        project_id,
    };

    let binding = if req.grant_type == "authorization_code" {
        match (&req.code, &req.client_id, &req.redirect_uri) {
            (Some(code), Some(client_id), Some(redirect_uri)) => state
                .op_store
                .authorization_code_matches_binding(code, client_id, redirect_uri)
                .await
                .map(Some),
            _ => Ok(Some(false)),
        }
    } else {
        Ok(None)
    };
    let response = match binding {
        Ok(Some(false)) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code is invalid",
        ),
        Err(_) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "authorization-code storage unavailable",
        ),
        Ok(_) => match handle_token(req, auth_header, &state.op_config, &scoped, &tokens).await {
            Ok(resp) => success_response(resp),
            Err(err) => error_response(&err),
        },
    };
    cors_response(response, origin.as_deref(), &state)
}

async fn device_authorization_endpoint(
    State(state): State<TokenExchangeState>,
    headers: HeaderMap,
    Form(request): Form<DeviceAuthorizationRequest>,
) -> Response {
    if headers.contains_key(header::AUTHORIZATION)
        || request
            .client_secret
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || request.client_assertion.is_some()
        || request.client_assertion_type.is_some()
    {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "device clients must not present a client credential",
        );
    }
    let Some(client_id) = request
        .client_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };
    let session = match state
        .op_store
        .create_device_authorization(
            client_id,
            request.scope.as_deref(),
            request.project_id.as_deref(),
        )
        .await
    {
        Ok(session) => session,
        Err(error) => return error_response(&error),
    };
    let mut complete = match reqwest::Url::parse(&state.device_verification_uri) {
        Ok(url) => url,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "device verification URI is invalid",
            );
        }
    };
    complete
        .query_pairs_mut()
        .append_pair("user_code", &session.user_code);
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(DeviceAuthorizationResponse {
            device_code: session.device_code,
            user_code: session.user_code,
            verification_uri: state.device_verification_uri,
            verification_uri_complete: complete.to_string(),
            expires_in: state.device_code_ttl_secs,
            interval: state.device_poll_interval_secs,
        }),
    )
        .into_response()
}

async fn device_token_endpoint(
    state: TokenExchangeState,
    headers: HeaderMap,
    request: RawTokenRequest,
) -> Response {
    if headers.contains_key(header::AUTHORIZATION)
        || request
            .client_secret
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || request.client_assertion.is_some()
        || request.client_assertion_type.is_some()
    {
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "device clients must not present a client credential",
        );
    }
    let Some(client_id) = request
        .client_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id is required",
        );
    };
    let Some(device_code) = request
        .device_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device_code is required",
        );
    };
    let tokens = match state.signer.token_manager().await {
        Ok(tokens) => tokens,
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "signing key unavailable",
            );
        }
    };
    match state
        .op_store
        .poll_device_grant(client_id, device_code, &tokens)
        .await
    {
        Ok(response) => success_response(response),
        Err(error) => error_response(&error),
    }
}

fn success_response(resp: AkTokenResponse) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(TokenResponseBody {
            access_token: resp.access_token,
            token_type: resp.token_type,
            expires_in: resp.expires_in,
            issued_token_type: resp.issued_token_type,
            refresh_token: resp.refresh_token,
            scope: resp.scope,
            id_token: resp.id_token,
        }),
    )
        .into_response()
}

/// RFC 6749 §5.1 and §5.2 require both directives on every token-endpoint response containing
/// credentials or their error details. Applying them as route middleware also covers extractor
/// rejections before [`token_endpoint`] runs.
async fn apply_token_response_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn error_response(err: &AkTokenErrorResponse) -> Response {
    oauth_error(
        status_for_oauth_error(&err.error),
        &err.error,
        &err.error_description,
    )
}

/// RFC 6749 §5.2 error body.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

async fn token_preflight(State(state): State<TokenExchangeState>, headers: HeaderMap) -> Response {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    cors_response(StatusCode::NO_CONTENT.into_response(), origin, &state)
}

fn cors_response(
    mut response: Response,
    origin: Option<&str>,
    state: &TokenExchangeState,
) -> Response {
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin.filter(|origin| state.allows_cors_origin(origin))
        && let Ok(value) = HeaderValue::from_str(origin)
    {
        response
            .headers_mut()
            .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("POST"),
        );
        response.headers_mut().insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("content-type"),
        );
    }
    response
}

/// `TokenErrorResponse` carries no HTTP status (`authkestra_op::handlers::token`'s own type
/// docs it as opaque to transport), so this is the one place that decides it, from the `error`
/// string alone. `invalid_client`/`invalid_token` map to 401 (client-authentication failures);
/// `access_denied` (non-member project, an authorization outcome, not an authentication one)
/// maps to 403; `server_error` maps to 500; everything else RFC 6749 §5.2 defines
/// (`invalid_request` -- including subject_token validation failures, which use this
/// token-endpoint convention rather than RFC 6750's resource-server `invalid_token` -- plus
/// `invalid_grant`, `invalid_scope`, `unsupported_grant_type`, `unauthorized_client`,
/// `invalid_target`) maps to 400.
fn status_for_oauth_error(error: &str) -> StatusCode {
    match error {
        "invalid_client" | "invalid_token" => StatusCode::UNAUTHORIZED,
        "access_denied" => StatusCode::FORBIDDEN,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

// --- RFC 7009 OAuth 2.0 Token Revocation (`POST /oauth2/revoke`) -----------------------------
//
// Only refresh tokens are ever revocable here: access tokens are stateless self-signed JWTs with
// no server-side record to flip, so a presented access token (or `token_type_hint=access_token`)
// simply never matches a row below -- indistinguishable, on the wire, from an unknown token. RFC
// 7009 §2.1 explicitly allows a server to ignore `token_type_hint` "particularly if it is able to
// detect the token type automatically", which describes this deployment exactly: there is only
// one revocable token type to look up, so the hint changes nothing about how the lookup runs.

/// RFC 7009 §2.1 request body.
#[derive(Debug, Deserialize)]
struct RevokeRequest {
    token: Option<String>,
    #[serde(default)]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}

/// The client-authentication credential a `/oauth2/revoke` request presents. A mirror of
/// `authkestra_op::handlers::token::PresentedCredential` (`pub(crate)` to `authkestra-op`, and so
/// unreachable from this crate), narrowed to the two methods any client registered in this
/// deployment ever uses -- see `oauth2_op::client_store::to_registration`: every configured
/// client is `NoAuth` (public) or `PrivateKeyJwt` (confidential), and `client_secret_hash` is
/// always `None`, so a presented `client_secret` (Basic or POST) can never verify regardless of
/// which registration it is checked against. `Secret` exists so a presented-but-doomed-to-fail
/// secret is still routed through the same "at most one credential" and "unknown method ->
/// invalid_client" logic real upstream code applies, rather than silently ignored.
enum PresentedCredential {
    NoCredential,
    Secret { client_id: Option<String> },
    Assertion(String),
}

/// A `/oauth2/revoke` failure, kept small and `Response`-free until the final conversion at the
/// handler boundary (`EndpointAuthError::into_response`) -- returning `axum::response::Response`
/// directly from a `Result::Err` trips `clippy::result_large_err` (a `Response` is well over the
/// 128-byte threshold), the same reason `authkestra_op::handlers::token`'s own error path uses a
/// small `TokenErrorResponse` struct instead of building a `Response` early.
struct EndpointAuthError {
    status: StatusCode,
    error: &'static str,
    description: String,
}

impl EndpointAuthError {
    fn new(status: StatusCode, error: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            error,
            description: description.into(),
        }
    }

    fn into_response(self) -> Response {
        oauth_error(self.status, self.error, &self.description)
    }
}

fn invalid_client() -> EndpointAuthError {
    EndpointAuthError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "Client authentication failed",
    )
}

/// Mirrors `authkestra_op::handlers::token::extract_credential` for the subset of
/// [`PresentedCredential`] this deployment's clients ever present. Returns `Err` for a malformed
/// *request* -- more than one credential presented at once (RFC 6749 §2.3 / RFC 7521 §4.2), or a
/// `client_assertion` with a missing/wrong `client_assertion_type` -- which is distinct from a
/// malformed *token value*, the case RFC 7009 §2.2 requires to be a bare 200 (see
/// `revoke_endpoint`).
fn extract_presented_credential(
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
    auth_header: Option<&str>,
) -> Result<PresentedCredential, EndpointAuthError> {
    let basic = auth_header
        .and_then(|auth| auth.strip_prefix("Basic "))
        .and_then(|stripped| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(stripped)
                .ok()
        })
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|creds| creds.split_once(':').map(|(id, _secret)| id.to_string()));

    let post = client_secret.filter(|s| !s.is_empty()).map(str::to_string);

    let assertion = match client_assertion {
        Some(assertion) => match client_assertion_type {
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER) => Some(assertion.to_string()),
            _ => {
                return Err(EndpointAuthError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("client_assertion_type must be {CLIENT_ASSERTION_TYPE_JWT_BEARER}"),
                ));
            }
        },
        None => None,
    };

    let presented =
        u8::from(basic.is_some()) + u8::from(post.is_some()) + u8::from(assertion.is_some());
    if presented > 1 {
        return Err(EndpointAuthError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Only one client authentication method may be used per request",
        ));
    }

    Ok(match (basic, post, assertion) {
        (Some(client_id), _, _) => PresentedCredential::Secret {
            client_id: Some(client_id),
        },
        (_, Some(_), _) => PresentedCredential::Secret { client_id: None },
        (_, _, Some(assertion)) => PresentedCredential::Assertion(assertion),
        (None, None, None) => PresentedCredential::NoCredential,
    })
}

/// Mirrors `authkestra_op::handlers::token::resolve_client_id`.
fn resolve_presented_client_id(
    req_client_id: Option<&str>,
    credential: &PresentedCredential,
) -> Option<String> {
    match credential {
        PresentedCredential::Secret {
            client_id: Some(id),
        } => Some(id.clone()),
        PresentedCredential::Assertion(assertion) => req_client_id
            .map(str::to_string)
            .or_else(|| peek_client_assertion_subject(assertion)),
        _ => req_client_id.map(str::to_string),
    }
}

/// Mirrors `authkestra_op::handlers::token::authenticate_client` for the two methods any client
/// in this deployment ever registers (see [`PresentedCredential`]'s doc comment). Any other
/// combination -- a presented secret, or a method/credential mismatch -- is an authentication
/// failure. This is the one case RFC 7009 §2.2 carves out as NOT a bare 200: client-authentication
/// failure is the only outcome this endpoint reports as an error.
async fn authenticate_presented_client(
    client: &ClientRegistration,
    credential: &PresentedCredential,
    op_config: &OpConfig,
    op_store: &TokenExchangeOpStore,
) -> Result<(), EndpointAuthError> {
    match (client.token_endpoint_auth_method, credential) {
        (Some(TokenEndpointAuthMethod::NoAuth), PresentedCredential::NoCredential) => Ok(()),
        (
            Some(TokenEndpointAuthMethod::PrivateKeyJwt),
            PresentedCredential::Assertion(assertion),
        ) => {
            let verified = verify_client_assertion(
                assertion,
                client,
                &[op_config.token_endpoint(), op_config.issuer.clone()],
            )
            .map_err(|_| invalid_client())?;
            match op_store
                .record_client_assertion_jti(&verified.jti, verified.expires_at)
                .await
            {
                Ok(true) => Ok(()),
                Ok(false) => {
                    tracing::warn!(
                        client_id = %client.client_id,
                        "client assertion jti has already been spent -- replay refused"
                    );
                    Err(invalid_client())
                }
                Err(_) => Err(EndpointAuthError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "internal error",
                )),
            }
        }
        _ => Err(invalid_client()),
    }
}

/// `POST /oauth2/revoke` (RFC 7009). Client authentication mirrors the token endpoint's own
/// (`handle_token`'s `extract_credential`/`resolve_client_id`/`authenticate_client`, all
/// `pub(crate)` to `authkestra-op` and so unreachable from this crate -- mirrored above instead
/// of reimplemented from scratch for their full generality, narrowed to the methods this
/// deployment's clients actually register).
///
/// RFC 7009 §2.2, the counter-intuitive part: an unknown, already-revoked, or malformed *token*
/// always gets `200 OK` with an empty body -- never an error -- so this endpoint can never be
/// used as an oracle to probe whether a given token string is currently valid. The ONLY error
/// this handler ever returns is client-authentication failure (missing/invalid credential, or an
/// unknown client), which happens entirely before the token itself is even looked up. A missing
/// `token` form field is a malformed *request*, not a malformed *token value*, so that alone is
/// `invalid_request` (400) -- RFC 7009 §2.1 marks `token` REQUIRED.
async fn revoke_endpoint(
    State(state): State<TokenExchangeState>,
    headers: HeaderMap,
    Form(raw): Form<RevokeRequest>,
) -> Response {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(token) = raw.token.as_deref().filter(|s| !s.trim().is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is required",
        );
    };
    // Accepted per RFC 7009 §2.1's request shape, deliberately not branched on -- see this
    // module's header comment for why the hint changes nothing about how the lookup runs.
    tracing::debug!(
        token_type_hint = raw.token_type_hint.as_deref().unwrap_or("none"),
        "revocation request received"
    );

    let credential = match extract_presented_credential(
        raw.client_secret.as_deref(),
        raw.client_assertion.as_deref(),
        raw.client_assertion_type.as_deref(),
        auth_header,
    ) {
        Ok(credential) => credential,
        Err(err) => return err.into_response(),
    };

    let Some(client_id) = resolve_presented_client_id(raw.client_id.as_deref(), &credential) else {
        return invalid_client().into_response();
    };

    let client = match state.op_store.find_client(&client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return invalid_client().into_response(),
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            );
        }
    };

    if let Err(err) =
        authenticate_presented_client(&client, &credential, &state.op_config, &state.op_store).await
    {
        return err.into_response();
    }

    if let Err(err) = state
        .op_store
        .revoke_refresh_token_for_client(token, &client_id)
        .await
    {
        tracing::error!(error = ?err, "refresh token revocation storage failure");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "revocation failed",
        );
    }

    // RFC 7009 §2.2: success, uniformly, whether a live token was actually revoked, was already
    // dead, never existed, or belonged to a different client -- see this function's doc comment.
    StatusCode::OK.into_response()
}

// --- RFC 7662 OAuth 2.0 Token Introspection (`POST /oauth2/introspect`) ----------------------
//
// Client authentication is byte-identical to `/oauth2/revoke`'s (the shared
// `extract_presented_credential`/`resolve_presented_client_id`/`authenticate_presented_client`
// machinery above), and the same anti-oracle posture applies: RFC 7662 §2.1 requires the endpoint
// to prevent token scanning, so a token that does not verify, has expired, or was issued to a
// DIFFERENT client than the authenticated caller all collapse to the identical
// `{"active": false}` -- never an error, never a distinguishable response. The ONLY error this
// endpoint returns is client-authentication failure, exactly like revocation.
//
// Two token families are introspectable, matching what this server actually issues:
//
// - Refresh tokens: opaque DB rows (`exchange_refresh_tokens`), looked up by hash and scoped to
//   the caller's `client_id`
//   (`TokenExchangeOpStore::find_introspectable_refresh_token_for_client`), which layers the SAME
//   re-validation `handle_refresh_token` (`oauth2_op/store.rs`) applies before it will actually
//   rotate the token -- the absolute chain-expiry cap, `resolve_context` membership, and
//   `require_active_project_and_account` suspension checks -- on top of the base row lookup.
//   Without this, a token the refresh grant would itself refuse (chain expired, subject removed
//   from the project, account/project suspended) could still introspect as `active: true`, which
//   RFC 7662 forbids: introspection must report the token's real usability, not just "a row
//   exists and hasn't expired yet."
// - Access tokens: self-signed JWTs, verified against the same DB-backed JWK set
//   `/.well-known/jwks.json` serves (active + stale keys, so tokens signed by a rotated-out key
//   keep introspecting until they expire), then gated on `azp == <caller's client_id>` -- the
//   same per-client azp discriminant `handlers/exchange_token.rs`'s `verify_self_issued_token`
//   documents -- AND `typ == "Bearer"`. The `typ` check matters because `azp` alone is not a
//   token-type discriminant: `id_token_extra` (`signing.rs`) stamps the very same `azp` (the
//   requesting client's own `client_id`) on ID tokens minted alongside an access token, so an
//   `azp`-only gate would introspect a presented ID token as an active Bearer access token.
//   `access_token_extra` (`signing.rs`) is the only place that stamps `typ: "Bearer"`;
//   `id_token_extra` stamps no `typ` at all, so a genuine ID token fails this gate and falls
//   through to `inactive_token_response`. A self-signed API-key JWT's `azp` is the fixed
//   `oauth2.signing.audience` value, never a registered OAuth2 `client_id` (deployment
//   convention, see that doc comment), so API keys are structurally not introspectable here
//   regardless of who asks.

/// RFC 7662 §2.1 request body. `token_type_hint` is accepted and ignored for the same reason
/// revocation ignores it: both token families are always tried, cheapest first.
#[derive(Debug, Deserialize)]
struct IntrospectRequest {
    token: Option<String>,
    #[serde(default)]
    token_type_hint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}

/// The uniform RFC 7662 §2.2 negative response -- see the module-section comment above for every
/// case that must collapse to it.
fn inactive_token_response() -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(serde_json::json!({ "active": false })),
    )
        .into_response()
}

fn active_token_response(body: serde_json::Value) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

/// Verifies a presented access token as one of this server's own self-signed JWTs: `kid` from the
/// header, matching JWK from the DB-backed verification set, RS256 signature + `exp` via
/// `jsonwebtoken`'s defaults (`validate_aud` off -- `aud` here is the requesting client's own id,
/// not a fixed value). `jsonwebtoken`'s `Validation::new` defaults are NOT "validate every
/// standard claim": `validate_exp` is on with a 60-second leeway, but `validate_nbf` is off, so an
/// `nbf` claim (this server never mints one) would not be checked even if present. Matches
/// `handlers/exchange_token.rs`'s sibling `verify_self_issued_token`, which builds its
/// `Validation` the same way and is left alone here for consistency rather than opting this path
/// alone into `validate_nbf`. Returns the raw claims map so the introspection response can carry every
/// claim the token itself already discloses to its holder, or `None` for anything that fails --
/// indistinguishably, per the section comment above.
async fn verify_own_access_token(
    state: &TokenExchangeState,
    token: &str,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};

    let header = decode_header(token).ok()?;
    let kid = header.kid?;
    let jwks = state.op_store.list_verification_jwks().await.ok()?;
    let matching = jwks
        .into_iter()
        .find(|raw| raw.get("kid").and_then(serde_json::Value::as_str) == Some(kid.as_str()))?;
    let jwk = serde_json::from_value::<Jwk>(matching).ok()?;
    let decoding_key = DecodingKey::from_jwk(&jwk).ok()?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![Algorithm::RS256];
    validation.validate_aud = false;
    decode::<serde_json::Map<String, serde_json::Value>>(token, &decoding_key, &validation)
        .ok()
        .map(|data| data.claims)
}

/// `POST /oauth2/introspect` (RFC 7662). See the section comment above for the client-auth and
/// anti-oracle contract; advertised by `signing::discovery_document` as `introspection_endpoint`
/// the moment the token surface is mounted, because this route is mounted unconditionally right
/// beside it (`token_exchange_router`).
async fn introspect_endpoint(
    State(state): State<TokenExchangeState>,
    headers: HeaderMap,
    Form(raw): Form<IntrospectRequest>,
) -> Response {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(token) = raw.token.as_deref().filter(|s| !s.trim().is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "token is required",
        );
    };
    tracing::debug!(
        token_type_hint = raw.token_type_hint.as_deref().unwrap_or("none"),
        "introspection request received"
    );

    let credential = match extract_presented_credential(
        raw.client_secret.as_deref(),
        raw.client_assertion.as_deref(),
        raw.client_assertion_type.as_deref(),
        auth_header,
    ) {
        Ok(credential) => credential,
        Err(err) => return err.into_response(),
    };

    let Some(client_id) = resolve_presented_client_id(raw.client_id.as_deref(), &credential) else {
        return invalid_client().into_response();
    };

    let client = match state.op_store.find_client(&client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return invalid_client().into_response(),
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            );
        }
    };

    if let Err(err) =
        authenticate_presented_client(&client, &credential, &state.op_config, &state.op_store).await
    {
        return err.into_response();
    }

    let now = chrono::Utc::now();
    match state
        .op_store
        .find_introspectable_refresh_token_for_client(token, &client_id, now)
        .await
    {
        Ok(Some(row)) => {
            // No `token_type` here: RFC 7662 §2.2 lists it as OPTIONAL, and "refresh_token" is
            // not an RFC 6749 §7.1 access token type -- the field only means something for an
            // access-token response (the `"Bearer"` case below), so it is simply omitted rather
            // than populated with a value the spec never defines.
            let mut body = serde_json::Map::new();
            body.insert("active".to_string(), serde_json::Value::Bool(true));
            body.insert(
                "client_id".to_string(),
                serde_json::Value::String(row.client_id),
            );
            body.insert("sub".to_string(), serde_json::Value::String(row.subject));
            body.insert(
                "account_id".to_string(),
                serde_json::Value::String(row.account_id),
            );
            body.insert(
                "project_id".to_string(),
                serde_json::Value::String(row.project_id),
            );
            body.insert(
                "iss".to_string(),
                serde_json::Value::String(state.op_config.issuer.clone()),
            );
            if let Some(scope) = row.scope {
                body.insert("scope".to_string(), serde_json::Value::String(scope));
            }
            body.insert("iat".to_string(), row.created_at.timestamp().into());
            body.insert("exp".to_string(), row.expires_at.timestamp().into());
            body.insert("jti".to_string(), serde_json::Value::String(row.id));
            return active_token_response(serde_json::Value::Object(body));
        }
        Ok(None) => {}
        Err(_) => {
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            );
        }
    }

    match verify_own_access_token(&state, token).await {
        Some(claims)
            if claims.get("azp").and_then(serde_json::Value::as_str)
                == Some(client_id.as_str())
                && claims.get("typ").and_then(serde_json::Value::as_str) == Some("Bearer") =>
        {
            let mut body = claims;
            body.insert("active".to_string(), serde_json::Value::Bool(true));
            body.insert(
                "token_type".to_string(),
                serde_json::Value::String("Bearer".to_string()),
            );
            body.insert(
                "client_id".to_string(),
                serde_json::Value::String(client_id),
            );
            active_token_response(serde_json::Value::Object(body))
        }
        _ => inactive_token_response(),
    }
}

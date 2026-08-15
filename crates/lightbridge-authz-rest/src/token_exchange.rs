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
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::oauth2_op::ACCESS_TOKEN_TYPE;
use crate::oauth2_op::store::{RequestScopedOpStore, TokenExchangeOpStore};
use crate::signing::ApiKeyJwtSigner;

/// Also referenced from `crate::signing::discovery_document` so the discovery document's
/// `grant_types_supported` stays in lockstep with what this endpoint actually dispatches.
pub(crate) const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub(crate) const REFRESH_TOKEN_GRANT: &str = "refresh_token";

/// Everything the native token-exchange endpoint needs: the self-signed-JWT signer (used only to
/// build the per-request `TokenManager` `handle_token` requires), the OP-level config discovery
/// also reads, and the shared `OpStore` implementation.
#[derive(Clone)]
pub struct TokenExchangeState {
    signer: ApiKeyJwtSigner,
    op_config: OpConfig,
    op_store: Arc<TokenExchangeOpStore>,
}

impl TokenExchangeState {
    pub fn new(
        signer: ApiKeyJwtSigner,
        op_config: OpConfig,
        op_store: Arc<TokenExchangeOpStore>,
    ) -> Self {
        Self {
            signer,
            op_config,
            op_store,
        }
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
        .route("/oauth2/token", post(token_endpoint))
        .route("/oauth2/revoke", post(revoke_endpoint))
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

/// RFC 8693 §2.2.1 response, plus `issued_token_type` (REQUIRED there, but absent from
/// `authkestra_op::handlers::token::TokenResponse` -- zero hits for the field in that crate).
/// Always `access_token`: this endpoint never returns any other primary token type on the wire (an
/// `id_token` rides alongside it in the same response, never as `access_token` itself).
#[derive(Serialize)]
struct TokenResponseBody {
    access_token: String,
    token_type: String,
    expires_in: u64,
    issued_token_type: &'static str,
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
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let project_id = raw.project_id.clone();
    let req: AkTokenRequest = raw.into();

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

    let scoped = RequestScopedOpStore {
        inner: state.op_store.as_ref(),
        project_id,
    };

    match handle_token(req, auth_header, &state.op_config, &scoped, &tokens).await {
        Ok(resp) => success_response(resp),
        Err(err) => error_response(&err),
    }
}

fn success_response(resp: AkTokenResponse) -> Response {
    (
        StatusCode::OK,
        Json(TokenResponseBody {
            access_token: resp.access_token,
            token_type: resp.token_type,
            expires_in: resp.expires_in,
            issued_token_type: ACCESS_TOKEN_TYPE,
            refresh_token: resp.refresh_token,
            scope: resp.scope,
            id_token: resp.id_token,
        }),
    )
        .into_response()
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
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// `TokenErrorResponse` carries no HTTP status (`authkestra_op::handlers::token`'s own type
/// docs it as opaque to transport), so this is the one place that decides it, from the `error`
/// string alone. `invalid_client`/`invalid_token` (subject_token, presented like a bearer
/// credential) map to 401; `access_denied` (non-member project, an authorization outcome, not an
/// authentication one) maps to 403; `server_error` maps to 500; everything else RFC 6749 §5.2
/// defines (`invalid_request`, `invalid_grant`, `invalid_scope`, `unsupported_grant_type`,
/// `unauthorized_client`, `invalid_target`) maps to 400.
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
enum RevokeCredential {
    NoCredential,
    Secret { client_id: Option<String> },
    Assertion(String),
}

/// A `/oauth2/revoke` failure, kept small and `Response`-free until the final conversion at the
/// handler boundary (`RevokeError::into_response`) -- returning `axum::response::Response`
/// directly from a `Result::Err` trips `clippy::result_large_err` (a `Response` is well over the
/// 128-byte threshold), the same reason `authkestra_op::handlers::token`'s own error path uses a
/// small `TokenErrorResponse` struct instead of building a `Response` early.
struct RevokeError {
    status: StatusCode,
    error: &'static str,
    description: String,
}

impl RevokeError {
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

fn invalid_client() -> RevokeError {
    RevokeError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "Client authentication failed",
    )
}

/// Mirrors `authkestra_op::handlers::token::extract_credential` for the subset of
/// [`RevokeCredential`] this deployment's clients ever present. Returns `Err` for a malformed
/// *request* -- more than one credential presented at once (RFC 6749 §2.3 / RFC 7521 §4.2), or a
/// `client_assertion` with a missing/wrong `client_assertion_type` -- which is distinct from a
/// malformed *token value*, the case RFC 7009 §2.2 requires to be a bare 200 (see
/// `revoke_endpoint`).
fn extract_revoke_credential(
    client_secret: Option<&str>,
    client_assertion: Option<&str>,
    client_assertion_type: Option<&str>,
    auth_header: Option<&str>,
) -> Result<RevokeCredential, RevokeError> {
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
                return Err(RevokeError::new(
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
        return Err(RevokeError::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Only one client authentication method may be used per request",
        ));
    }

    Ok(match (basic, post, assertion) {
        (Some(client_id), _, _) => RevokeCredential::Secret {
            client_id: Some(client_id),
        },
        (_, Some(_), _) => RevokeCredential::Secret { client_id: None },
        (_, _, Some(assertion)) => RevokeCredential::Assertion(assertion),
        (None, None, None) => RevokeCredential::NoCredential,
    })
}

/// Mirrors `authkestra_op::handlers::token::resolve_client_id`.
fn resolve_revoke_client_id(
    req_client_id: Option<&str>,
    credential: &RevokeCredential,
) -> Option<String> {
    match credential {
        RevokeCredential::Secret {
            client_id: Some(id),
        } => Some(id.clone()),
        RevokeCredential::Assertion(assertion) => req_client_id
            .map(str::to_string)
            .or_else(|| peek_client_assertion_subject(assertion)),
        _ => req_client_id.map(str::to_string),
    }
}

/// Mirrors `authkestra_op::handlers::token::authenticate_client` for the two methods any client
/// in this deployment ever registers (see [`RevokeCredential`]'s doc comment). Any other
/// combination -- a presented secret, or a method/credential mismatch -- is an authentication
/// failure. This is the one case RFC 7009 §2.2 carves out as NOT a bare 200: client-authentication
/// failure is the only outcome this endpoint reports as an error.
async fn authenticate_revoke_client(
    client: &ClientRegistration,
    credential: &RevokeCredential,
    op_config: &OpConfig,
    op_store: &TokenExchangeOpStore,
) -> Result<(), RevokeError> {
    match (client.token_endpoint_auth_method, credential) {
        (Some(TokenEndpointAuthMethod::NoAuth), RevokeCredential::NoCredential) => Ok(()),
        (Some(TokenEndpointAuthMethod::PrivateKeyJwt), RevokeCredential::Assertion(assertion)) => {
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
                Err(_) => Err(RevokeError::new(
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

    let credential = match extract_revoke_credential(
        raw.client_secret.as_deref(),
        raw.client_assertion.as_deref(),
        raw.client_assertion_type.as_deref(),
        auth_header,
    ) {
        Ok(credential) => credential,
        Err(err) => return err.into_response(),
    };

    let Some(client_id) = resolve_revoke_client_id(raw.client_id.as_deref(), &credential) else {
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
        authenticate_revoke_client(&client, &credential, &state.op_config, &state.op_store).await
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

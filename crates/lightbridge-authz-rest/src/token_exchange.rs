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

/// Public `/oauth2/token` route. Public because the presented `subject_token` (or `refresh_token`,
/// or `client_assertion`) is itself the credential -- no bearer middleware. Provides its own state
/// so it merges into any parent router.
pub fn token_exchange_router<S>(state: TokenExchangeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/oauth2/token", post(token_endpoint))
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

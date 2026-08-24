//! Browser-facing authorization endpoint for ADR-0019.

use std::collections::HashMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::client::GrantType;
use authkestra_op::handlers::{AuthorizeOutcome, AuthorizeRequest, handle_authorize};
use axum::Router;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use chrono::Utc;
use serde::Deserialize;

use crate::oauth2_op::store::RequestScopedOpStore;
use crate::relying_party::{BrowserLoginTarget, KeycloakRelyingParty};
use crate::session_cookie::read_session_cookie;
use crate::token_exchange::TokenExchangeState;

#[derive(Clone)]
pub struct AuthorizeState {
    rp: Arc<KeycloakRelyingParty>,
    token: TokenExchangeState,
}

impl AuthorizeState {
    pub fn new(rp: Arc<KeycloakRelyingParty>, token: TokenExchangeState) -> Self {
        Self { rp, token }
    }
}

#[derive(Deserialize)]
struct BrowserAuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    #[serde(default)]
    scope: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    project_id: Option<String>,
}

impl From<BrowserAuthorizeRequest> for AuthorizeRequest {
    fn from(value: BrowserAuthorizeRequest) -> Self {
        Self {
            client_id: value.client_id,
            redirect_uri: value.redirect_uri,
            response_type: value.response_type,
            scope: value.scope,
            state: value.state,
            code_challenge: value.code_challenge,
            code_challenge_method: value.code_challenge_method,
            nonce: value.nonce,
        }
    }
}

pub fn router<S>(state: AuthorizeState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/authorize", get(authorize))
        .with_state(state)
}

async fn authorize(
    State(state): State<AuthorizeState>,
    headers: axum::http::HeaderMap,
    OriginalUri(original_uri): OriginalUri,
    Query(browser_request): Query<BrowserAuthorizeRequest>,
) -> Response {
    let project_id = browser_request.project_id.clone();
    let request: AuthorizeRequest = browser_request.into();
    let client = match state
        .token
        .op_store()
        .find_client_registration(&request.client_id)
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) => return direct_error(StatusCode::BAD_REQUEST, "unknown client"),
        Err(_) => return direct_error(StatusCode::INTERNAL_SERVER_ERROR, "client lookup failed"),
    };
    if !client.allows_redirect_uri(&request.redirect_uri) {
        return direct_error(StatusCode::BAD_REQUEST, "invalid redirect_uri");
    }
    if request.response_type != "code" || !client.allows_grant_type(&GrantType::AuthorizationCode) {
        return redirect_error(
            &request,
            "unauthorized_client",
            "unsupported authorization request",
        );
    }
    if client.require_pkce
        && (request.code_challenge.is_none()
            || request.code_challenge_method.as_deref() != Some("S256"))
    {
        return redirect_error(&request, "invalid_request", "PKCE S256 is required");
    }
    if request.code_challenge.is_some() && request.code_challenge_method.as_deref() != Some("S256")
    {
        return redirect_error(&request, "invalid_request", "only PKCE S256 is supported");
    }
    if !scopes_are_allowed(
        &request.scope,
        &client.scopes,
        &state.token.op_config().scopes_supported,
    ) {
        return redirect_error(&request, "invalid_scope", "requested scope is not allowed");
    }

    let session = match read_session_cookie(&headers) {
        Some(session_id) => state
            .rp
            .find_active_browser_session(&session_id, Utc::now())
            .await
            .ok()
            .flatten(),
        None => None,
    };
    if let Some(session) = session {
        return issue_code(&state, request, session.account_id, session.project_id).await;
    }

    let Some(path_and_query) = original_uri.path_and_query() else {
        return direct_error(StatusCode::BAD_REQUEST, "invalid authorization request");
    };
    let target = BrowserLoginTarget {
        project_id,
        resume_path: path_and_query.as_str().to_owned(),
    };
    match state.rp.begin_browser(target).await {
        Ok((location, cookie)) => {
            let mut response = Redirect::temporary(&location).into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie.to_string()).expect("cookie is a valid header value"),
            );
            response
        }
        Err(_) => direct_error(StatusCode::BAD_GATEWAY, "sign-in unavailable"),
    }
}

async fn issue_code(
    state: &AuthorizeState,
    request: AuthorizeRequest,
    account_id: String,
    project_id: String,
) -> Response {
    let mut attributes = HashMap::new();
    attributes.insert("account_id".to_string(), account_id.clone());
    attributes.insert("project_id".to_string(), project_id);
    let identity = Identity {
        provider_id: "keycloak".to_string(),
        external_id: account_id,
        email: None,
        username: None,
        attributes,
    };
    let scoped = RequestScopedOpStore {
        inner: state.token.op_store(),
        project_id: None,
    };
    match handle_authorize(request, identity, state.token.op_config(), &scoped).await {
        AuthorizeOutcome::Redirect(location) => Redirect::temporary(&location).into_response(),
        AuthorizeOutcome::DirectError(_) => {
            direct_error(StatusCode::INTERNAL_SERVER_ERROR, "authorization failed")
        }
    }
}

fn scopes_are_allowed(scope: &str, client_scopes: &[String], server_scopes: &[String]) -> bool {
    scope.split_whitespace().all(|requested| {
        client_scopes.iter().any(|scope| scope == requested)
            && server_scopes.iter().any(|scope| scope == requested)
    })
}

fn direct_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        message.to_owned(),
    )
        .into_response()
}

fn redirect_error(request: &AuthorizeRequest, error: &str, description: &str) -> Response {
    let mut location = match reqwest::Url::parse(&request.redirect_uri) {
        Ok(location) => location,
        Err(_) => return direct_error(StatusCode::BAD_REQUEST, "invalid redirect_uri"),
    };
    let mut query = location.query_pairs_mut();
    query.append_pair("error", error);
    query.append_pair("error_description", description);
    if let Some(state) = &request.state {
        query.append_pair("state", state);
    }
    drop(query);
    Redirect::temporary(location.as_ref()).into_response()
}

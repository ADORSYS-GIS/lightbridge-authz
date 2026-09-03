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

use crate::authorize_session_state::{append_session_state, redirect_carries_error};
use crate::loopback::{is_loopback_redirect, issue_loopback_code};
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
        // `AuthorizeRequest` is `#[non_exhaustive]` upstream with NO constructor and no
        // `Default` -- marcjazz/authkestra#271 added constructors to code.rs/device.rs/refresh.rs/
        // token.rs/attestation.rs but missed handlers/authorize.rs, so a literal and functional-
        // update syntax are both refused cross-crate. It does derive `Deserialize`, and serde's
        // generated impl lives INSIDE that crate, so deserialization is the one construction path
        // still open to us. Replace this with `AuthorizeRequest::new(..)` the moment upstream
        // adds one -- this is a workaround for a gap, not a preferred idiom.
        serde_json::from_value(serde_json::json!({
            "client_id": value.client_id,
            "redirect_uri": value.redirect_uri,
            "response_type": value.response_type,
            "scope": value.scope,
            "state": value.state,
            "code_challenge": value.code_challenge,
            "code_challenge_method": value.code_challenge_method,
            "nonce": value.nonce,
        }))
        .expect("AuthorizeRequest is built from its own field types, so this cannot fail")
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
    let op_browser_state = crate::session_management::read_op_browser_state(&headers);
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
    // Exact registry match first; the RFC 8252 §7.3 loopback rule (`crate::loopback`) is a
    // narrow second chance for a public native app's ephemeral-port listener, never a
    // replacement. Every client that matched exactly before still matches exactly now.
    if !client.allows_redirect_uri(&request.redirect_uri)
        && !is_loopback_redirect(&client, &request.redirect_uri)
    {
        return direct_error(StatusCode::BAD_REQUEST, "invalid redirect_uri");
    }
    if request.response_type != "code" || !client.allows_grant_type(&GrantType::AuthorizationCode) {
        return redirect_error(
            &request,
            "unauthorized_client",
            "unsupported authorization request",
        );
    }
    // PKCE (RFC 7636, S256 only) is required for every authorization_code client, confidential
    // included -- OAuth 2.1 / RFC 9700 (OAuth Security BCP) recommend it for all client types, not
    // only public ones, because it defends against authorization-code injection, a threat client
    // authentication at the token endpoint does not address (that proves who redeemed the code,
    // not that the code belongs to the session redeeming it). `client.require_pkce` is validated
    // to always be `true` for authorization_code clients at startup
    // (`validate_authorization_code_clients` in `lib.rs`), but this check does not read that flag
    // at all: it is unconditional defense-in-depth, so a config that somehow reached this endpoint
    // with `require_pkce: false` still can never start a codeless-challenge authorization_code
    // flow.
    if request.code_challenge.is_none() || request.code_challenge_method.as_deref() != Some("S256")
    {
        return redirect_error(&request, "invalid_request", "PKCE S256 is required");
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
    // A session row with no persisted `subject` predates
    // `migrations/20260824000003_sessions_add_subject.sql` -- there is no real authenticated
    // subject to recover for it, so this falls through to a fresh Keycloak login below rather
    // than ever falling back to `session.account_id` for `external_id` (the identity-
    // substitution bug that column exists to fix -- see `issue_code`'s doc comment).
    if let Some(session) = session
        && let Some(subject) = session.subject.clone()
    {
        return match project_id.as_deref() {
            // The request names a DIFFERENT project than the one this session is pinned to: do
            // NOT silently issue a code scoped to `session.project_id` (the pre-fix behavior --
            // it ignored `project_id` entirely once a session existed). Re-resolve authorization
            // for the REQUESTED project against the session's real subject, applying the same
            // Active-status gate a fresh login would, and refuse outright -- rather than
            // substituting the session's own project -- when the subject isn't authorized for it.
            Some(requested) if requested != session.project_id => {
                match state
                    .rp
                    .resolve_authorized_context(&subject, requested)
                    .await
                {
                    Ok(context) => {
                        issue_code(
                            &state,
                            &client,
                            request,
                            subject,
                            context.account_id,
                            context.project_id,
                            op_browser_state.as_deref(),
                        )
                        .await
                    }
                    Err(_) => redirect_error(
                        &request,
                        "access_denied",
                        "subject is not authorized for the requested project",
                    ),
                }
            }
            _ => {
                issue_code(
                    &state,
                    &client,
                    request,
                    subject,
                    session.account_id,
                    session.project_id,
                    op_browser_state.as_deref(),
                )
                .await
            }
        };
    }

    let Some(path_and_query) = original_uri.path_and_query() else {
        return direct_error(StatusCode::BAD_REQUEST, "invalid authorization request");
    };
    let target = BrowserLoginTarget {
        project_id,
        resume_path: path_and_query.as_str().to_owned(),
        // Every refusal above has already run, including the client-registry lookup that produced
        // `client` -- so this is a REGISTERED client id, never an arbitrary query-string value,
        // by the time it can reach a `sessions` row. It travels in the encrypted `state` payload
        // and is stamped onto the browser session the RP-leg callback mints, which is how
        // `/admin/sessions` can finally name the app behind a browser login.
        client_id: request.client_id.clone(),
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

/// Mints the authorization code's underlying `Identity`. `external_id` (which ends up as the
/// eventual access/id token's JWT `sub` claim) is `subject` -- the REAL authenticated IdP
/// subject the browser session was minted for -- never `account_id`. `resolve_context`
/// (`crates/lightbridge-authz-api-key/src/repo.rs`) always resolves `account_id` to the
/// project's OWNING account, including when `subject` only holds a `project_members` roster row
/// rather than ownership; substituting `account_id` for `external_id` here would attribute a
/// non-owner member's actions to the owner's account instead of their own (the bug
/// `sessions.subject`, added by `migrations/20260824000003_sessions_add_subject.sql`, exists to
/// fix). `account_id` still rides along as its own `attributes["account_id"]` claim, matching
/// every other grant (`identity_for`/`access_token_extra` in `crates/lightbridge-authz-rest/src/signing.rs`).
async fn issue_code(
    state: &AuthorizeState,
    client: &authkestra_op::client::ClientRegistration,
    request: AuthorizeRequest,
    subject: String,
    account_id: String,
    project_id: String,
    op_browser_state: Option<&str>,
) -> Response {
    let session_state = op_browser_state.and_then(|opbs| {
        let origin = reqwest::Url::parse(&request.redirect_uri)
            .ok()
            .map(|url| url.origin().ascii_serialization())?;
        Some(crate::session_management::fresh_session_state(
            &request.client_id,
            &origin,
            opbs,
        ))
    });
    let mut attributes = HashMap::new();
    attributes.insert("account_id".to_string(), account_id);
    attributes.insert("project_id".to_string(), project_id);
    let identity = Identity {
        provider_id: "keycloak".to_string(),
        external_id: subject,
        email: None,
        username: None,
        attributes,
    };
    let scoped = RequestScopedOpStore {
        inner: state.token.op_store(),
        project_id: None,
    };
    // A loopback URI admitted by the carve-out must NOT go through `handle_authorize`: it
    // re-runs the exact-match check and would refuse it (see `crate::loopback::code`).
    let outcome = if is_loopback_redirect(client, &request.redirect_uri) {
        issue_loopback_code(client, request, identity, state.token.op_config(), &scoped).await
    } else {
        handle_authorize(request, identity, state.token.op_config(), &scoped).await
    };
    match outcome {
        AuthorizeOutcome::Redirect(location) => {
            let location = match session_state {
                Some(session_state) if !redirect_carries_error(&location) => {
                    append_session_state(&location, &session_state)
                }
                _ => location,
            };
            Redirect::temporary(&location).into_response()
        }
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

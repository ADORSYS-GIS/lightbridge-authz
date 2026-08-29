//! `GET|POST /oauth2/end_session` -- OIDC RP-Initiated Logout 1.0.
//!
//! The browser session cookie is the authority for *whose* session ends, never `id_token_hint`.
//! A hint is an unauthenticated request parameter: anyone can paste anyone's id_token. It is used
//! for one thing only -- naming the client whose *registered* `post_logout_redirect_uris` are then
//! consulted -- and never to select a victim.
//!
//! **Logout cascades to every session the subject holds, browser and token alike.** That is a
//! deliberate choice, not an overreach: this deployment has no front-channel or back-channel
//! logout, so revoking the refresh chains is the only mechanism by which ending the SSO session
//! can actually terminate the RP sessions it authorised. Leaving them alive would make logout a
//! cosmetic act -- the cookie gone, every downstream token still renewing.
//!
//! What logout does NOT do is kill an access token already in flight. Nothing consults `sessions`
//! on the resource-server path (`lightbridge-authz-bearer` validates the JWT and stops), so a
//! bearer minted seconds before logout stays valid for the remainder of
//! `token_exchange.access_ttl_seconds`. Renewal dies instantly; the current token ages out. Say so
//! plainly rather than implying logout is a kill switch it is not.
//!
//! Two failure directions, resolved opposite ways on purpose:
//!
//! - Revocation itself failing is a hard `500`. Redirecting a user to "you are logged out" while
//!   their session is live is the one outcome worse than an error page.
//! - Everything else -- no cookie, dead session, bad hint, unregistered redirect -- is a success.
//!   Logout is idempotent, and a user who is already logged out asked for the state they are in.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Form;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::OauthClient;
use lightbridge_authz_core::identity::AccountId;
use serde::Deserialize;

use crate::html_page::{page, secure_headers};
use crate::post_logout::{registry_from_clients, resolve_client_id, resolve_post_logout_redirect};
use crate::session_cookie::{clear_session_cookie, read_session_cookie};
use crate::token_exchange::{TokenExchangeState, verify_own_token};

#[derive(Clone)]
pub struct EndSessionState {
    pub repo: Arc<StoreRepo>,
    /// Only ever used to signature-verify an `id_token_hint`. This endpoint mints nothing.
    pub token: TokenExchangeState,
    /// `client_id -> post_logout_redirect_uris`, read once from config at router-build time, like
    /// `ConfigClientStore` (ADR-0011 Decision 5: clients are a config change plus redeploy).
    pub post_logout_redirect_uris: Arc<HashMap<String, Vec<String>>>,
}

impl EndSessionState {
    pub fn new(repo: Arc<StoreRepo>, token: TokenExchangeState, clients: &[OauthClient]) -> Self {
        Self {
            repo,
            token,
            post_logout_redirect_uris: Arc::new(registry_from_clients(clients)),
        }
    }
}

/// OIDC RP-Initiated Logout 1.0 §2. `logout_hint` and `ui_locales` are accepted by the spec and
/// deliberately not modelled: this OP has no account chooser to hint at and renders no localised
/// copy, so binding them to fields would advertise handling that does not exist.
#[derive(Debug, Default, Deserialize)]
pub struct EndSessionRequest {
    pub(crate) id_token_hint: Option<String>,
    pub(crate) client_id: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
}

/// Ends every session held by the cookie's subject. `Ok(false)` means there was nothing to end.
async fn revoke_current_session(state: &EndSessionState, headers: &HeaderMap) -> Result<bool, ()> {
    let Some(session_id) = read_session_cookie(headers) else {
        return Ok(false);
    };
    let session = match state
        .repo
        .find_active_browser_session(&session_id, Utc::now())
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return Ok(false),
        Err(error) => {
            tracing::error!(?error, "logout failed: session lookup");
            return Err(());
        }
    };
    // `None` only for a row predating `migrations/20260824000003_sessions_add_subject.sql`. There
    // is no safe fallback -- `account_id` is the project's OWNING account, so revoking on it would
    // log out every member of a shared project (`revoke_sessions_and_cascade`'s own comment
    // records that incident). Such rows are TTL-bounded and self-heal; clearing the cookie below
    // still ends this browser's use of it.
    let Some(subject) = session.subject else {
        tracing::warn!("logout: session row predates the subject column; clearing cookie only");
        return Ok(false);
    };
    match state
        .repo
        .revoke_sessions_and_cascade(&AccountId::assert_already_resolved(&subject))
        .await
    {
        Ok(revoked) => {
            tracing::info!(revoked, "rp-initiated logout ended the subject's sessions");
            Ok(true)
        }
        Err(error) => {
            tracing::error!(?error, "logout failed: session revocation");
            Err(())
        }
    }
}

async fn end_session(
    state: EndSessionState,
    headers: HeaderMap,
    request: EndSessionRequest,
) -> Response {
    if revoke_current_session(&state, &headers).await.is_err() {
        // No cookie clearing here, deliberately: the session is still live, and a cleared cookie
        // would leave the user believing otherwise with no way to retry.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            secure_headers(),
            page(
                "Could not sign you out",
                "<h1>Could not sign you out</h1><p>Your session is still active. Please try \
                 again.</p>",
            ),
        )
            .into_response();
    }

    // Verified for `azp` only, and with expiry ignored -- see `verify_own_token`'s doc comment for
    // why an expired hint at logout is the normal case rather than an error.
    let hint = match request.id_token_hint.as_deref() {
        Some(hint) => verify_own_token(&state.token, hint, false).await,
        None => None,
    };
    let client_id = resolve_client_id(&request, hint.as_ref());
    let redirect = resolve_post_logout_redirect(
        &state.post_logout_redirect_uris,
        client_id.as_deref(),
        request.post_logout_redirect_uri.as_deref(),
        request.state.as_deref(),
    );

    let cookie = clear_session_cookie().to_string();
    match redirect {
        Some(location) => (
            StatusCode::SEE_OTHER,
            [
                (header::LOCATION, location),
                (header::SET_COOKIE, cookie),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
        )
            .into_response(),
        None => (
            StatusCode::OK,
            secure_headers(),
            [(header::SET_COOKIE, cookie)],
            page(
                "Signed out",
                "<h1>Signed out</h1><p>Your session has ended. You can close this tab.</p>",
            ),
        )
            .into_response(),
    }
}

/// A malformed query string degrades to "no parameters" rather than `400`. Logout must be hard to
/// break: a rejection here would leave the user signed in because a redirect parameter they never
/// see was mistyped. With no parameters the cookie still ends the session; only the redirect is
/// lost, and the OP's own page says so.
async fn end_session_get(
    State(state): State<EndSessionState>,
    headers: HeaderMap,
    request: Result<Query<EndSessionRequest>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let request = request.map_or_else(|_| EndSessionRequest::default(), |Query(request)| request);
    end_session(state, headers, request).await
}

async fn end_session_post(
    State(state): State<EndSessionState>,
    headers: HeaderMap,
    form: Result<Form<EndSessionRequest>, axum::extract::rejection::FormRejection>,
) -> Response {
    let request = form.map_or_else(|_| EndSessionRequest::default(), |Form(request)| request);
    end_session(state, headers, request).await
}

/// The `/oauth2/end_session` routes, advertised by `signing::discovery_document` as
/// `end_session_endpoint`. OIDC RP-Initiated Logout 1.0 §2 requires GET and recommends POST.
pub fn router<S>(state: EndSessionState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/oauth2/end_session", get(end_session_get))
        .route("/oauth2/end_session", post(end_session_post))
        .with_state(state)
}

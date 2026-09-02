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
//! **Logout also cascades UPSTREAM, back-channel, to the Keycloak SSO session.** Without it the
//! whole act is theatre: the local sessions die, the cookie clears, and the user's very next
//! `/authorize` silently re-authenticates through a Keycloak session that never ended -- no
//! prompt, no credentials, straight back in. `KeycloakRelyingParty::end_upstream_session` POSTs
//! the stored refresh token to the discovered `end_session_endpoint`; see its doc comment for why
//! that, and not a browser redirect carrying an `id_token_hint`.
//!
//! What logout does NOT do is kill an access token already in flight. Nothing consults `sessions`
//! on the resource-server path (`lightbridge-authz-bearer` validates the JWT and stops), so a
//! bearer minted seconds before logout stays valid for the remainder of
//! `token_exchange.access_ttl_seconds`. Renewal dies instantly; the current token ages out. Say so
//! plainly rather than implying logout is a kill switch it is not.
//!
//! Two failure directions, resolved opposite ways on purpose:
//!
//! - LOCAL revocation failing is a hard `500`. Redirecting a user to "you are logged out" while
//!   their session is live is the one outcome worse than an error page.
//! - Everything else -- no cookie, dead session, bad hint, unregistered redirect, **and every
//!   upstream failure** -- is a success. Logout is idempotent, and a user who is already logged
//!   out asked for the state they are in.
//!
//! That second bullet is load-bearing for the upstream leg specifically, so it is worth stating
//! flatly: an unreachable Keycloak, an expired refresh token, or an envelope sealed under a
//! since-rotated `token_encryption_key` must NEVER stop the local session from being revoked, the
//! cookie from being cleared, or the redirect from being honoured. Those are logged loudly and
//! then dropped. The hard `500` above stays reserved for local revocation, and must not widen:
//! failing logout because a third party is down would leave the user *more* signed in than if we
//! had never called it.

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
use crate::relying_party::{KeycloakRelyingParty, UpstreamLogout};
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
    /// The upstream leg. Held for one call -- `end_upstream_session` -- and never to mint,
    /// validate, or redirect anything: this endpoint's authority over *whose* session ends is
    /// still the cookie alone.
    pub relying_party: Arc<KeycloakRelyingParty>,
}

impl EndSessionState {
    pub fn new(
        repo: Arc<StoreRepo>,
        token: TokenExchangeState,
        clients: &[OauthClient],
        relying_party: Arc<KeycloakRelyingParty>,
    ) -> Self {
        Self {
            repo,
            token,
            post_logout_redirect_uris: Arc::new(registry_from_clients(clients)),
            relying_party,
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

/// The single failure [`revoke_sessions_for_cookie`] reports: the LOCAL revocation did not happen,
/// so the user's session is still live and the router owes them a hard `500`.
///
/// A named unit struct rather than `()`. It is deliberately not an [`Error`] variant and carries
/// no detail, because widening what this can express is exactly the change this module's own doc
/// comment argues against: an upstream Keycloak fault must NOT reach the caller as a failure, or
/// a Keycloak outage starts refusing local logouts. One named type with one meaning keeps that
/// property visible at the signature instead of resting on a comment. The underlying cause is
/// logged at the point of failure; the caller's only decision is `500` or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRevocationFailed;

/// Ends every session held by the cookie's subject, locally and then upstream at Keycloak.
/// `Ok(false)` means there was nothing to end. `Err(LocalRevocationFailed)` -- the caller's hard
/// `500` -- is reserved for LOCAL revocation failing and is never returned for an upstream fault
/// (see this module's own doc comment for why widening it would make logout worse, not safer).
///
/// `pub`, and taking its two collaborators directly rather than an `EndSessionState`, so
/// `end_session_upstream_tests.rs` can drive exactly this seam: it is where the two failure
/// directions are decided, and an integration test is a separate crate that cannot see a private
/// function. The narrow parameters also keep the test free of the whole `TokenExchangeState`
/// apparatus, which this function provably never touches.
pub async fn revoke_sessions_for_cookie(
    repo: &StoreRepo,
    relying_party: &KeycloakRelyingParty,
    headers: &HeaderMap,
    client_id: Option<&str>,
) -> Result<bool, LocalRevocationFailed> {
    let Some(session_id) = read_session_cookie(headers) else {
        return Ok(false);
    };
    let session = match repo
        .find_active_browser_session(&session_id, Utc::now())
        .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return Ok(false),
        Err(error) => {
            tracing::error!(?error, "logout failed: session lookup");
            return Err(LocalRevocationFailed);
        }
    };
    // `None` only for a row predating `migrations/20260824000003_sessions_add_subject.sql`. No
    // safe fallback: `account_id` is the project's OWNING account, so revoking on it would log out
    // every member of a shared project. TTL-bounded and self-healing; the cookie is still cleared.
    let Some(subject) = session.subject else {
        tracing::warn!("logout: session row predates the subject column; clearing cookie only");
        return Ok(false);
    };
    match repo
        .revoke_for_logout(&AccountId::assert_already_resolved(&subject), client_id)
        .await
    {
        Ok(revoked) => {
            tracing::info!(revoked, "rp-initiated logout ended the subject's sessions");
        }
        Err(error) => {
            tracing::error!(?error, "logout failed: session revocation");
            return Err(LocalRevocationFailed);
        }
    }
    // Strictly after local revocation, and strictly best-effort. Ordered this way so the outcome
    // this endpoint is judged on -- the local session being gone -- is already durable before a
    // third party gets a chance to be slow or down.
    end_upstream_session(relying_party, &subject).await;
    Ok(true)
}

/// The upstream half, with every outcome absorbed. Returns nothing on purpose: there is no
/// upstream result the caller is allowed to act on, so handing it one would be an invitation to
/// start failing logout on it.
async fn end_upstream_session(relying_party: &KeycloakRelyingParty, subject: &str) {
    match relying_party.end_upstream_session(subject).await {
        Ok(UpstreamLogout::Terminated) => {
            tracing::info!("rp-initiated logout ended the upstream Keycloak SSO session");
        }
        Ok(UpstreamLogout::NoStoredCredential) => {
            // Ordinary, not exceptional: an aged-out refresh token or an envelope predating a
            // `token_encryption_key` rotation both land here. Worth a line, because it means this
            // logout did NOT reach Keycloak and the next `/authorize` may still be silent.
            tracing::info!(
                "rp-initiated logout had no usable stored Keycloak refresh token; upstream SSO \
                 session left untouched"
            );
        }
        Err(error) => {
            // Loud, and deliberately not fatal. `Error`'s own `Display`/`Debug` carry no
            // credential -- `end_upstream_session` builds its messages from a status code, never
            // from a response body or the token it sent.
            tracing::warn!(
                ?error,
                "rp-initiated logout could not end the upstream Keycloak SSO session; local \
                 logout still applied"
            );
        }
    }
}

async fn end_session(
    state: EndSessionState,
    headers: HeaderMap,
    request: EndSessionRequest,
) -> Response {
    // Verified for `azp` only, and with expiry ignored -- see `verify_own_token`'s doc comment for
    // why an expired hint at logout is the normal case; resolved BEFORE the scoped revocation.
    let hint = match request.id_token_hint.as_deref() {
        Some(hint) => verify_own_token(&state.token, hint, false).await,
        None => None,
    };
    let client_id = resolve_client_id(&request, hint.as_ref());
    let logout_client = client_id.as_deref();
    if revoke_sessions_for_cookie(&state.repo, &state.relying_party, &headers, logout_client)
        .await
        .is_err()
    {
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

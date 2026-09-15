//! Credential handling for the authenticated ingest surface (#585).
//!
//! Every gate that turns "an HTTP request arrived" into "this credential may assert this source".
//! Split out of `handlers/auth_ingest.rs`, which the LoC gate caps -- the pairing is unchanged and
//! `auth_ingest` re-exports nothing here: this is the module's private half, called by the
//! handlers' shared `ingest` body and by nothing else.
//!
//! The whole module is deny-by-default. Read [`authenticate_and_authorize`] for the gate order and
//! [`super`]'s doc comment for why each gate exists.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use lightbridge_authz_bearer::SERVICE_CALLER_KIND;
use tracing::debug;

use crate::{UsageState, config::IngestAuthConfig};

/// `401` with the `WWW-Authenticate` challenge an RFC 7235-conformant client expects.
pub(super) fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// `403` for a caller that authenticated but is not entitled to this surface, and for every
/// malformed-credential case. Deliberately opaque: it does not say whether the token was unmapped,
/// mapped to a different source, the wrong kind, or minted for the wrong audience. Distinguishing
/// those would let an unauthenticated prober enumerate configured principals.
pub(super) fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

/// Extracts `Authorization: Bearer <token>` from `headers`, if present.
///
/// RFC 7235 treats the scheme name as case-insensitive, so the match is lowercased -- some OTel
/// exporter HTTP clients send `bearer`. The token is sliced out of the ORIGINAL string at a fixed
/// offset (the two spellings are the same length) so the token's own case is preserved. Same
/// pattern as `handlers::query` and `lightbridge-authz-rest`'s middleware.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .filter(|s| s.to_ascii_lowercase().starts_with("bearer "))
        .map(|s| s["bearer ".len()..].trim())
        .filter(|token| !token.is_empty())
}

/// Authenticates the caller and returns the ONE `X-Source` value the credential entitles them to
/// assert, or the refusal to send.
///
/// Gates, in order -- all four deny-by-default:
///
/// 1. **`ingest_auth` is configured.** Unreachable through a correctly composed router (the routes
///    are mounted only when it is set), refused rather than unwrapped anyway: an unreachable branch
///    that admits is the exact failure this surface exists to prevent.
/// 2. **A bearer token is present and validates.** Any validation failure -- unreachable JWKS, bad
///    signature, expired, undecodable -- is a `401`. Nothing here maps "unavailable" to "allow".
/// 3. **`caller_kind` is [`SERVICE_CALLER_KIND`]** (a `client_credentials` token, #534/ADR-0030).
///    This is what stops a human OIDC login, or an API-key-derived token, whose `sub` happens to
///    collide with a configured principal from being admitted.
/// 4. **Its `aud` names this endpoint** (`IngestAuthConfig::audience`, AC4). Without it, any valid
///    machine token from any client whose `sub` were in `principals` would pass regardless of what
///    resource it was minted for -- the audience is what binds the credential to this surface.
///
/// Then `X-Source` is resolved and must equal the source `principals` maps that `sub` to. An
/// unmapped `sub`, or a mapped `sub` asserting a different source, is a `403`.
pub(super) async fn authenticate_and_authorize(
    state: &UsageState,
    headers: &HeaderMap,
) -> Result<&'static str, Box<Response>> {
    let Some(IngestAuthConfig {
        principals,
        audience,
    }) = state.ingest_auth.as_ref()
    else {
        debug!("authenticated ingest reached with no ingest_auth configured; refusing");
        return Err(Box::new(forbidden()));
    };

    let Some(token) = bearer_token(headers) else {
        return Err(Box::new(unauthorized()));
    };

    let token_info = state
        .bearer
        .validate_bearer_token(token)
        .await
        .map_err(|_| Box::new(unauthorized()))?;

    if token_info.caller_kind.as_deref() != Some(SERVICE_CALLER_KIND) {
        debug!(
            "rejecting token with caller_kind {:?} (expected service)",
            token_info.caller_kind
        );
        return Err(Box::new(forbidden()));
    }

    if !token_info.aud.iter().any(|aud| aud == audience) {
        debug!(
            principal = %token_info.sub,
            expected_audience = %audience,
            actual_audiences = ?token_info.aud,
            "rejecting token whose audience does not name this endpoint"
        );
        return Err(Box::new(forbidden()));
    }

    let source =
        crate::normalizer::resolve_source(headers).map_err(|e| Box::new(e.into_response()))?;

    match principals.get(&token_info.sub) {
        Some(allowed) if allowed == source => {
            debug!(
                "principal {} authorized for source {}",
                token_info.sub, source
            );
            Ok(source)
        }
        Some(allowed) => {
            debug!(
                "principal {} is mapped to {}, but asserted source {}",
                token_info.sub, allowed, source
            );
            Err(Box::new(forbidden()))
        }
        None => {
            debug!(
                "principal {} is not authorized for any source",
                token_info.sub
            );
            Err(Box::new(forbidden()))
        }
    }
}

//! Shared bearer-token extraction and auth-failure responses for the query listener.
//!
//! Split out of `handlers/query.rs` by the LoC gate (`.github/actions/loc-gate`): these helpers
//! are a self-contained unit that does not belong to the query handler, and keeping them here lets
//! `query.rs` stay under its ceiling. The pairing is unchanged -- `query.rs` re-exports them so
//! every existing path still resolves, and the two files move together.

use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

/// Extracts a bearer token from `Authorization: Bearer <token>` (case-insensitive on `Bearer`,
/// mirroring `lightbridge_authz_rest::middleware::bearer_auth`'s own extraction so the two
/// services parse the same header shape identically). `None` for a missing header, an empty
/// value, or a value that is not a `Bearer` credential.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?
        .trim();
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return None;
    }
    let token = value[7..].trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// `401` with a `WWW-Authenticate: Bearer` challenge, exactly as `bearer_auth` middleware on the
/// authz-api side responds. Deliberately opaque -- no distinction between "missing header" and
/// "token failed validation" is surfaced.
pub fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// `403` with a deliberately opaque body (#570's acceptance criteria) -- unlike
/// `handlers::idp::authorize_usage_scope`'s uniform-`404` convention on the authz-opa side (which
/// exists to avoid leaking whether a `scope_id` exists at all), this endpoint's caller already
/// knows exactly which scope/scope_id they asked for, so there is no oracle to protect; `403` is
/// the correct, standard "authenticated but not authorized" status here, not a borrowed 404.
pub fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

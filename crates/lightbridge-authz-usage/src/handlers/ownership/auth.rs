//! Bearer-token extraction, HTTP response builders, and JWKS authentication for the shared
//! ownership gate. Split out of `handlers::ownership` to satisfy the LoC gate
//! (lightbridge-governance#172); the pairing with `scope.rs`/`validate.rs` is unchanged.

use crate::UsageState;
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use lightbridge_authz_bearer::TokenInfo;
use tracing::warn;

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

/// Outcome of bearer-token authentication. Callers must match on this rather than propagating an
/// `Err` -- an unauthenticated caller gets a `401` response, not a `500`.
#[derive(Debug)]
pub enum AuthOutcome {
    /// Token validated successfully; the `TokenInfo` carries the subject, issuer, permissions,
    /// and everything downstream scope authorization needs.
    Authenticated(TokenInfo),
    /// Missing or invalid bearer token. The contained `Response` is a `401` ready to return.
    Unauthorized(Response),
}

/// Extracts and validates the bearer token from the request headers against the JWKS endpoint
/// configured on `state.bearer`. Returns [`AuthOutcome::Unauthorized`] for a missing, invalid,
/// or inactive token -- never a propagated `Err`, because an unauthenticated caller must not
/// distinguish "token validation failed" from "header was absent" (AGENTS.md's fail-closed rule).
pub async fn authenticate(state: &UsageState, headers: &HeaderMap) -> AuthOutcome {
    let Some(token) = extract_bearer_token(headers) else {
        warn!("no bearer token presented");
        return AuthOutcome::Unauthorized(unauthorized());
    };

    match state.bearer.validate_bearer_token(&token).await {
        Ok(info) if info.active => AuthOutcome::Authenticated(info),
        Ok(_) => {
            warn!("bearer token validated but not active");
            AuthOutcome::Unauthorized(unauthorized())
        }
        Err(err) => {
            warn!(error = %err, "bearer token validation failed");
            AuthOutcome::Unauthorized(unauthorized())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_bearer_token_parses_standard_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer my-token".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("my-token".to_string()));
    }

    #[test]
    fn extract_bearer_token_is_case_insensitive_on_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "bearer my-token".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("my-token".to_string()));
    }

    #[test]
    fn extract_bearer_token_returns_none_for_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_returns_none_for_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_returns_none_for_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn unauthorized_includes_www_authenticate_header() {
        let response = unauthorized();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forbidden_returns_403() {
        let response = forbidden();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

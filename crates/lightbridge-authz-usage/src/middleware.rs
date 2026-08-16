use axum::{
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use std::sync::Arc;

use crate::UsageState;

/// Middleware that validates HTTP Basic authentication for the internal `/usage/v1/spend/query`
/// endpoint. Mirrors `lightbridge_authz_rest::middleware::basic_auth` (the same mechanism used by
/// `server.opa.basic_auth`) byte-for-byte -- same header parsing, same `401` + `WWW-Authenticate:
/// Basic` response on any failure -- so the two Basic-auth-gated servers in this workspace behave
/// identically to a caller. Kept as a separate small implementation rather than a shared crate
/// dependency: `lightbridge-authz-usage-rest` does not otherwise depend on `lightbridge-authz-rest`
/// (see `AGENTS.md`'s crate-layering notes), and the two `State` types (`UsageState`/`OpaState`)
/// differ, so sharing would mean a new abstraction for one call site on each side.
pub async fn basic_auth(
    State(state): State<Arc<UsageState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let unauthorized_response = || {
        let mut res = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
        res
    };

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let Some(auth_header) = auth_header else {
        return unauthorized_response();
    };

    let prefix = "Basic ";
    if !auth_header.starts_with(prefix) {
        return unauthorized_response();
    }

    let encoded = auth_header.trim_start_matches(prefix);
    let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(bytes) => bytes,
        Err(_) => return unauthorized_response(),
    };
    let decoded = match String::from_utf8(decoded) {
        Ok(value) => value,
        Err(_) => return unauthorized_response(),
    };
    let mut parts = decoded.splitn(2, ':');
    let username = parts.next().unwrap_or("");
    let password = parts.next().unwrap_or("");

    if username != state.basic_auth.username || password != state.basic_auth.password {
        return unauthorized_response();
    }

    next.run(req).await
}

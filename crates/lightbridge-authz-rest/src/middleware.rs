use axum::{
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use lightbridge_authz_api::AppState;
use std::sync::Arc;

use crate::OpaState;

/// Middleware that validates the bearer token using the application's shared AppState.
///
/// The middleware extracts the shared `Arc<AppState>` from the router state and uses
/// its `bearer` field (the `BearerTokenService`) to validate incoming bearer tokens.
pub async fn bearer_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let unauthorized_response = || {
        let mut res = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        res
    };

    let token = auth_header.filter(|h| !h.is_empty()).and_then(|h| {
        let lower = h.to_ascii_lowercase();
        h.strip_prefix("Bearer ")
            .or_else(|| h.strip_prefix("bearer "))
            .map(|s| s.trim().to_string())
            .or_else(|| {
                if lower.starts_with("bearer ") {
                    Some(h[7..].trim().to_string())
                } else {
                    None
                }
            })
    });

    let Some(token) = token else {
        return unauthorized_response();
    };

    // Use the BearerTokenService stored in the shared state
    match state.bearer.validate_bearer_token(&token).await {
        Ok(token_info) if token_info.active => {
            req.extensions_mut().insert(token_info);
            next.run(req).await
        }
        _ => unauthorized_response(),
    }
}

/// Middleware that validates HTTP Basic authentication for OPA server.
pub async fn basic_auth(
    State(state): State<Arc<OpaState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let unauthorized_response = || {
        let mut res = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        res.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic"),
        );
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

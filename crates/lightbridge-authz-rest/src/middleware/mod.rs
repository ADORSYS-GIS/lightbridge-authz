use axum::{
    extract::{MatchedPath, State},
    http::{HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine;
use lightbridge_authz_api::AppState;
use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::Permission;
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
        tracing::debug!("bearer_auth: no token found in Authorization header");
        return unauthorized_response();
    };

    // Use the BearerTokenService stored in the shared state
    match state.bearer.validate_bearer_token(&token).await {
        Ok(token_info) if token_info.active => {
            tracing::debug!(
                "bearer_auth: token validated successfully for sub: {}",
                token_info.sub
            );
            req.extensions_mut().insert(token_info);
            next.run(req).await
        }
        Ok(_) => {
            tracing::warn!("bearer_auth: token validated but not active");
            unauthorized_response()
        }
        Err(e) => {
            tracing::warn!("bearer_auth: token validation failed: {}", e);
            unauthorized_response()
        }
    }
}

/// The permission a CRUD endpoint requires, keyed by HTTP method and the axum `MatchedPath`
/// route pattern (nested under `/api/v1`). This is the single source of truth for RBAC on the
/// REST surface and mirrors the tool → permission map on the MCP server; keep both in sync with
/// `docs/rbac.md`. Auto-generated `HEAD` routes inherit their `GET` handler's permission.
fn required_permission(method: &Method, matched_path: &str) -> Option<Permission> {
    let method = if *method == Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    Some(match (method, matched_path) {
        ("POST", "/api/v1/accounts") => Permission::AccountCreate,
        ("GET", "/api/v1/accounts") => Permission::AccountRead,
        ("GET", "/api/v1/accounts/{account_id}") => Permission::AccountRead,
        ("PATCH", "/api/v1/accounts/{account_id}") => Permission::AccountUpdate,
        ("DELETE", "/api/v1/accounts/{account_id}") => Permission::AccountDelete,
        ("POST", "/api/v1/accounts/{account_id}/disable") => Permission::AccountDisable,
        ("POST", "/api/v1/accounts/{account_id}/enable") => Permission::AccountDisable,
        ("POST", "/api/v1/accounts/{account_id}/members") => Permission::AccountMember,
        ("DELETE", "/api/v1/accounts/{account_id}/members/{member}") => Permission::AccountMember,
        ("POST", "/api/v1/accounts/{account_id}/projects") => Permission::ProjectCreate,
        ("GET", "/api/v1/accounts/{account_id}/projects") => Permission::ProjectRead,
        ("GET", "/api/v1/projects/{project_id}") => Permission::ProjectRead,
        ("PATCH", "/api/v1/projects/{project_id}") => Permission::ProjectUpdate,
        ("DELETE", "/api/v1/projects/{project_id}") => Permission::ProjectDelete,
        ("POST", "/api/v1/projects/{project_id}/disable") => Permission::ProjectDisable,
        ("POST", "/api/v1/projects/{project_id}/enable") => Permission::ProjectDisable,
        ("POST", "/api/v1/projects/{project_id}/api-keys") => Permission::ApiKeyCreate,
        ("GET", "/api/v1/projects/{project_id}/api-keys") => Permission::ApiKeyRead,
        ("GET", "/api/v1/api-keys/{key_id}") => Permission::ApiKeyRead,
        ("PATCH", "/api/v1/api-keys/{key_id}") => Permission::ApiKeyUpdate,
        ("DELETE", "/api/v1/api-keys/{key_id}") => Permission::ApiKeyDelete,
        ("POST", "/api/v1/api-keys/{key_id}/revoke") => Permission::ApiKeyRevoke,
        ("POST", "/api/v1/api-keys/{key_id}/rotate") => Permission::ApiKeyRotate,
        _ => return None,
    })
}

/// RBAC enforcement for the CRUD API. Runs after `bearer_auth` (so `TokenInfo` is present) and
/// after route matching (so `MatchedPath` is populated — hence it must be attached with
/// `route_layer`). Resolves the permission the matched route requires and rejects the request
/// with `403 Forbidden` unless the caller holds it. Fails closed: a protected route with no
/// mapping, a missing matched path, or a missing token is denied.
pub async fn authorize(req: Request<axum::body::Body>, next: Next) -> Response {
    let forbidden = || (StatusCode::FORBIDDEN, "Forbidden").into_response();

    let Some(matched_path) = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
    else {
        tracing::warn!("authorize: no matched path; denying");
        return forbidden();
    };

    let Some(required) = required_permission(req.method(), &matched_path) else {
        tracing::warn!(path = %matched_path, "authorize: no permission mapping for route; denying");
        return forbidden();
    };

    let granted = req
        .extensions()
        .get::<TokenInfo>()
        .is_some_and(|token_info| token_info.has_permission(required));

    if granted {
        next.run(req).await
    } else {
        tracing::debug!(
            path = %matched_path,
            required = %required.as_str(),
            "authorize: caller lacks required permission"
        );
        forbidden()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_permission_maps_head_to_get() {
        assert_eq!(
            required_permission(&Method::HEAD, "/api/v1/accounts"),
            Some(Permission::AccountRead)
        );
    }

    #[test]
    fn required_permission_covers_every_crud_route() {
        let cases = [
            ("POST", "/api/v1/accounts", Permission::AccountCreate),
            ("GET", "/api/v1/accounts", Permission::AccountRead),
            (
                "GET",
                "/api/v1/accounts/{account_id}",
                Permission::AccountRead,
            ),
            (
                "PATCH",
                "/api/v1/accounts/{account_id}",
                Permission::AccountUpdate,
            ),
            (
                "DELETE",
                "/api/v1/accounts/{account_id}",
                Permission::AccountDelete,
            ),
            (
                "POST",
                "/api/v1/accounts/{account_id}/disable",
                Permission::AccountDisable,
            ),
            (
                "POST",
                "/api/v1/accounts/{account_id}/enable",
                Permission::AccountDisable,
            ),
            (
                "POST",
                "/api/v1/accounts/{account_id}/members",
                Permission::AccountMember,
            ),
            (
                "DELETE",
                "/api/v1/accounts/{account_id}/members/{member}",
                Permission::AccountMember,
            ),
            (
                "POST",
                "/api/v1/accounts/{account_id}/projects",
                Permission::ProjectCreate,
            ),
            (
                "GET",
                "/api/v1/accounts/{account_id}/projects",
                Permission::ProjectRead,
            ),
            (
                "GET",
                "/api/v1/projects/{project_id}",
                Permission::ProjectRead,
            ),
            (
                "PATCH",
                "/api/v1/projects/{project_id}",
                Permission::ProjectUpdate,
            ),
            (
                "DELETE",
                "/api/v1/projects/{project_id}",
                Permission::ProjectDelete,
            ),
            (
                "POST",
                "/api/v1/projects/{project_id}/disable",
                Permission::ProjectDisable,
            ),
            (
                "POST",
                "/api/v1/projects/{project_id}/enable",
                Permission::ProjectDisable,
            ),
            (
                "POST",
                "/api/v1/projects/{project_id}/api-keys",
                Permission::ApiKeyCreate,
            ),
            (
                "GET",
                "/api/v1/projects/{project_id}/api-keys",
                Permission::ApiKeyRead,
            ),
            ("GET", "/api/v1/api-keys/{key_id}", Permission::ApiKeyRead),
            (
                "PATCH",
                "/api/v1/api-keys/{key_id}",
                Permission::ApiKeyUpdate,
            ),
            (
                "DELETE",
                "/api/v1/api-keys/{key_id}",
                Permission::ApiKeyDelete,
            ),
            (
                "POST",
                "/api/v1/api-keys/{key_id}/revoke",
                Permission::ApiKeyRevoke,
            ),
            (
                "POST",
                "/api/v1/api-keys/{key_id}/rotate",
                Permission::ApiKeyRotate,
            ),
        ];

        for (method, path, expected) in cases {
            let method = Method::from_bytes(method.as_bytes()).unwrap();
            assert_eq!(
                required_permission(&method, path),
                Some(expected),
                "method={method} path={path}"
            );
        }
    }

    #[test]
    fn required_permission_denies_unmapped_route() {
        assert_eq!(required_permission(&Method::GET, "/api/v1/unknown"), None);
    }
}

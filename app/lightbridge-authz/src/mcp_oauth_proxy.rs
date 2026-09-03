//! The three unauthenticated OAuth2 discovery/registration endpoints the MCP listener proxies to
//! the configured upstream issuer, so an MCP client can complete dynamic client registration
//! against `lightbridge-mcp`'s own origin.
//!
//! Split out of `mcp.rs` for the same LoC-gate reason as its sibling `mcp_oauth_metadata` -- see
//! that module's doc comment. Moved verbatim.

use std::sync::Arc;

use axum::{
    Json as AxumJson,
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use crate::mcp_oauth_metadata::{
    OauthProxyState, oauth_metadata_response, registration_endpoint_for_request,
};

pub(crate) async fn oauth_authorization_server_metadata_handler(
    state: Arc<OauthProxyState>,
    headers: HeaderMap,
) -> Response {
    let Some(endpoints) = state.endpoints.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(json!({
                "error": "server_error",
                "error_description": "OAuth2 issuer URL could not be derived from configuration"
            })),
        )
            .into_response();
    };

    let registration_endpoint =
        registration_endpoint_for_request(&headers, &state.fallback_registration_endpoint);
    let metadata = oauth_metadata_response(endpoints, &registration_endpoint);
    (StatusCode::OK, AxumJson(metadata)).into_response()
}

pub(crate) async fn openid_configuration_handler(
    state: Arc<OauthProxyState>,
    headers: HeaderMap,
) -> Response {
    oauth_authorization_server_metadata_handler(state, headers).await
}

pub(crate) async fn oauth_register_handler(
    state: Arc<OauthProxyState>,
    headers: HeaderMap,
    AxumJson(payload): AxumJson<Value>,
) -> Response {
    let Some(endpoints) = state.endpoints.as_ref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            AxumJson(json!({
                "error": "server_error",
                "error_description": "OAuth2 registration endpoint could not be derived from configuration"
            })),
        )
            .into_response();
    };

    let mut request = state
        .client
        .post(&endpoints.registration_endpoint)
        .json(&payload);
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(header::AUTHORIZATION, auth);
    }

    let upstream = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                AxumJson(json!({
                    "error": "bad_gateway",
                    "error_description": format!("failed to reach upstream registration endpoint: {error}")
                })),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let body = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                AxumJson(json!({
                    "error": "bad_gateway",
                    "error_description": format!("failed to read upstream registration response: {error}")
                })),
            )
                .into_response();
        }
    };

    let mut response = Response::new(Body::from(body.to_vec()));
    *response.status_mut() = status;
    if let Some(content_type) = content_type
        && let Ok(header_value) = HeaderValue::from_str(&content_type)
    {
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, header_value);
    }
    response
}

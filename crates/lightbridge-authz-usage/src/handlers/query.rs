use crate::UsageState;
use crate::models::{UsageErrorResponse, UsageQueryRequest, UsageQueryResponse, UsageScope};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use lightbridge_authz_core::{Error, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Extracts a bearer token from `Authorization: Bearer <token>` (case-insensitive on `Bearer`,
/// mirroring `lightbridge_authz_rest::middleware::bearer_auth`'s own extraction so the two
/// services parse the same header shape identically). `None` for a missing header, an empty
/// value, or a value that is not a `Bearer` credential.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
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
fn unauthorized() -> Response {
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
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Forbidden").into_response()
}

#[utoipa::path(
    post,
    path = "/usage/v1/usage/query",
    request_body = UsageQueryRequest,
    responses(
        (status = 200, body = UsageQueryResponse),
        (status = 400, body = UsageErrorResponse),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Authenticated but not authorized for the requested scope")
    ),
    tag = "usage"
)]
#[instrument(skip(state, headers))]
pub async fn query_usage(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    Json(input): Json<UsageQueryRequest>,
) -> Result<Response> {
    info!(
        "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
        input.scope, input.scope_id, input.bucket, input.limit
    );
    if input.start_time >= input.end_time {
        warn!(
            "invalid time range: start_time={} end_time={}",
            input.start_time, input.end_time
        );
        return Err(Error::BadRequest(
            "start_time must be before end_time".to_string(),
        ));
    }

    if input.scope_id.trim().is_empty() {
        warn!("missing scope_id for usage query");
        return Err(Error::BadRequest(
            "scope_id is required for usage queries".to_string(),
        ));
    }

    if input.limit == 0 {
        warn!("invalid limit for usage query: limit=0");
        return Err(Error::BadRequest(
            "limit must be greater than zero".to_string(),
        ));
    }

    // #570: `/usage/v1/usage/query` now requires an end-user bearer token, validated via JWKS --
    // this is the query listener's own authentication boundary, layered on top of the mTLS the
    // listener already requires at the TLS level. A missing/invalid token is "unknown", which per
    // AGENTS.md's fail-closed rule routes to the strictest branch: refuse, never proceed.
    let Some(token) = extract_bearer_token(&headers) else {
        warn!("query_usage: no bearer token presented");
        return Ok(unauthorized());
    };

    let token_info = match state.bearer.validate_bearer_token(&token).await {
        Ok(info) if info.active => info,
        Ok(_) => {
            warn!("query_usage: bearer token validated but not active");
            return Ok(unauthorized());
        }
        Err(err) => {
            warn!(error = %err, "query_usage: bearer token validation failed");
            return Ok(unauthorized());
        }
    };

    // `user`/`api_key` scopes have no resolvable ownership authority at all (no `accounts`/
    // `projects` row is ever keyed by a raw `user_id`/`api_key_id`) -- refused unconditionally,
    // matching the console's own guard, and never reaching `scope_authority` at all.
    match &input.scope {
        UsageScope::User | UsageScope::ApiKey => {
            warn!(
                scope = ?input.scope,
                "query_usage: scope has no resolvable ownership authority; refusing"
            );
            return Ok(forbidden());
        }
        UsageScope::Account | UsageScope::Project => {
            let authorized = state
                .scope_authority
                .authorize(
                    &token_info.iss,
                    &token_info.sub,
                    &input.scope,
                    &input.scope_id,
                )
                .await?;
            if !authorized {
                warn!(
                    scope = ?input.scope,
                    scope_id = %input.scope_id,
                    "query_usage: scope authority refused the requested scope"
                );
                return Ok(forbidden());
            }
        }
    }

    let (points, truncated) = state.repo.query_usage(&input).await?;

    Ok((
        StatusCode::OK,
        Json(UsageQueryResponse { points, truncated }),
    )
        .into_response())
}

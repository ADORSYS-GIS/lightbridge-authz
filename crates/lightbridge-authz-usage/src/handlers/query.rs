use crate::UsageState;
use crate::handlers::ownership::{
    AuthOutcome, GrainScope, ScopeAuthOutcome, authenticate, authorize_scope,
    validate_common_request,
};
use crate::models::{UsageErrorResponse, UsageQueryRequest, UsageQueryResponse};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use lightbridge_authz_core::{Error, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

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
// `input` is deliberately skipped too (not just `state`/`headers`): `#[instrument]` records every
// non-skipped parameter into the span at function ENTRY, before any code in this body runs -- so
// leaving `input` unskipped would still have put `scope_id` into the trace span for an
// unauthenticated caller no matter where the `info!` call below moved to. The `info!` line after
// the bearer check is what actually logs the request's shape now, and only once the caller is
// authenticated.
#[instrument(skip(state, headers, input))]
pub async fn query_usage(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    Json(input): Json<UsageQueryRequest>,
) -> Result<Response> {
    // #570: authentication runs BEFORE body validation, deliberately -- an unauthenticated caller
    // must never be able to distinguish a well-formed from a malformed request (a differentiated
    // 400 is itself a signal), and `input.scope_id` must never reach this span (or any other log
    // line) before the caller presenting it has been authenticated. This is the query listener's
    // own authentication boundary, layered on top of the mTLS the listener already requires at
    // the TLS level. A missing/invalid token is "unknown", which per AGENTS.md's fail-closed rule
    // routes to the strictest branch: refuse, never proceed, and never validate the body first.
    let token_info = match authenticate(&state, &headers).await {
        AuthOutcome::Authenticated(info) => info,
        AuthOutcome::Unauthorized(response) => return Ok(response),
    };

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

    validate_common_request(&input.scope, &input.scope_id, input.limit)?;

    // #648: `filters.operation_in` is a CLOSED vocabulary, so an unknown entry is a 400 here and
    // not an empty result set from the repo -- a caller who typed `chat` instead of
    // `chat_completions` deserves to be told, not handed a blank chart that looks like "no usage".
    input.filters.validate()?;

    // Scope authorization via the shared gate (Legacy model: all five scopes).
    match authorize_scope(
        state.scope_authority.as_ref(),
        &token_info,
        &input.scope,
        &input.scope_id,
        GrainScope::Legacy,
    )
    .await
    {
        ScopeAuthOutcome::Authorized => {}
        ScopeAuthOutcome::Forbidden(response) => return Ok(response),
        ScopeAuthOutcome::BadRequest(err) => return Err(err),
    }

    // Captured BEFORE the query so the echo describes what was ASKED for, not what came back --
    // a response with zero points still has to say whether percentiles were computed.
    let metrics = input.effective_metrics();
    let (points, truncated) = state.repo.query_usage(&input).await?;

    Ok((
        StatusCode::OK,
        Json(UsageQueryResponse {
            points,
            truncated,
            metrics,
        }),
    )
        .into_response())
}

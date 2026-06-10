use crate::UsageState;
use crate::models::{UsageErrorResponse, UsageQueryRequest, UsageQueryResponse};
use crate::repo::validate_bucket_interval;
use axum::{Json, extract::State, http::StatusCode};
use std::sync::Arc;
use tracing::{info, instrument, warn};

type UsageHandlerResult<T> = std::result::Result<T, (StatusCode, Json<UsageErrorResponse>)>;

#[utoipa::path(
    post,
    path = "/usage/v1/usage/query",
    request_body = UsageQueryRequest,
    responses(
        (status = 200, body = UsageQueryResponse),
        (status = 400, body = UsageErrorResponse),
        (status = 500, body = UsageErrorResponse),
        (status = 503, body = UsageErrorResponse)
    ),
    tag = "usage"
)]
#[instrument(skip(state))]
pub async fn query_usage(
    State(state): State<Arc<UsageState>>,
    Json(input): Json<UsageQueryRequest>,
) -> UsageHandlerResult<(StatusCode, Json<UsageQueryResponse>)> {
    info!(
        "querying usage with scope={:?}, scope_id={}, bucket={}, limit={}",
        input.scope, input.scope_id, input.bucket, input.limit
    );
    if input.start_time >= input.end_time {
        warn!(
            "invalid time range: start_time={} end_time={}",
            input.start_time, input.end_time
        );
        return Err(bad_request("start_time must be before end_time"));
    }

    if input.scope_id.trim().is_empty() {
        warn!("missing scope_id for usage query");
        return Err(bad_request("scope_id is required for usage queries"));
    }

    if input.limit == 0 {
        warn!("invalid limit for usage query: limit=0");
        return Err(bad_request("limit must be greater than zero"));
    }

    if let Err(message) = validate_bucket_interval(&input.bucket) {
        warn!("invalid bucket for usage query: bucket={}", input.bucket);
        return Err(bad_request(message));
    }

    let points = state
        .repo
        .query_usage(&input)
        .await
        .map_err(|err| {
            // Preserve the status mapping (e.g. transient pool failures -> 503)
            // while returning the structured UsageErrorResponse JSON shape.
            (
                err.status_code(),
                Json(UsageErrorResponse {
                    error: err.to_string(),
                }),
            )
        })?;

    Ok((StatusCode::OK, Json(UsageQueryResponse { points })))
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<UsageErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(UsageErrorResponse {
            error: message.into(),
        }),
    )
}

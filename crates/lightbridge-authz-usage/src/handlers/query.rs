use crate::UsageState;
use crate::models::{UsageErrorResponse, UsageQueryRequest, UsageQueryResponse};
use axum::{Json, extract::State, http::StatusCode};
use lightbridge_authz_core::{Error, Result};
use std::sync::Arc;

#[utoipa::path(
    post,
    path = "/usage/v1/usage/query",
    request_body = UsageQueryRequest,
    responses(
        (status = 200, body = UsageQueryResponse),
        (status = 400, body = UsageErrorResponse)
    ),
    tag = "usage"
)]
pub async fn query_usage(
    State(state): State<Arc<UsageState>>,
    Json(input): Json<UsageQueryRequest>,
) -> Result<(StatusCode, Json<UsageQueryResponse>)> {
    if input.start_time >= input.end_time {
        return Err(Error::Database(
            "start_time must be before end_time".to_string(),
        ));
    }

    if input.scope_id.trim().is_empty() {
        return Err(Error::Database(
            "scope_id is required for usage queries".to_string(),
        ));
    }

    if input.limit == 0 {
        return Err(Error::Database(
            "limit must be greater than zero".to_string(),
        ));
    }

    let points = state.repo.query_usage(&input).await?;

    Ok((StatusCode::OK, Json(UsageQueryResponse { points })))
}

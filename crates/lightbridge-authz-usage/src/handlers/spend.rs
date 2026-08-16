use crate::UsageState;
use crate::models::{SpendQueryRequest, SpendQueryResponse, UsageErrorResponse};
use axum::{Json, extract::State, http::StatusCode};
use lightbridge_authz_core::{Error, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Internal, Basic-auth-protected endpoint answering exactly the spend question
/// `lightbridge-authz-budget`'s `SpendReader` asks: the summed `usage_events.total_cost` for one
/// account over a half-open `[start, end)` interval. See `crate::repo::StoreRepo::spend_for_account`
/// for why `total_cost` stays nullable rather than collapsing to `0.0`.
#[utoipa::path(
    post,
    path = "/usage/v1/spend/query",
    request_body = SpendQueryRequest,
    responses(
        (status = 200, body = SpendQueryResponse),
        (status = 400, body = UsageErrorResponse),
        (status = 401, description = "missing or invalid Basic-auth credentials")
    ),
    tag = "spend"
)]
#[instrument(skip(state))]
pub async fn query_spend(
    State(state): State<Arc<UsageState>>,
    Json(input): Json<SpendQueryRequest>,
) -> Result<(StatusCode, Json<SpendQueryResponse>)> {
    info!(
        "querying spend for account_id={} start={} end={}",
        input.account_id, input.start, input.end
    );

    if input.account_id.trim().is_empty() {
        warn!("missing account_id for spend query");
        return Err(Error::BadRequest(
            "account_id is required for spend queries".to_string(),
        ));
    }

    if input.start >= input.end {
        warn!(
            "invalid time range: start={} end={}",
            input.start, input.end
        );
        return Err(Error::BadRequest("start must be before end".to_string()));
    }

    let total_cost = state
        .repo
        .spend_for_account(&input.account_id, input.start, input.end)
        .await?;

    Ok((StatusCode::OK, Json(SpendQueryResponse { total_cost })))
}

use crate::UsageState;
use crate::models::{SpendQueryRequest, SpendQueryResponse, UsageErrorResponse};
use axum::{Json, extract::State, http::HeaderMap, http::StatusCode, http::header};
use lightbridge_authz_core::{Error, Result};
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Internal endpoint answering exactly the spend question `lightbridge-authz-budget`'s
/// `SpendReader` asks: the summed `usage_events.total_cost` for one account over a half-open
/// `[start, end)` interval. See `crate::repo::StoreRepo::spend_for_account` for why `total_cost`
/// stays nullable rather than collapsing to `0.0`. This handler applies no bearer/Basic-auth check
/// of its own -- it is mounted on the mTLS-required query listener (`crate::routers::query_router`,
/// `UsageServerGroup::query`, #347), which is what actually gates it, and its only caller is
/// `authz-budget`'s `UsageServiceSpendReader`, a service-to-service reader that never sends a
/// bearer token.
///
/// #570: this route now REFUSES any request carrying an `Authorization` header. This is a
/// service-to-service route with a legitimate cross-account reach (unlike `/usage/v1/usage/query`,
/// it has no per-caller ownership check at all -- `UsageServiceSpendReader` asks about ANY
/// account), so it has no business ever receiving a user's bearer token. Before this check, a
/// misrouted or malicious request carrying `Authorization: Bearer <token>` would have been
/// answered exactly like any other spend request -- the live "console catch-all-proxy" hole this
/// closes: a proxy misconfigured to forward every header to whichever usage-service route matched
/// would let a browser's own bearer token silently reach this ownerless read. Refusing outright
/// (rather than merely ignoring the header) makes a misrouted request fail loudly instead of
/// quietly returning cross-account data.
#[utoipa::path(
    post,
    path = "/usage/v1/spend/query",
    request_body = SpendQueryRequest,
    responses(
        (status = 200, body = SpendQueryResponse),
        (status = 400, body = UsageErrorResponse),
        (status = 403, description = "Request carried an Authorization header")
    ),
    tag = "spend"
)]
#[instrument(skip(state, headers))]
pub async fn query_spend(
    State(state): State<Arc<UsageState>>,
    headers: HeaderMap,
    Json(input): Json<SpendQueryRequest>,
) -> Result<(StatusCode, Json<SpendQueryResponse>)> {
    if headers.contains_key(header::AUTHORIZATION) {
        warn!(
            "query_spend: refusing a request carrying an Authorization header -- this is a \
             service-to-service route with no per-caller ownership check"
        );
        return Err(Error::Forbidden(
            "this endpoint does not accept an Authorization header".to_string(),
        ));
    }

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

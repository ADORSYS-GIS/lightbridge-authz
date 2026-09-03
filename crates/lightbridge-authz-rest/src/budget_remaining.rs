//! `GET /budget/v1/remaining` — the service-to-service read behind the gateway's Dynamic Budget
//! Limiter (ADR-0034 + its 2026-09-03 amendment, lightbridge-authz#658).
//!
//! ## What this is for
//!
//! Authorino calls it as an AuthConfig `metadata` step, publishes the answer as ext_authz
//! **dynamic metadata** (never a response header — a header is visible to, and forgeable by, the
//! client), and a Lua `EnvoyExtensionPolicy` on the gateway reads that metadata and refuses the
//! request with `402` when nothing is left. Nothing here decides anything: this endpoint reports
//! two numbers and their difference, and the gateway decides.
//!
//! ## Why it is its own listener
//!
//! `authz-budget`'s main listener is a bearer-JWT RPC surface reachable by the console. This
//! answer must be readable by Authorino, which holds no user token, and must NOT be readable by
//! anything else — it is a cross-account read with no per-caller ownership check at all, exactly
//! like `lightbridge-authz-usage`'s `/usage/v1/spend/query` (#347). Keeping it off the RPC
//! listener means the console's bearer surface stays untouched and this route's own credential
//! cannot be bypassed by hitting a sibling route.
//!
//! That credential is a **shared secret in a custom header**, not a client certificate — see
//! [`crate::budget_remaining_auth`] for the `kubectl explain` output that rules mTLS out, what is
//! given up by taking the secret instead, and what would bring mTLS back. Like
//! `/usage/v1/spend/query`, the route additionally **refuses** any request carrying an
//! `Authorization` header.
//!
//! ## The contract, and the one rule that matters
//!
//! ```text
//! 200  {"budget_account_id","period","ceiling_micros","spent_micros","remaining_micros",
//!       "next_reset_at","source_lag_seconds"}
//! 400  {"error":"bad_request","message":...}      malformed account id / period
//! 401  {"error":"unauthorized","message":...}     the shared secret was missing or wrong
//! 403  {"error":"forbidden","message":...}        an Authorization header was present
//! 404  {"error":"unknown_account","account_id":...} the id names no account
//! 503  {"error":"budget_unavailable","reason":...} the answer is not knowable right now
//! ```
//!
//! **A `503` is never a `0`.** "The ledger is unreadable" and "the spend store cannot be asked"
//! must not render as "you have spent everything": that would bill a user's exhausted-budget page
//! for our own outage. The gateway distinguishes them — it rides a `503` out on the last cached
//! value for a bounded grace window and then refuses with `budget_unavailable`, which is a
//! different error, a different status, and a different runbook from `budget_exhausted`.
//!
//! **A `404` is never a `0` either** (owner directive, 2026-09-03). An id nothing has ever heard
//! of used to sum to an ordinary zero ceiling and answer `200 {"remaining_micros": 0}`, so a typo
//! in an identity mapping reached the gateway as `402 budget_exhausted` for a phantom account. It
//! is now `404 unknown_account`. What is **not** a `404`: a real account with no grants booked
//! this period — that is `200`, `ceiling_micros: 0`, `remaining_micros: -spent_micros`, the state
//! of every account between its creation and its first grant and the figure the console's Budget
//! card shows for it. The policy's `starting_amount_micros` (ADR-0015 Decision 5) materialises
//! **only when a grant is booked**; this endpoint reports the ledger, never an unbooked amount.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use lightbridge_authz_budget::{Period, Remaining};

pub use crate::budget_remaining_router::{
    BUDGET_REMAINING_PATH, BudgetInternalState, budget_remaining_router,
};
pub use crate::budget_remaining_wire::{
    ERROR_BUDGET_UNAVAILABLE, ERROR_UNKNOWN_ACCOUNT, RemainingErrorResponse, RemainingQuery,
    RemainingResponse, UnknownAccountResponse, error_response, unknown_account_response,
};

/// Reports `ceiling − spend` for one budget account and period.
///
/// Every failure mode ends as a `503` carrying `budget_unavailable`, never a `200` with a
/// fabricated `0` — see this module's doc comment for why that distinction is the whole point of
/// the endpoint.
///
/// **The span is the SLO.** ADR-0034 §9 makes this route's p99 a *hard* shadow-mode exit criterion
/// — Authorino v0.24.0 has no `metadata.http.timeout`, so nothing else bounds the tail — and until
/// this attribute nothing emitted a span for it, so that criterion had no data source. The exit
/// query filters on `http.route`; `http.response.status_code` separates p99 from the 503 rate.
#[tracing::instrument(
    name = "GET /budget/v1/remaining", skip_all,
    fields(otel.kind = "server", http.request.method = "GET", http.route = BUDGET_REMAINING_PATH,
        budget_account_id = tracing::field::Empty, period = tracing::field::Empty,
        http.response.status_code = tracing::field::Empty)
)]
pub async fn budget_remaining(
    state: State<Arc<BudgetInternalState>>,
    query: Query<RemainingQuery>,
) -> Response {
    let response = remaining_response(state, query).await;
    tracing::Span::current().record("http.response.status_code", response.status().as_u16());
    response
}

async fn remaining_response(
    State(state): State<Arc<BudgetInternalState>>,
    Query(query): Query<RemainingQuery>,
) -> Response {
    let account_id = query.account_id.trim();
    if account_id.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "account_id is required".to_string(),
        );
    }

    let now = Utc::now();
    let period = match query.period.as_deref().map(str::trim) {
        None | Some("") => Period::current(now),
        Some(raw) => match Period::parse(raw) {
            Ok(period) => period,
            Err(err) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "bad_request",
                    format!("period must be 'YYYY-MM': {err}"),
                );
            }
        },
    };

    let span = tracing::Span::current();
    span.record("budget_account_id", account_id);
    span.record("period", tracing::field::display(&period));

    match state
        .remaining
        .remaining_for_account(account_id, &period, now)
        .await
    {
        Ok(Remaining::Known(remaining)) => (
            StatusCode::OK,
            Json(RemainingResponse {
                budget_account_id: remaining.budget_account_id,
                period: remaining.period.to_string(),
                ceiling_micros: remaining.ceiling_micros,
                spent_micros: remaining.spent_micros,
                remaining_micros: remaining.remaining_micros,
                next_reset_at: remaining.next_reset_at,
                source_lag_seconds: remaining.source_lag_seconds,
            }),
        )
            .into_response(),
        Ok(Remaining::UnknownAccount) => {
            // `warn`, not `error`: the fault is upstream of this process and this process handled
            // it correctly. It is still the loudest thing this endpoint can say, and a sustained
            // rate of it is the signal that an identity mapping is wrong.
            tracing::warn!(
                budget_account_id = %account_id,
                period = %period,
                "budget remaining was asked for an account that does not exist"
            );
            unknown_account_response(account_id)
        }
        Ok(Remaining::Unavailable) => {
            // Logged at warn, not error: an unreachable usage service is an expected transient
            // the gateway is designed to ride out, and paging on it would train the team to
            // ignore this line. The gateway's own `budget_unavailable` refusal rate is the alert.
            tracing::warn!(
                budget_account_id = %account_id,
                period = %period,
                "budget remaining is unknowable: the spend source could not be asked"
            );
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ERROR_BUDGET_UNAVAILABLE,
                "spend for this period could not be read".to_string(),
            )
        }
        Err(err) => {
            tracing::error!(
                budget_account_id = %account_id,
                period = %period,
                error = %err,
                "budget remaining could not be computed"
            );
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ERROR_BUDGET_UNAVAILABLE,
                "the budget ledger could not be read".to_string(),
            )
        }
    }
}

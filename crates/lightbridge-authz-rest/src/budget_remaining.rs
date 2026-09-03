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
//! 503  {"error":"budget_unavailable","reason":...} the answer is not knowable right now
//! ```
//!
//! **A `503` is never a `0`.** "The ledger is unreadable" and "the spend store cannot be asked"
//! must not render as "you have spent everything": that would bill a user's exhausted-budget page
//! for our own outage. The gateway distinguishes them — it rides a `503` out on the last cached
//! value for a bounded grace window and then refuses with `budget_unavailable`, which is a
//! different error, a different status, and a different runbook from `budget_exhausted`.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use lightbridge_authz_budget::{Period, Remaining, RemainingReader};

pub use crate::budget_remaining_wire::{
    ERROR_BUDGET_UNAVAILABLE, RemainingErrorResponse, RemainingQuery, RemainingResponse,
    error_response,
};

/// Path the budget-remaining read is served on. Versioned under `/budget/v1` rather than mounted
/// beside the RPC surface's `/budget/rpc/*`: this is a plain REST read for a non-RPC client
/// (Authorino speaks HTTP, not cratestack), and it lives on a different listener entirely.
pub const BUDGET_REMAINING_PATH: &str = "/budget/v1/remaining";

/// State for [`budget_remaining_router`]. A struct rather than a bare `Arc<dyn RemainingReader>`
/// so a later addition to this listener does not have to churn every handler signature.
pub struct BudgetInternalState {
    pub remaining: Arc<dyn RemainingReader>,
    /// The secret [`crate::budget_remaining_auth::require_shared_secret`] requires, verbatim from
    /// `server.budget_internal.shared_secret`. Never empty in a running process —
    /// `start_budget_server` refuses to start on an empty one.
    pub shared_secret: String,
    /// The header that secret must arrive in — `server.budget_internal.shared_secret_header`,
    /// which must equal the AuthConfig's `metadata.http.credentials.customHeader.name`.
    pub shared_secret_header: HeaderName,
}

/// Reports `ceiling − spend` for one budget account and period.
///
/// Every failure mode ends as a `503` carrying `budget_unavailable`, never a `200` with a
/// fabricated `0` — see this module's doc comment for why that distinction is the whole point of
/// the endpoint.
pub async fn budget_remaining(
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

/// The internal listener's router: the remaining read, behind the shared-secret check.
///
/// The credential is a **route-layer** concern here rather than a TLS-handshake one, which is the
/// one structural difference from `lightbridge-authz-usage`'s query listener — see
/// [`crate::budget_remaining_auth`] for why Authorino leaves no other option. The layer is
/// attached here, not at the call site, so no future caller can mount this router unprotected.
pub fn budget_remaining_router(
    state: Arc<BudgetInternalState>,
) -> Router<Arc<BudgetInternalState>> {
    Router::new()
        .route(BUDGET_REMAINING_PATH, get(budget_remaining))
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::budget_remaining_auth::require_shared_secret,
        ))
}

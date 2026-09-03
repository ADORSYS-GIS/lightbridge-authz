//! The wire shapes for `GET /budget/v1/remaining` (ADR-0034) — the query it accepts, the `200`
//! body, and the single error body every non-`200` uses.
//!
//! Split out of `budget_remaining.rs` (code moved, not rewritten) under the LoC gate, following
//! the same convention as `budget_convert.rs`/`reset_schedule_convert.rs`: the handler module
//! re-exports every name, so `crate::budget_remaining::RemainingResponse` still resolves.
//!
//! Field names are snake_case, matching the budget domain's own wire convention (`rule_data.rs`,
//! `Facts`) rather than the RPC schema layer's camelCase — the consumers are an Authorino CEL
//! expression and a Lua script, neither of which cares, and agreeing with the crate that produces
//! the numbers is worth more than agreeing with a surface this does not belong to.

use axum::{Json, http::StatusCode, response::IntoResponse, response::Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RemainingQuery {
    /// The **budget** account id — `budget_grants.budget_account_id`, i.e. the `account_id` claim,
    /// NOT the token's `sub`. See ADR-0034's counter-identity section: they are the same string
    /// today and ADR-0026 makes them diverge, at which point keying this on `sub` would meter one
    /// person's several accounts against a single balance.
    pub account_id: String,
    /// `YYYY-MM`, UTC. Omitted means the calendar period containing the server's `now`, which is
    /// what every caller on the request path wants and what the ledger keys on.
    #[serde(default)]
    pub period: Option<String>,
}

/// The `200` body. Field names are snake_case, matching this domain's own wire convention
/// (`rule_data.rs`, `Facts`) rather than the RPC schema layer's camelCase — the consumer is an
/// Authorino CEL expression and a Lua script, neither of which cares, and consistency with the
/// crate that produces the numbers is worth more than consistency with a surface this does not
/// belong to.
#[derive(Debug, Serialize)]
pub struct RemainingResponse {
    pub budget_account_id: String,
    pub period: String,
    pub ceiling_micros: i64,
    pub spent_micros: i64,
    /// Signed, unclamped. Negative means the account overshot — possible by construction, because
    /// the gateway charges `llm_custom_total_cost` only after a response completes.
    pub remaining_micros: i64,
    pub next_reset_at: DateTime<Utc>,
    /// `null` when unknown — see `BudgetRemaining::source_lag_seconds`. Never `0` as a stand-in
    /// for "we did not measure it".
    pub source_lag_seconds: Option<u64>,
}

/// The non-`200` body. `error` is a stable machine token the gateway's Lua branches on; `message`
/// is for a human reading logs and is never parsed.
#[derive(Debug, Serialize)]
pub struct RemainingErrorResponse {
    pub error: &'static str,
    pub message: String,
}

/// Stable `error` token for "the answer is not knowable right now". Deliberately distinct from
/// the gateway's `budget_exhausted`: one is our outage, the other is the user's spending.
pub const ERROR_BUDGET_UNAVAILABLE: &str = "budget_unavailable";

/// Builds a non-`200` response. `error` is a stable machine token the gateway's Lua branches on;
/// `message` is for a human reading logs and is never parsed.
pub fn error_response(status: StatusCode, error: &'static str, message: String) -> Response {
    (status, Json(RemainingErrorResponse { error, message })).into_response()
}

//! The internal listener's route table and its state — the path constant,
//! [`BudgetInternalState`], and [`budget_remaining_router`].
//!
//! Split out of `budget_remaining.rs` verbatim (code moved, not rewritten) under the 200-LoC gate,
//! following the same convention as `budget_remaining_wire.rs`: the handler module re-exports
//! every name, so `crate::budget_remaining::BudgetInternalState` and
//! `crate::budget_remaining::budget_remaining_router` both still resolve and no caller changed.
//! The pairing is unchanged — the credential layer is still attached to the router here rather
//! than at the call site, so no future caller can mount this route unprotected.

use std::sync::Arc;

use axum::{Router, http::HeaderName, routing::get};
use lightbridge_authz_budget::RemainingReader;

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
        .route(
            BUDGET_REMAINING_PATH,
            get(crate::budget_remaining::budget_remaining),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::budget_remaining_auth::require_shared_secret,
        ))
}

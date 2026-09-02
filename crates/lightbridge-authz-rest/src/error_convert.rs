//! The two error-to-`CratestackError` converters every procedure body in this crate funnels
//! through.
//!
//! Split out of `lib.rs` rather than left beside the `ProcedureRegistry` impl purely because that
//! file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be touched
//! but not grown — the same reason `rpc_permission_map` is separate from `rpc_authorize` and
//! `budget_convert` from `lib.rs`. Moved verbatim, and `lib.rs` re-exports both, so every existing
//! `crate::{to_cratestack_error, budget_error_to_cratestack_error}` path still resolves.

use cratestack::CratestackError;
use lightbridge_authz_core::Error;

/// Maps a core repository `Error` (reused hand-written sqlx) into cratestack's `CratestackError` so an RPC
/// procedure failure surfaces with the right HTTP status through the RPC error envelope.
pub(crate) fn to_cratestack_error(err: Error) -> CratestackError {
    match err {
        Error::NotFound => CratestackError::NotFound("not found".to_owned()),
        Error::Forbidden(m) => CratestackError::Forbidden(m),
        Error::Conflict(m) => CratestackError::Conflict(m),
        Error::BadRequest(m) => CratestackError::BadRequest(m),
        other => CratestackError::Internal(other.to_string()),
    }
}

/// Maps a [`lightbridge_authz_budget::BudgetError`] into cratestack's `CratestackError`, mirroring
/// [`to_cratestack_error`] above for the (unrelated) core `Error` type. Exhaustive match, no wildcard
/// arm, so a new `BudgetError` variant fails this crate's build until it is triaged here rather
/// than silently falling into some default status.
pub(crate) fn budget_error_to_cratestack_error(
    err: lightbridge_authz_budget::BudgetError,
) -> CratestackError {
    use lightbridge_authz_budget::BudgetError;
    match err {
        BudgetError::InvalidRuleData(m) => CratestackError::BadRequest(m),
        BudgetError::InvalidAmount(_)
        | BudgetError::InvalidPeriod(_)
        | BudgetError::UnknownSource(_)
        | BudgetError::UnknownTier(_)
        | BudgetError::UnknownStatus(_)
        | BudgetError::InvalidReviewOutcome(_)
        | BudgetError::MissingRejectionReason
        | BudgetError::AmountNotOffered(_)
        | BudgetError::InvalidSchedule(_) => CratestackError::BadRequest(err.to_string()),
        BudgetError::AlreadyGranted | BudgetError::AlreadyReviewed(_) => {
            CratestackError::Conflict(err.to_string())
        }
        BudgetError::PolicyDenied(_) => CratestackError::Forbidden(err.to_string()),
        BudgetError::NotFound(m) => CratestackError::NotFound(m),
        BudgetError::StorageFailed(m) => CratestackError::Internal(m),
    }
}

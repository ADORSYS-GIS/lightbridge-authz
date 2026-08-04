//! Error taxonomy for the budget domain. Per #189, callers must be able to distinguish
//! "already granted" from "policy denied" from "storage failed" -- this PR only raises the
//! validation variants (`InvalidAmount`, `InvalidPeriod`, `UnknownSource`, `UnknownTier`), but
//! the ledger/policy variants are included now so later PRs in the #188 epic have a stable
//! taxonomy to grow into rather than reshaping this enum mid-epic.
//!
//! `NotFound`, `UnknownStatus`, `InvalidReviewOutcome`, and `MissingRejectionReason` are added by
//! PR 3.1 (#191) for `augmentation`: a caller looking up an augmentation request by id, or
//! reviewing one, needs to distinguish "no such request" from "you asked for a review outcome
//! that isn't a legitimate review outcome" from "a rejection must carry a reason" -- three
//! genuinely different caller errors, not one generic failure.
//!
//! `AlreadyReviewed` is added by PR 3.3 (#191) for the review queue's concurrency guard: it is
//! distinct from `NotFound` (no row with that id exists at all) -- it means the row exists but
//! lost the `WHERE status = 'pending_review'` race, i.e. it was already reviewed (or resolved
//! some other way) by the time this call's `UPDATE` ran. An admin who just lost that race needs
//! a legible reason, not a generic failure indistinguishable from a typo'd id.

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("amount must be positive micro-USD, got {0}")]
    InvalidAmount(i64),
    #[error("invalid period, expected YYYY-MM: {0}")]
    InvalidPeriod(String),
    #[error("unknown grant source: {0}")]
    UnknownSource(String),
    #[error("unknown budget tier: {0}")]
    UnknownTier(String),
    #[error("a grant already exists for this idempotency key")]
    AlreadyGranted,
    #[error("policy denied this request: {0}")]
    PolicyDenied(String),
    #[error("storage operation failed: {0}")]
    StorageFailed(String),
    #[error("invalid rule data: {0}")]
    InvalidRuleData(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unknown augmentation request status: {0}")]
    UnknownStatus(String),
    #[error("'{0}' is not a legitimate review outcome")]
    InvalidReviewOutcome(String),
    #[error("a rejection must carry a non-empty rejection reason")]
    MissingRejectionReason,
    #[error(
        "augmentation request '{0}' is not pending review (already reviewed, or does not exist)"
    )]
    AlreadyReviewed(String),
}

pub type Result<T> = std::result::Result<T, BudgetError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_render_sensibly() {
        assert_eq!(
            BudgetError::InvalidAmount(-5).to_string(),
            "amount must be positive micro-USD, got -5"
        );
        assert_eq!(
            BudgetError::InvalidPeriod("garbage".to_string()).to_string(),
            "invalid period, expected YYYY-MM: garbage"
        );
        assert_eq!(
            BudgetError::UnknownSource("bogus".to_string()).to_string(),
            "unknown grant source: bogus"
        );
        assert_eq!(
            BudgetError::UnknownTier("b-2000".to_string()).to_string(),
            "unknown budget tier: b-2000"
        );
        assert_eq!(
            BudgetError::AlreadyGranted.to_string(),
            "a grant already exists for this idempotency key"
        );
        assert_eq!(
            BudgetError::PolicyDenied("over rung limit".to_string()).to_string(),
            "policy denied this request: over rung limit"
        );
        assert_eq!(
            BudgetError::StorageFailed("connection reset".to_string()).to_string(),
            "storage operation failed: connection reset"
        );
        assert_eq!(
            BudgetError::InvalidRuleData("policy_revision must not be empty".to_string())
                .to_string(),
            "invalid rule data: policy_revision must not be empty"
        );
        assert_eq!(
            BudgetError::NotFound("augmentation request req-1".to_string()).to_string(),
            "not found: augmentation request req-1"
        );
        assert_eq!(
            BudgetError::UnknownStatus("bogus".to_string()).to_string(),
            "unknown augmentation request status: bogus"
        );
        assert_eq!(
            BudgetError::InvalidReviewOutcome("cancelled".to_string()).to_string(),
            "'cancelled' is not a legitimate review outcome"
        );
        assert_eq!(
            BudgetError::MissingRejectionReason.to_string(),
            "a rejection must carry a non-empty rejection reason"
        );
        assert_eq!(
            BudgetError::AlreadyReviewed("req-1".to_string()).to_string(),
            "augmentation request 'req-1' is not pending review (already reviewed, or does not exist)"
        );
    }
}

//! Error taxonomy for the budget domain. Per #189, callers must be able to distinguish
//! "already granted" from "policy denied" from "storage failed" -- this PR only raises the
//! validation variants (`InvalidAmount`, `InvalidPeriod`, `UnknownSource`, `UnknownTier`), but
//! the ledger/policy variants are included now so later PRs in the #188 epic have a stable
//! taxonomy to grow into rather than reshaping this enum mid-epic.

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
    }
}

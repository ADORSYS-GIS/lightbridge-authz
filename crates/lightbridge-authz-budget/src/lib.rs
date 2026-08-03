//! Domain crate for the dynamic budget refill epic (#188): an immutable budget-grant ledger,
//! derived balances, augmentation requests, and the policy engine that decides refills. Per
//! ADR-0010, this domain is deliberately hand-written procedures and a hand-written repository
//! rather than cratestack `model` blocks, so this crate holds domain types, repository, and
//! policy engine code directly instead of relying on generated CRUD. This is a skeleton: no
//! ledger types, repository, or policy engine yet -- those land in later PRs in the epic's
//! delivery sequence.

pub mod amount;
pub mod error;
pub mod period;
pub mod source;
pub mod spend;
pub mod tier;

pub use amount::AmountMicros;
pub use error::BudgetError;
pub use period::Period;
pub use source::GrantSource;
pub use spend::{Spend, SpendReader, TimescaleSpendReader};
pub use tier::BudgetTier;

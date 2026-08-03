//! Domain crate for the dynamic budget refill epic (#188): an immutable budget-grant ledger,
//! derived balances, augmentation requests, and the policy engine that decides refills. Per
//! ADR-0010, this domain is deliberately hand-written procedures and a hand-written repository
//! rather than cratestack `model` blocks, so this crate holds domain types, repository, and
//! policy engine code directly instead of relying on generated CRUD.
//!
//! Per ADR-0007, [`decision`]/[`facts`] define the decision contract and fact set that any
//! policy engine sits behind (the [`decision::PolicyEngine`] trait); no evaluator implementation
//! lives in this crate yet -- see `docs/budget-decision-contract.md`.

pub mod amount;
pub mod decision;
pub mod error;
pub mod facts;
pub mod period;
pub mod repo;
pub mod source;
pub mod spend;
pub mod tier;

pub use amount::AmountMicros;
pub use decision::{Decision, Effect, Obligations, PolicyEngine};
pub use error::BudgetError;
pub use facts::Facts;
pub use period::Period;
pub use source::GrantSource;
pub use spend::{Spend, SpendReader, TimescaleSpendReader};
pub use tier::BudgetTier;

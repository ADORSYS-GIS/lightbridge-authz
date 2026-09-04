//! Domain crate for the dynamic budget refill epic (#188): an immutable budget-grant ledger,
//! derived balances, augmentation requests, and the policy engine that decides refills. Per
//! ADR-0010, this domain is deliberately hand-written procedures and a hand-written repository
//! rather than cratestack `model` blocks, so this crate holds domain types, repository, and
//! policy engine code directly instead of relying on generated CRUD.
//!
//! Per ADR-0007, [`decision`]/[`facts`] define the decision contract and fact set that any
//! policy engine sits behind (the [`decision::PolicyEngine`] trait); [`rule_data`] is the first
//! (rule-data-driven) evaluator against it, with an OPA-Wasm evaluator planned for a later PR --
//! see `docs/budget-decision-contract.md`.

pub mod amount;
pub mod augmentation;
pub mod decision;
pub mod error;
pub mod facts;
mod known_account;
pub mod period;
pub mod policy_store;
mod policy_store_sql;
pub mod refill;
pub mod remaining;
mod remaining_cache;
pub mod remaining_service;
pub mod remaining_snapshot;
pub mod repo;
mod repo_grant_sql;
pub mod reset_schedule;
pub mod reset_schedule_validate;
pub mod reset_scheduler;
pub mod review;
pub mod rule_data;
pub mod snapshot;
mod snapshot_refresh_one;
pub mod snapshot_refresher;
pub mod snapshot_store;
pub mod source;
pub mod spend;
mod spend_units;
pub mod tier;

pub use amount::AmountMicros;
pub use augmentation::{
    ApprovedDecision, AugmentationRepo, AugmentationRequest, AugmentationStatus,
    NewAugmentationRequest, RecordedDecision, UnapprovedDecision,
};
pub use decision::{Decision, Effect, Obligations, PolicyEngine};
pub use error::BudgetError;
pub use facts::Facts;
pub use period::Period;
pub use policy_store::PolicyStore;
pub use refill::{RefillRequest, RefillService, RefillStatus};
pub use remaining::{
    BudgetRemaining, Remaining, RemainingReader, RemainingService, SnapshotRemainingService,
};
pub use reset_schedule::{
    BudgetResetSchedule, BudgetResetScheduleUpdate, Cadence, NewBudgetResetSchedule, ResetMode,
    ResetScheduleRepo, ScheduleScopeKind, first_window_after, next_window_after, parse_run_at_utc,
    render_run_at_utc,
};
pub use reset_scheduler::{
    EffectiveSchedule, PlannedGrant, ResetScheduler, ScheduleRunOutcome, TickReport,
};
pub use review::ReviewService;
pub use rule_data::{
    Condition, Field, Operator, Rule, RuleDataEngine, RuleSet, default_rule_set_json,
    validate_rule_data,
};
pub use snapshot::{BudgetSnapshot, BudgetSnapshotReader, RefreshReport, SnapshotRefreshConfig};
pub use snapshot_refresher::SnapshotRefresher;
pub use snapshot_store::SnapshotStore;
pub use source::GrantSource;
pub use spend::{
    Spend, SpendObservation, SpendReader, UnavailableSpendReader, UsageServiceSpendReader,
};
pub use tier::BudgetTier;

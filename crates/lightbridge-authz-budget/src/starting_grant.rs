//! The starting grant every account is funded with the moment it is created (#697).
//!
//! Before this, nothing booked a grant at account creation: an account was funded only when a
//! reset schedule with a matching predicate next ran, which is weekly. That was invisible while
//! the gateway read `known: false` and failed open; under the enforcing budget limiter (ADR-0034
//! §15.7, enforcing in production since 2026-09-04) it is up to seven days of `402`.
//!
//! **How much** is [`crate::starting_grant_amount`]'s subject and is where the `$8`-vs-`$15` rule
//! is written down. This module owns the write.
//!
//! ## Idempotency
//!
//! One key per (account, period): `budget-start-<period>-<account_id>`. A retried creation flow, a
//! replayed provisioning job, or a second call for an account that already has its grant all
//! resolve to the grant that already exists — [`crate::repo::BudgetRepo::grant`]'s
//! `ON CONFLICT (idempotency_key) DO NOTHING` path — because ADR-0009 makes the ledger
//! append-only and a double grant has no undo.
//!
//! ## Why it is not in the account insert's own transaction
//!
//! `accounts` is written by `lightbridge-authz-api-key`'s `StoreRepo::create_account`, a crate
//! that does not (and should not) depend on this one — the budget domain is downstream of the
//! tenancy domain, not beside it. The grant is therefore booked immediately after the insert
//! commits, with the idempotency key as the retry guard rather than a shared transaction.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;

use crate::decision::PolicyEngine;
use crate::effective_schedule::effective_schedule;
use crate::error::BudgetError;
use crate::period::Period;
use crate::policy_store::PolicyStore;
use crate::repo::{BudgetGrant, BudgetRepo, GrantRequest};
use crate::reset_schedule::ResetScheduleRepo;
use crate::snapshot::BudgetSnapshotReader;
use crate::snapshot_store::SnapshotStore;
use crate::source::GrantSource;
use crate::starting_grant_amount::{StartingAmount, starting_grant_idempotency_key};

/// Books the starting grant. Built from the pool alone so every construction site of the account
/// handler gets one — there is no "server without starting grants" configuration, and an optional
/// dependency here would be a silent re-introduction of #697. Its `BudgetRepo`/`SnapshotStore`/
/// `ResetScheduleRepo` are stateless handles over that same pool, the same way
/// `Procedures.budget_repo` is a second independent handle over the one database.
#[derive(Debug, Clone)]
pub struct StartingGrantService {
    pool: Arc<dyn DbPoolTrait>,
    budget_repo: Arc<BudgetRepo>,
    schedules: ResetScheduleRepo,
    snapshots: SnapshotStore,
    policy_set_id: String,
    evaluation_budget: usize,
}

impl StartingGrantService {
    pub fn new(
        pool: Arc<dyn DbPoolTrait>,
        policy_set_id: impl Into<String>,
        evaluation_budget: usize,
    ) -> Self {
        Self {
            budget_repo: Arc::new(BudgetRepo::new(pool.clone())),
            schedules: ResetScheduleRepo::new(pool.clone()),
            snapshots: SnapshotStore::new(pool.clone()),
            pool,
            policy_set_id: policy_set_id.into(),
            evaluation_budget,
        }
    }

    /// What this account's starting grant must be worth. See [`crate::starting_grant_amount`] for
    /// why the schedule wins over the policy default.
    ///
    /// The policy is read from the database on the fallback path rather than cached at startup:
    /// account creation is rare, and `activateBudgetPolicy` can move `starting_amount_micros`
    /// between two signups.
    pub async fn resolve_amount(
        &self,
        budget_account_id: &str,
    ) -> Result<StartingAmount, BudgetError> {
        if let Some(effective) =
            effective_schedule(self.pool.pool(), &self.schedules, budget_account_id).await?
        {
            return Ok(StartingAmount::Schedule {
                schedule_id: effective.schedule.id,
                schedule_name: effective.schedule.name,
                amount_micros: effective.schedule.amount_micros,
            });
        }

        let policy = PolicyStore::load_active_from_db(
            self.pool.clone(),
            &self.policy_set_id,
            self.evaluation_budget,
        )
        .await?;
        Ok(StartingAmount::PolicyDefault {
            amount_micros: policy.engine().starting_amount_micros(),
        })
    }

    /// Books this account's starting grant for the period `now` falls in, then joins it to the
    /// snapshot working set so the gateway reads `known: true` on the refresher's next tick
    /// instead of on the account's first metered request.
    ///
    /// [`crate::snapshot_store::SnapshotStore::apply_grant_delta_tx`] inside the grant's own
    /// transaction cannot help here — it deliberately refuses a row that carries no reading yet,
    /// and a brand-new account has no row at all — so the existing `touch` path is what puts it
    /// in front of the refresher.
    pub async fn book(
        &self,
        budget_account_id: &str,
        now: DateTime<Utc>,
    ) -> Result<BudgetGrant, BudgetError> {
        let period = Period::current(now);
        let amount = self.resolve_amount(budget_account_id).await?;
        let idempotency_key = starting_grant_idempotency_key(&period, budget_account_id);

        let grant = self
            .budget_repo
            .grant(GrantRequest {
                budget_account_id: budget_account_id.to_string(),
                account_id: budget_account_id.to_string(),
                project_id: None,
                period,
                amount_micros: amount.amount_micros(),
                // `automatic`, not `admin`: this grant stands in for the schedule run that would
                // otherwise have funded the account, so `budget_balances` must bucket it the way
                // that run would have (`docs/budget-cli.md`, "The $8-vs-$15 rule").
                source: GrantSource::Automatic,
                actor_id: None,
                reason: Some(amount.reason()),
                policy_revision: None,
                matched_rule_ids: None,
                idempotency_key: Some(idempotency_key),
                trigger_key: None,
                expires_at: None,
            })
            .await?;

        self.snapshots.touch(budget_account_id).await?;

        tracing::info!(
            budget_account_id = %budget_account_id,
            grant_id = %grant.id,
            period = %grant.period,
            amount_micros = grant.amount_micros,
            rule = match amount {
                StartingAmount::Schedule { .. } => "effective_schedule",
                StartingAmount::PolicyDefault { .. } => "policy_starting_amount",
            },
            "booked the starting grant for a new account"
        );
        Ok(grant)
    }
}

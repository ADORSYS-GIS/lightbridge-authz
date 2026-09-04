//! [`SnapshotRemainingService`] — the snapshot-first [`RemainingReader`] `GET
//! /budget/v1/remaining` is served through since ADR-0034 §15.
//!
//! A decorator, not a rewrite. It answers from `budget_remaining_snapshots` when that row carries
//! a usable reading, and otherwise delegates verbatim to the inner live reader
//! ([`crate::remaining_service::RemainingService`]). Two consequences worth stating:
//!
//! - **The endpoint's contract is bit-for-bit unchanged.** `404 unknown_account`, `503
//!   budget_unavailable`, the existence probe, the cached-grace window — all of it still lives in
//!   the inner reader and is still reached on exactly the paths that need it. This layer can only
//!   ever turn a *slow, correct* answer into a *fast, slightly older, equally correct* one.
//! - **A cold account is not a failure.** The first request for an account nobody has asked about
//!   recently finds no reading and falls through to the live path, which answers correctly and
//!   pays the old price once. The introspection hot path deliberately does NOT do this (it omits
//!   the field instead) — an operator's read may cost a spend query; a metered model request may
//!   not.

use chrono::{DateTime, Utc};
use std::sync::Arc;

use crate::error::BudgetError;
use crate::period::Period;
use crate::remaining::{BudgetRemaining, Remaining, RemainingReader};
use crate::snapshot::BudgetSnapshotReader;

/// Serves `ceiling − spend` from the precomputed snapshot, falling back to `inner` when there is
/// nothing usable stored.
#[derive(Debug)]
pub struct SnapshotRemainingService {
    snapshots: Arc<dyn BudgetSnapshotReader>,
    inner: Arc<dyn RemainingReader>,
}

impl SnapshotRemainingService {
    pub fn new(snapshots: Arc<dyn BudgetSnapshotReader>, inner: Arc<dyn RemainingReader>) -> Self {
        Self { snapshots, inner }
    }
}

#[lightbridge_authz_core::async_trait]
impl RemainingReader for SnapshotRemainingService {
    async fn remaining_for_account(
        &self,
        budget_account_id: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError> {
        // A snapshot READ failing is not a reason to fail the request: the live path below can
        // still answer. It is logged and treated as a miss -- the one degradation that costs
        // latency and never correctness.
        let snapshot = match self.snapshots.read(budget_account_id).await {
            Ok(snapshot) => snapshot,
            Err(err) => {
                tracing::warn!(
                    budget_account_id = %budget_account_id,
                    error = %err,
                    "budget snapshot read failed; computing the remaining balance live"
                );
                None
            }
        };

        // `remaining_for` is what enforces the period check: a stored reading that describes last
        // month is not a stale approximation of this month's balance, it is a different quantity,
        // and serving it would hand the whole fleet a balance it already spent.
        let usable = snapshot.as_ref().and_then(|row| {
            let remaining_micros = row.remaining_for(period)?;
            Some((remaining_micros, row))
        });

        let Some((remaining_micros, row)) = usable else {
            return self
                .inner
                .remaining_for_account(budget_account_id, period, now)
                .await;
        };

        Ok(Remaining::Known(Box::new(BudgetRemaining {
            budget_account_id: row.budget_account_id.clone(),
            period: period.clone(),
            // Both halves are non-NULL whenever `remaining_micros` is: the refresher writes all
            // three in one statement. `unwrap_or_default` is a type guard, not a fabrication --
            // and it can only ever be reached on a row hand-edited outside this code.
            ceiling_micros: row.ceiling_micros.unwrap_or_default(),
            spent_micros: row.spent_micros.unwrap_or_default(),
            remaining_micros,
            // The refresher always writes one. A row without it predates a successful refresh, and
            // such a row has no `remaining_micros` either, so it never reaches here.
            next_reset_at: row
                .next_reset_at
                .unwrap_or_else(|| crate::remaining::next_period_start_utc(period)),
            // Reported ONLY while the spend source is known to be failing. `stale_since` is the
            // instant that outage started, so its age is the honest lower bound on how old the
            // spend half of this figure is -- distinct from the snapshot's own age below, which
            // exists on every snapshot-served answer.
            source_lag_seconds: row
                .stale_since
                .map(|since| now.signed_duration_since(since).num_seconds().max(0) as u64),
            snapshot_age_seconds: row.age_seconds(now),
        })))
    }

    /// Skips this layer entirely — `?fresh=true`'s whole purpose is to bypass the snapshot and
    /// make the inner reader do the ledger `SUM` and the spend query for real.
    async fn remaining_for_account_live(
        &self,
        budget_account_id: &str,
        period: &Period,
        now: DateTime<Utc>,
    ) -> Result<Remaining, BudgetError> {
        self.inner
            .remaining_for_account(budget_account_id, period, now)
            .await
    }
}

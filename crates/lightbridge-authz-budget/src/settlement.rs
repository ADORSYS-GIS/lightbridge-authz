//! ADR-0035 D6: settlement books spend into the ledger, up to a watermark on usage INGESTION time.
//! One account at a time: read the watermark, ask `authz-usage` for the spend ingested since it
//! (outside any transaction), then book it in one transaction (`settlement_book.rs`). Unknown
//! spend is never zero spend: if the usage service does not answer, nothing is written and the
//! watermark stays where it is (the ADR-0032 D5 rule).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::{PgPool, Row};

use crate::error::BudgetError;
use crate::period::Period;
use crate::settlement_book::{Booked, book};
use crate::spend::{SpendObservation, SpendReader};
use crate::spend_units::period_bounds_utc;

/// How far behind real time a settlement window ends: longer than any ingest transaction, whose
/// rows carry the time it STARTED (`NOW()`), not the time it committed (D6).
pub const SETTLE_LAG: chrono::Duration = chrono::Duration::seconds(120);
const SETTLE_ADVISORY_LOCK_KEY: i64 = 0x4255_4447_5F53_4554;
const READ_STATE_SQL: &str =
    "SELECT settled_through FROM settlement_state WHERE budget_account_id = $1";
// Recently active accounts, plus any holding a granted lot that has expired and needs booking.
const DUE_ACCOUNTS_SQL: &str = "SELECT budget_account_id FROM budget_remaining_snapshots \
    WHERE last_seen_at >= $1 UNION SELECT budget_account_id FROM credit_lots \
    WHERE remaining_micros > 0 AND expires_at <= $2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    Settled(Booked),
    /// The usage service did not answer; nothing was written.
    Deferred,
    /// Another run moved the watermark first; nothing was written.
    Raced,
}

#[derive(Debug)]
pub struct Settlement {
    pool: Arc<dyn DbPoolTrait>,
    spend_reader: Arc<dyn SpendReader>,
    interval: Duration,
    active_window: Duration,
}

impl Settlement {
    pub fn new(
        pool: Arc<dyn DbPoolTrait>,
        spend_reader: Arc<dyn SpendReader>,
        interval: Duration,
        active_window: Duration,
    ) -> Self {
        Self {
            pool,
            spend_reader,
            interval,
            active_window,
        }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    pub(crate) fn spend_reader(&self) -> &Arc<dyn SpendReader> {
        &self.spend_reader
    }

    /// Where an account's watermark stands, or where it starts: the beginning of the current
    /// allowance period -- which makes the first reading exactly today's "grants minus this
    /// month's spend" (ADR-0035 *Rollout*).
    pub async fn settled_through(
        &self,
        account: &str,
        now: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, BudgetError> {
        let row = sqlx::query(READ_STATE_SQL)
            .bind(account)
            .fetch_optional(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(match row {
            Some(row) => row.get("settled_through"),
            None => period_bounds_utc(&Period::current(now)).0,
        })
    }

    pub async fn settle_account(
        &self,
        account: &str,
        now: DateTime<Utc>,
    ) -> Result<SettleOutcome, BudgetError> {
        let from = self.settled_through(account, now).await?;
        let to = (now - SETTLE_LAG).max(from);
        let spend = if to > from {
            match self
                .spend_reader
                .observe_spend_ingested(account, from, to)
                .await?
            {
                SpendObservation::Answered(micros) => micros,
                SpendObservation::Empty => 0,
                SpendObservation::Unreachable => return Ok(SettleOutcome::Deferred),
            }
        } else {
            0
        };
        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        let booked = book(
            &mut tx,
            account,
            &Period::current(now),
            from,
            to,
            spend,
            now,
        )
        .await?;
        tx.commit()
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(booked.map_or(SettleOutcome::Raced, SettleOutcome::Settled))
    }

    /// D7/D8: a reset renews the allowance, so it forgives the account's debt.
    pub async fn forgive_debt(&self, account: &str) -> Result<(), BudgetError> {
        sqlx::query("UPDATE settlement_state SET debt_micros = 0, updated_at = now() WHERE budget_account_id = $1")
            .bind(account)
            .execute(self.pool())
            .await
            .map_err(|err| BudgetError::StorageFailed(err.to_string()))?;
        Ok(())
    }

    /// Settles every due account. Replica-safe: one replica at a time holds the advisory lock;
    /// the others skip the tick (and the watermark check makes even an overlap harmless).
    pub async fn tick(&self, now: DateTime<Utc>) -> Result<usize, BudgetError> {
        let storage = |err: sqlx::Error| BudgetError::StorageFailed(err.to_string());
        let mut lock_tx = self.pool().begin().await.map_err(storage)?;
        let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(SETTLE_ADVISORY_LOCK_KEY)
            .fetch_one(&mut *lock_tx)
            .await
            .map_err(storage)?;
        if !acquired {
            return Ok(0);
        }
        let active_since = now - chrono::Duration::from_std(self.active_window).unwrap_or_default();
        let accounts: Vec<String> = sqlx::query_scalar(DUE_ACCOUNTS_SQL)
            .bind(active_since)
            .bind(now)
            .fetch_all(self.pool())
            .await
            .map_err(storage)?;
        let mut settled = 0;
        for account in &accounts {
            match self.settle_account(account, now).await {
                Ok(SettleOutcome::Settled(_)) => settled += 1,
                Ok(outcome) => {
                    tracing::debug!(budget_account_id = %account, ?outcome, "settlement skipped")
                }
                Err(err) => {
                    tracing::warn!(budget_account_id = %account, error = %err, "settlement failed")
                }
            }
        }
        lock_tx.rollback().await.map_err(storage)?;
        Ok(settled)
    }

    /// Runs [`Self::tick`] every `interval` until the process exits. A failing tick is logged,
    /// never fatal.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match self.tick(Utc::now()).await {
                    Ok(settled) if settled > 0 => tracing::info!(settled, "settlement tick"),
                    Ok(_) => {}
                    Err(err) => tracing::warn!(error = %err, "settlement tick failed"),
                }
            }
        })
    }
}

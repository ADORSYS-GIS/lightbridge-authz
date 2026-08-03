//! The transactional grant-write path (ADR-0009, #189): the one place a `budget_grants` row is
//! inserted and `budget_balances` is updated, atomically, under a lock, with idempotency. Every
//! write to the ledger must go through [`BudgetRepo::grant`] -- a direct `UPDATE budget_balances`
//! anywhere else would be silent and would work, which is exactly what ADR-0009 warns against.
//!
//! The transaction, per (account, period):
//!
//! 1. `INSERT ... ON CONFLICT (budget_account_id, period) DO NOTHING` bootstraps a zero-valued
//!    balance row if one doesn't exist yet.
//! 2. `SELECT ... FOR UPDATE` locks that row for the rest of the transaction, serializing
//!    concurrent grants for the same (account, period).
//! 3. The grant insert itself, with `ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT
//!    NULL DO NOTHING` -- a genuine idempotency-key replay resolves to zero rows returned, at
//!    which point the already-committed row is read back instead of granting twice.
//! 4. Only a fresh insert (a new idempotency key, or none supplied) updates the balance; a
//!    replay leaves it untouched.

use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::PgPool;

use crate::error::BudgetError;
use crate::period::Period;
use crate::source::GrantSource;

#[derive(Debug, Clone)]
pub struct BudgetRepo {
    pool: Arc<dyn DbPoolTrait>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GrantRequest {
    pub budget_account_id: String,
    pub account_id: String,
    pub project_id: Option<String>,
    pub period: Period,
    pub amount_micros: i64,
    pub source: GrantSource,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub policy_revision: Option<String>,
    pub matched_rule_ids: Option<Vec<String>>,
    pub idempotency_key: Option<String>,
    pub trigger_key: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BudgetGrant {
    pub id: String,
    pub budget_account_id: String,
    pub account_id: String,
    pub project_id: Option<String>,
    pub period: Period,
    pub amount_micros: i64,
    pub source: GrantSource,
    pub actor_id: Option<String>,
    pub reason: Option<String>,
    pub policy_revision: Option<String>,
    pub matched_rule_ids: Option<Vec<String>>,
    pub idempotency_key: Option<String>,
    pub trigger_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct BudgetGrantRow {
    id: String,
    budget_account_id: String,
    account_id: String,
    project_id: Option<String>,
    period: String,
    amount_micros: i64,
    source: String,
    actor_id: Option<String>,
    reason: Option<String>,
    policy_revision: Option<String>,
    matched_rule_ids: Option<Vec<String>>,
    idempotency_key: Option<String>,
    trigger_key: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<BudgetGrantRow> for BudgetGrant {
    type Error = BudgetError;

    fn try_from(row: BudgetGrantRow) -> Result<Self, Self::Error> {
        let period = Period::parse(&row.period).map_err(|err| {
            BudgetError::StorageFailed(format!("stored budget_grants.period is invalid: {err}"))
        })?;
        let source = GrantSource::from_str(&row.source).map_err(|err| {
            BudgetError::StorageFailed(format!("stored budget_grants.source is invalid: {err}"))
        })?;

        Ok(Self {
            id: row.id,
            budget_account_id: row.budget_account_id,
            account_id: row.account_id,
            project_id: row.project_id,
            period,
            amount_micros: row.amount_micros,
            source,
            actor_id: row.actor_id,
            reason: row.reason,
            policy_revision: row.policy_revision,
            matched_rule_ids: row.matched_rule_ids,
            idempotency_key: row.idempotency_key,
            trigger_key: row.trigger_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        })
    }
}

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

fn validate_amount_sign(source: GrantSource, amount_micros: i64) -> Result<(), BudgetError> {
    let sign_is_valid = match source {
        GrantSource::Correction => amount_micros != 0,
        _ => amount_micros > 0,
    };

    if sign_is_valid {
        Ok(())
    } else {
        Err(BudgetError::InvalidAmount(amount_micros))
    }
}

const GRANT_INSERT_SQL: &str = "INSERT INTO budget_grants \
    (id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, \
     trigger_key, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
     ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING \
     RETURNING id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at";

const GRANT_SELECT_BY_IDEMPOTENCY_KEY_SQL: &str = "SELECT \
     id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at \
     FROM budget_grants WHERE idempotency_key = $1";

impl BudgetRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    pub async fn grant(&self, request: GrantRequest) -> Result<BudgetGrant, BudgetError> {
        validate_amount_sign(request.source, request.amount_micros)?;

        let period_str = request.period.to_string();
        let source_str = request.source.to_string();

        let mut tx = self.pool().begin().await.map_err(storage_failed)?;

        sqlx::query(
            "INSERT INTO budget_balances (budget_account_id, period) VALUES ($1, $2) \
             ON CONFLICT (budget_account_id, period) DO NOTHING",
        )
        .bind(&request.budget_account_id)
        .bind(&period_str)
        .execute(&mut *tx)
        .await
        .map_err(storage_failed)?;

        sqlx::query(
            "SELECT budget_account_id FROM budget_balances \
             WHERE budget_account_id = $1 AND period = $2 FOR UPDATE",
        )
        .bind(&request.budget_account_id)
        .bind(&period_str)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_failed)?;

        let id = cuid2();

        let inserted: Option<BudgetGrantRow> = sqlx::query_as(GRANT_INSERT_SQL)
            .bind(&id)
            .bind(&request.budget_account_id)
            .bind(&request.account_id)
            .bind(&request.project_id)
            .bind(&period_str)
            .bind(request.amount_micros)
            .bind(&source_str)
            .bind(&request.actor_id)
            .bind(&request.reason)
            .bind(&request.policy_revision)
            .bind(&request.matched_rule_ids)
            .bind(&request.idempotency_key)
            .bind(&request.trigger_key)
            .bind(request.expires_at)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_failed)?;

        let grant_row = match inserted {
            Some(row) => {
                sqlx::query(
                    "UPDATE budget_balances SET \
                        base_total_micros = base_total_micros \
                            + CASE WHEN $3 IN ('base','migration') THEN $4 ELSE 0 END, \
                        self_service_total_micros = self_service_total_micros \
                            + CASE WHEN $3 = 'self_service' THEN $4 ELSE 0 END, \
                        admin_total_micros = admin_total_micros \
                            + CASE WHEN $3 IN ('admin','manual_approval','promotion') THEN $4 ELSE 0 END, \
                        automatic_total_micros = automatic_total_micros \
                            + CASE WHEN $3 = 'automatic' THEN $4 ELSE 0 END, \
                        refund_total_micros = refund_total_micros \
                            + CASE WHEN $3 = 'refund' THEN $4 ELSE 0 END, \
                        effective_budget_micros = effective_budget_micros + $4, \
                        self_service_grant_count = self_service_grant_count \
                            + CASE WHEN $3 = 'self_service' THEN 1 ELSE 0 END, \
                        automatic_grant_count = automatic_grant_count \
                            + CASE WHEN $3 = 'automatic' THEN 1 ELSE 0 END, \
                        version = version + 1, \
                        updated_at = now() \
                     WHERE budget_account_id = $1 AND period = $2",
                )
                .bind(&request.budget_account_id)
                .bind(&period_str)
                .bind(&source_str)
                .bind(request.amount_micros)
                .execute(&mut *tx)
                .await
                .map_err(storage_failed)?;

                row
            }
            None => sqlx::query_as(GRANT_SELECT_BY_IDEMPOTENCY_KEY_SQL)
                .bind(&request.idempotency_key)
                .fetch_one(&mut *tx)
                .await
                .map_err(storage_failed)?,
        };

        tx.commit().await.map_err(storage_failed)?;

        BudgetGrant::try_from(grant_row)
    }
}

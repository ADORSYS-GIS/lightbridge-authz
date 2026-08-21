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
use crate::tier::BudgetTier;

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

/// A `budget_balances` row recomputed directly from `budget_grants`, using the exact same
/// source-to-bucket mapping [`BudgetRepo::grant`]'s balance `UPDATE` uses. Deliberately
/// unconditional -- it does not filter on `expires_at`/`revoked_at`, because [`BudgetRepo::grant`]
/// does not either: the stored `budget_balances` totals already include amounts from grants that
/// carry an `expires_at` (even a past one) or, in the rare historical-import case, a `revoked_at`
/// set at insert time. Reproducing the raw stored projection bit-for-bit requires reproducing
/// that same unconditional behavior. Expiry/revocation-aware reads are a separate, narrower
/// concern -- see [`BudgetRepo::effective_balance`].
///
/// Deliberately does NOT carry `version`/`updated_at` -- those are mutation bookkeeping (how many
/// times the row changed, and when), not ledger-derived facts, and are out of scope for the
/// replay equality check (#189).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct DerivedBalance {
    pub budget_account_id: String,
    /// Raw string, not a parsed [`Period`] -- this is compared directly against
    /// `budget_balances.period`, which is also raw `TEXT`. Forcing a `Period::parse` round-trip
    /// here could fail on data this function must handle unconditionally.
    pub period: String,
    pub base_total_micros: i64,
    pub self_service_total_micros: i64,
    pub admin_total_micros: i64,
    pub automatic_total_micros: i64,
    pub refund_total_micros: i64,
    pub effective_budget_micros: i64,
    pub self_service_grant_count: i32,
    pub automatic_grant_count: i32,
}

const REBUILD_ALL_BALANCES_SQL: &str = "SELECT \
     budget_account_id, \
     period, \
     COALESCE(SUM(CASE WHEN source IN ('base','migration') THEN amount_micros ELSE 0 END), 0)::bigint \
        AS base_total_micros, \
     COALESCE(SUM(CASE WHEN source = 'self_service' THEN amount_micros ELSE 0 END), 0)::bigint \
        AS self_service_total_micros, \
     COALESCE(SUM(CASE WHEN source IN ('admin','manual_approval','promotion') THEN amount_micros ELSE 0 END), 0)::bigint \
        AS admin_total_micros, \
     COALESCE(SUM(CASE WHEN source = 'automatic' THEN amount_micros ELSE 0 END), 0)::bigint \
        AS automatic_total_micros, \
     COALESCE(SUM(CASE WHEN source = 'refund' THEN amount_micros ELSE 0 END), 0)::bigint \
        AS refund_total_micros, \
     COALESCE(SUM(amount_micros), 0)::bigint AS effective_budget_micros, \
     COALESCE(SUM(CASE WHEN source = 'self_service' THEN 1 ELSE 0 END), 0)::int \
        AS self_service_grant_count, \
     COALESCE(SUM(CASE WHEN source = 'automatic' THEN 1 ELSE 0 END), 0)::int \
        AS automatic_grant_count \
     FROM budget_grants \
     GROUP BY budget_account_id, period";

const EFFECTIVE_BALANCE_SQL: &str = "SELECT COALESCE(SUM(amount_micros), 0)::bigint \
     FROM budget_grants \
     WHERE budget_account_id = $1 AND period = $2 \
       AND (expires_at IS NULL OR expires_at > $3) \
       AND revoked_at IS NULL";

/// The grant whose most recent `amount_micros` for `(budget_account_id, period)` represents "the
/// tier this account is currently on" -- shared by [`crate::refill::RefillService`] (deciding the
/// next rung to request) and, since ADR-0014, the token-exchange minting path (deciding what to
/// stamp on a JWT). Deliberately excludes `correction`/`refund`: neither represents a tier an
/// account is on -- a `correction` can shift the raw ledger total in a way that no longer matches
/// any known rung, and a `refund` is a compensating adjustment, not a statement about the
/// account's current tier.
const LATEST_TIER_GRANT_AMOUNT_SQL: &str = "SELECT amount_micros FROM budget_grants \
     WHERE budget_account_id = $1 AND period = $2 \
       AND source IN ('base','self_service','automatic','admin','manual_approval','promotion') \
     ORDER BY created_at DESC LIMIT 1";

const GET_BALANCE_SQL: &str = "SELECT \
     budget_account_id, period, base_total_micros, self_service_total_micros, \
     admin_total_micros, automatic_total_micros, refund_total_micros, \
     effective_budget_micros, self_service_grant_count, automatic_grant_count, \
     version, updated_at \
     FROM budget_balances WHERE budget_account_id = $1 AND period = $2";

const GET_GRANT_BY_ID_SQL: &str = "SELECT \
     id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at \
     FROM budget_grants WHERE id = $1";

// `period` is `$2::text` -- an untyped `NULL` bind for an omitted period filter would otherwise
// require sqlx to infer the parameter's Postgres type from context, which it cannot always do
// reliably for a bare `IS NULL OR =` predicate; the explicit cast pins it. `created_at < $3` (not
// `<=`) makes the cursor exclusive, matching the "return rows strictly older than `before`"
// contract this module's callers document -- see [`BudgetRepo::list_grants`]. Ordered `DESC` by
// `created_at` ONLY (per ADR-0039: never sort or paginate by id -- ids are opaque CUID2 strings
// with no defined ordering, so `id` appears nowhere in this query, not even as a tie-breaker).
const LIST_GRANTS_SQL: &str = "SELECT \
     id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at \
     FROM budget_grants \
     WHERE budget_account_id = $1 \
       AND ($2::text IS NULL OR period = $2) \
       AND ($3::timestamptz IS NULL OR created_at < $3) \
     ORDER BY created_at DESC \
     LIMIT $4";

/// A single `budget_balances` row, read directly (not replayed from the ledger like
/// [`DerivedBalance`], and not filtered by expiry like [`BudgetRepo::effective_balance`]). `None`
/// from [`BudgetRepo::get_balance`] means no balance row exists yet for that (account, period) --
/// meaningfully different from a zero-valued row: an account that has never had any grant this
/// period, versus one that has but with zero self-service grants specifically.
#[derive(Debug, Clone, PartialEq)]
pub struct BalanceSnapshot {
    pub budget_account_id: String,
    pub period: Period,
    pub base_total_micros: i64,
    pub self_service_total_micros: i64,
    pub admin_total_micros: i64,
    pub automatic_total_micros: i64,
    pub refund_total_micros: i64,
    pub effective_budget_micros: i64,
    /// How many *unaided* (auto-approved) self-service refills this account has used this
    /// period -- the field [`crate::refill::RefillService`] actually reads.
    pub self_service_grant_count: i32,
    pub automatic_grant_count: i32,
    pub version: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct BalanceRow {
    budget_account_id: String,
    period: String,
    base_total_micros: i64,
    self_service_total_micros: i64,
    admin_total_micros: i64,
    automatic_total_micros: i64,
    refund_total_micros: i64,
    effective_budget_micros: i64,
    self_service_grant_count: i32,
    automatic_grant_count: i32,
    version: i64,
    updated_at: DateTime<Utc>,
}

impl BalanceSnapshot {
    /// A zero-valued snapshot for `(budget_account_id, period)`, used when
    /// [`BudgetRepo::get_balance`] returns `None` -- i.e. this account has never had a grant this
    /// period. Distinct from [`BudgetRepo::get_balance`] itself returning `None` (see that
    /// method's own doc comment for why the two are meaningfully different at the repo layer): a
    /// balance *read* procedure synthesizes this rather than surfacing "no row" as an error,
    /// because "you have zero budget this period" is a legitimate, common answer, not a fault.
    /// `updated_at` is set to `created_at`-less `Utc::now()` at call time -- there is no real
    /// "last updated" for a projection that was never written, so this is a synthesized
    /// placeholder, not a stored value.
    pub fn zero(budget_account_id: &str, period: &Period) -> Self {
        Self {
            budget_account_id: budget_account_id.to_string(),
            period: period.clone(),
            base_total_micros: 0,
            self_service_total_micros: 0,
            admin_total_micros: 0,
            automatic_total_micros: 0,
            refund_total_micros: 0,
            effective_budget_micros: 0,
            self_service_grant_count: 0,
            automatic_grant_count: 0,
            version: 0,
            updated_at: Utc::now(),
        }
    }
}

impl TryFrom<BalanceRow> for BalanceSnapshot {
    type Error = BudgetError;

    fn try_from(row: BalanceRow) -> Result<Self, Self::Error> {
        let period = Period::parse(&row.period).map_err(|err| {
            BudgetError::StorageFailed(format!("stored budget_balances.period is invalid: {err}"))
        })?;

        Ok(Self {
            budget_account_id: row.budget_account_id,
            period,
            base_total_micros: row.base_total_micros,
            self_service_total_micros: row.self_service_total_micros,
            admin_total_micros: row.admin_total_micros,
            automatic_total_micros: row.automatic_total_micros,
            refund_total_micros: row.refund_total_micros,
            effective_budget_micros: row.effective_budget_micros,
            self_service_grant_count: row.self_service_grant_count,
            automatic_grant_count: row.automatic_grant_count,
            version: row.version,
            updated_at: row.updated_at,
        })
    }
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

    /// `pub(crate)`, not private: [`crate::refill::RefillService`] needs a plain read against
    /// `budget_grants` (the most recent tier-representing grant) that doesn't fit any existing
    /// `BudgetRepo` method, and per this module's own docs "reads don't need to go through
    /// `BudgetRepo`, only writes do" -- exposing the pool within the crate is the smallest change
    /// that allows that read without adding a single-purpose method here for one caller.
    pub(crate) fn pool(&self) -> &PgPool {
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

    /// Replays the whole `budget_grants` ledger into the same shape `budget_balances` stores,
    /// using the identical source-to-bucket mapping [`BudgetRepo::grant`]'s `UPDATE` applies.
    /// This is #189's "replay" proof: the ledger is authoritative rather than decorative only if
    /// reconstructing balances from entries reproduces the live, stored projection exactly.
    ///
    /// Deliberately unconditional -- no `expires_at`/`revoked_at` filtering. `grant()` updates
    /// `budget_balances` unconditionally on every successful insert, so an exact replay of that
    /// stored state must be equally unconditional. Expiry/revocation-aware reads belong to
    /// [`BudgetRepo::effective_balance`], a separate, narrower concern -- not this function.
    pub async fn rebuild_all_balances(&self) -> Result<Vec<DerivedBalance>, BudgetError> {
        sqlx::query_as(REBUILD_ALL_BALANCES_SQL)
            .fetch_all(self.pool())
            .await
            .map_err(storage_failed)
    }

    /// The expiry- and revocation-aware read: the actual amount an (account, period) may spend
    /// right now, as of the caller-supplied `as_of`, excluding grants whose `expires_at` has
    /// passed or whose `revoked_at` is set. A real consumer (a policy evaluator, an admin-facing
    /// "how much can this account actually spend" view) should call this instead of trusting the
    /// raw `budget_balances.effective_budget_micros` column directly, since that column does not
    /// account for expiry.
    ///
    /// `as_of` is a parameter, not read from the clock internally -- the same discipline this
    /// crate already applies elsewhere (`Period` is clock-free; the spend adapter takes bounds as
    /// parameters).
    ///
    /// Makes zero writes -- a pure `SELECT`, so "without any entry being mutated" holds trivially
    /// by construction; nothing in `budget_grants` or `budget_balances` is touched.
    pub async fn effective_balance(
        &self,
        budget_account_id: &str,
        period: &Period,
        as_of: DateTime<Utc>,
    ) -> Result<i64, BudgetError> {
        let period_str = period.to_string();

        let (total,): (i64,) = sqlx::query_as(EFFECTIVE_BALANCE_SQL)
            .bind(budget_account_id)
            .bind(&period_str)
            .bind(as_of)
            .fetch_one(self.pool())
            .await
            .map_err(storage_failed)?;

        Ok(total)
    }

    /// Resolves the tier an account is currently on for `period`, from the most recent
    /// tier-representing grant (see [`LATEST_TIER_GRANT_AMOUNT_SQL`]'s doc comment for exactly
    /// which sources count). Moved here from [`crate::refill::RefillService`] (ADR-0014) so a
    /// caller that only needs a tier lookup -- notably the OIDC token-exchange/refresh minting
    /// path in `lightbridge-authz-rest`, which has no reason to construct a full
    /// `RefillService` (policy engine, spend reader, augmentation repo) just to read a tier --
    /// can depend on this crate's lightest-weight read primitive instead.
    ///
    /// Falls back to [`BudgetTier::B15`] (the lowest rung) in two cases, and both are deliberate,
    /// defensive fallbacks rather than a trusted derivation:
    ///
    /// - No qualifying grant exists yet this period (a genuinely new account/period).
    /// - A qualifying grant exists, but its `amount_micros` doesn't match any known rung (e.g. a
    ///   `correction` shifted the raw ledger total in a way that makes the *most recent
    ///   tier-grant* no longer reflect current reality -- or just data this service doesn't
    ///   expect in practice).
    ///
    /// **This does NOT cover a genuine storage failure** (DB unreachable, timeout, etc.) -- that
    /// still surfaces as `Err(BudgetError::StorageFailed)`, same as every other read on this
    /// type. A caller that must never omit a downstream claim on such a failure (the token-mint
    /// path -- see the budget-tier-rekey-cutover runbook's "an account with no claim lands on no
    /// matching rule, which is the difference between base budget and unlimited") is responsible
    /// for catching that `Err` itself and choosing its own fail-closed default; this method does
    /// not silently swallow a storage error into `B15` on its own, since a caller that actually
    /// wants to distinguish "new account" from "ledger unavailable" (e.g. for an operator alert)
    /// still can.
    ///
    /// **Known simplification, not solved here (ADR-0008):** "the billing plan determines the
    /// starting rung" has no `billing_plan` -> `BudgetTier` mapping anywhere in this codebase
    /// yet, so every account with no qualifying grant history this period defaults to `B15`
    /// regardless of plan. Safe (never grants/claims more than the cheapest plan would justify)
    /// but not the intended long-run behavior for e.g. an enterprise-plan account.
    ///
    /// **ADR-0015 note, so the two `B15` defaults above are never mistaken for the fail-closed
    /// floor:** neither is [`crate::decision::PolicyEngine::fail_closed_floor_micros`] (ADR-0015
    /// Decision 6) -- that is a distinct concept (an outage/unresolvable-data fallback) from
    /// "brand-new account, no grant yet" (Decision 5's `starting_amount_micros`, coincidentally
    /// $15 too under the shipped default policy, but not derived from it here) or "a grant exists
    /// but the amount predates/postdates the compile-time ladder." This method has no
    /// `PolicyEngine` to read either live value from, and after #387 removed the transitional,
    /// `BudgetTier`-shaped `RefillStatus` fields a live frontend used to read, its only remaining
    /// caller is the token-mint/refresh path below -- so both defaults deliberately stay `B15`
    /// rather than being wired to either policy field. The token-mint path that DOES need the real
    /// fail-closed floor (`TokenExchangeOpStore::resolve_budget_tier` in `lightbridge-authz-rest`)
    /// reads `fail_closed_floor_micros()` directly on its OWN `Err` branch below, never through
    /// this method's internal `B15` defaults.
    pub async fn current_tier(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<BudgetTier, BudgetError> {
        let period_str = period.to_string();

        let row: Option<(i64,)> = sqlx::query_as(LATEST_TIER_GRANT_AMOUNT_SQL)
            .bind(budget_account_id)
            .bind(&period_str)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        Ok(match row {
            Some((amount_micros,)) => {
                BudgetTier::from_amount_micros(amount_micros).unwrap_or(BudgetTier::B15)
            }
            None => BudgetTier::B15,
        })
    }

    /// A plain, single-row read of the stored `budget_balances` projection for `(budget_account_id,
    /// period)` -- not [`Self::rebuild_all_balances`] (which replays the whole ledger) and not
    /// [`Self::effective_balance`] (which sums `budget_grants` directly, filtered by expiry). `None`
    /// means no balance row exists yet for this (account, period) -- see [`BalanceSnapshot`]'s doc
    /// comment for why that is meaningfully different from a zero-valued row.
    pub async fn get_balance(
        &self,
        budget_account_id: &str,
        period: &Period,
    ) -> Result<Option<BalanceSnapshot>, BudgetError> {
        let period_str = period.to_string();

        let row: Option<BalanceRow> = sqlx::query_as(GET_BALANCE_SQL)
            .bind(budget_account_id)
            .bind(&period_str)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        row.map(BalanceSnapshot::try_from).transpose()
    }

    /// Fetches one `budget_grants` row by id, for [`crate::repo`]'s revoke-by-correction callers
    /// that need to read the original grant's exact `(budget_account_id, account_id, project_id,
    /// period, amount_micros)` before writing a compensating row against it. Not-found is a loud,
    /// typed [`BudgetError::NotFound`], mirroring [`crate::augmentation::AugmentationRepo::get`].
    pub async fn get_grant_by_id(&self, id: &str) -> Result<BudgetGrant, BudgetError> {
        let row: Option<BudgetGrantRow> = sqlx::query_as(GET_GRANT_BY_ID_SQL)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        let row = row.ok_or_else(|| BudgetError::NotFound(format!("budget grant '{id}'")))?;

        BudgetGrant::try_from(row)
    }

    /// The ledger's audit-read path (ADR-0039: paginated by `created_at`, never by id -- CUID2 has
    /// no defined ordering). Returns up to `limit` grants for `budget_account_id`, optionally
    /// scoped to one `period`, newest-first, strictly older than `before` when supplied (the
    /// caller's cursor: pass the `created_at` of the last row from the previous page). `limit` is
    /// clamped to `[1, MAX_LIST_GRANTS_LIMIT]` here -- a caller-supplied `0` or a very large value
    /// would otherwise either return nothing or force an unbounded scan.
    pub async fn list_grants(
        &self,
        budget_account_id: &str,
        period: Option<&Period>,
        before: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<BudgetGrant>, BudgetError> {
        let period_str = period.map(ToString::to_string);
        let clamped_limit = limit.clamp(1, MAX_LIST_GRANTS_LIMIT);

        let rows: Vec<BudgetGrantRow> = sqlx::query_as(LIST_GRANTS_SQL)
            .bind(budget_account_id)
            .bind(&period_str)
            .bind(before)
            .bind(clamped_limit)
            .fetch_all(self.pool())
            .await
            .map_err(storage_failed)?;

        rows.into_iter().map(BudgetGrant::try_from).collect()
    }
}

/// Upper bound on [`BudgetRepo::list_grants`]'s page size, independent of whatever the RPC
/// procedure layer additionally defaults/clamps to -- this repo method must never be made to scan
/// an unbounded page regardless of what a caller (procedure or test) asks for.
const MAX_LIST_GRANTS_LIMIT: i64 = 200;

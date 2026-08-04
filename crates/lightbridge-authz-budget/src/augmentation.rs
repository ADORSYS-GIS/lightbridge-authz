//! `budget_augmentation_requests`: the ledger for *decisions about* refill requests -- approved
//! and refused alike -- as distinct from [`crate::repo::BudgetRepo`], the ledger for *actual
//! money-granting events* only. See `migrations/20260804000002_budget_augmentation_requests.sql`
//! for the full reasoning and the schema this module maps onto.
//!
//! This module is persistence only (PR 3.1, #191): the table, the domain types, and
//! [`AugmentationRepo`]. It does not call [`crate::decision::PolicyEngine::evaluate`] or
//! [`crate::repo::BudgetRepo::grant`] -- a later PR builds the request-handling orchestration on
//! top of this exact shape, constructing [`RecordedDecision`] values directly from a
//! [`crate::decision::Decision`] the policy engine returns.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;
use sqlx::PgPool;

use crate::decision::Effect;
use crate::error::BudgetError;
use crate::period::Period;
use crate::tier::BudgetTier;

/// The augmentation-request state machine, quoted verbatim from
/// `docs/rfc/0001-budget-refill.md`'s "Domain (ADR-0009)" section: "`budget_augmentation_requests`
/// carrying the request state machine: `created`, `evaluating`, `auto_approved`,
/// `pending_review`, `approved`, `partially_approved`, `denied`, `cancelled`, `expired`,
/// `applied`." Matches the DB `CHECK` constraint in
/// `migrations/20260804000002_budget_augmentation_requests.sql` verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AugmentationStatus {
    Created,
    Evaluating,
    AutoApproved,
    PendingReview,
    Approved,
    PartiallyApproved,
    Denied,
    Cancelled,
    Expired,
    Applied,
}

impl AugmentationStatus {
    fn as_str(&self) -> &'static str {
        match self {
            AugmentationStatus::Created => "created",
            AugmentationStatus::Evaluating => "evaluating",
            AugmentationStatus::AutoApproved => "auto_approved",
            AugmentationStatus::PendingReview => "pending_review",
            AugmentationStatus::Approved => "approved",
            AugmentationStatus::PartiallyApproved => "partially_approved",
            AugmentationStatus::Denied => "denied",
            AugmentationStatus::Cancelled => "cancelled",
            AugmentationStatus::Expired => "expired",
            AugmentationStatus::Applied => "applied",
        }
    }
}

impl fmt::Display for AugmentationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AugmentationStatus {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "created" => Ok(AugmentationStatus::Created),
            "evaluating" => Ok(AugmentationStatus::Evaluating),
            "auto_approved" => Ok(AugmentationStatus::AutoApproved),
            "pending_review" => Ok(AugmentationStatus::PendingReview),
            "approved" => Ok(AugmentationStatus::Approved),
            "partially_approved" => Ok(AugmentationStatus::PartiallyApproved),
            "denied" => Ok(AugmentationStatus::Denied),
            "cancelled" => Ok(AugmentationStatus::Cancelled),
            "expired" => Ok(AugmentationStatus::Expired),
            "applied" => Ok(AugmentationStatus::Applied),
            _ => Err(BudgetError::UnknownStatus(s.to_string())),
        }
    }
}

/// A fully materialized `budget_augmentation_requests` row.
#[derive(Debug, Clone, PartialEq)]
pub struct AugmentationRequest {
    pub id: String,
    pub budget_account_id: String,
    pub account_id: String,
    pub project_id: Option<String>,
    pub period: Period,
    pub requested_tier: BudgetTier,
    pub requested_amount_micros: i64,
    pub status: AugmentationStatus,
    pub policy_effect: Option<Effect>,
    pub policy_reason_codes: Option<Vec<String>>,
    pub matched_rule_ids: Option<Vec<String>>,
    pub policy_revision: Option<String>,
    pub approved_amount_micros: Option<i64>,
    pub grant_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub reviewed_by: Option<String>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

/// Input to [`AugmentationRepo::create`]. Deliberately carries none of the policy/review fields
/// -- those only ever get written by [`AugmentationRepo::record_decision`] and
/// [`AugmentationRepo::record_review`] respectively, never at creation time.
#[derive(Debug, Clone, PartialEq)]
pub struct NewAugmentationRequest {
    pub budget_account_id: String,
    pub account_id: String,
    pub project_id: Option<String>,
    pub period: Period,
    pub requested_tier: BudgetTier,
    pub requested_amount_micros: i64,
    pub idempotency_key: Option<String>,
}

/// The policy-outcome fields common to a decision that resulted in an (auto-)approval: some
/// amount was approved, and a grant was written for it.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovedDecision {
    pub policy_effect: Effect,
    pub policy_reason_codes: Vec<String>,
    pub matched_rule_ids: Vec<String>,
    pub policy_revision: String,
    pub approved_amount_micros: i64,
    pub grant_id: String,
}

/// The policy-outcome fields common to a decision that did NOT result in a grant -- the request
/// is either waiting on a human, or refused outright.
#[derive(Debug, Clone, PartialEq)]
pub struct UnapprovedDecision {
    pub policy_effect: Effect,
    pub policy_reason_codes: Vec<String>,
    pub matched_rule_ids: Vec<String>,
    pub policy_revision: String,
}

/// The outcome [`AugmentationRepo::record_decision`] writes, constructed by a later PR's
/// orchestration directly from a [`crate::decision::Decision`]. One variant per
/// meaningfully-different outcome shape, rather than one struct with a pile of `Option`s that are
/// only sometimes populated together:
///
/// - [`Effect::AutoApprove`] -> [`RecordedDecision::AutoApproved`]
/// - [`Effect::AutoApproveCapped`] -> [`RecordedDecision::PartiallyApproved`]
/// - [`Effect::ManualReview`] -> [`RecordedDecision::PendingReview`]
/// - [`Effect::Deny`] -> [`RecordedDecision::Denied`]
///
/// [`Effect::NoAction`] has no representative here: it has no defined meaning for a request that
/// was actively submitted and is awaiting an outcome -- a later PR must map it to one of the
/// above (most likely `Denied`, refused-because-unavailable per #191's own distinction between
/// "refused-because-unavailable" and "refused-because-policy") rather than this module inventing
/// a fifth status for it.
#[derive(Debug, Clone, PartialEq)]
pub enum RecordedDecision {
    AutoApproved(ApprovedDecision),
    PartiallyApproved(ApprovedDecision),
    PendingReview(UnapprovedDecision),
    Denied(UnapprovedDecision),
}

#[allow(clippy::type_complexity)]
struct DecomposedDecision {
    status: AugmentationStatus,
    policy_effect: Effect,
    policy_reason_codes: Vec<String>,
    matched_rule_ids: Vec<String>,
    policy_revision: String,
    approved_amount_micros: Option<i64>,
    grant_id: Option<String>,
}

impl RecordedDecision {
    fn decompose(self) -> DecomposedDecision {
        match self {
            RecordedDecision::AutoApproved(d) => DecomposedDecision {
                status: AugmentationStatus::AutoApproved,
                policy_effect: d.policy_effect,
                policy_reason_codes: d.policy_reason_codes,
                matched_rule_ids: d.matched_rule_ids,
                policy_revision: d.policy_revision,
                approved_amount_micros: Some(d.approved_amount_micros),
                grant_id: Some(d.grant_id),
            },
            RecordedDecision::PartiallyApproved(d) => DecomposedDecision {
                status: AugmentationStatus::PartiallyApproved,
                policy_effect: d.policy_effect,
                policy_reason_codes: d.policy_reason_codes,
                matched_rule_ids: d.matched_rule_ids,
                policy_revision: d.policy_revision,
                approved_amount_micros: Some(d.approved_amount_micros),
                grant_id: Some(d.grant_id),
            },
            RecordedDecision::PendingReview(d) => DecomposedDecision {
                status: AugmentationStatus::PendingReview,
                policy_effect: d.policy_effect,
                policy_reason_codes: d.policy_reason_codes,
                matched_rule_ids: d.matched_rule_ids,
                policy_revision: d.policy_revision,
                approved_amount_micros: None,
                grant_id: None,
            },
            RecordedDecision::Denied(d) => DecomposedDecision {
                status: AugmentationStatus::Denied,
                policy_effect: d.policy_effect,
                policy_reason_codes: d.policy_reason_codes,
                matched_rule_ids: d.matched_rule_ids,
                policy_revision: d.policy_revision,
                approved_amount_micros: None,
                grant_id: None,
            },
        }
    }
}

/// Renders an [`Effect`] to the exact string [`AugmentationRequestRow::policy_effect`] stores,
/// reusing `Effect`'s own `#[serde(rename_all = "snake_case")]` mapping rather than duplicating
/// a second hand-written match against the same variants (which could silently drift from it).
fn effect_to_db(effect: Effect) -> String {
    match serde_json::to_value(effect).expect("Effect always serializes") {
        serde_json::Value::String(s) => s,
        other => unreachable!("Effect must serialize to a JSON string, got {other:?}"),
    }
}

/// The inverse of [`effect_to_db`], for reading a stored `policy_effect` back. A value that
/// doesn't match one of `Effect`'s snake_case variants is a schema/data inconsistency, not a
/// normal validation error -- mapped to [`BudgetError::StorageFailed`], mirroring how
/// [`crate::repo`] treats an unparseable stored `period`/`source`.
fn effect_from_db(s: &str) -> Result<Effect, BudgetError> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|err| {
        BudgetError::StorageFailed(format!("stored policy_effect '{s}' is invalid: {err}"))
    })
}

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

// sqlx 0.9's injection-safety check requires `'static` SQL literals for `query`/`query_as`, so
// (mirroring `repo.rs`'s `GRANT_INSERT_SQL`/`GRANT_SELECT_BY_IDEMPOTENCY_KEY_SQL`) each query is
// its own literal constant with the column list spelled out in full, rather than building the
// column list dynamically at call time.
const REQUEST_INSERT_SQL: &str = "INSERT INTO budget_augmentation_requests \
     (id, budget_account_id, account_id, project_id, period, requested_tier, \
      requested_amount_micros, status, idempotency_key) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING \
     RETURNING id, budget_account_id, account_id, project_id, period, requested_tier, \
     requested_amount_micros, status, policy_effect, policy_reason_codes, matched_rule_ids, \
     policy_revision, approved_amount_micros, grant_id, idempotency_key, reviewed_by, \
     rejection_reason, created_at, reviewed_at";

const REQUEST_SELECT_BY_IDEMPOTENCY_KEY_SQL: &str = "SELECT id, budget_account_id, account_id, \
     project_id, period, requested_tier, requested_amount_micros, status, policy_effect, \
     policy_reason_codes, matched_rule_ids, policy_revision, approved_amount_micros, grant_id, \
     idempotency_key, reviewed_by, rejection_reason, created_at, reviewed_at \
     FROM budget_augmentation_requests WHERE idempotency_key = $1";

const REQUEST_UPDATE_DECISION_SQL: &str = "UPDATE budget_augmentation_requests SET \
     status = $2, policy_effect = $3, policy_reason_codes = $4, matched_rule_ids = $5, \
     policy_revision = $6, approved_amount_micros = $7, grant_id = $8 \
     WHERE id = $1 \
     RETURNING id, budget_account_id, account_id, project_id, period, requested_tier, \
     requested_amount_micros, status, policy_effect, policy_reason_codes, matched_rule_ids, \
     policy_revision, approved_amount_micros, grant_id, idempotency_key, reviewed_by, \
     rejection_reason, created_at, reviewed_at";

// The `AND status = 'pending_review'` guard is the fix for a real concurrency gap (PR 3.3,
// #191): without it, two concurrent review actions on the same row -- two admins racing an
// approve and a reject, or a genuine double-submit -- would both succeed unconditionally, and
// whichever write landed last would silently overwrite the other's decision with no error at
// all. With the guard, a call that loses the race matches zero rows, `RETURNING` yields nothing,
// and `record_review` (below) turns that `None` into a loud, typed [`BudgetError::AlreadyReviewed`]
// instead of a silent double-write.
//
// `grant_id = $5` lets an approval record which grant it actually produced -- before PR 3.3
// nothing could ever populate this column even though it exists specifically for this; a
// rejection always binds `None` here, which is a no-op against a column that was already NULL.
const REQUEST_UPDATE_REVIEW_SQL: &str = "UPDATE budget_augmentation_requests SET \
     status = $2, reviewed_by = $3, rejection_reason = $4, reviewed_at = now(), grant_id = $5 \
     WHERE id = $1 AND status = 'pending_review' \
     RETURNING id, budget_account_id, account_id, project_id, period, requested_tier, \
     requested_amount_micros, status, policy_effect, policy_reason_codes, matched_rule_ids, \
     policy_revision, approved_amount_micros, grant_id, idempotency_key, reviewed_by, \
     rejection_reason, created_at, reviewed_at";

const REQUEST_SELECT_BY_ID_SQL: &str = "SELECT id, budget_account_id, account_id, project_id, \
     period, requested_tier, requested_amount_micros, status, policy_effect, \
     policy_reason_codes, matched_rule_ids, policy_revision, approved_amount_micros, grant_id, \
     idempotency_key, reviewed_by, rejection_reason, created_at, reviewed_at \
     FROM budget_augmentation_requests WHERE id = $1";

const REQUEST_LIST_PENDING_REVIEW_SQL: &str = "SELECT id, budget_account_id, account_id, \
     project_id, period, requested_tier, requested_amount_micros, status, policy_effect, \
     policy_reason_codes, matched_rule_ids, policy_revision, approved_amount_micros, grant_id, \
     idempotency_key, reviewed_by, rejection_reason, created_at, reviewed_at \
     FROM budget_augmentation_requests \
     WHERE status = 'pending_review' AND ($1::text IS NULL OR budget_account_id = $1) \
     ORDER BY created_at ASC";

#[derive(Debug, sqlx::FromRow)]
struct AugmentationRequestRow {
    id: String,
    budget_account_id: String,
    account_id: String,
    project_id: Option<String>,
    period: String,
    requested_tier: String,
    requested_amount_micros: i64,
    status: String,
    policy_effect: Option<String>,
    policy_reason_codes: Option<Vec<String>>,
    matched_rule_ids: Option<Vec<String>>,
    policy_revision: Option<String>,
    approved_amount_micros: Option<i64>,
    grant_id: Option<String>,
    idempotency_key: Option<String>,
    reviewed_by: Option<String>,
    rejection_reason: Option<String>,
    created_at: DateTime<Utc>,
    reviewed_at: Option<DateTime<Utc>>,
}

impl TryFrom<AugmentationRequestRow> for AugmentationRequest {
    type Error = BudgetError;

    fn try_from(row: AugmentationRequestRow) -> Result<Self, Self::Error> {
        let period = Period::parse(&row.period).map_err(|err| {
            BudgetError::StorageFailed(format!(
                "stored budget_augmentation_requests.period is invalid: {err}"
            ))
        })?;
        let requested_tier = BudgetTier::from_str(&row.requested_tier).map_err(|err| {
            BudgetError::StorageFailed(format!(
                "stored budget_augmentation_requests.requested_tier is invalid: {err}"
            ))
        })?;
        let status = AugmentationStatus::from_str(&row.status).map_err(|err| {
            BudgetError::StorageFailed(format!(
                "stored budget_augmentation_requests.status is invalid: {err}"
            ))
        })?;
        let policy_effect = row
            .policy_effect
            .as_deref()
            .map(effect_from_db)
            .transpose()?;

        Ok(Self {
            id: row.id,
            budget_account_id: row.budget_account_id,
            account_id: row.account_id,
            project_id: row.project_id,
            period,
            requested_tier,
            requested_amount_micros: row.requested_amount_micros,
            status,
            policy_effect,
            policy_reason_codes: row.policy_reason_codes,
            matched_rule_ids: row.matched_rule_ids,
            policy_revision: row.policy_revision,
            approved_amount_micros: row.approved_amount_micros,
            grant_id: row.grant_id,
            idempotency_key: row.idempotency_key,
            reviewed_by: row.reviewed_by,
            rejection_reason: row.rejection_reason,
            created_at: row.created_at,
            reviewed_at: row.reviewed_at,
        })
    }
}

/// Repository for `budget_augmentation_requests`: the request/decision ledger described in
/// `migrations/20260804000002_budget_augmentation_requests.sql`. Persistence only -- no policy
/// evaluation, no grant issuance; see the module docs.
#[derive(Debug, Clone)]
pub struct AugmentationRepo {
    pool: Arc<dyn DbPoolTrait>,
}

impl AugmentationRepo {
    pub fn new(pool: Arc<dyn DbPoolTrait>) -> Self {
        Self { pool }
    }

    fn pool(&self) -> &PgPool {
        self.pool.pool()
    }

    /// Inserts a fresh request with `status = 'created'` -- the state a request is in the moment
    /// it's persisted, before any policy evaluation has touched it. A later PR's orchestration is
    /// expected to move it to `'evaluating'` itself (via [`Self::record_decision`], or a similar
    /// narrow status-only transition this PR does not need to provide) once it actually starts
    /// evaluating; this repository does not assume that transition happens synchronously with
    /// creation.
    ///
    /// If `idempotency_key` is supplied and a row with that key already exists, returns the
    /// EXISTING row rather than erroring or inserting a duplicate -- the same
    /// `INSERT ... ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`
    /// plus fallback-`SELECT` idiom [`crate::repo::BudgetRepo::grant`] uses, mirrored here
    /// precisely rather than inventing a second idempotency mechanism for this table.
    pub async fn create(
        &self,
        request: NewAugmentationRequest,
    ) -> Result<AugmentationRequest, BudgetError> {
        let id = cuid2();
        let period_str = request.period.to_string();
        let requested_tier_str = request.requested_tier.label();
        let status_str = AugmentationStatus::Created.as_str();

        let inserted: Option<AugmentationRequestRow> = sqlx::query_as(REQUEST_INSERT_SQL)
            .bind(&id)
            .bind(&request.budget_account_id)
            .bind(&request.account_id)
            .bind(&request.project_id)
            .bind(&period_str)
            .bind(requested_tier_str)
            .bind(request.requested_amount_micros)
            .bind(status_str)
            .bind(&request.idempotency_key)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        let row = match inserted {
            Some(row) => row,
            None => sqlx::query_as(REQUEST_SELECT_BY_IDEMPOTENCY_KEY_SQL)
                .bind(&request.idempotency_key)
                .fetch_one(self.pool())
                .await
                .map_err(storage_failed)?,
        };

        AugmentationRequest::try_from(row)
    }

    /// Looks up a request by `idempotency_key`, returning `None` if nothing matches. This is
    /// what lets [`crate::refill::RefillService::request_refill`] short-circuit a genuine retry
    /// *before* doing any evaluation work at all -- distinct from [`Self::create`]'s own
    /// idempotency handling, which resolves duplicates at the database level (via
    /// `INSERT ... ON CONFLICT ... DO NOTHING` plus a fallback `SELECT`) but has no way to tell
    /// its caller whether the row it returned was freshly inserted or already existed.
    pub async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<AugmentationRequest>, BudgetError> {
        let row: Option<AugmentationRequestRow> =
            sqlx::query_as(REQUEST_SELECT_BY_IDEMPOTENCY_KEY_SQL)
                .bind(key)
                .fetch_optional(self.pool())
                .await
                .map_err(storage_failed)?;

        row.map(AugmentationRequest::try_from).transpose()
    }

    /// The ONE place `policy_effect`/`policy_reason_codes`/`matched_rule_ids`/`policy_revision`/
    /// `status`/`approved_amount_micros`/`grant_id` ever get written after creation. See
    /// [`RecordedDecision`] for the outcome shapes this accepts.
    pub async fn record_decision(
        &self,
        id: &str,
        decision: RecordedDecision,
    ) -> Result<AugmentationRequest, BudgetError> {
        let decomposed = decision.decompose();
        let policy_effect_str = effect_to_db(decomposed.policy_effect);

        let updated: Option<AugmentationRequestRow> = sqlx::query_as(REQUEST_UPDATE_DECISION_SQL)
            .bind(id)
            .bind(decomposed.status.as_str())
            .bind(&policy_effect_str)
            .bind(&decomposed.policy_reason_codes)
            .bind(&decomposed.matched_rule_ids)
            .bind(&decomposed.policy_revision)
            .bind(decomposed.approved_amount_micros)
            .bind(&decomposed.grant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        let row =
            updated.ok_or_else(|| BudgetError::NotFound(format!("augmentation request '{id}'")))?;

        AugmentationRequest::try_from(row)
    }

    /// Transitions a `pending_review` row to a review outcome, recording who reviewed it and,
    /// for a rejection, why. Only [`AugmentationStatus::Approved`] and
    /// [`AugmentationStatus::Denied`] are legitimate review outcomes -- anything else (including
    /// statuses that are real elsewhere in the state machine, like `cancelled` or `expired`) is
    /// rejected as a caller error before any write happens.
    ///
    /// A rejection (`status = Denied`) must carry a non-empty `rejection_reason` (#191's own
    /// implementation note: "Make the review queue's rejection reason mandatory. A rejection
    /// without a reason turns into a support conversation."). This is validated in Rust, before
    /// the database is touched at all, so a caller error never leaves a partial write -- the
    /// row's status stays whatever it was if validation fails.
    ///
    /// `grant_id` is only ever `Some` for an approval (the grant it produced) and always `None`
    /// for a rejection; see [`REQUEST_UPDATE_REVIEW_SQL`]'s doc comment.
    ///
    /// The `WHERE status = 'pending_review'` guard in [`REQUEST_UPDATE_REVIEW_SQL`] means this
    /// can lose a race: if the row was already reviewed (by a concurrent call, or a stale retry)
    /// between the caller reading it and calling this method, the `UPDATE` matches zero rows and
    /// this returns [`BudgetError::AlreadyReviewed`] -- distinct from [`BudgetError::NotFound`],
    /// which means no row with that id exists at all.
    pub async fn record_review(
        &self,
        id: &str,
        status: AugmentationStatus,
        reviewed_by: &str,
        rejection_reason: Option<&str>,
        grant_id: Option<&str>,
    ) -> Result<AugmentationRequest, BudgetError> {
        if !matches!(
            status,
            AugmentationStatus::Approved | AugmentationStatus::Denied
        ) {
            return Err(BudgetError::InvalidReviewOutcome(status.to_string()));
        }

        if status == AugmentationStatus::Denied {
            let reason_is_present = rejection_reason.is_some_and(|r| !r.trim().is_empty());
            if !reason_is_present {
                return Err(BudgetError::MissingRejectionReason);
            }
        }

        let updated: Option<AugmentationRequestRow> = sqlx::query_as(REQUEST_UPDATE_REVIEW_SQL)
            .bind(id)
            .bind(status.as_str())
            .bind(reviewed_by)
            .bind(rejection_reason)
            .bind(grant_id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        let row = updated.ok_or_else(|| BudgetError::AlreadyReviewed(id.to_string()))?;

        AugmentationRequest::try_from(row)
    }

    /// Fetches one request by id. Not-found is a loud, typed [`BudgetError::NotFound`].
    pub async fn get(&self, id: &str) -> Result<AugmentationRequest, BudgetError> {
        let row: Option<AugmentationRequestRow> = sqlx::query_as(REQUEST_SELECT_BY_ID_SQL)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(storage_failed)?;

        let row =
            row.ok_or_else(|| BudgetError::NotFound(format!("augmentation request '{id}'")))?;

        AugmentationRequest::try_from(row)
    }

    /// The review queue's read path: every `pending_review` request, oldest-first (a queue, not
    /// a stack). `budget_account_id: None` lists across every account (an admin's global queue);
    /// `Some(id)` scopes to one account.
    pub async fn list_pending_review(
        &self,
        budget_account_id: Option<&str>,
    ) -> Result<Vec<AugmentationRequest>, BudgetError> {
        let rows: Vec<AugmentationRequestRow> = sqlx::query_as(REQUEST_LIST_PENDING_REVIEW_SQL)
            .bind(budget_account_id)
            .fetch_all(self.pool())
            .await
            .map_err(storage_failed)?;

        rows.into_iter()
            .map(AugmentationRequest::try_from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_STATUSES: [AugmentationStatus; 10] = [
        AugmentationStatus::Created,
        AugmentationStatus::Evaluating,
        AugmentationStatus::AutoApproved,
        AugmentationStatus::PendingReview,
        AugmentationStatus::Approved,
        AugmentationStatus::PartiallyApproved,
        AugmentationStatus::Denied,
        AugmentationStatus::Cancelled,
        AugmentationStatus::Expired,
        AugmentationStatus::Applied,
    ];

    #[test]
    fn every_status_round_trips_through_display_and_from_str() {
        for status in ALL_STATUSES {
            let rendered = status.to_string();
            let parsed: AugmentationStatus =
                rendered.parse().expect("rendered form must parse back");
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn every_status_round_trips_through_serde() {
        for status in ALL_STATUSES {
            let json = serde_json::to_string(&status).expect("status must serialize");
            let parsed: AugmentationStatus =
                serde_json::from_str(&json).expect("status must deserialize");
            assert_eq!(parsed, status);
            assert_eq!(json, format!("\"{}\"", status.as_str()));
        }
    }

    #[test]
    fn unrecognized_status_string_is_a_typed_error() {
        assert!(matches!(
            "not_a_status".parse::<AugmentationStatus>(),
            Err(BudgetError::UnknownStatus(_))
        ));
    }

    #[test]
    fn effect_db_round_trip_covers_every_variant() {
        for effect in [
            Effect::AutoApprove,
            Effect::AutoApproveCapped,
            Effect::ManualReview,
            Effect::Deny,
            Effect::NoAction,
        ] {
            let stored = effect_to_db(effect);
            let parsed = effect_from_db(&stored).expect("stored effect must parse back");
            assert_eq!(parsed, effect);
        }
    }

    #[test]
    fn effect_from_db_rejects_garbage() {
        assert!(matches!(
            effect_from_db("not_an_effect"),
            Err(BudgetError::StorageFailed(_))
        ));
    }
}

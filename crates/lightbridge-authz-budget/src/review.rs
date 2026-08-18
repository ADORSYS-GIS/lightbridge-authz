//! The admin review queue (#191, PR 3.3): `approve`/`reject` on top of the `pending_review` rows
//! [`crate::refill::RefillService`] already writes via [`crate::augmentation::AugmentationRepo`].
//!
//! ## The concurrency design, in one place
//!
//! Two admins can race an approve and a reject on the same request, or a genuine double-submit
//! can fire the same action twice. Three mechanisms combine to close that window:
//!
//! 1. **The row-status guard.** [`crate::augmentation::AugmentationRepo::record_review`]'s
//!    `WHERE status = 'pending_review'` (added alongside this module) means at most one review
//!    action's `UPDATE` matches the row; the other gets zero rows back and a loud
//!    [`BudgetError::AlreadyReviewed`].
//! 2. **The deterministic idempotency key.** [`ReviewService::approve`] derives the grant's
//!    idempotency key from `request_id` alone (`augmentation-approval:{request_id}`), not the
//!    original request's own (possibly absent) `idempotency_key`. Every concurrent `approve()`
//!    call for the same request collides on the exact same key, so
//!    [`crate::repo::BudgetRepo::grant`]'s own idempotency guarantee ensures at most one grant
//!    results from any number of racing or retried `approve()` calls -- including a retry after
//!    a crash between `grant()` succeeding and `record_review` committing (see point 3 below for
//!    why that specific crash-recovery property is worth keeping even with the lock in place).
//! 3. **A per-request advisory lock**, added after this module's first version failed its own
//!    concurrency test. Read on for why (1) and (2) alone are not enough.
//!
//! ### Why the advisory lock exists: a real, highly reproducible race
//!
//! (1) and (2) alone handle two concurrent `approve()` calls correctly, and were the originally
//! specified design (deterministic key closes the double-grant window; the row guard picks one
//! winner). But an **`approve()` racing a concurrent `reject()`** on the same request is a
//! different shape of race, and the first version of this module -- `get` the row, `grant`, then
//! `record_review`, with no lock -- got it wrong: `reject()` is a single `UPDATE` and routinely
//! wins the row-status race against `approve()`'s slower `grant()` transaction (balance
//! bootstrap, row lock, insert, balance update, commit). Since `approve()`'s own pre-check
//! (`get`, per step 1 below) is a plain, unsynchronized read taken *before* that slower `grant()`
//! call, it can observe `pending_review`, proceed to `grant()`, and only discover -- via
//! `record_review`'s `AlreadyReviewed` -- that `reject()` won, *after* the grant already
//! committed. Measured empirically while building this module: **this was not a rare interleaving
//! -- it reproduced on roughly 3 of every 4 concurrent approve-vs-reject runs**, leaving a real
//! `manual_approval` grant on the ledger for a request whose row plainly reads `denied`. In a
//! budget-governance system that is exactly the failure mode CLAUDE.md calls out as
//! unacceptable: an outcome that reads as refused while money moved anyway.
//!
//! The fix is [`Self::acquire_review_lock`]: both `approve()` and `reject()` take a
//! transaction-scoped Postgres advisory lock (`pg_advisory_xact_lock`, keyed by
//! `hashtextextended(request_id, 0)`) as their very first action, and hold it -- via a
//! transaction kept open across every subsequent `.await`, including calls into
//! [`crate::repo::BudgetRepo`] and [`crate::augmentation::AugmentationRepo`] on their own,
//! separate pooled connections -- until their own logic has fully completed. This fully
//! serializes any two review actions on the *same* `request_id` (advisory locks are cross-session
//! and keyed, not tied to a specific row or table, so this works across the separate connections
//! each repository call borrows from the pool) without requiring `BudgetRepo::grant` or
//! `AugmentationRepo::record_review` to change their signatures to accept an externally supplied
//! transaction. Unrelated `request_id`s only serialize against each other on the rare hash
//! collision (a harmless, brief extra wait, not a correctness issue).
//!
//! With the lock in place, (2)'s deterministic key stops being what prevents a double-grant
//! between two *concurrent* `approve()` calls -- serialization already does that -- but it is
//! still what makes a **sequential retry** safe: if a single `approve()` call crashes after
//! `grant()` commits but before `record_review` runs, the row is left at `pending_review`
//! forever under the old (no-lock) design's own logic, but a *later* retry of `approve()` for the
//! same `request_id` re-derives the same idempotency key, so `grant()` returns the
//! already-committed grant instead of creating a second one, and `record_review` completes the
//! row normally. This crash-recovery property is why `grant()` still runs before `record_review`
//! rather than the other way around -- see [`Self::approve`]'s doc comment for the ordering
//! rationale in detail, and for why reversing it (claim `Approved` first, grant second) would
//! trade this self-healing property for a *worse*, non-recoverable stuck state.
//!
//! Per ADR-0007's own follow-up ("re-evaluate a pending request under lock at approval time"):
//! this module's lock is concurrency control, not policy re-evaluation. It deliberately does NOT
//! re-run the policy engine at approval time -- the policy already answered "needs review" for
//! this request; an admin approval is an authoritative override of that specific outcome, not a
//! request to re-ask the same policy the same question.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Transaction};

use crate::augmentation::{AugmentationRepo, AugmentationRequest, AugmentationStatus};
use crate::error::BudgetError;
use crate::repo::{BudgetRepo, GrantRequest};
use crate::source::GrantSource;

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

/// Thin orchestration over [`AugmentationRepo`] and [`BudgetRepo`] for the admin review queue.
/// Deliberately does not call [`crate::decision::PolicyEngine`] at all -- see the module doc for
/// why re-evaluation is not part of this design.
#[derive(Debug, Clone)]
pub struct ReviewService {
    budget_repo: Arc<BudgetRepo>,
    augmentation_repo: Arc<AugmentationRepo>,
}

impl ReviewService {
    pub fn new(budget_repo: Arc<BudgetRepo>, augmentation_repo: Arc<AugmentationRepo>) -> Self {
        Self {
            budget_repo,
            augmentation_repo,
        }
    }

    /// The review queue's read path. Thin delegation to
    /// [`AugmentationRepo::list_pending_review`] -- this exists on `ReviewService` (rather than
    /// callers reaching into `AugmentationRepo` directly) so the review queue has exactly one
    /// place a caller depends on for both reads and writes.
    ///
    /// Paginated by `created_at` (#296) -- see [`AugmentationRepo::list_pending_review`]'s own
    /// doc comment for the ASC/`after` cursor semantics this preserves from before pagination
    /// existed.
    pub async fn list_pending(
        &self,
        budget_account_id: Option<&str>,
        after: Option<DateTime<Utc>>,
        limit: i64,
    ) -> Result<Vec<AugmentationRequest>, BudgetError> {
        self.augmentation_repo
            .list_pending_review(budget_account_id, after, limit)
            .await
    }

    /// Takes a transaction-scoped Postgres advisory lock keyed by `request_id`, serializing any
    /// two review actions (`approve`/`reject`, in any combination) on the same request. See the
    /// module doc's "Why the advisory lock exists" section for the race this closes.
    ///
    /// The returned transaction must be held open (not dropped, not committed) for the entire
    /// duration of the caller's review logic -- the lock releases the moment this transaction
    /// ends, by commit *or* rollback, so an early `?` return before an explicit `.commit()` would
    /// silently release the lock too soon. Callers use an inner `async` block plus an explicit
    /// `.commit()` afterward specifically to avoid that trap; see [`Self::approve`] for the
    /// pattern.
    async fn acquire_review_lock(
        &self,
        request_id: &str,
    ) -> Result<Transaction<'static, Postgres>, BudgetError> {
        let mut tx = self
            .budget_repo
            .pool()
            .begin()
            .await
            .map_err(storage_failed)?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(request_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_failed)?;

        Ok(tx)
    }

    /// Approves a pending request: grants the requested amount, then records the review outcome.
    /// The whole sequence runs while holding [`Self::acquire_review_lock`]'s advisory lock, so a
    /// concurrent `approve`/`reject` on the same `request_id` blocks until this call finishes.
    ///
    /// Sequence, and it matters:
    ///
    /// 1. Read the row first. With the lock held, this is no longer racy against another review
    ///    action on the same request -- but it is still the right place to distinguish "no such
    ///    request at all" ([`BudgetError::NotFound`], from [`AugmentationRepo::get`] itself) from
    ///    "this request exists but is not (or no longer) pending"
    ///    ([`BudgetError::AlreadyReviewed`]), with a clean, specific error either way.
    /// 2. Grant using a **deterministic** idempotency key derived from `request_id` alone, not
    ///    the original request's own `idempotency_key` (which may be `None`). Under the lock this
    ///    is no longer needed to prevent a double-grant between *concurrent* callers -- the lock
    ///    already guarantees only one `approve()` for this request is ever in flight -- but it is
    ///    what makes a **sequential retry** (e.g. after a crash between this step and step 3, or
    ///    a client retrying a request whose response was lost) idempotent: it re-derives the same
    ///    key and gets back the same, already-committed grant rather than creating a second one.
    /// 3. Record the review outcome, via the row-status-guarded `record_review`. Because of the
    ///    lock, this cannot lose a race to a concurrent reviewer of the *same* request any more --
    ///    it can still return [`BudgetError::AlreadyReviewed`] if the row was already resolved
    ///    before this call started (step 1 already would have caught that) or in the narrow
    ///    window between step 1's read and this write, which the lock also closes since nothing
    ///    else can touch this `request_id`'s row while the lock is held.
    ///
    /// Grant-before-record-review (rather than the reverse) is deliberate independent of the
    /// lock: claiming `Approved` first and granting second would leave a **stuck, non-recoverable**
    /// row (`status = 'approved'`, `grant_id IS NULL` forever) if the process crashed between
    /// those two steps, because `record_review`'s `WHERE status = 'pending_review'` guard would
    /// never match again on retry. Granting first means the worst case of a crash between step 2
    /// and step 3 is a row stuck at `pending_review` with an already-issued grant -- fully
    /// self-healing, because a later retry of `approve()` re-derives the same idempotency key,
    /// gets the existing grant back from step 2, and completes step 3 normally.
    pub async fn approve(
        &self,
        request_id: &str,
        reviewer_account_id: &str,
    ) -> Result<AugmentationRequest, BudgetError> {
        let lock_tx = self.acquire_review_lock(request_id).await?;

        let result: Result<AugmentationRequest, BudgetError> = async {
            let request = self.augmentation_repo.get(request_id).await?;
            if request.status != AugmentationStatus::PendingReview {
                return Err(BudgetError::AlreadyReviewed(request_id.to_string()));
            }

            let approval_idempotency_key = format!("augmentation-approval:{request_id}");

            let grant = self
                .budget_repo
                .grant(GrantRequest {
                    budget_account_id: request.budget_account_id.clone(),
                    account_id: request.account_id.clone(),
                    project_id: request.project_id.clone(),
                    period: request.period.clone(),
                    amount_micros: request.requested_amount_micros,
                    source: GrantSource::ManualApproval,
                    actor_id: Some(reviewer_account_id.to_string()),
                    reason: Some(format!(
                        "approved via review queue by {reviewer_account_id}"
                    )),
                    policy_revision: request.policy_revision.clone(),
                    matched_rule_ids: request.matched_rule_ids.clone(),
                    idempotency_key: Some(approval_idempotency_key),
                    trigger_key: None,
                    expires_at: None,
                })
                .await?;

            self.augmentation_repo
                .record_review(
                    request_id,
                    AugmentationStatus::Approved,
                    reviewer_account_id,
                    None,
                    Some(&grant.id),
                )
                .await
        }
        .await;

        lock_tx.commit().await.map_err(storage_failed)?;
        result
    }

    /// Rejects a pending request: no grant, just the review outcome plus a mandatory reason. Like
    /// [`Self::approve`], runs while holding [`Self::acquire_review_lock`]'s advisory lock, so it
    /// cannot race a concurrent `approve`/`reject` on the same `request_id`.
    ///
    /// `reason` is validated non-empty here, before the lock is even acquired -- defense in depth
    /// on top of [`AugmentationRepo::record_review`]'s own mandatory-reason validation, so a
    /// caller gets a clear error without even the cost of a lookup or a lock round-trip for the
    /// common "forgot to type a reason" case.
    ///
    /// After that, the same pre-check-status-then-let-the-guard-be-the-real-defense pattern as
    /// [`Self::approve`]: read the row for a clean [`BudgetError::NotFound`] versus
    /// [`BudgetError::AlreadyReviewed`] distinction, then `record_review`.
    pub async fn reject(
        &self,
        request_id: &str,
        reviewer_account_id: &str,
        reason: &str,
    ) -> Result<AugmentationRequest, BudgetError> {
        if reason.trim().is_empty() {
            return Err(BudgetError::MissingRejectionReason);
        }

        let lock_tx = self.acquire_review_lock(request_id).await?;

        let result: Result<AugmentationRequest, BudgetError> = async {
            let request = self.augmentation_repo.get(request_id).await?;
            if request.status != AugmentationStatus::PendingReview {
                return Err(BudgetError::AlreadyReviewed(request_id.to_string()));
            }

            self.augmentation_repo
                .record_review(
                    request_id,
                    AugmentationStatus::Denied,
                    reviewer_account_id,
                    Some(reason),
                    None,
                )
                .await
        }
        .await;

        lock_tx.commit().await.map_err(storage_failed)?;
        result
    }
}

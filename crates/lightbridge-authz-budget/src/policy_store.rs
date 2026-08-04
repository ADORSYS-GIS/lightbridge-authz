//! Ties one DB-persisted, named policy set (ADR-0007's policy lifecycle) to one long-lived,
//! hot-swappable [`RuleDataEngine`] instance. This module owns *persistence* and the DB<->engine
//! tie only -- no RPC, no HTTP, no `/health` wiring, and no permission checks live here. Those are
//! a later PR that depends on this module's exact shape (`PolicyStore::activate`'s signature and
//! ordering, `PolicyStore::engine`'s accessor) staying stable, per #190.
//!
//! Schema: `migrations/20260804000001_budget_policy_sets_and_revisions.sql` -- one
//! `budget_policy_sets` row per named policy set (this epic needs exactly one, `"budget-refill"`),
//! an append-oriented `budget_policy_revisions` history under it, and
//! `budget_policy_sets.active_revision_id` pointing at whichever revision is currently serving.
//! That migration also seeds `"budget-refill"` with ADR-0008's real policy already active, so
//! there is never a "nothing is active yet" state for [`PolicyStore::load_active_from_db`] to
//! special-case in production -- only in a hand-rolled test database that skips the seed, which
//! this module still treats as a real, loud error rather than assuming it can't happen.

use std::sync::Arc;

use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPoolTrait;

use crate::error::BudgetError;
use crate::rule_data::{RuleDataEngine, validate_rule_data};

fn storage_failed(err: sqlx::Error) -> BudgetError {
    BudgetError::StorageFailed(err.to_string())
}

const LOAD_ACTIVE_REVISION_SQL: &str = "SELECT r.rule_data_json::text AS rule_data_json \
     FROM budget_policy_sets s \
     JOIN budget_policy_revisions r ON r.id = s.active_revision_id \
     WHERE s.id = $1";

const INSERT_REVISION_SQL: &str = "INSERT INTO budget_policy_revisions \
     (id, policy_set_id, policy_revision, rule_data_json, created_by) \
     VALUES ($1, $2, $3, $4::jsonb, $5)";

const ACTIVATE_REVISION_SQL: &str =
    "UPDATE budget_policy_sets SET active_revision_id = $1 WHERE id = $2";

/// Ties one DB-persisted policy set (identified by `policy_set_id`) to one live
/// [`RuleDataEngine`]. Cheaply `Clone` -- `pool` and `engine` are both `Arc`s, so cloning a
/// `PolicyStore` shares the same live engine rather than constructing a second, independent one.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    pool: Arc<dyn DbPoolTrait>,
    policy_set_id: String,
    engine: Arc<RuleDataEngine>,
}

impl PolicyStore {
    /// Loads the currently active revision for `policy_set_id` from the database and constructs
    /// a fresh [`RuleDataEngine`] from it. This is what server startup (and, in tests, "simulate a
    /// restart") calls -- it is the read path that proves persistence and the in-memory engine
    /// genuinely agree, not just at the moment of the last [`Self::activate`] call but from cold.
    ///
    /// Returns a loud [`BudgetError::StorageFailed`] rather than any kind of default/empty engine
    /// when `policy_set_id` doesn't name a real policy set, or that policy set has no active
    /// revision (`active_revision_id IS NULL`) -- both collapse to the same "no active revision
    /// found" outcome because the query is a `JOIN` on `active_revision_id`, which returns zero
    /// rows in either case. The migration this module depends on seeds `"budget-refill"` with an
    /// active revision from the start, so in production this should never actually happen; a
    /// hand-rolled test database that skips that seed (or that never activates a revision for a
    /// freshly inserted policy set) is the one place it genuinely can, and it must fail loudly
    /// here rather than silently serving an empty/default policy.
    pub async fn load_active_from_db(
        pool: Arc<dyn DbPoolTrait>,
        policy_set_id: &str,
        evaluation_budget: usize,
    ) -> Result<Self, BudgetError> {
        let row: Option<(String,)> = sqlx::query_as(LOAD_ACTIVE_REVISION_SQL)
            .bind(policy_set_id)
            .fetch_optional(pool.pool())
            .await
            .map_err(storage_failed)?;

        let (rule_data_json,) = row.ok_or_else(|| {
            BudgetError::StorageFailed(format!(
                "no active policy revision found for policy set '{policy_set_id}' -- either \
                 the policy set does not exist, or it has no active_revision_id set"
            ))
        })?;

        let engine = RuleDataEngine::new(&rule_data_json, evaluation_budget)?;

        Ok(Self {
            pool,
            policy_set_id: policy_set_id.to_string(),
            engine: Arc::new(engine),
        })
    }

    /// Activates `new_rule_data_json` as the new revision for this store's policy set. Returns
    /// the new revision's `policy_revision` string on success.
    ///
    /// The sequence matters and is deliberately in this order:
    ///
    /// 1. Validate first, before touching the database at all. A rejected activation attempt
    ///    leaves **no** trace whatsoever in `budget_policy_revisions` -- not even a "rejected"
    ///    row -- so that table only ever holds revisions that were genuinely, successfully
    ///    activated at some point. A later PR must not assume a row's mere existence there implies
    ///    anything other than "this was live at some point"; it does not need to filter out
    ///    "attempted but rejected" rows, because there are none.
    /// 2. Insert the new revision and repoint `active_revision_id` at it, in one transaction.
    /// 3. Only after that transaction commits, hot-swap the live in-memory engine via
    ///    [`RuleDataEngine::load`] -- for real, not skipped. The data was already validated in
    ///    step 1 with the exact same [`validate_rule_data`] function `load` uses internally, so
    ///    this call should never itself fail from bad data, but it goes through the real
    ///    hot-swap path regardless so the engine's internal state is genuinely updated rather
    ///    than assumed to be.
    ///
    /// If step 3 somehow fails despite step 1's validation having already passed (a genuine bug,
    /// or some other engine-internal reason), the database and the in-memory engine have now
    /// diverged: the database says the new revision is active, but the engine is still serving
    /// the old one. This function does not attempt to "fix" that by retrying or rolling back --
    /// the transaction already committed, so there is nothing to roll back to. It returns
    /// [`BudgetError::StorageFailed`] instead, with a message that says plainly that the database
    /// and the engine now disagree, mirroring the runbooks' own "stop mutating and reconcile,
    /// don't paper over a divergence" philosophy (see
    /// `docs/runbooks/roll-back-a-budget-policy.md`).
    pub async fn activate(
        &self,
        new_rule_data_json: &str,
        actor_id: Option<&str>,
    ) -> Result<String, BudgetError> {
        let rule_set = validate_rule_data(new_rule_data_json)?;

        let revision_id = cuid2();

        let mut tx = self.pool.pool().begin().await.map_err(storage_failed)?;

        sqlx::query(INSERT_REVISION_SQL)
            .bind(&revision_id)
            .bind(&self.policy_set_id)
            .bind(&rule_set.policy_revision)
            .bind(new_rule_data_json)
            .bind(actor_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_failed)?;

        sqlx::query(ACTIVATE_REVISION_SQL)
            .bind(&revision_id)
            .bind(&self.policy_set_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_failed)?;

        tx.commit().await.map_err(storage_failed)?;

        self.engine.load(new_rule_data_json).map_err(|load_err| {
            BudgetError::StorageFailed(format!(
                "DB and engine now disagree on the active policy revision: revision \
                 '{}' (id '{revision_id}') committed to the database for policy set '{}' \
                 but the in-memory engine failed to hot-swap to it ({load_err}) -- this is a \
                 serious, unusual state that needs manual reconciliation, not a retry",
                rule_set.policy_revision, self.policy_set_id
            ))
        })?;

        Ok(rule_set.policy_revision)
    }

    /// The live, hot-swappable engine this store activates against. A later PR's request-handling
    /// code holds onto this `Arc` and calls `.evaluate()` on it directly -- `PolicyStore` itself is
    /// a lifecycle/activation concern, not something every evaluation caller needs to go through.
    pub fn engine(&self) -> Arc<RuleDataEngine> {
        Arc::clone(&self.engine)
    }

    /// The `policy_revision` currently serving `engine().evaluate()` calls. Delegates directly to
    /// [`RuleDataEngine::active_policy_revision`].
    pub fn active_policy_revision(&self) -> String {
        self.engine.active_policy_revision()
    }
}

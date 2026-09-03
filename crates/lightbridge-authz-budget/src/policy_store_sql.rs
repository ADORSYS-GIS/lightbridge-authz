//! The five statements [`crate::policy_store::PolicyStore`] runs against
//! `budget_policy_sets`/`budget_policy_revisions`
//! (`migrations/20260804000001_budget_policy_sets_and_revisions.sql`).
//!
//! Split out of `policy_store.rs` when that file, which sits on its committed LoC-gate baseline
//! (`.github/loc-baseline.json`) and may be touched but not grown, needed room for
//! `PolicyStore::with_engine` (lightbridge-authz#645). Moved verbatim — same reason
//! `rpc_permission_map.rs` sits beside `rpc_authorize.rs` in `lightbridge-authz-rest`. Keeping the
//! SQL together in one module also makes "which statements touch the policy tables" a single file
//! to read before any migration that changes their shape.

pub(crate) const LOAD_ACTIVE_REVISION_SQL: &str = "SELECT r.rule_data_json::text AS rule_data_json \
     FROM budget_policy_sets s \
     JOIN budget_policy_revisions r ON r.id = s.active_revision_id \
     WHERE s.id = $1";

pub(crate) const INSERT_REVISION_SQL: &str = "INSERT INTO budget_policy_revisions \
     (id, policy_set_id, policy_revision, rule_data_json, created_by) \
     VALUES ($1, $2, $3, $4::jsonb, $5)";

pub(crate) const ACTIVATE_REVISION_SQL: &str =
    "UPDATE budget_policy_sets SET active_revision_id = $1 WHERE id = $2";

pub(crate) const SELECT_REVISION_BY_ID_SQL: &str = "SELECT policy_revision, rule_data_json::text \
     FROM budget_policy_revisions WHERE id = $1 AND policy_set_id = $2";

pub(crate) const INSERT_REVISION_RETURNING_ID_SQL: &str = "INSERT INTO budget_policy_revisions \
     (id, policy_set_id, policy_revision, rule_data_json, created_by) \
     VALUES ($1, $2, $3, $4::jsonb, $5) \
     RETURNING id";

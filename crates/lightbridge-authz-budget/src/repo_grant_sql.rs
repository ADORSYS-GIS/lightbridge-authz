//! The two grant statements [`crate::repo::BudgetRepo::grant`] runs, kept next door rather than
//! inline so `repo.rs` stays under its grandfathered line budget. Code moved, not rewritten — the
//! same convention `remaining_service.rs` / `remaining_cache.rs` follow in this crate.
//!
//! Both are `pub(crate)` and have exactly one caller: the transactional write path is the only
//! place a `budget_grants` row is ever inserted (ADR-0009), and that must stay true.

pub(crate) const GRANT_INSERT_SQL: &str = "INSERT INTO budget_grants \
    (id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, \
     trigger_key, expires_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
     ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING \
     RETURNING id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at";

pub(crate) const GRANT_SELECT_BY_IDEMPOTENCY_KEY_SQL: &str = "SELECT \
     id, budget_account_id, account_id, project_id, period, amount_micros, source, \
     actor_id, reason, policy_revision, matched_rule_ids, idempotency_key, trigger_key, \
     created_at, expires_at, revoked_at \
     FROM budget_grants WHERE idempotency_key = $1";

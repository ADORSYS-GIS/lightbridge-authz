-- ADR-0015: refill amounts move out of the compile-time `BudgetTier` enum and into the active
-- rule-data policy document (`RuleSet` gains `allowed_amounts_micros`, `starting_amount_micros`,
-- `fail_closed_floor_micros` -- see `crates/lightbridge-authz-budget/src/rule_data.rs`).
--
-- This does NOT edit `20260804000001_budget_policy_sets_and_revisions.sql`'s seed row --
-- migrations are immutable once applied (ADR-0009's append-only discipline applies here too, per
-- that file's own "Revisions are append-only in spirit" comment). Instead this inserts a second
-- revision under the same `budget-refill` policy set and activates it, exactly the way a real
-- operator would ship a policy change through `PolicyStore::create_revision`/`activate` -- this
-- migration is standing in for that RPC call for the one deployment that needs it to happen
-- automatically, at upgrade time, everywhere at once.
--
-- Values chosen to change nothing observable for an existing account: `starting_amount_micros`
-- is $15 (`15_000_000`), the same amount every account already defaulted to via the old
-- `BudgetTier::B15` fallback -- ADR-0015 Decision 5 is explicit that this must not silently cut
-- new-signup budgets. `fail_closed_floor_micros` is the new $6 floor
-- (`6_000_000`); `allowed_amounts_micros` is `[$6, $15, $30]`, i.e. today's $15 rung plus the new
-- $6 floor and $30 self-service ceiling from the product requirement.
--
-- ⚠️ KEEP IN SYNC WITH `default_rule_set_json()` in
-- crates/lightbridge-authz-budget/src/rule_data.rs, exactly as the original seed migration's own
-- comment requires -- a migration cannot call a Rust function, so this duplication is
-- unavoidable; if you change one, change the other in the same PR.
INSERT INTO budget_policy_revisions (id, policy_set_id, policy_revision, rule_data_json)
VALUES (
    'budget-refill-v2-adr0015',
    'budget-refill',
    'budget-policy-v2-adr0015',
    '{
  "policy_revision": "budget-policy-v2-adr0015",
  "rules": [
    {
      "id": "within-unaided-allowance",
      "condition": { "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 2 },
      "effect": "auto_approve",
      "reason_code": "within_unaided_allowance"
    }
  ],
  "default_effect": "manual_review",
  "default_reason_code": "unaided_allowance_exhausted",
  "allowed_amounts_micros": [6000000, 15000000, 30000000],
  "starting_amount_micros": 15000000,
  "fail_closed_floor_micros": 6000000
}'::jsonb
);

UPDATE budget_policy_sets
SET active_revision_id = 'budget-refill-v2-adr0015'
WHERE id = 'budget-refill';

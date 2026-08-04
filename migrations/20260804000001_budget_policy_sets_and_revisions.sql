-- ADR-0007: the policy lifecycle's persistence layer -- one named policy set ("the budget
-- refill policy"), an append-oriented history of revisions under it, and exactly one active
-- revision at a time. This does NOT attempt a general CRUD surface for policy sets -- #190's
-- acceptance criteria (and this epic's actual need) call for exactly one policy set, so this
-- schema models "one policy set, with revisions, one active", not N arbitrary policy sets. A
-- second policy set can be added later by inserting another `budget_policy_sets` row; nothing
-- here assumes there is only ever one row, but nothing builds a CRUD surface for creating more
-- either -- that is deliberately out of scope.
--
-- `budget_policy_sets.active_revision_id` is the pointer a later PR's `/health` endpoint reports
-- as `activePolicyRevision` and the one `POST /rpc/activateBudgetPolicy` (see
-- docs/runbooks/roll-back-a-budget-policy.md) moves. It is nullable at the column level only
-- because Postgres cannot otherwise express "these two tables reference each other" (the FK
-- below needs `budget_policy_revisions` to exist first, and each revision references its
-- `policy_set_id`) -- the seed data immediately below populates it, so in practice, from the very
-- first migrated deployment onward, it is never actually NULL. `PolicyStore::load_active_from_db`
-- (crates/lightbridge-authz-budget/src/policy_store.rs) still treats a NULL as a real, loud error
-- rather than assuming the seed always ran -- a hand-rolled test database that skips this
-- migration's seed, or a future policy set inserted without immediately activating a revision,
-- both leave it genuinely NULL, and "no policy is active" must fail closed, not silently serve an
-- empty/default engine.
CREATE TABLE budget_policy_sets (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    active_revision_id  TEXT NULL
);

-- Revisions are append-only in spirit (nothing in this PR updates or deletes a row here), mirroring
-- budget_grants' ledger discipline -- see migrations/20260803000001_budget_grants.sql for the fuller
-- append-only rationale. Unlike budget_grants this migration does not add a trigger forbidding
-- UPDATE/DELETE: PolicyStore never issues either, and the RPC layer that will be the only other
-- writer is a later PR (2.4b) that this PR does not have visibility into yet. Revisit adding the
-- same belt-and-suspenders trigger once that RPC lands, if it turns out something other than
-- PolicyStore::activate can reach this table.
CREATE TABLE budget_policy_revisions (
    id                  TEXT PRIMARY KEY,
    policy_set_id       TEXT NOT NULL REFERENCES budget_policy_sets(id),
    policy_revision     TEXT NOT NULL,
    rule_data_json      JSONB NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          TEXT NULL,

    UNIQUE (policy_set_id, policy_revision)
);

ALTER TABLE budget_policy_sets
    ADD CONSTRAINT budget_policy_sets_active_revision_fk
    FOREIGN KEY (active_revision_id) REFERENCES budget_policy_revisions(id);

-- Seed: the one policy set this epic needs, with its first revision already active. This is a
-- deliberate choice, not a placeholder -- it means every migrated deployment starts with
-- ADR-0008's real policy live from the first migration, so there is never a "nothing is active
-- yet" state for PolicyStore, an activation RPC, or a /health endpoint to special-case. The
-- alternative (ship the tables empty, require a first-activation step before anything can
-- evaluate) would make "no policy is active" a real, reachable state in production, which is
-- exactly the ambiguity ADR-0007's "on any failure the safe default is manual_review or deny"
-- language is trying to avoid -- better to never let that state exist than to handle it well.
--
-- ⚠️ KEEP IN SYNC WITH `default_rule_set_json()` in
-- crates/lightbridge-authz-budget/src/rule_data.rs -- the `rule_data_json` literal below must be
-- byte-for-byte the same JSON that function returns. A migration cannot call a Rust function, so
-- this duplication is unavoidable; if you change one, change the other in the same PR. There is a
-- matching comment on `default_rule_set_json()` pointing back here.
INSERT INTO budget_policy_sets (id, name) VALUES ('budget-refill', 'Budget refill policy');

INSERT INTO budget_policy_revisions (id, policy_set_id, policy_revision, rule_data_json)
VALUES (
    'budget-refill-v1',
    'budget-refill',
    'budget-policy-v1',
    '{
  "policy_revision": "budget-policy-v1",
  "rules": [
    {
      "id": "within-unaided-allowance",
      "condition": { "type": "threshold", "field": "self_service_grant_count", "operator": "lt", "value": 2 },
      "effect": "auto_approve",
      "reason_code": "within_unaided_allowance"
    }
  ],
  "default_effect": "manual_review",
  "default_reason_code": "unaided_allowance_exhausted"
}'::jsonb
);

UPDATE budget_policy_sets SET active_revision_id = 'budget-refill-v1' WHERE id = 'budget-refill';

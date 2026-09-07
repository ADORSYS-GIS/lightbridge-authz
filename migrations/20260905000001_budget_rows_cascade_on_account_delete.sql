-- #697: `deleteAccountPermanently` must survive an account that has budget rows.
--
-- Every account now carries a starting grant from the moment it is created (ADR-0015 Decision 9),
-- so "an account with no `budget_grants` row" has stopped being a state that exists. Before this,
-- `DELETE FROM accounts` succeeded only for accounts that had never been funded -- which was every
-- brand-new one, which is why the gap never surfaced. It would have surfaced the first time anyone
-- tried to hard-delete a funded account: `budget_grants_budget_account_id_fkey` is NO ACTION, so
-- the delete fails with a foreign-key violation the RPC surfaces as an opaque `500`. Two things
-- had to change together, because either one alone is still a wall.
--
-- 1. THE APPEND-ONLY TRIGGER GAINS EXACTLY ONE EXEMPTION, AND IT IS NOT A LOOPHOLE.
--
--    `budget_grants_forbid_mutation()` (20260803000001) is ADR-0009 made physical: it fires for
--    every role including `postgres`, and it refuses UPDATE and DELETE outright. That is still
--    true here, with one narrow carve-out: a DELETE whose owning `accounts` row is ALREADY GONE
--    inside the same transaction. In Postgres a referential-action cascade deletes the parent
--    first and then issues the child DELETE as its own command, so "the account no longer exists"
--    is precisely, and only, the signature of `deleteAccountPermanently` cascading.
--
--    A hand-written `DELETE FROM budget_grants WHERE id = ...` against a live account still
--    raises, exactly as before -- the account row is right there. UPDATE still raises
--    unconditionally; the exemption does not look at it. So the only way to remove a ledger row
--    remains destroying the entire account it belongs to, which is erasure, not an edit. ADR-0009
--    forbids rewriting a living account's history; it was never a promise to keep a deleted
--    tenant's money rows forever, and the ledger is meaningless once the account it keys on is
--    gone.
--
--    The alternative -- dropping `budget_grants`' foreign key to `accounts` so the ledger simply
--    outlives the tenant -- was rejected: that key is what makes a typo'd `grantBudget` a loud
--    error instead of an unreadable orphan row, and `known_account`'s doc comment names it as part
--    of the definition of "a budget account exists".
--
-- 2. THE BUDGET TABLES CASCADE, like the tenancy tables and `budget_remaining_snapshots` already
--    do (`projects`, `api_keys`, `project_members`, `federated_identities` are all ON DELETE
--    CASCADE; `budget_remaining_snapshots` was created that way in 20260904000001).
--
--    `budget_balances` must go in the same breath as `budget_grants`, not separately: #189's
--    replay proof (`BudgetRepo::rebuild_all_balances`) asserts the stored projection equals a
--    replay of the whole ledger. Keeping one and dropping the other breaks that equality for
--    every deleted account.
--
--    `budget_grants` carries TWO keys into `accounts` -- `budget_account_id` ("whose budget") and
--    `account_id` ("who this is attributed to") -- and every writer in the codebase sets them to
--    the same id. Both cascade. If they ever diverge, deleting the `account_id` side would try to
--    remove a row whose `budget_account_id` account is still alive, and the trigger's exemption
--    does not apply: it raises, the whole delete rolls back, and nobody's live ledger is touched.
--    That is the fail-safe direction -- a refused delete, never a silently mutilated balance.
--
-- Postgres has no `ALTER CONSTRAINT ... ON DELETE`, so each constraint is dropped and re-added.

CREATE OR REPLACE FUNCTION budget_grants_forbid_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND NOT EXISTS (SELECT 1 FROM accounts WHERE id = OLD.budget_account_id) THEN
        -- The owning account was deleted earlier in this same transaction, so this DELETE is the
        -- foreign-key cascade from `deleteAccountPermanently`. See the header above for why this
        -- is the one exemption and why it cannot be reached any other way.
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'budget_grants is append-only: % is not permitted (id=%)', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE budget_grants
    DROP CONSTRAINT budget_grants_budget_account_id_fkey,
    ADD CONSTRAINT budget_grants_budget_account_id_fkey
        FOREIGN KEY (budget_account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE budget_grants
    DROP CONSTRAINT budget_grants_account_id_fkey,
    ADD CONSTRAINT budget_grants_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE budget_balances
    DROP CONSTRAINT budget_balances_budget_account_id_fkey,
    ADD CONSTRAINT budget_balances_budget_account_id_fkey
        FOREIGN KEY (budget_account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE budget_augmentation_requests
    DROP CONSTRAINT budget_augmentation_requests_budget_account_id_fkey,
    ADD CONSTRAINT budget_augmentation_requests_budget_account_id_fkey
        FOREIGN KEY (budget_account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE budget_augmentation_requests
    DROP CONSTRAINT budget_augmentation_requests_account_id_fkey,
    ADD CONSTRAINT budget_augmentation_requests_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- An augmentation request points at the grant that satisfied it. Cascading the account's grants
-- above would otherwise hit this NO ACTION constraint and fail the whole delete for exactly the
-- accounts that have used self-service refill.
ALTER TABLE budget_augmentation_requests
    DROP CONSTRAINT budget_augmentation_requests_grant_id_fkey,
    ADD CONSTRAINT budget_augmentation_requests_grant_id_fkey
        FOREIGN KEY (grant_id) REFERENCES budget_grants(id) ON DELETE CASCADE;

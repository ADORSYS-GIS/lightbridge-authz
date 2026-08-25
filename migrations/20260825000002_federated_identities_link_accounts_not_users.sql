-- ADR-0024 Correction (2026-08-25): a federated identity links to an ACCOUNT, never directly to a
-- user. `20260825000001_users_and_federated_identities.sql`'s original shape gave every
-- `federated_identities` row its own `user_id` (minting a fresh `users` row when no pre-existing
-- `accounts` row matched the subject) alongside the already-optional `account_id` adopted from a
-- grandfathered account. That third edge was both redundant and, worse, sometimes wrong: a person
-- is reached through `users`, but the only legitimate way in is `federated_identities.account_id ->
-- accounts.user_id -> users.id` (a derived join, never a second stored pointer). The
-- `user_id`-when-no-account branch let a Keycloak login mint a brand-new, permanently orphaned
-- `users` row with no `accounts` row behind it -- a person this service has no relationship with
-- otherwise (no project, no budget, nothing reachable through the RBAC-gated surface). That
-- acceptance was explicitly CONDITIONAL, in ADR-0024's own "ACCEPTED RISK" consequence, on the
-- configured realm not permitting self-registration; the owner has since confirmed the realm DOES
-- permit it, so the acceptance is WITHDRAWN here and the risk is removed structurally rather than
-- left as a standing exception. See the ADR's "Correction (2026-08-25)" section for the full
-- rationale; `crates/lightbridge-authz-api-key/src/repo.rs`'s `upsert_federated_identity` now
-- REFUSES (`Error::Forbidden`) any login for a subject with no pre-existing `accounts` row, inside
-- the same transaction that would otherwise insert -- so no row from that branch is minted going
-- forward. This migration is the one-time cleanup for rows the old branch already produced.
--
-- Row disposition (in order):
--   1. DELETE the `users` rows this service minted for an accountless login -- scoped narrowly to
--      "a `users` row that is the target of an accountless `federated_identities` row (account_id
--      IS NULL) AND is not the backfilled/trigger-provisioned user of any surviving `accounts`
--      row." The second clause is the important guard: a `users` row orphaned by a legitimate
--      `deleteAccountPermanently` call (its account gone, no federated_identities row pointing at
--      it at all) is NOT touched here -- this step's scope is strictly "rows the login-mint branch
--      created," not "every unreferenced user." Deleting these rows cascades the DELETE onto their
--      `federated_identities` rows too, via the still-present `federated_identities.user_id`
--      `ON DELETE CASCADE` foreign key -- so step 2 below only has belt-and-braces work left.
--   2. DELETE any remaining `federated_identities` row with `account_id IS NULL` outright -- belt
--      and braces for the (expected-empty-by-now) case step 1's cascade didn't already clear, e.g.
--      an accountless row whose `users` row was, for whatever reason, still reachable some other
--      way. After this step, every surviving `federated_identities` row has a non-NULL
--      `account_id`.
--   3. Drop `federated_identities.user_id` entirely -- the column, its `idx_federated_identities_user_id`
--      index, and its `federated_identities_user_id_fkey` foreign key all go with it (Postgres drops
--      a column's own index/FK implicitly; nothing else references this column). The user is now
--      always DERIVED: `federated_identities.account_id -> accounts.user_id -> users.id`, never
--      stored a second time.
--   4. Swap `federated_identities_account_id_fkey`'s action from `ON DELETE SET NULL` to
--      `ON DELETE CASCADE`. This is not optional cleanup -- it is REQUIRED for step 5 below to be
--      satisfiable at all: `SET NULL` on a column this migration is about to make `NOT NULL` is a
--      contradiction the database cannot honor, and the live `deleteAccountPermanently` procedure
--      (the only way an `accounts` row is ever deleted) would otherwise start failing every call
--      with `23502 null value in column "account_id" violates not-null constraint` the moment it
--      tried to delete an account with an adopted federated identity. Under the corrected model
--      this is also the semantically right behavior: a federated identity with no account is no
--      longer a representable state, so deleting the account it is keyed to must delete the
--      identity row too, not orphan it into an invalid NULL.
--   5. `ALTER COLUMN account_id SET NOT NULL` -- the structural backstop behind
--      `upsert_federated_identity`'s in-transaction refusal: even a future write that bypassed the
--      Rust guard could not insert an accountless row.
--
-- Deliberately UNTOUCHED: both unique indexes (`federated_identities_issuer_subject_uidx`,
-- `federated_identities_account_uidx`) survive verbatim -- the account-adoption uniqueness they
-- enforce is unchanged by this correction, and `federated_identities_account_uidx`'s partial
-- predicate (`WHERE account_id IS NOT NULL`) simply becomes vacuously true once account_id is
-- NOT NULL, which is harmless (an index whose predicate is always true is just a plain unique
-- index from that point on).
--
-- Lock posture: `federated_identities` is a near-empty table at this point in the service's
-- lifetime (ADR-0024 landed in the immediately-preceding migration), so every statement against it
-- below -- the DELETEs, DROP COLUMN, DROP/ADD CONSTRAINT, SET NOT NULL, all of which take
-- AccessExclusiveLock on `federated_identities` -- runs in microseconds, not the ~500ms this repo
-- measured against a 100k-row `accounts` table in the sibling migration. The one statement that
-- touches `accounts` (dropping and re-adding the FK that references it) takes a ShareRowExclusive
-- lock on `accounts`, which blocks concurrent WRITES to `accounts` but not reads -- a materially
-- lighter posture than `20260825000001`'s AccessExclusive-on-accounts window. `SET LOCAL
-- lock_timeout` is kept anyway for the same fail-fast-and-retry reason as that migration: sqlx
-- applies this whole file as one transaction, so scoping the timeout here means a blocked lock
-- request fails this migration fast and visibly instead of queuing indefinitely behind whatever
-- else is holding a lock on either table.
SET LOCAL lock_timeout = '5s';

DELETE FROM users u
WHERE EXISTS (
        SELECT 1 FROM federated_identities f
        WHERE f.user_id = u.id AND f.account_id IS NULL
      )
  AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.user_id = u.id);

DELETE FROM federated_identities WHERE account_id IS NULL;

ALTER TABLE federated_identities DROP COLUMN user_id;

ALTER TABLE federated_identities DROP CONSTRAINT federated_identities_account_id_fkey;
ALTER TABLE federated_identities
    ADD CONSTRAINT federated_identities_account_id_fkey
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE;

ALTER TABLE federated_identities ALTER COLUMN account_id SET NOT NULL;

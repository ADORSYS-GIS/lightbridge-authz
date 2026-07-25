-- Fixes an incorrect backfill in migrations/20260725000001_default_account_project.sql:
-- `UPDATE accounts SET is_default = true;` marked EVERY existing account row default,
-- unconditionally, on the assumption that "every existing account is currently somebody's only
-- account." That assumption was wrong for any subject who already belonged to more than one
-- account at the time that migration ran -- all of that subject's accounts came out of it marked
-- `is_default = true` simultaneously, instead of just their genuine first one.
--
-- This mostly went unnoticed because nothing could flip `is_default` back at the time (`@readonly`,
-- no reassignment procedure existed yet). Once `setDefaultAccount` shipped
-- (20260725-era feature, see docs/rbac.md's "Escape hatch" section), promoting a *new* account to
-- default for an affected subject happened to self-heal the bug for that one subject --
-- `StoreRepo::set_default_account` unsets `is_default` on every account the calling subject is a
-- member of, not just "the" previous default, so it swept up every stray `true` in one transaction.
-- Subjects who haven't called `setDefaultAccount` yet are still stuck with every account showing as
-- default (and therefore permanently undeletable) until this backfill runs.
--
-- Correct definition, matching what `createAccount` computes for a *new* account (true only if the
-- creating subject had zero prior memberships): for each subject, keep `is_default = true` only on
-- the earliest account (by `created_at`, `id` tie-break) they belong to among their currently-true
-- accounts; unset every later one for that subject.
--
-- `is_default` lives on `accounts`, not scoped per subject, so a single account can legitimately
-- stay the "earliest true account" for more than one of its members at once (e.g. two people who
-- joined the same bootstrap account) -- that's fine, no conflict. An account is only ever flipped
-- false here if it is NOT the earliest true account for ANY of its member subjects.
WITH subject_first_default AS (
    SELECT DISTINCT ON (m.subject)
        m.subject,
        a.id AS keeper_account_id
    FROM account_memberships m
    JOIN accounts a ON a.id = m.account_id
    WHERE a.is_default = true
    ORDER BY m.subject, a.created_at ASC, a.id ASC
),
keeper_accounts AS (
    SELECT DISTINCT keeper_account_id AS account_id FROM subject_first_default
)
UPDATE accounts
SET is_default = false, updated_at = now()
WHERE is_default = true
  AND id NOT IN (SELECT account_id FROM keeper_accounts);

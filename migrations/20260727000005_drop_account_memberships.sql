-- ADR-0006: account-level membership is removed entirely -- a person's
-- defining identity is their accountId, with no account-level membership of
-- any kind. project_members (20260724000001_create_project_members.sql) is
-- the replacement, at the project level only.
--
-- This makes 20260722000001_account_membership_roles.sql's role-column
-- addition dead weight (its target table no longer exists) -- that migration
-- is not reverted/edited in place (migrations are never edited after
-- landing), it is simply superseded by this one dropping the whole table it
-- altered. See ADR-0006 for the full account-roles-to-project-membership
-- rationale.
DROP TRIGGER IF EXISTS prune_account_without_memberships ON account_memberships;
DROP FUNCTION IF EXISTS delete_account_without_memberships();

DROP TABLE account_memberships;

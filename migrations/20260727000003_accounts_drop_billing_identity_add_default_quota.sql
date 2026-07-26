-- ADR-0006: `billing_identity` is fully moved to `projects` as of the prior
-- migration (every account's default project now carries it) -- drop the
-- now-redundant column from `accounts`, along with its unique index.
--
-- `default_quota` replaces it conceptually as the account-level field: the
-- governance tier for usage under the account's own default project (which
-- has no roster to hang a per-member quota on). Left NULL for existing
-- accounts -- there's no prior "billing plan"-shaped value to backfill it
-- from, unlike billing_identity; NULL is a valid "no tier assigned yet"
-- state the application already handles for the analogous nullable tier
-- fields (`Project.projectQuota`, `ProjectMember.quotaTier`).
DROP INDEX IF EXISTS idx_accounts_billing_identity;

ALTER TABLE accounts DROP COLUMN billing_identity;
ALTER TABLE accounts ADD COLUMN default_quota TEXT;

-- ADR-0006: `billingIdentity` moves from `Account` to `Project` ("one project,
-- one billing identity"), plus the new pooled `projectQuota` ceiling and the
-- `isDefault` marker for each account's auto-provisioned, roster-less
-- project.
--
-- Backfill strategy: every existing account needs exactly one default
-- project carrying its old billing identity, so nothing breaks for accounts
-- that predate this migration.
--   1. Accounts that already have at least one project: the earliest project
--      (by created_at, ties broken by id for determinism) becomes the
--      default and inherits the account's billing_identity.
--   2. Accounts with zero projects: a new default project is inserted for
--      them (id via gen_random_uuid(), built into Postgres core since 13 --
--      no pgcrypto extension needed; app-generated ids are opaque TEXT so a
--      UUID string is a legal value here).
--   3. Every OTHER pre-existing (non-default) project has no natural billing
--      identity to inherit -- account-level billing was previously shared
--      across all of an account's projects, so there's no 1:1 source value.
--      These get a synthesized, deterministically-unique placeholder
--      (`legacy-<project id>`) so the column can be made NOT NULL UNIQUE for
--      every row; operators should assign these a real billing identity
--      post-migration if they need one.

ALTER TABLE projects ADD COLUMN billing_identity TEXT;
ALTER TABLE projects ADD COLUMN project_quota TEXT;
ALTER TABLE projects ADD COLUMN is_default BOOLEAN NOT NULL DEFAULT false;

WITH earliest_project AS (
    SELECT DISTINCT ON (account_id) id, account_id
    FROM projects
    ORDER BY account_id, created_at ASC, id ASC
)
UPDATE projects
SET is_default = true,
    billing_identity = accounts.billing_identity
FROM earliest_project, accounts
WHERE projects.id = earliest_project.id
  AND accounts.id = earliest_project.account_id;

INSERT INTO projects (
    id, account_id, name, allowed_models, default_limits, billing_plan,
    billing_identity, is_default, status, created_at, updated_at
)
SELECT
    gen_random_uuid()::text,
    accounts.id,
    'Default',
    NULL,
    '{}'::jsonb,
    'free',
    accounts.billing_identity,
    true,
    'active',
    now(),
    now()
FROM accounts
WHERE NOT EXISTS (SELECT 1 FROM projects WHERE projects.account_id = accounts.id);

UPDATE projects
SET billing_identity = 'legacy-' || id
WHERE billing_identity IS NULL;

ALTER TABLE projects ALTER COLUMN billing_identity SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_billing_identity ON projects(billing_identity);

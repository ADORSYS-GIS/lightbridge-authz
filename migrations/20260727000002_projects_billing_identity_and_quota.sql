-- ADR-0006: `billingIdentity` moves from `Account` to `Project` ("one project,
-- one billing identity"), plus the new pooled `projectQuota` ceiling.
--
-- The `isDefault` marker itself is NOT owned by this migration. It was added
-- concurrently upstream by 20260725000001_default_account_project.sql (the
-- `projects.is_default` column, the `set_project_is_default` BEFORE INSERT
-- trigger, and the `projects_account_id_default_uidx` partial unique index)
-- while this migration sat uncommitted in a previous session under an
-- earlier, now-renumbered name (20260724000002) that duplicated the same
-- column addition and would have collided with upstream's on a fresh DB.
-- This migration now runs strictly after 20260725000001 (renumbered into the
-- 20260727* range) and relies on its backfill instead of redoing it.
--
-- Backfill strategy: every existing project needs a `billing_identity`, so
-- nothing breaks for projects that predate this migration.
--   1. Each account's already-marked default project (`is_default = true`,
--      computed by 20260725000001's backfill/trigger -- not recomputed here)
--      inherits the account's old `billing_identity`.
--   2. Every OTHER pre-existing (non-default) project has no natural billing
--      identity to inherit -- account-level billing was previously shared
--      across all of an account's projects, so there's no 1:1 source value.
--      These get a synthesized, deterministically-unique placeholder
--      (`legacy-<project id>`) so the column can be made NOT NULL UNIQUE for
--      every row; operators should assign these a real billing identity
--      post-migration if they need one.
--   3. Accounts with zero projects still need one: a new default project is
--      inserted for them (id via gen_random_uuid(), built into Postgres core
--      since 13 -- no pgcrypto extension needed; app-generated ids are
--      opaque TEXT so a UUID string is a legal value here). Its column list
--      deliberately omits `is_default` -- 20260725000001's BEFORE INSERT
--      trigger computes it (and does fire here: this is a plain
--      `INSERT INTO projects`), so listing it explicitly would fight the
--      trigger's own NEW.is_default assignment.

ALTER TABLE projects ADD COLUMN billing_identity TEXT;
ALTER TABLE projects ADD COLUMN project_quota TEXT;

UPDATE projects
SET billing_identity = accounts.billing_identity
FROM accounts
WHERE projects.account_id = accounts.id
  AND projects.is_default = true;

INSERT INTO projects (
    id, account_id, name, allowed_models, default_limits, billing_plan,
    billing_identity, status, created_at, updated_at
)
SELECT
    gen_random_uuid()::text,
    accounts.id,
    'Default',
    NULL,
    '{}'::jsonb,
    'free',
    accounts.billing_identity,
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

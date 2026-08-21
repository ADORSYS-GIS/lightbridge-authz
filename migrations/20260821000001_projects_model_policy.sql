-- ADR-0018 ("A model_policy enum on projects makes 'no models allowed' a reachable state,
-- defaulting to today's allow-all behavior"): `allowed_models` alone cannot express "no models
-- allowed" -- NULL and [] both mean "all models allowed" today, so that state is unreachable.
-- This adds the enum column that makes `allowlist`/`deny_all` reachable going forward, while
-- leaving every existing project's *observable behavior* unchanged.
--
-- `NOT NULL DEFAULT 'allow_all'` is a single-statement, no-backfill-needed migration: Postgres 11+
-- stores a constant default for a new NOT NULL column as catalog metadata rather than rewriting
-- the table, so this is safe on a live, populated `projects` table with no separate UPDATE step
-- (contrast `20260820000001_api_keys_require_expiry.sql`'s explicit backfill-then-constrain
-- migration, needed there only because that column already held real NULLs before being
-- constrained -- `model_policy` is brand new, so there is nothing to backfill). Every existing
-- row reads back as `allow_all`, which is exactly the "all models allowed" behavior that same row
-- already had via `allowed_models` being NULL/[] -- deploying this migration alone changes
-- nothing observable.
--
-- The `CHECK` constraint follows this repo's established convention for enum-like TEXT columns
-- (`accounts.status`/`projects.status` in migrations/20260714000001_account_project_status.sql,
-- `project_members.role` in migrations/20260727000001_create_project_members.sql): it makes the
-- three-value invariant true regardless of code path, not only the application layer's own
-- fail-closed `ModelPolicy::from(String)` parsing (`crates/lightbridge-authz-core/src/dto.rs`).
-- Safe to add unconditionally here (unlike the `expires_at` CHECK the linked migration explicitly
-- declined to add) because this is a brand-new column with a single, freshly-applied default --
-- there is no pre-existing, unknown-at-authoring-time data that could already violate it.
DO $$
DECLARE
    total_projects INT;
BEGIN
    SELECT COUNT(*) INTO total_projects FROM projects;
    RAISE NOTICE 'ADR-0018 projects.model_policy backfill: % existing project(s) will read back as ''allow_all'' (identical to their current NULL/[] allowed_models behavior); no data changes, only a new column default',
      total_projects;
END $$;

ALTER TABLE projects
    ADD COLUMN model_policy TEXT NOT NULL DEFAULT 'allow_all'
        CHECK (model_policy IN ('allow_all', 'allowlist', 'deny_all'));

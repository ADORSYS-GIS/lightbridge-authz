-- Schema evolution required by the cratestack-pg CRUD migration (ADR-0003). cratestack does NOT
-- own DDL for these tables (see ADR-0003, "Migration ownership — REVISED after the spike"); this is
-- an ordinary hand-written SQLx migration applied by the existing runner.
--
-- Three concerns, all on the CRUD-owned tables (accounts, projects, api_keys):
--
-- 1. Soft-delete for api_keys. `ApiKey` declares `@@soft_delete` with a `deletedAt` field, so the
--    generated `delete()` becomes `UPDATE ... SET deleted_at = NOW()` and every generated read adds
--    `deleted_at IS NULL` to its predicate. The column must physically exist.
--
-- 2. `api_keys.updated_at`. The `AuditFields` mixin gives every model a `createdAt`/`updatedAt`
--    pair. `accounts`/`projects` already have `updated_at`; `api_keys` did not, so add it (NOT NULL,
--    backfilled from `created_at`).
--
-- 3. Real Postgres-level `DEFAULT now()` for every `@default(dbgenerated())` column. cratestack's
--    generated `create()` OMITS the `createdAt`/`updatedAt` columns from the INSERT and relies on a
--    DB-level default; without one the insert fails with a NOT NULL violation (confirmed by the
--    spike — ADR-0003, "Known cratestack-pg 0.4.9 bugs", item 3). `accounts`/`projects` created_at
--    /updated_at had no default; add `DEFAULT now()` to all four, and the new api_keys columns get
--    theirs inline below.

ALTER TABLE api_keys
    ADD COLUMN deleted_at TIMESTAMPTZ NULL;

ALTER TABLE api_keys
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE api_keys SET updated_at = created_at;

-- api_keys.created_at already exists (init migration); ensure it also carries a DB-level default so
-- the generated `create()` can omit it, matching the AuditFields `dbgenerated()` contract.
ALTER TABLE api_keys  ALTER COLUMN created_at SET DEFAULT now();

ALTER TABLE accounts  ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE accounts  ALTER COLUMN updated_at SET DEFAULT now();
ALTER TABLE projects  ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE projects  ALTER COLUMN updated_at SET DEFAULT now();

-- Security-critical (ADR-0003, "Soft-delete for api_keys only" — the fail-open hazard): the
-- hand-written validation view consumed by authz-opa must exclude soft-deleted keys, otherwise a
-- key deleted through the cratestack CRUD surface would still validate at the OPA layer. The prior
-- migration (20260714000001) cannot be edited once applied, so replace the view here, adding the
-- single `AND k.deleted_at IS NULL` predicate. Column list/order is unchanged so CREATE OR REPLACE
-- is legal.
CREATE OR REPLACE VIEW api_key_validation AS
SELECT
    k.id            AS api_key_id,
    k.key_hash      AS key_hash,
    k.project_id    AS project_id,
    p.account_id    AS account_id,
    k.status        AS api_key_status,
    p.status        AS project_status,
    a.status        AS account_status,
    k.expires_at    AS expires_at,
    CASE
        WHEN k.status <> 'active'                                    THEN 'key_revoked'
        WHEN k.expires_at IS NOT NULL AND k.expires_at <= now()      THEN 'key_expired'
        WHEN p.status <> 'active'                                    THEN 'project_suspended'
        WHEN a.status <> 'active'                                    THEN 'account_suspended'
        ELSE 'active'
    END             AS effective_status
FROM api_keys k
JOIN projects p ON p.id = k.project_id
JOIN accounts a ON a.id = p.account_id
WHERE k.deleted_at IS NULL;

-- ADR-0006, decision 1 (2026-07-26): `accounts.id` IS the JWT subject. One account = one
-- person; there is no membership indirection at the account level any more (that's what
-- 20260727000005_drop_account_memberships.sql, née 20260724000004, removes next -- this
-- migration must run BEFORE it, since it still reads `account_memberships` to figure out who
-- owns what). Every future `@@allow` becomes `id == auth().id` / `account.id == auth().id`, and
-- `createAccount` stops generating an id -- it uses the caller's subject directly. Existing rows
-- need remapping first, which is what this migration does.
--
-- Written column-agnostically for `accounts`: this migration only ever touches the `id` column
-- via an in-place `UPDATE accounts SET id = ...`, never an INSERT/copy/DELETE of account rows
-- (aside from deleting rows that end up genuinely empty). `accounts`' other columns have already
-- changed shape twice in this same migration batch (billing_identity/owners_admins dropped,
-- default_quota/is_default added) and will change again later -- enumerating them here would be
-- both unnecessary and a maintenance trap.
--
-- Algorithm, in order:
--   1. For each account, find its "owning subject" from `account_memberships`: whoever has role
--      'owner' wins; failing that, the earliest-joined member; ties broken by subject string for
--      determinism. (`role` was added by 20260722000001_account_membership_roles.sql.)
--   2. A subject may currently own more than one account (multi-account membership was legal
--      pre-pivot). Pick ONE survivor per subject -- preferring whichever of their accounts still
--      carries the legacy `accounts.is_default = true` flag (added by
--      20260725000001_default_account_project.sql, dropped later in this same batch by
--      20260727000006_accounts_drop_is_default.sql -- it is still present and meaningful at this
--      point in the migration order), then earliest `created_at`, then `id` for determinism.
--   3. Re-point the `account_id` foreign keys on `projects`, `account_memberships`, and
--      `project_members` to `ON DELETE CASCADE ON UPDATE CASCADE` (they were `ON DELETE CASCADE`
--      only). Without `ON UPDATE CASCADE`, step 5's `UPDATE accounts SET id = ...` would be
--      rejected outright by every one of these FKs the moment a referencing row exists -- which,
--      for a survivor account, is guaranteed (it has at least the membership row that identified
--      its owning subject). Real constraint names were looked up against
--      `information_schema.table_constraints` on a scratch DB seeded from
--      20260203000001_init_authz.sql + 20260304000001_account_memberships.sql +
--      20260727000001_create_project_members.sql, all three of which declare their FK inline
--      (no explicit `CONSTRAINT` name), so Postgres's default `<table>_<column>_fkey` naming
--      applies uniformly: `projects_account_id_fkey`, `account_memberships_account_id_fkey`,
--      `project_members_account_id_fkey`. (`project_members_project_id_fkey` references
--      `projects.id`, which this migration never rewrites, so it is left untouched.)
--   4. Re-parent every project belonging to a non-survivor account onto that subject's survivor
--      account. `is_default` is forced to `false` on those projects in a separate UPDATE that
--      runs BEFORE the re-parenting UPDATE -- otherwise the move would land a second
--      `is_default = true` row under the survivor's `account_id` and trip the partial unique
--      index `projects_account_id_default_uidx` (20260725000001). The survivor's own pre-existing
--      default project is untouched, so exactly one `is_default = true` project survives the
--      merge.
--   5. Rewrite each survivor account's `id` to its owning subject (skipped when they already
--      match). The FK updates from step 3 cascade this into `projects.account_id` and
--      `account_memberships.account_id` (and `project_members.account_id`, wherever that
--      survivor account already appears as a project member) automatically.
--   6. Delete the now-empty non-survivor accounts. Their `projects` were already moved away in
--      step 4, so `ON DELETE CASCADE` here only removes their (now-redundant) membership rows.
--   7. `exchange_refresh_tokens.account_id` carries no foreign key at all
--      (20260709000002_exchange_refresh_tokens.sql) -- it is intentionally decoupled from
--      `accounts` for token-revocation-survives-account-changes reasons unrelated to this
--      migration, so the cascades from step 3 never reach it. It is remapped explicitly here.
--   8. Accounts with ZERO membership rows never appear in the mapping built in step 1, so steps
--      4-7 never touch them -- they are left completely untouched (no id rewrite, no delete).
--      They are already unreachable under every membership-scoped policy in place today, so
--      leaving them alone is the non-destructive choice; there is nothing to migrate them TO.
--   8b. A merge can leave a survivor account holding projects but no default one: if the survivor
--      itself had no projects and every project it inherits came from a non-survivor account, step
--      4 has just forced `is_default = false` on all of them. The promotion below re-establishes
--      "an account with projects has exactly one default project" by promoting the earliest
--      inherited project. Scoped to survivor accounts only -- nothing else in this migration can
--      open that hole.
--   ACCESS LAPSE, DECIDED DELIBERATELY (2026-07-26, confirmed with the user): only each account's
--      OWNING subject survives this remap. A subject who was a non-owner member of someone else's
--      account loses all access to that account and its projects the moment
--      20260727000005_drop_account_memberships.sql runs -- no `project_members` rows are
--      synthesized for them here. The alternative (convert every non-owner membership into a
--      project-member row, auto-creating an account per orphaned subject) was considered and
--      rejected in favour of keeping the migration auditable; the project's lead re-adds anyone who
--      still needs access via `addProjectMember`. THIS IS SILENT FROM THE AFFECTED USER'S SIDE --
--      operators should count affected subjects before running this in production:
--        SELECT m.subject, count(DISTINCT m.account_id)
--        FROM account_memberships m
--        WHERE m.role <> 'owner'
--          AND NOT EXISTS (SELECT 1 FROM account_memberships o
--                          WHERE o.account_id = m.account_id AND o.subject = m.subject
--                            AND o.role = 'owner')
--        GROUP BY m.subject;
--   9. Loud-failure case (intentionally NOT caught or swallowed): if a subject string collides
--      with the `id` of an existing, unrelated account, step 5's `UPDATE accounts SET id = ...`
--      violates the `accounts` primary key and the whole migration transaction aborts. That is
--      correct -- a silent merge of two unrelated accounts under a colliding id would be a data
--      integrity incident, not a migration nicety to paper over.
--
-- cratestack `@@audit` check: as of this migration, `crates/lightbridge-authz-api/schema/authz.cstack`
-- declares `@@audit` on `Account`/`Project`/`ApiKey`, but no SQL migration under `migrations/`
-- has ever created a corresponding audit table (confirmed: no `_audit`-suffixed table exists in
-- this database). There is therefore nothing here to remap or document an exception for; if a
-- physical audit table is introduced later, that migration will need its own explicit call on
-- whether to remap historical account ids or preserve them as-is.
--
-- `migrations-usage/` is a separate database (append-only OTEL/usage telemetry) and is
-- deliberately NOT touched by this migration. Historical usage rows keep referencing whatever
-- account id was current at ingest time; they are not a live foreign-key relationship and
-- reconciling them retroactively is out of scope for this pivot.

CREATE TEMP TABLE account_owning_subject ON COMMIT DROP AS
SELECT DISTINCT ON (account_id)
    account_id,
    subject
FROM account_memberships
ORDER BY account_id, (role = 'owner') DESC, created_at ASC, subject ASC;

CREATE TEMP TABLE subject_survivor_account ON COMMIT DROP AS
SELECT DISTINCT ON (aos.subject)
    aos.subject,
    a.id AS survivor_account_id
FROM account_owning_subject aos
JOIN accounts a ON a.id = aos.account_id
ORDER BY aos.subject, a.is_default DESC, a.created_at ASC, a.id ASC;

CREATE TEMP TABLE account_survivor_map ON COMMIT DROP AS
SELECT
    aos.account_id,
    ssa.survivor_account_id
FROM account_owning_subject aos
JOIN subject_survivor_account ssa ON ssa.subject = aos.subject;

ALTER TABLE projects
    DROP CONSTRAINT projects_account_id_fkey,
    ADD CONSTRAINT projects_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id)
        ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE account_memberships
    DROP CONSTRAINT account_memberships_account_id_fkey,
    ADD CONSTRAINT account_memberships_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id)
        ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE project_members
    DROP CONSTRAINT project_members_account_id_fkey,
    ADD CONSTRAINT project_members_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id)
        ON DELETE CASCADE ON UPDATE CASCADE;

UPDATE projects
SET is_default = false
FROM account_survivor_map m
WHERE projects.account_id = m.account_id
  AND m.account_id <> m.survivor_account_id;

UPDATE projects
SET account_id = m.survivor_account_id
FROM account_survivor_map m
WHERE projects.account_id = m.account_id
  AND m.account_id <> m.survivor_account_id;

UPDATE projects
SET is_default = true
WHERE id IN (
    SELECT DISTINCT ON (p.account_id) p.id
    FROM projects p
    JOIN subject_survivor_account ssa ON ssa.survivor_account_id = p.account_id
    WHERE NOT EXISTS (
        SELECT 1
        FROM projects existing_default
        WHERE existing_default.account_id = p.account_id
          AND existing_default.is_default
    )
    ORDER BY p.account_id, p.created_at ASC, p.id ASC
);

UPDATE accounts
SET id = ssa.subject,
    updated_at = now()
FROM subject_survivor_account ssa
WHERE accounts.id = ssa.survivor_account_id
  AND accounts.id <> ssa.subject;

DELETE FROM accounts
WHERE id IN (
    SELECT account_id
    FROM account_survivor_map
    WHERE account_id <> survivor_account_id
);

UPDATE exchange_refresh_tokens
SET account_id = aos.subject
FROM account_owning_subject aos
WHERE exchange_refresh_tokens.account_id = aos.account_id
  AND exchange_refresh_tokens.account_id <> aos.subject;

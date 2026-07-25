-- The account/project auto-provisioned for a brand-new tenant (`createAccount` / the frontend's
-- "ensure default project" bootstrap flow) is protected from hard deletion -- it can still be
-- suspended (disableAccount/disableProject), but deleteAccountPermanently / model.Project.delete
-- refuse when is_default is true. Prevents a tenant from accidentally deleting their only
-- account/project and losing every API key underneath it.
ALTER TABLE accounts ADD COLUMN is_default boolean NOT NULL DEFAULT false;
ALTER TABLE projects ADD COLUMN is_default boolean NOT NULL DEFAULT false;

-- Backfill: multi-account creation isn't exposed anywhere in the product today (createAccount is
-- only ever called by the bootstrap "ensure default account" flow), so every existing account is
-- currently somebody's only account -- mark them all default.
UPDATE accounts SET is_default = true;

-- Backfill: mark each account's oldest project as its default (the bootstrap "ensure default
-- project" flow only creates a project when the account has none, so the oldest project per
-- account is the best available proxy for "the one it created").
UPDATE projects SET is_default = true
WHERE id IN (
    SELECT DISTINCT ON (account_id) id
    FROM projects
    ORDER BY account_id, created_at ASC, id ASC
);

-- New projects: is_default is server-computed, not client-suppliable (schema marks it @readonly,
-- excluding it from the generated CreateProjectInput/UpdateProjectInput). Project creation was
-- never moved to a hand-written procedure the way Account/ApiKey were (see the `Project` model's
-- @@allow("create", ...) in authz.cstack), so a BEFORE INSERT trigger is the only available hook
-- for this per-request "is this the account's first project" computation.
CREATE OR REPLACE FUNCTION set_project_is_default() RETURNS trigger AS $$
BEGIN
    NEW.is_default := NOT EXISTS (
        SELECT 1 FROM projects WHERE account_id = NEW.account_id
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER projects_set_is_default
    BEFORE INSERT ON projects
    FOR EACH ROW EXECUTE FUNCTION set_project_is_default();

-- Backstop against the race where two concurrent first-project creates for the same brand-new
-- account both see zero existing rows and the trigger sets is_default on both.
CREATE UNIQUE INDEX projects_account_id_default_uidx ON projects (account_id) WHERE is_default;

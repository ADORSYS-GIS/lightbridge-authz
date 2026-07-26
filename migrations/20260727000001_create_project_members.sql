-- Project-level membership (ADR-0006), replacing account-level membership
-- (account_memberships, ADR-0002/0005 -- dropped in
-- 20260724000004_drop_account_memberships.sql). Shape mirrors
-- account_memberships exactly: composite PK, no `id`/`updated_at`/
-- `deleted_at` columns, one lookup index on the member side.
--
-- Unlike account_memberships (which stored a raw `subject` string), this
-- carries a real FK to accounts -- per the agreed vision, a project member IS
-- an account.
--
-- No `prune_*`-style trigger here (contrast account_memberships' prior
-- `prune_account_without_memberships`): a project with zero members is a
-- normal, expected state (every default project has one forever), not an
-- error condition to auto-delete on.
CREATE TABLE project_members (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('lead', 'member')),
    quota_tier TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_project_members_account_id ON project_members(account_id);

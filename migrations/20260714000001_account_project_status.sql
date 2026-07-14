-- Soft-disable state for accounts and projects. `suspended` keeps the row (and its keys) intact
-- but makes every descendant API key fail validation at the OPA layer. Defaults to `active` so the
-- migration is a no-op for existing rows.
ALTER TABLE accounts
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

ALTER TABLE projects
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended'));

-- Single source of truth for an API key's *effective* validity, cascading account -> project ->
-- key. OPA reads one row by `key_hash` (served by the existing UNIQUE index on api_keys.key_hash)
-- and gets the whole decision, so suspending an account instantly invalidates every key beneath it
-- with no fan-out writes. `effective_status = 'active'` means the key is usable; any other value is
-- the deny reason.
--
-- The INNER JOINs are safe: api_keys.project_id -> projects(id) and projects.account_id ->
-- accounts(id) are both `ON DELETE CASCADE` foreign keys, so a key can never outlive its parent
-- project/account. Soft-disable is expressed via `status = 'suspended'` (the row stays), never by
-- deletion, so a suspended tenant still produces a row here with an explicit deny reason rather
-- than vanishing into a `not_found`.
CREATE VIEW api_key_validation AS
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
JOIN accounts a ON a.id = p.account_id;

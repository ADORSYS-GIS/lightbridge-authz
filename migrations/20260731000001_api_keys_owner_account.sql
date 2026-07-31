-- ADR-0006 follow-up: record WHICH member an API key belongs to, so the per-member governance
-- tier (`project_members.quota_tier`) can be resolved at introspection time.
--
-- Why this is needed at all: the epic gave projects two ceilings -- a pooled `projects.
-- project_quota` and a per-member `project_members.quota_tier`. The pooled one reaches the gateway
-- fine (introspection returns it, Authorino stamps `x-project-quota`). The per-member one had no
-- path: `api_keys` recorded only `project_id`, so given a presented key there was no way to say
-- which person's ceiling applied. ai-helm's ADR-0094 rate-limit rules key the per-member ceilings
-- on `x-quota-tier` with an `Exact` selector, so without this the header stayed empty and those
-- rules could never fire -- the tier was settable in the API and the UI but enforced nowhere.
--
-- Backfill choice: existing keys are attributed to their project's owning account. That is the
-- only attribution the data supports (nothing recorded the creator), and it is the conservative
-- one -- see the NULL-tier note below for why it cannot tighten anyone's limits retroactively.
--
-- NOT NULL is deliberate. Every key must be attributable to someone: an unattributable key is
-- exactly the case where "whose ceiling applies?" has no answer, and silently falling back to the
-- pooled quota would let a key escape a per-member limit by having no owner.
ALTER TABLE api_keys ADD COLUMN owner_account_id TEXT;

UPDATE api_keys k
SET owner_account_id = p.account_id
FROM projects p
WHERE p.id = k.project_id
  AND k.owner_account_id IS NULL;

ALTER TABLE api_keys ALTER COLUMN owner_account_id SET NOT NULL;

-- ON DELETE CASCADE matches `project_members.account_id`: deleting an account already cascades to
-- its projects and their keys, so this adds no new deletion behaviour -- it only keeps the column
-- honest for keys owned by a member of someone else's project, which `ON DELETE SET NULL` could
-- not do without violating the NOT NULL above.
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_owner_account_id_fkey
    FOREIGN KEY (owner_account_id) REFERENCES accounts(id) ON DELETE CASCADE;

-- Introspection resolves the tier by (project_id, owner_account_id) on every validation, which is
-- the hot path -- Authorino caches 30s per key, but that is still ~2 lookups/min per active key.
CREATE INDEX IF NOT EXISTS idx_api_keys_owner_account_id ON api_keys(owner_account_id);

-- Surfaced through the validation view so introspection keeps its single indexed read rather than
-- adding a round trip. `quota_tier` is a LEFT JOIN on purpose: the project's owning account
-- normally holds NO `project_members` row (ownership and roster membership are separate standings
-- -- see `authorize_project_lead`), so an owner's tier is legitimately NULL. NULL means "no
-- per-member ceiling", the caller is bounded by the pooled `project_quota` alone. That is the
-- correct reading, and it is also why the backfill above cannot retroactively tighten any existing
-- key: attributing old keys to the project owner yields a NULL tier, i.e. today's behaviour.
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
    END             AS effective_status,
    -- APPENDED, not inserted mid-list. `CREATE OR REPLACE VIEW` may only add columns to the END:
    -- the replacement query has to generate the existing columns with the same names, order and
    -- types, so slotting these in after `account_id` (where they read better) fails with
    -- "cannot change name of view column". Column order is irrelevant to callers here — the
    -- repository selects by name.
    k.owner_account_id AS owner_account_id,
    pm.role         AS owner_role,
    pm.quota_tier   AS owner_quota_tier
FROM api_keys k
JOIN projects p ON p.id = k.project_id
JOIN accounts a ON a.id = p.account_id
LEFT JOIN project_members pm
       ON pm.project_id = k.project_id
      AND pm.account_id = k.owner_account_id
WHERE k.deleted_at IS NULL;

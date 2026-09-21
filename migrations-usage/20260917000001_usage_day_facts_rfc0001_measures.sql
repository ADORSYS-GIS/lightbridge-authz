-- #588: add the RFC-0001 day-grain measure columns to `usage_day_facts`.
--
-- The day-grain receiver (#588) parses the OTLP log records governance-ctl emits under the
-- RFC-0001 "OTLP day-grain encoding contract" (lightbridge-governance
-- `docs/rfc/0001-github-copilot-connector.md`). That contract's per-report measures are the
-- GitHub Copilot **Reports API** shapes (`active_users`, `engaged_users`, `total_interactions`,
-- `total_completions`, `ai_credits`, `coding_agent_activity`, `code_review_activity`,
-- `pull_request_activity`), which are NOT the same vocabulary as the #583 `usage_day_facts`
-- columns (seeded from the Copilot **Metrics API** shapes: `total_suggestions_count`,
-- `total_acceptances_count`, ...).
--
-- The RFC-0001 contract is the pinned, authoritative emit contract (it is what governance-ctl
-- actually sends), so the receiver maps its measures onto dedicated columns here rather than
-- forcing a lossy remap onto the Metrics-API columns. All new columns are NULLable BIGINT
-- (NULL = unknown, ADR-0028 D0) and empty-string-guarded where they are opaque strings, matching
-- the existing day-facts conventions.
--
-- `user-teams-1-day` carries `team_id`/`team_slug` (strings) on a `subject_kind=user_team` row.
-- RFC-0001 known-issue #1 flags that report's `subject_id` (the user) is not unique per record
-- for a multi-team user, so it collides on the natural key and must not be cut over until that
-- is resolved. The columns are added so the normalizer can parse the report faithfully, but the
-- ingest refuses `user_team` records until the coordinated key change lands (see the normalizer).
--
-- No `EXCEPTION WHEN OTHERS` (authz-migration skill Rule 5): a genuine failure aborts loudly.
-- This is a catalog-only ALTER (adds nullable columns, no rewrite), so it is safe to run in one
-- transaction against a live table.

ALTER TABLE usage_day_facts
    ADD COLUMN active_users            BIGINT,
    ADD COLUMN engaged_users           BIGINT,
    ADD COLUMN total_interactions      BIGINT,
    ADD COLUMN total_completions       BIGINT,
    ADD COLUMN ai_credits              BIGINT,
    ADD COLUMN coding_agent_activity   BIGINT,
    ADD COLUMN code_review_activity    BIGINT,
    ADD COLUMN pull_request_activity   BIGINT,
    ADD COLUMN team_id                 TEXT,
    ADD COLUMN team_slug               TEXT;

COMMENT ON COLUMN usage_day_facts.active_users IS
    'RFC-0001 organization-1-day measure: active users. NULL = unknown (ADR-0028 D0).';
COMMENT ON COLUMN usage_day_facts.engaged_users IS
    'RFC-0001 organization-1-day measure: engaged users. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.total_interactions IS
    'RFC-0001 organization-1-day / users-1-day measure: total interactions. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.total_completions IS
    'RFC-0001 organization-1-day / users-1-day measure: total completions. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.ai_credits IS
    'RFC-0001 organization-1-day / users-1-day measure: AI credits. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.coding_agent_activity IS
    'RFC-0001 repos-1-day measure: coding-agent activity. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.code_review_activity IS
    'RFC-0001 repos-1-day measure: code-review activity. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.pull_request_activity IS
    'RFC-0001 repos-1-day measure: pull-request activity. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.team_id IS
    'RFC-0001 user-teams-1-day: the team id. NULL = unknown.';
COMMENT ON COLUMN usage_day_facts.team_slug IS
    'RFC-0001 user-teams-1-day: the team slug. NULL = unknown.';

-- #583: `usage_day_facts` — generalized day-grain facts table.
--
-- ADR-0027 Decision 2: grain partitions storage, vendor never does. Every daily aggregate from every
-- source (GitHub Copilot org/user/repo dailies today; Cursor, JetBrains, M365 tomorrow) lands here.
-- `source` is a TEXT NOT NULL dimension column — never a table name. Adding a source requires no
-- schema change: one normalizer + one registry row (governance#167's acceptance criterion).
--
-- ADR-0028 D3: the partition column is `day DATE`, not `observed_at TIMESTAMPTZ` — a daily bucket
-- is not an observation instant, and renaming it would misdescribe the key.
-- ADR-0028 D4: canonical source vocabulary is kebab-case, closed at the registry (not a DB enum).
-- ADR-0028 D5: no `add_dimension` / space partitioning — `source` is a dimension column and a
-- compression segment, not a space partition.
-- ADR-0028 D6: retention 25 months (vs. 13 months for raw request grain). Rationale: day-grain
-- facts are tiny (~10^4–10^5 rows/year vs. 10^7 for request grain) and long-lived — enterprise
-- year-over-year budgeting requires two complete fiscal years. Compression at 30 days (chunks are
-- monthly; a completed month is safe to compress immediately).
-- ADR-0028 D7: no verbatim `attributes` JSONB blob — only the allowlisted, typed columns below.
-- ADR-0028 D22: the UNIQUE key includes `day`, the partition column.
--
-- Money columns: `BIGINT` micro-USD, NULL = unknown, NEVER zero (ADR-0028 D0). The governance
-- store's `net_cost_micro_usd NOT NULL` is deliberately NOT copied — the NULL-means-unknown rule
-- applies universally here: a known-free cost is `0`, an unreported one is `NULL`.
--
-- No surrogate id. ADR-0039 bans minting ids outside `lightbridge_authz_core::cuid::cuid2()`, and
-- `DEFAULT gen_random_uuid()` is a banned call site. The natural key IS the row identity — the
-- dedup constraint and the upsert conflict target are the primary key itself, so no surrogate is
-- needed and none is minted (#583 review 2026-09-08: dropped `id DEFAULT gen_random_uuid()`).
--
-- The hypertable/compression/retention boilerplate below is duplicated near-verbatim in the seat
-- migration by design: each migration is an immutable, self-contained file (sqlx applies them
-- independently, and an applied migration's bytes are frozen), so a shared SQL routine could not
-- be factored across files without editing an applied migration.
--
-- No `EXCEPTION WHEN OTHERS` anywhere. A migration that swallows its own error reports success
-- against a schema it did not produce; every later `IF NOT EXISTS` agrees. The service refusing
-- to start is the correct outcome (authz-migration skill Rule 5) -- on a target where Timescale
-- is supposed to be present. See the hypertable block below for the one exception this migration
-- makes: skipping the block entirely when `timescaledb` is not even installable, which is the
-- documented, standing state of production and CI today, not a failure to swallow.
--
-- subject_kind closed vocabulary via CHECK: org, user, repo, user_team. Extensible via a forward
-- migration adding a new value to the constraint (no DB enum per D4's rationale). An unknown
-- subject_kind is refused at ingest, not written with a guessed or NULL value.
--
-- Every PK member that is an opaque string (`source`, `subject_id`) is empty-string-guarded via a
-- `CHECK (... <> '')`. `NOT NULL` alone would still admit `''`, and two distinct entities that
-- both collapse to `''` would collide onto the same PK tuple and be silently merged by the
-- natural-key `ON CONFLICT ... DO UPDATE` (#714 review: Stephane).

CREATE TABLE usage_day_facts (
    source      TEXT        NOT NULL,
    day         DATE        NOT NULL,
    subject_kind TEXT       NOT NULL,
    subject_id  TEXT        NOT NULL,

    -- Provider-scoped subject identity. Opaque string — never shape-validated, never joined across
    -- providers except through `usage_identities` (owned by #582, `20260907000001`). The join key
    -- per governance#185 is `provider_user_id`, never `user_login`.
    provider_user_id TEXT,

    -- Typed measure columns — allowlist seeded from the known GitHub Copilot Metrics API shapes
    -- (org/user/repo/user_team dailies) plus the vendor-neutral cost column. NULL = unknown for
    -- every measure: a source that does not report a given measure leaves it NULL, never 0.
    total_suggestions_count     BIGINT,
    total_acceptances_count     BIGINT,
    total_lines_suggested       BIGINT,
    total_lines_accepted        BIGINT,
    total_active_users          BIGINT,
    total_chat_acceptances      BIGINT,
    total_chat_turns            BIGINT,
    total_active_chat_users     BIGINT,

    -- Money: BIGINT micro-USD, NULL = unknown (ADR-0028 D0, governance ADR-0008).
    cost_micro_usd  BIGINT,

    -- Aggregate-only flag (AC6): the GitHub Copilot Metrics API enforces a 5-seat minimum floor —
    -- data is only reported when ≥5 active users exist, and reported values are aggregated/floored.
    -- Rows from aggregate-only sources are tagged TRUE so callers can distinguish them and avoid
    -- averaging them into per-user data. Default FALSE: most sources are per-entity.
    is_aggregate_only BOOLEAN NOT NULL DEFAULT FALSE,

    -- Allowlisted extension tail — nullable TEXT for vendor-specific breakdowns that are
    -- common enough to promote to typed columns (language, editor, model). A source that does not
    -- report a given breakdown leaves the column NULL, never a sentinel string.
    language    TEXT,
    editor      TEXT,
    model       TEXT,

    -- Schema versioning for the raw source payload — opaque, stored verbatim.
    raw_schema_version TEXT,

    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The natural key IS the primary key (ADR-0028 D22: the dedup constraint and the upsert
    -- conflict target). The set includes `day`, the partition column, so TimescaleDB accepts it
    -- as the hypertable's unique constraint. Leading `source` keeps per-source scans on the PK.
    PRIMARY KEY (source, day, subject_kind, subject_id),

    CONSTRAINT chk_usage_day_facts_subject_kind
        CHECK (subject_kind IN ('org', 'user', 'repo', 'user_team')),

    CONSTRAINT chk_usage_day_facts_source_not_empty
        CHECK (source <> ''),

    CONSTRAINT chk_usage_day_facts_subject_id_not_empty
        CHECK (subject_id <> '')
);

COMMENT ON TABLE usage_day_facts IS
    'Generalized day-grain facts: one row per (source, day, subject_kind, subject_id). '
    'Adding a source requires no schema change — source is a dimension column, never a table name '
    '(ADR-0027 Decision 2). See migrations-usage/20260908000001_usage_day_facts.sql for full rationale.';

COMMENT ON COLUMN usage_day_facts.source IS
    'Canonical source token from the registry (kebab-case, ADR-0028 D4). '
    'e.g. ''github-copilot'', ''m365-copilot''. TEXT NOT NULL, not a DB enum — vocabulary is '
    'closed at the registry, not the schema, so adding a source is a registry row, not a migration.';

COMMENT ON COLUMN usage_day_facts.subject_kind IS
    'The type of entity this fact describes. Closed vocabulary: org, user, repo, user_team. '
    'Enforced by CHK constraint; extensible via a forward migration adding a new value.';

COMMENT ON COLUMN usage_day_facts.subject_id IS
    'Opaque provider-scoped string. Never shape-validated, never joined across providers except '
    'through usage_identities. For GitHub: numeric org/user/repo id as a string.';

COMMENT ON COLUMN usage_day_facts.provider_user_id IS
    'Provider-scoped user identity for the subject — the join key per governance#185. '
    'NULL for org-level or repo-level facts where there is no per-user identity.';

COMMENT ON COLUMN usage_day_facts.cost_micro_usd IS
    'Cost in integer micro-USD (1 USD = 1,000,000). NULL = unknown, NEVER zero. '
    'A source that does not report cost leaves this NULL; a known-free operation is 0.';

COMMENT ON COLUMN usage_day_facts.is_aggregate_only IS
    'TRUE when this row comes from an aggregate-only source (e.g. GitHub Copilot Metrics API ''s '
    '5-seat floor). These rows must not be averaged into per-user breakdowns.';

-- Upsert idempotency rides the PRIMARY KEY itself (ADR-0028 D22): reprocessing the same
-- (source, day, subject_kind, subject_id) tuple conflicts on it and replaces the measures in
-- place, changing no counts. No separate unique index is needed.

-- Query index: (subject_kind, day) for cross-source breakdowns by subject type. There is
-- deliberately NO (source, day) index — the primary key's leading (source, day) prefix serves
-- per-source daily range scans (it-test review 2026-09-08: duplicates of a PK prefix are
-- maintained on every chunk for nothing).
CREATE INDEX idx_usage_day_facts_subject_day
    ON usage_day_facts (subject_kind, day DESC);

-- Assert hypertable -- gated on the extension actually being installed (2026-09-09 review, #714).
-- `migrations-usage/` is a deliberately plain-Postgres-safe directory: production and CI both run
-- vanilla Postgres today (#549 Finding 2; `.github/actions/tests/action.yml` defers Timescale-shaped
-- CI to the #581 D1 image decision and explicitly says not to reintroduce a Timescale container
-- here before that lands), and `20260223000001_init_usage.sql` / `20260829000001_usage_event_latency.sql`
-- both hold that line already. An earlier version of this migration called `create_hypertable`
-- unconditionally, which is exactly what those files warn against: it made `migrations-usage`
-- fail to apply at all on plain Postgres, breaking every `#[sqlx::test]` in this crate (including
-- `repo_it_tests`/`spend_query_it_tests`/`scope_ownership_it_tests`, which already run in CI) and
-- any real `just migrate` against production.
--
-- This is NOT the silent-fallback pattern authz-migration skill Rule 5 bans: Rule 5 is about
-- swallowing a genuine failure on a Timescale-capable database (a real misconfiguration should
-- fail loud). This guard only skips the block when `timescaledb` is not even installable
-- (`pg_available_extensions` has no row for it) -- the documented, standing state of prod/CI
-- today, not a transient error. If the extension IS available, everything inside this block still
-- runs with NO exception handler: a genuine failure on a Timescale-capable target still aborts the
-- migration loudly, exactly as the rest of this file's design intends.
--
-- Chunk interval: 1 month. Day-grain facts accumulate ~10^4–10^5 rows/year, not 10^7 — monthly
-- chunks are the right granularity for data this sparse (a daily chunk would have O(100) rows and
-- produce a planning overhead that dwarfs the query time).
--
-- `by_range('day', INTERVAL '1 month')` is the TS 2.x API. The legacy positional API
-- (`create_hypertable('t', 'col')`) is also available but the keyword form is unambiguous.
--
-- Compression: segment by source and subject_kind for per-origin and per-entity-type chunk pruning.
-- Order by day DESC inside each segment so range scans over recent days decompress the fewest
-- segments. Column order inside `segmentby` carries no semantic weight in Timescale — pruning comes
-- from the column being segmented at all (ADR-0028 D5 note).
--
-- Compress completed chunks older than 30 days. Day/seat facts are small and long-lived; a
-- completed month is cold immediately after the reporting period closes.
--
-- Retention: 25 months. ADR-0028 D6 rationale — enterprise year-over-year budgeting requires two
-- complete fiscal years (24 months) plus the current billing month (= 25 months total). This is
-- the same +1 logic as 13 months for raw request grain (12 months + current). Day/seat facts are
-- tiny compared to raw request grain, so the longer window is a rounding error in storage terms
-- (see ADR-0028 storage sizing section).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;

        PERFORM create_hypertable(
            'usage_day_facts',
            by_range('day', INTERVAL '1 month')
        );

        EXECUTE 'ALTER TABLE usage_day_facts SET (
            timescaledb.compress = true,
            timescaledb.compress_segmentby = ''source, subject_kind'',
            timescaledb.compress_orderby = ''day DESC, subject_id''
        )';

        PERFORM add_compression_policy('usage_day_facts', INTERVAL '30 days');
        PERFORM add_retention_policy('usage_day_facts', INTERVAL '25 months');
    END IF;
END $$;

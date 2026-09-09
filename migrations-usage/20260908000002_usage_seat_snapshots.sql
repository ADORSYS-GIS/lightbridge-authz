-- #583: `usage_seat_snapshots` — generalized seat-grain snapshots table.
--
-- ADR-0027 Decision 2: grain partitions storage, vendor never does. Seat snapshots from any source
-- (GitHub Copilot seat assignments today; Cursor, JetBrains seat data tomorrow) land here. `source`
-- is a TEXT NOT NULL dimension column — never a table name.
--
-- ADR-0028 D3: the partition column is `snapshot_day DATE` — a daily seat snapshot is not an
-- observation instant. See the D3 reading recorded in the ADR for why the day/seat grain uses DATE
-- while the request/execution grains use TIMESTAMPTZ.
-- ADR-0028 D4: canonical source vocabulary is kebab-case, closed at the registry (not a DB enum).
-- ADR-0028 D5: no `add_dimension` / space partitioning — `source` is a dimension column and
-- compression segment only.
-- ADR-0028 D6: retention 25 months, same as `usage_day_facts`. Compression at 30 days.
-- ADR-0028 D22: the UNIQUE key includes `snapshot_day`, the partition column.
--
-- Identity rule (governance#185): `provider_user_id` is the join key, NEVER `user_login`.
-- `assignee_login` is stored for display only — it must not be used as a join key across providers.
-- recorded decision (2026-09-08 review): the login is part of the provider's seat report itself
-- (the snapshot literally is per-login state), so it stays embedded as a display column here;
-- identity *joins* for attribution go through `usage_identities` (lands with #582 / PR-1b) via
-- `provider_user_id`, and the PII-erasure surface remains the identities table.
--
-- No surrogate id: ADR-0039 bans minting ids outside `cuid2()`, `DEFAULT gen_random_uuid()` is a
-- banned call site, and the natural key IS the row identity — it is the PRIMARY KEY, so the dedup
-- constraint and the upsert conflict target are the key itself.
--
-- Recorded decision (2026-09-08 review): `provider_user_id` is NOT NULL and part of the primary
-- key — "every seat is per-user". That is true of the initial occupant (GitHub Copilot) and of the
-- natural key semantics. A future pooled/floating-license vendor (Cursor, JetBrains) that reports
-- unassigned seats will need a forward migration to represent them (PK changes to an applied
-- migration are forbidden); the decision to stay per-user is explicit now rather than silent.
--
-- Every PK/identity member that is an opaque string (`source`, `subject_id`, `provider_user_id`)
-- is empty-string-guarded via a `CHECK (... <> '')`. `NOT NULL` alone would still admit `''`, and
-- two distinct seats that both collapse to `''` for `provider_user_id` (or `subject_id`) would
-- collide onto one PK tuple and be silently merged by the natural-key `ON CONFLICT ... DO UPDATE`,
-- corrupting seat state with no constraint violation (#714 review: Stephane).
--
-- No `EXCEPTION WHEN OTHERS` anywhere (authz-migration skill Rule 5). Fail loud -- on a target
-- where Timescale is supposed to be present. See the hypertable block below for the one
-- exception: skipping it entirely when `timescaledb` isn't even installable, the documented,
-- standing state of production and CI today.

CREATE TABLE usage_seat_snapshots (
    source          TEXT        NOT NULL,
    snapshot_day    DATE        NOT NULL,
    subject_kind    TEXT        NOT NULL,

    -- The org/team/entity this seat belongs to (opaque provider-scoped id, never shape-validated).
    subject_id      TEXT        NOT NULL,

    -- Provider-scoped user identity — the join key per governance#185. NOT NULL for seat rows
    -- (a seat is always assigned to a specific user; an unassigned seat is not a snapshot row).
    provider_user_id TEXT       NOT NULL,

    -- Seat state columns — typed, nullable, from GitHub Copilot seat shape as the initial occupant.
    -- A source that does not report a given field leaves it NULL.
    -- `seat_state` is the only NOT NULL state column: the provider's own vocabulary, stored
    -- verbatim (opaque — closed at the normalizer, not here, same rationale as D4 for `source`).
    seat_state                  TEXT NOT NULL,
    assignee_login              TEXT,
    assignee_team               TEXT,
    seat_created_at             TIMESTAMPTZ,
    last_activity_at            TIMESTAMPTZ,
    last_activity_editor        TEXT,
    pending_cancellation_date   DATE,
    plan_type                   TEXT,

    -- Schema versioning for the raw source payload — opaque, stored verbatim.
    raw_schema_version TEXT,

    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- The natural key IS the primary key (ADR-0028 D22), includes `snapshot_day` (the partition
    -- column). One seat row per user per subject per day per source.
    PRIMARY KEY (source, snapshot_day, subject_kind, subject_id, provider_user_id),

    CONSTRAINT chk_usage_seat_snapshots_subject_kind
        CHECK (subject_kind IN ('org', 'user', 'repo', 'user_team')),

    CONSTRAINT chk_usage_seat_snapshots_source_not_empty
        CHECK (source <> ''),

    CONSTRAINT chk_usage_seat_snapshots_subject_id_not_empty
        CHECK (subject_id <> ''),

    CONSTRAINT chk_usage_seat_snapshots_provider_user_id_not_empty
        CHECK (provider_user_id <> '')
);

COMMENT ON TABLE usage_seat_snapshots IS
    'Generalized seat-grain snapshots: one row per (source, snapshot_day, subject_kind, subject_id, '
    'provider_user_id). Adding a source requires no schema change — source is a dimension column, '
    'never a table name (ADR-0027 Decision 2). Retention: 25 months (ADR-0028 D6).';

COMMENT ON COLUMN usage_seat_snapshots.source IS
    'Canonical source token from the registry (kebab-case, ADR-0028 D4). '
    'e.g. ''github-copilot''. TEXT NOT NULL, not a DB enum.';

COMMENT ON COLUMN usage_seat_snapshots.snapshot_day IS
    'The calendar day this snapshot was taken. The partition column (DATE, not TIMESTAMPTZ — '
    'a daily seat snapshot is not an observation instant, see ADR-0028 D3).';

COMMENT ON COLUMN usage_seat_snapshots.provider_user_id IS
    'Provider-scoped user identity — the join key per governance#185. NEVER user_login. '
    'For GitHub: the numeric user id as a string. NOT NULL: a seat is always per-user.';

COMMENT ON COLUMN usage_seat_snapshots.assignee_login IS
    'Provider login name (e.g. GitHub username). Stored for display only. '
    'MUST NOT be used as a join key across providers — use provider_user_id instead (gov#185).';

COMMENT ON COLUMN usage_seat_snapshots.seat_created_at IS
    'When this seat assignment was created by the provider. NULL if not reported.';

COMMENT ON COLUMN usage_seat_snapshots.last_activity_at IS
    'Timestamp of the seat holder''s last recorded activity. NULL if not reported.';

COMMENT ON COLUMN usage_seat_snapshots.pending_cancellation_date IS
    'If the seat is pending cancellation, the date it will be cancelled. NULL if not cancelling.';

COMMENT ON COLUMN usage_seat_snapshots.seat_state IS
    'The provider''s own seat-state token, stored verbatim (e.g. GitHub Copilot seat states). '
    'Opaque, closed at the normalizer — not CHECKed here, for the same reason `source` is TEXT: '
    'a new state in a provider report must never be a migration.';

-- Upsert idempotency rides the PRIMARY KEY itself (ADR-0028 D22): reprocessing the same snapshot
-- conflicts on it and replaces the state columns in place, changing no counts. No separate unique
-- index is needed.

-- Query index: per-user seat history. There is deliberately NO (source, snapshot_day) index —
-- the primary key's leading (source, snapshot_day) prefix serves per-source daily range scans.
CREATE INDEX idx_usage_seat_snapshots_provider_user
    ON usage_seat_snapshots (provider_user_id, snapshot_day DESC);

-- Assert hypertable -- gated on the extension being installed, same reasoning and same guard
-- shape as `usage_day_facts.sql` (2026-09-09 review, #714): production/CI are plain Postgres
-- today (#549 Finding 2), so this skips gracefully when `timescaledb` isn't even available
-- rather than failing `migrations-usage` to apply at all. No exception handler once inside the
-- `IF` -- a genuine failure on a Timescale-capable target still fails loud.
-- Chunk interval: 1 month (same rationale as usage_day_facts — seat data is sparse).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;

        PERFORM create_hypertable(
            'usage_seat_snapshots',
            by_range('snapshot_day', INTERVAL '1 month')
        );

        -- Compression: segment by source and subject_kind.
        EXECUTE 'ALTER TABLE usage_seat_snapshots SET (
            timescaledb.compress = true,
            timescaledb.compress_segmentby = ''source, subject_kind'',
            timescaledb.compress_orderby = ''snapshot_day DESC, provider_user_id''
        )';

        -- Compress completed chunks older than 30 days.
        PERFORM add_compression_policy('usage_seat_snapshots', INTERVAL '30 days');

        -- Retention: 25 months (ADR-0028 D6 — same rationale as usage_day_facts).
        PERFORM add_retention_policy('usage_seat_snapshots', INTERVAL '25 months');
    END IF;
END $$;

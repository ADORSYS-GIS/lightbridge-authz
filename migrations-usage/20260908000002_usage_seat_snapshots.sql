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
--
-- No `EXCEPTION WHEN OTHERS` anywhere (authz-migration skill Rule 5). Fail loud.

CREATE TABLE usage_seat_snapshots (
    id              TEXT        NOT NULL DEFAULT gen_random_uuid()::text,
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

    PRIMARY KEY (snapshot_day, id),

    CONSTRAINT chk_usage_seat_snapshots_subject_kind
        CHECK (subject_kind IN ('org', 'user', 'repo', 'user_team')),

    CONSTRAINT chk_usage_seat_snapshots_source_not_empty
        CHECK (source <> '')
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

-- Natural-key unique constraint (ADR-0028 D22). `snapshot_day` is the partition column.
-- One seat row per user per subject per day per source. Reprocessing the same snapshot is safe.
CREATE UNIQUE INDEX idx_usage_seat_snapshots_natural_key
    ON usage_seat_snapshots (source, snapshot_day, subject_kind, subject_id, provider_user_id);

-- Query indexes.
CREATE INDEX idx_usage_seat_snapshots_source_day
    ON usage_seat_snapshots (source, snapshot_day DESC);

CREATE INDEX idx_usage_seat_snapshots_provider_user
    ON usage_seat_snapshots (provider_user_id, snapshot_day DESC);

-- Assert hypertable. Fail loud, no fallback.
-- Chunk interval: 1 month (same rationale as usage_day_facts — seat data is sparse).
SELECT create_hypertable(
    'usage_seat_snapshots',
    by_range('snapshot_day', INTERVAL '1 month')
);

-- Compression: segment by source and subject_kind.
ALTER TABLE usage_seat_snapshots SET (
    timescaledb.compress = true,
    timescaledb.compress_segmentby = 'source, subject_kind',
    timescaledb.compress_orderby = 'snapshot_day DESC, provider_user_id'
);

-- Compress completed chunks older than 30 days.
SELECT add_compression_policy('usage_seat_snapshots', INTERVAL '30 days');

-- Retention: 25 months (ADR-0028 D6 — same rationale as usage_day_facts).
SELECT add_retention_policy('usage_seat_snapshots', INTERVAL '25 months');

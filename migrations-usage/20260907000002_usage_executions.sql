-- usage_executions: the execution grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `executions` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions:
--   * `source TEXT NOT NULL` -- the usage-store origin dimension (gateway, claude_code,
--     codex, opencode, ...), replacing governance's tenant_id/integration_id split.
--   * identity via a `usage_identities` reference, not embedded user_email/internal_user_id
--     (ADR-0028 D7 -- PII is joined, erasable with one UPDATE).
--   * `id` is the sole PRIMARY KEY -- globally unique, matching governance -- so a downstream
--     join on `execution_id` alone is unambiguous. The dedup key
--     `UNIQUE (started_at, trace_id, span_id)` includes the partition column (ADR-0028 D22).
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): the ticket's acceptance criteria call for this to be a
-- hypertable with compression + retention policies. TimescaleDB is NOT deployed on the usage
-- CNPG tenant (#489/D1) and is not required for this grain -- production is plain Postgres,
-- exactly as lightbridge-governance's donor `executions` table runs. This migration therefore
-- creates a plain table. The dedup key includes the partition column (hypertable-ready); the
-- PRIMARY KEY is `id` per governance, so a future hypertable conversion would move `started_at`
-- into the PK. See the ticket note.
--
-- IDEMPOTENCY BOUNDARY (ADR-0028 D22): the dedup key includes wall-clock `started_at`, so
-- idempotency is only as good as `started_at` stability across retries -- two deliveries of the
-- same logical span with a different `started_at` (source clock skew, re-normalization) produce
-- two rows. This is the documented tradeoff of putting the partition column in the key.
CREATE TABLE usage_executions (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    provider TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    identity_id TEXT REFERENCES usage_identities (id),
    duration_ms BIGINT NOT NULL,
    -- NULL = cost unknown (no pricing row, or unknown token counts). Unknown is honest: a
    -- zero would read as "free" on a dashboard, so 0 is rejected outright.
    estimated_cost_micro_usd BIGINT,
    raw_backend TEXT,
    raw_schema_version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT usage_executions_cost_positive
        CHECK (estimated_cost_micro_usd IS NULL OR estimated_cost_micro_usd > 0),
    UNIQUE (started_at, trace_id, span_id)
);

-- Postgres does not auto-index FK columns. These support the natural access patterns of the
-- grain: joining an execution to its identity, and looking an execution up by its trace/span.
-- NOTE for a future hypertable conversion: Timescale requires every index to include the
-- partition column (`started_at`), so these would need `started_at` prepended then.
CREATE INDEX idx_usage_executions_identity_id ON usage_executions (identity_id);
CREATE INDEX idx_usage_executions_trace_span ON usage_executions (trace_id, span_id);

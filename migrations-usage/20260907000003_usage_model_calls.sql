-- usage_model_calls: the model-call grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `model_calls` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions: `source TEXT NOT NULL` (the origin dimension) and `observed_at`
-- as the grain's time column, inherited from the parent execution.
--
-- `span_id` is the MODEL CALL'S OWN span (each model call is its own OTLP span), NOT the
-- parent execution's span. That is what lets one execution carry N model calls: each has a
-- distinct `span_id`, so the dedup key `UNIQUE (trace_id, span_id)` does not collide. The id
-- is derived from this span (`{span_id}:mc`), bijective with the dedup key.
--
-- The `execution_id` FK is `DEFERRABLE INITIALLY DEFERRED` because OTLP exports child spans
-- (model calls) before the parent execution span when an agent run outlives a single
-- BatchSpanProcessor flush. Deferring the check to commit time lets the ingest insert the
-- parent and its children in one transaction in any order. If ingest ever processes children
-- in a SEPARATE transaction before the parent exists, `execution_id` would need to be nullable
-- instead -- an ingest-design decision, not a schema one.
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): see the note in `20260907000002_usage_executions.sql` --
-- TimescaleDB is not deployed on the usage tenant and is not required; this is a plain table.
CREATE TABLE usage_model_calls (
    id TEXT PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    execution_id TEXT NOT NULL
        REFERENCES usage_executions (id) DEFERRABLE INITIALLY DEFERRED,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    model TEXT NOT NULL,
    -- NULL = unknown (the payload did not report token counts): cost is then also NULL,
    -- never a zero that a dashboard would read as "free". A genuine 0 is storable; the
    -- NULL-vs-0 discipline is enforced by ingest, not a CHECK (the donor ships none).
    input_tokens BIGINT,
    output_tokens BIGINT,
    cost_micro_usd BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (trace_id, span_id)
);

-- Postgres does not auto-index FK columns. This supports the natural access pattern of the
-- grain: joining model calls to their parent execution. (trace_id, span_id) is covered by the
-- UNIQUE constraint above.
CREATE INDEX idx_usage_model_calls_execution_id ON usage_model_calls (execution_id);

-- The grain is a time-series; index the time column for time-range reads (see the note in
-- `20260907000002_usage_executions.sql`).
CREATE INDEX idx_usage_model_calls_observed_at ON usage_model_calls (observed_at);

-- usage_model_calls: the model-call grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `model_calls` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions: `source TEXT NOT NULL` (the origin dimension) and `started_at`
-- as the grain's time/partition column, inherited from the parent execution.
--
-- `span_id` is the MODEL CALL'S OWN span (each model call is its own OTLP span), NOT the
-- parent execution's span. That is what lets one execution carry N model calls: each has a
-- distinct `span_id`, so the dedup key `UNIQUE (started_at, trace_id, span_id)` does not
-- collide. The id is derived from this span (`{span_id}:mc`).
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): see the note in `20260907000002_usage_executions.sql` --
-- TimescaleDB is not deployed on the usage tenant and is not required; this is a plain table.
CREATE TABLE usage_model_calls (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    execution_id TEXT NOT NULL REFERENCES usage_executions (id),
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    model TEXT NOT NULL,
    -- NULL = unknown (the payload did not report token counts): cost is then also NULL,
    -- never a zero that a dashboard would read as "free", so 0 is rejected outright.
    input_tokens BIGINT,
    output_tokens BIGINT,
    cost_micro_usd BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT usage_model_calls_cost_positive
        CHECK (cost_micro_usd IS NULL OR cost_micro_usd > 0),
    UNIQUE (started_at, trace_id, span_id)
);

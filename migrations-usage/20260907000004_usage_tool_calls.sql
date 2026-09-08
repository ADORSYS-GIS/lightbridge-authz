-- usage_tool_calls: the tool-call grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `tool_calls` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions: `source TEXT NOT NULL` (the origin dimension) and `observed_at`
-- as the grain's time column, inherited from the parent execution.
--
-- `span_id` is the TOOL CALL'S OWN span (each tool call is its own OTLP span), NOT the
-- parent execution's span. That is what lets one execution carry M tool calls: each has a
-- distinct `span_id`, so the dedup key `UNIQUE (source, trace_id, span_id)` does not collide.
-- Tool calls are strictly one-per-span, so the id is derived from `source` + `trace_id` + the
-- span (`{source}_{trace_id}_{span_id}:tc`), matching model calls' `{source}_{trace_id}_{span_id}:mc`
-- -- there is no `{idx}` component, because a second tool call sharing a span would be
-- silently absorbed by the dedup key. `source` and `trace_id` are embedded so the id is
-- globally unique (an OTLP `span_id` is only unique within a trace, and `trace_id` only within
-- a source), matching `usage_executions`.
--
-- The `execution_id` FK is `DEFERRABLE INITIALLY DEFERRED` for the same child-before-parent
-- OTLP export reason as `usage_model_calls` (see that migration's header).
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): see the note in `20260907000002_usage_executions.sql` --
-- TimescaleDB is not deployed on the usage tenant and is not required; this is a plain table.
CREATE TABLE usage_tool_calls (
    id TEXT PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    execution_id TEXT NOT NULL
        REFERENCES usage_executions (id) DEFERRABLE INITIALLY DEFERRED,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    duration_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- See `20260907000002_usage_executions.sql` -- the `_` separator must never appear in a
    -- component or the derived id stops being injective.
    CONSTRAINT usage_tool_calls_id_components_no_separator
        CHECK (position('_' in trace_id) = 0 AND position('_' in span_id) = 0),
    UNIQUE (source, trace_id, span_id)
);

-- Postgres does not auto-index FK columns. This supports the natural access pattern of the
-- grain: joining tool calls to their parent execution. (trace_id, span_id) is covered by the
-- UNIQUE constraint above.
CREATE INDEX idx_usage_tool_calls_execution_id ON usage_tool_calls (execution_id);

-- The grain is a time-series; index the time column for time-range reads (see the note in
-- `20260907000002_usage_executions.sql`).
CREATE INDEX idx_usage_tool_calls_observed_at ON usage_tool_calls (observed_at);

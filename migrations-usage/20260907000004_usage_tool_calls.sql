-- usage_tool_calls: the tool-call grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `tool_calls` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions: `source TEXT NOT NULL` (the origin dimension) and `started_at`
-- as the grain's time/partition column, inherited from the parent execution.
--
-- `span_id` is the TOOL CALL'S OWN span (each tool call is its own OTLP span), NOT the
-- parent execution's span. That is what lets one execution carry M tool calls: each has a
-- distinct `span_id`, so the dedup key `UNIQUE (started_at, trace_id, span_id)` does not
-- collide. The id is derived from this span (`{span_id}:tc:{idx}`).
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): see the note in `20260907000002_usage_executions.sql` --
-- TimescaleDB is not deployed on the usage tenant and is not required; this is a plain table.
CREATE TABLE usage_tool_calls (
    id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    execution_id TEXT NOT NULL REFERENCES usage_executions (id),
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    duration_ms BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (started_at, trace_id, span_id)
);

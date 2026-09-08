-- usage_executions: the execution grain of the usage store (ADR-0027/0028, #582).
--
-- Ported from lightbridge-governance's proven `executions` table
-- (governance-core/migrations/postgres/20260803000001_telemetry_models), adapted to the
-- usage store's conventions:
--   * `source TEXT NOT NULL` -- the usage-store origin dimension (gateway, claude_code,
--     codex, opencode, ...), replacing governance's tenant_id/integration_id split.
--   * identity via a `usage_identities` reference, not embedded user_email/internal_user_id
--     (ADR-0028 D7 -- PII is joined, erasable with one UPDATE).
--   * `observed_at` is the grain's time column (the usage-store convention -- `usage_events`
--     and ADR-0028 D3/D22 both use `observed_at`), kept as a plain column, not in the key.
--   * `id` is the sole PRIMARY KEY -- globally unique, matching governance -- so a downstream
--     join on `execution_id` alone is unambiguous.
--   * the dedup key is `UNIQUE (trace_id, span_id)`, matching the donor. It is deliberately
--     bijective with the derived id (`exec_{trace_id}_{span_id}`): a redelivery of the same
--     logical span -- even with a drifted `observed_at` -- hits the same key and is absorbed by
--     `ON CONFLICT`, never a 23505 on the PK. Putting the time column in the key would break
--     that bijection (a drifted timestamp would miss the conflict target and collide on the
--     derived id), so it is left out; the hypertable partition-column-in-key rule
--     (ADR-0028 D22) is deferred with the Timescale work below.
--   * the id embeds BOTH `trace_id` and `span_id` because an OTLP `span_id` is only unique
--     within a trace, not globally -- a `span_id`-only id would collide across two unrelated
--     traces (birthday-bound over an unbounded table) and surface as an unabsorbed 23505 on
--     the PK instead of the intended upsert. `trace_id` and `span_id` are hex-encoded, so the
--     `_` separator is unambiguous.
--   * `duration_ms` and `raw_schema_version` are NULLABLE because OTLP exports child spans
--     (model/tool calls) BEFORE the parent execution span -- a child ends before its parent,
--     and BatchSpanProcessor flushes every ~5s, so for any run longer than one flush the
--     children arrive in an earlier export than the execution that parents them. Ingest
--     therefore mints a STUB `usage_executions` row (id derived from the child's
--     `trace_id` + `parent_span_id`, `duration_ms`/`raw_schema_version` NULL) on first sight of
--     any child, in the SAME transaction as the child, so the NOT NULL `execution_id` FK on the
--     child tables is satisfiable. The real execution span later fills the stub via the upsert
--     (`ON CONFLICT DO UPDATE`). A stub whose execution never ends (agent killed mid-run) is
--     honest: the children are kept, the execution is recorded as never-completed. The
--     `execution_id` FK is `DEFERRABLE INITIALLY DEFERRED` so parent and children may be
--     inserted in any order within one transaction.
--
-- ADR-0038 persistence exception, same class as `secret_claims`: a grain-partitioned
-- time-series with CAS/upsert (ON CONFLICT) semantics that generated CRUD cannot express.
-- The usage DB is already hand-written SQL (see `usage_events`); this table follows it.
--
-- TIMESCALE DEVIATION (2026-09-07): the ticket's acceptance criteria call for this to be a
-- hypertable with compression + retention policies. TimescaleDB is NOT deployed on the usage
-- CNPG tenant (#489/D1) and is not required for this grain -- production is plain Postgres,
-- exactly as lightbridge-governance's donor `executions` table runs. This migration therefore
-- creates a plain table. See the ticket note.
CREATE TABLE usage_executions (
    id TEXT PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    provider TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    span_id TEXT NOT NULL,
    identity_id TEXT REFERENCES usage_identities (id),
    -- NULL = a stub execution (created on first sight of a child, before the real execution
    -- span arrives); the real span fills it via the upsert. A completed execution always has
    -- a duration.
    duration_ms BIGINT,
    -- NULL = cost unknown (no pricing row, or unknown token counts). Unknown is honest: a
    -- zero would read as "free" on a dashboard, so unknown is written as NULL, never 0. A
    -- genuine 0 (a run that truly cost nothing) is a legitimate value and is storable -- the
    -- NULL-vs-0 discipline is enforced by the ingest writing NULL for unknown, not by a CHECK
    -- (the donor ships no CHECK for the same reason).
    estimated_cost_micro_usd BIGINT,
    raw_backend TEXT,
    -- NULL = a stub execution (see duration_ms); the real execution span fills it.
    raw_schema_version BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (trace_id, span_id)
);

-- Postgres does not auto-index FK columns. This supports the natural access pattern of the
-- grain: joining an execution to its identity. (trace_id, span_id) is covered by the UNIQUE
-- constraint above.
CREATE INDEX idx_usage_executions_identity_id ON usage_executions (identity_id);

-- The grain is a time-series; its defining access pattern is a time-range read
-- (`WHERE observed_at >= ... AND observed_at < ...`). Index the time column so those reads do
-- not seq-scan as the (unbounded, see the TIMESCALE DEVIATION note) table grows.
CREATE INDEX idx_usage_executions_observed_at ON usage_executions (observed_at);

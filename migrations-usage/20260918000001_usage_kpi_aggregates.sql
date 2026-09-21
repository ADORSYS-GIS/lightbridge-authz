-- #587: named KPI aggregates on the grain tables, one per measure, never spanning grains.
--
-- The epic (#581) and this story (#587) were written for TimescaleDB continuous aggregates, but
-- the owner decision (2026-09-21) is: **no TimescaleDB in this project — plain Postgres achieves
-- the same.** On vanilla Postgres the "continuous aggregate" is a plain materialized view refreshed
-- by a background job in the usage service (Option A, mirroring the existing `retention_loop`), not
-- a Timescale incremental aggregate. This migration therefore creates ordinary materialized views
-- (one per KPI measure), each built on EXACTLY ONE grain table — no aggregate joins or unions
-- across grains (governance#166) — plus a unique index per view (required for
-- `REFRESH MATERIALIZED VIEW CONCURRENTLY`) and a small state table the refresh job writes.
--
-- The KPI measures and their single authoritative grain source:
--   * spend          -> usage_executions.estimated_cost_micro_usd        (mv_executions_spend_hourly)
--   * requests       -> usage_executions                                (mv_executions_requests_hourly)
--   * latency p50/95/99 -> usage_executions.duration_ms                 (mv_executions_latency_hourly)
--   * tokens         -> usage_model_calls.input_tokens/output_tokens    (mv_model_calls_tokens_hourly)
--   * spend          -> usage_model_calls.cost_micro_usd                (mv_model_calls_spend_hourly)
--   * requests       -> usage_model_calls                               (mv_model_calls_requests_hourly)
--   * active users   -> usage_day_facts.total_active_users              (mv_day_facts_active_users_daily)
--   * acceptances    -> usage_day_facts.total_acceptances_count         (mv_day_facts_acceptances_daily)
--   * spend          -> usage_day_facts.cost_micro_usd                  (mv_day_facts_spend_daily)
--   * active seats   -> usage_seat_snapshots.pending_cancellation_date  (mv_seat_snapshots_active_daily)
--
-- Execution/model-call grains are bucketed HOURLY (they are high-frequency, per-request); day/seat
-- grains are bucketed DAILY (their natural granularity). A coarser query re-buckets the view's
-- bucket column; a finer query than the view's granularity is not representable and must read raw.
--
-- Money discipline (ADR-0028 D0): NULL = unknown, never 0. Every spend aggregate carries BOTH the
-- `SUM(...)` of known costs (which is NULL when every row in the bucket is unknown — never coerced
-- to 0) AND a separate `unknown_cost_count` of the rows whose cost was NULL, so unknown-cost rows
-- are counted separately and never silently folded in as free.
--
-- Latency percentiles use Postgres's exact `percentile_cont` ordered-set aggregate, computed once
-- at refresh time (the whole point of the aggregate — the percentile becomes a lookup, not a
-- per-query computation). No `timescaledb_toolkit` is needed on plain Postgres, so the D1/gov#163
-- toolkit image question is moot here; no approximation is used, so none needs naming in the API
-- docs.
--
-- No `EXCEPTION WHEN OTHERS` (authz-migration skill Rule 5): a genuine failure aborts loudly. These
-- are plain-Postgres objects (no Timescale gating needed — unlike the hypertable blocks in the
-- day/seat migrations, which are gated because `create_hypertable` does not exist on vanilla
-- Postgres). Materialized views, unique indexes and `REFRESH ... CONCURRENTLY` are all vanilla
-- Postgres, so this migration applies unconditionally and is fully testable in CI.

-- ---------------------------------------------------------------------------
-- usage_executions grain (hourly)
-- ---------------------------------------------------------------------------

-- KPI: spend. `cost_micro_usd` is NULL when every execution in the bucket had unknown cost;
-- `unknown_cost_count` counts those rows separately (never coerced to 0).
CREATE MATERIALIZED VIEW mv_executions_spend_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    SUM(estimated_cost_micro_usd)::bigint AS cost_micro_usd,
    COUNT(*) FILTER (WHERE estimated_cost_micro_usd IS NULL) AS unknown_cost_count
FROM usage_executions
GROUP BY bucket_start, source;

CREATE UNIQUE INDEX mv_executions_spend_hourly_pk
    ON mv_executions_spend_hourly (bucket_start, source);

-- KPI: requests (execution count).
CREATE MATERIALIZED VIEW mv_executions_requests_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    COUNT(*) AS requests
FROM usage_executions
GROUP BY bucket_start, source;

CREATE UNIQUE INDEX mv_executions_requests_hourly_pk
    ON mv_executions_requests_hourly (bucket_start, source);

-- KPI: latency percentiles. Exact `percentile_cont` over `duration_ms`, computed at refresh.
-- `latency_samples` is the count of executions that reported a duration (NULL durations are
-- stubs, not 0ms); a percentile is NULL when the bucket has no samples.
CREATE MATERIALIZED VIEW mv_executions_latency_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    COUNT(duration_ms) AS latency_samples,
    percentile_cont(0.5) WITHIN GROUP (ORDER BY duration_ms) AS latency_p50_ms,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) AS latency_p95_ms,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) AS latency_p99_ms
FROM usage_executions
GROUP BY bucket_start, source;

CREATE UNIQUE INDEX mv_executions_latency_hourly_pk
    ON mv_executions_latency_hourly (bucket_start, source);

-- ---------------------------------------------------------------------------
-- usage_model_calls grain (hourly)
-- ---------------------------------------------------------------------------

-- KPI: tokens (input + output), grouped by model.
CREATE MATERIALIZED VIEW mv_model_calls_tokens_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    model,
    SUM(input_tokens)::bigint AS input_tokens,
    SUM(output_tokens)::bigint AS output_tokens
FROM usage_model_calls
GROUP BY bucket_start, source, model;

CREATE UNIQUE INDEX mv_model_calls_tokens_hourly_pk
    ON mv_model_calls_tokens_hourly (bucket_start, source, model);

-- KPI: spend on the model-call grain, with unknown-cost rows counted separately.
CREATE MATERIALIZED VIEW mv_model_calls_spend_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    model,
    SUM(cost_micro_usd)::bigint AS cost_micro_usd,
    COUNT(*) FILTER (WHERE cost_micro_usd IS NULL) AS unknown_cost_count
FROM usage_model_calls
GROUP BY bucket_start, source, model;

CREATE UNIQUE INDEX mv_model_calls_spend_hourly_pk
    ON mv_model_calls_spend_hourly (bucket_start, source, model);

-- KPI: requests (model-call count).
CREATE MATERIALIZED VIEW mv_model_calls_requests_hourly AS
SELECT
    date_trunc('hour', observed_at) AS bucket_start,
    source,
    COUNT(*) AS requests
FROM usage_model_calls
GROUP BY bucket_start, source;

CREATE UNIQUE INDEX mv_model_calls_requests_hourly_pk
    ON mv_model_calls_requests_hourly (bucket_start, source);

-- ---------------------------------------------------------------------------
-- usage_day_facts grain (daily)
-- ---------------------------------------------------------------------------

-- KPI: active users. `total_active_users` is a per-day DISTINCT count, so it is NOT additive
-- across days; MAX reports the peak daily active users in the bucket (the honest reading of a
-- distinct count we cannot re-derive from daily aggregates). Carries the full dimension set the
-- day-facts query can filter/group on (`is_aggregate_only`, `language`, `editor`, `model`,
-- `provider_user_id`) so the query endpoint routes to this aggregate with no semantic change.
CREATE MATERIALIZED VIEW mv_day_facts_active_users_daily AS
SELECT
    day,
    source,
    subject_kind,
    subject_id,
    is_aggregate_only,
    language,
    editor,
    model,
    provider_user_id,
    MAX(total_active_users) AS active_users
FROM usage_day_facts
GROUP BY day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id;

CREATE UNIQUE INDEX mv_day_facts_active_users_daily_pk
    ON mv_day_facts_active_users_daily (day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id);

-- KPI: acceptance placeholders (acceptances + suggestions + lines). Carries the same dimension set
-- as the other day-facts aggregates so the query endpoint can JOIN them on the natural key.
CREATE MATERIALIZED VIEW mv_day_facts_acceptances_daily AS
SELECT
    day,
    source,
    subject_kind,
    subject_id,
    is_aggregate_only,
    language,
    editor,
    model,
    provider_user_id,
    SUM(total_acceptances_count)::bigint AS acceptances,
    SUM(total_suggestions_count)::bigint AS suggestions,
    SUM(total_lines_suggested)::bigint AS lines_suggested,
    SUM(total_lines_accepted)::bigint AS lines_accepted
FROM usage_day_facts
GROUP BY day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id;

CREATE UNIQUE INDEX mv_day_facts_acceptances_daily_pk
    ON mv_day_facts_acceptances_daily (day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id);

-- KPI: spend on the day grain, with unknown-cost rows counted separately. Carries the same
-- dimension set as the other day-facts aggregates.
CREATE MATERIALIZED VIEW mv_day_facts_spend_daily AS
SELECT
    day,
    source,
    subject_kind,
    subject_id,
    is_aggregate_only,
    language,
    editor,
    model,
    provider_user_id,
    SUM(cost_micro_usd)::bigint AS cost_micro_usd,
    COUNT(*) FILTER (WHERE cost_micro_usd IS NULL) AS unknown_cost_count
FROM usage_day_facts
GROUP BY day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id;

CREATE UNIQUE INDEX mv_day_facts_spend_daily_pk
    ON mv_day_facts_spend_daily (day, source, subject_kind, subject_id, is_aggregate_only, language, editor, model, provider_user_id);

-- ---------------------------------------------------------------------------
-- usage_seat_snapshots grain (daily)
-- ---------------------------------------------------------------------------

-- KPI: active seats. "Active" is `pending_cancellation_date IS NULL` (never the opaque
-- `seat_state` token), matching the seat query's `active_count` definition. Carries the full
-- dimension set the seat query can filter/group on (`seat_state`, `assignee_team`, `plan_type`,
-- `provider_user_id`) plus the three partition-disjoint seat counts, so the seat query endpoint
-- routes to this aggregate with no semantic change.
CREATE MATERIALIZED VIEW mv_seat_snapshots_active_daily AS
SELECT
    snapshot_day,
    source,
    subject_kind,
    subject_id,
    seat_state,
    assignee_team,
    plan_type,
    provider_user_id,
    COUNT(*) AS seat_count,
    COUNT(*) FILTER (WHERE pending_cancellation_date IS NULL) AS active_count,
    COUNT(*) FILTER (WHERE pending_cancellation_date IS NOT NULL) AS pending_cancellation_count
FROM usage_seat_snapshots
GROUP BY snapshot_day, source, subject_kind, subject_id, seat_state, assignee_team, plan_type, provider_user_id;

CREATE UNIQUE INDEX mv_seat_snapshots_active_daily_pk
    ON mv_seat_snapshots_active_daily (snapshot_day, source, subject_kind, subject_id, seat_state, assignee_team, plan_type, provider_user_id);

-- ---------------------------------------------------------------------------
-- Refresh bookkeeping
-- ---------------------------------------------------------------------------

-- The aggregate-refresh background job writes its last successful refresh here, so a test or an
-- operator can prove the refresh has run (the ticket's "refresh policies ... have demonstrably
-- run" acceptance criterion, on plain Postgres). `id BOOLEAN PRIMARY KEY DEFAULT TRUE` is the
-- single-row sentinel, the same shape `usage_retention_state` uses.
CREATE TABLE usage_aggregate_refresh_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE,
    last_refreshed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

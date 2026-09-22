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
-- The KPI measures and their single authoritative grain source. Only the day/seat grains are
-- aggregate-backed: the day-facts and seat query endpoints route to these views (raw fallback when
-- absent), and the execution/model-call endpoints span grains (executions + model_calls +
-- tool_calls), so per the "no aggregate spans grains" rule they are NOT aggregate-backed and read
-- raw -- there is deliberately no hourly aggregate on the execution/model-call grains, because no
-- query would read it (the #587 review's P2: a refreshed-but-never-read aggregate is dead weight).
--   * active users   -> usage_day_facts.total_active_users              (mv_day_facts_active_users_daily)
--   * acceptances    -> usage_day_facts.total_acceptances_count         (mv_day_facts_acceptances_daily)
--   * spend          -> usage_day_facts.cost_micro_usd                  (mv_day_facts_spend_daily)
--   * active seats   -> usage_seat_snapshots.pending_cancellation_date  (mv_seat_snapshots_active_daily)
--
-- Day/seat grains are bucketed DAILY (their natural granularity). A coarser query re-buckets the
-- view's bucket column; a finer query than the view's granularity is not representable and must
-- read raw.
--
-- Money discipline (ADR-0028 D0): NULL = unknown, never 0. Every spend aggregate carries BOTH the
-- `SUM(...)` of known costs (which is NULL when every row in the bucket is unknown — never coerced
-- to 0) AND a separate `unknown_cost_count` of the rows whose cost was NULL, so unknown-cost rows
-- are counted separately and never silently folded in as free.
--
-- REFRESH CONCURRENTLY safety (reviewed, no finding): each view's GROUP BY key is byte-for-byte the
-- same column list as its UNIQUE index key, so the index is a true uniqueness proof over the view's
-- rows -- a duplicate would require two rows equal on every group column, which GROUP BY collapses
-- into one. This holds even though several key columns are nullable: Postgres treats NULLs as
-- distinct in a plain index, but GROUP BY groups all NULLs together, so the distinct-NULL
-- combinations collapse and no duplicate key can arise. The index therefore stays a valid
-- `REFRESH MATERIALIZED VIEW CONCURRENTLY` uniqueness proof. Do not "fix" the index to add
-- `NULLS NOT DISTINCT` or to drop a nullable key column -- either would break the byte-for-byte
-- match with the GROUP BY key that makes the proof sound.
--
-- No `EXCEPTION WHEN OTHERS` (authz-migration skill Rule 5): a genuine failure aborts loudly. These
-- are plain-Postgres objects (no Timescale gating needed — unlike the hypertable blocks in the
-- day/seat migrations, which are gated because `create_hypertable` does not exist on vanilla
-- Postgres). Materialized views, unique indexes and `REFRESH ... CONCURRENTLY` are all vanilla
-- Postgres, so this migration applies unconditionally and is fully testable in CI.

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

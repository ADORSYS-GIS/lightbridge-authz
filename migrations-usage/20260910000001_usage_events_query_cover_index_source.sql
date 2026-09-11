-- #584: `source` is now a groupable/filterable dimension (UsageGroupBy::Source, and a
-- `WHERE source = …` filter), but the covering index the usage query was rewritten around
-- (`idx_usage_events_query_cover`, 20260903000002, #665) was built before the column existed
-- and does not INCLUDE it.
--
-- The covering index exists precisely so `build_usage_query` stays on an Index Only Scan and
-- never falls back onto the wide heap (measured there at 27 s / 3.17 GB off-index vs 105 MB
-- with every needed column covered, 20260903000002's own writeup). Every dimension added since
-- that index was built has had its own index/INCLUDE update land alongside it (e.g.
-- 20260902000003 for `azp`/`operation`/`billing_plan`); `source` is the first that did not.
--
-- This is a NEW migration, deliberately NOT an edit to 20260903000002:
--   - `20260903000002` predates this PR and is already applied + checksummed in every DB that
--     has run `main`; editing it would trip sqlx's checksum check and fail the next migrate
--     (ADR-0031 migrations-in-init-containers), and sqlx would not re-run it anyway.
--   - This file's `20260910` prefix places it after both `20260903000002` and this PR's own
--     `20260908000003` (the `source` column), so `source` exists before the index references it.
--
-- A plain `DROP INDEX` + `CREATE INDEX` (not CONCURRENTLY), for the same structural reasons
-- 20260903000002 states at length: sqlx applies a migration file as one multi-statement simple
-- query wrapped in an implicit transaction, which rejects CONCURRENTLY outright, and a failed
-- CONCURRENTLY build leaves an INVALID index that a re-run silently skips.
DROP INDEX IF EXISTS idx_usage_events_query_cover;
CREATE INDEX idx_usage_events_query_cover
    ON usage_events (observed_at)
    INCLUDE (
        account_id,
        project_id,
        api_key_id,
        user_id,
        user_name,
        model,
        metric_name,
        signal_type,
        source,
        azp,
        operation,
        billing_plan,
        request_count,
        usage_value,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        total_cost,
        latency_ms
    );

-- Refresh planner statistics so the recreated index is considered immediately (mirrors the tail
-- of 20260903000002).
ANALYZE usage_events;

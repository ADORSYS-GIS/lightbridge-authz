-- The `/usage/v1/usage/query` covering index (owner report, 2026-09-03: "requests made to the
-- query backend are very slow").
--
-- ## The measurement this index exists for
--
-- Taken read-only on the production replica (`lightbridge-main-db-2`, database `usage`,
-- PostgreSQL 18.4, 933,494 rows / 3,267 MB heap / 625 MB indexes, `shared_buffers = 128MB`,
-- `work_mem = 4MB`), for the console's estate-wide 30-day overview query:
--
--   Parallel Seq Scan on usage_events
--     Buffers: shared hit=3170 read=415026        <-- 3.17 GB, essentially all of it uncached
--     (actual time=99.381..27085.608)             <-- 27 s of the query's 31.8 s
--
-- The scan reads 3.17 GB to aggregate eighteen narrow columns, because those columns live in a
-- heap whose width is dominated by a column the query never touches. From `pg_stats` on the same
-- table:
--
--   attributes   avg_width 1445      <-- 87% of the row, never read by any query in repo.rs
--   every other column, summed        ~205 bytes
--
-- `attributes` averages 1,445 bytes and peaks at 2,084 -- just under the ~2 KB TOAST threshold --
-- so it is stored INLINE and every heap page holds ~4 rows instead of ~35. The usage query is
-- paying an 8x page-count tax for a write-only column.
--
-- This index carries the eighteen columns the query actually reads, keyed on the column every
-- query is bounded by. Measured on a 2M-row fixture built to production's width
-- (`.docker/it/seed-usage-perf-fixture.sql`): the index is 436 MB against a 3,906 MB heap, and the
-- estate-wide 30-day query goes from 279,627 buffers (2,185 MB, an index scan that still lands on
-- the heap for every row) to 13,436 buffers (105 MB, `Index Only Scan using
-- idx_usage_events_query_cover`) -- 20.8x fewer pages. The 7-day shape moves the same way, 57,951
-- -> 2,785 buffers. At production's shape (933k rows, ~205 bytes of payload per row) the index
-- lands around 215 MB against a 3,267 MB heap.
--
-- ## Why INCLUDE and not a composite key
--
-- The included columns are payload, not key: they are never used for ordering or for an index
-- condition, only to satisfy the query from the index alone. Putting them in the key would bloat
-- the internal pages, force them into every non-leaf tuple, and buy nothing -- the only predicate
-- this index serves is `observed_at >= $1 AND observed_at < $2`.
--
-- `attributes` is deliberately NOT included. Including it would reproduce the exact heap width
-- this index exists to escape, and no query in `crates/lightbridge-authz-usage/src/repo.rs`
-- selects it.
--
-- ## What this index does NOT do
--
-- An index-only scan still consults the visibility map, and a page that is not all-visible costs
-- a heap fetch anyway. `usage_events` is append-only apart from the one-off #648 backfill, so
-- autovacuum keeps almost all of it all-visible -- but a table that has just been mass-updated
-- (as this one was on 2026-09-02) will fall back to heap fetches until autovacuum catches up.
-- That is a transient cost, not a reason to skip the index.
--
-- BRIN on `observed_at` was measured as the alternative and rejected on the numbers. On the same
-- 2M-row production-width fixture, `USING brin (observed_at) WITH (pages_per_range=32)` builds a
-- 536 kB index -- and changes the estate-wide query's buffer count not at all:
--
--   no index at all                  279,627 buffers   (2,185 MB)
--   BRIN on observed_at              279,627 buffers   (2,185 MB)   <-- identical
--   this covering index               13,436 buffers   (  105 MB)   <-- 20.8x fewer
--
-- BRIN narrows WHICH heap pages are read; it cannot avoid reading the wide heap, which is the
-- entire problem here. For a range covering the whole retention window it narrows nothing at all.
--
-- NOT `CONCURRENTLY`, for the reasons `20260902000003_usage_event_dimensions_indexes.sql` states
-- at length: sqlx runs a migration file as one implicit transaction block, which rejects
-- `CREATE INDEX CONCURRENTLY` outright, and a failed `CONCURRENTLY` build leaves an INVALID index
-- that a re-run's `IF NOT EXISTS` then silently skips -- a migration that reports success while
-- the index it promised never comes into service. A plain build takes a SHARE lock that blocks
-- writes for the seconds it needs, and the only writer is an OTLP exporter that retries.
CREATE INDEX IF NOT EXISTS idx_usage_events_query_cover
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

-- Refresh the planner's statistics over the whole table. The #648 backfill
-- (`20260902000002`) rewrote nearly every row the day before this index was written, and stale
-- statistics are how a plan that should be an index-only scan ends up a sequential one.
ANALYZE usage_events;

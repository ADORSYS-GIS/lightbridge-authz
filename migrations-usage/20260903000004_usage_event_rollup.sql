-- AC2 (ADORSYS-GIS/lightbridge-authz#549): the retention/rollup path -- a daily rollup of
-- `usage_events`.
--
-- ## Why this table exists
--
-- `usage_events` grows ~100 MB/day with no retention (#549). The dashboard offers 7d/30d/90d
-- ranges, so 90 days of raw events is the product commitment; budget spend reads the current
-- billing period, which must never be truncated. The mechanism (per the ticket's audit: "date_bin
-- rollup tables plus a scheduled delete satisfy it", no hypertable needed on plain Postgres):
--
--   1. Raw `usage_events` is kept for a retention window (default 90 days, configurable).
--   2. A background job in the usage service periodically rolls rows OLDER than the window into
--      this daily aggregate table, then deletes them from `usage_events` -- in one transaction, so
--      a crash leaves no partial state and a re-run is idempotent.
--   3. `spend_for_account` reads `usage_events` UNION ALL `usage_events_daily`, so a spend query
--      is correct whether its rows are still raw or have aged into the rollup (AC3).
--
-- The rollup is keyed by the same dimensions `usage_events` carries (`account_id`, `project_id`,
-- `model`, `azp`, `operation`, `billing_plan`, ...) so it can serve the same group-by/filter
-- shapes the dashboard issues, and carries the same aggregate columns (`requests`, `usage_value`,
-- token sums, `total_cost`, `latency_samples`). It deliberately does NOT carry latency percentiles
-- -- an ordered-set aggregate cannot be exactly rolled up from daily sums -- so the dashboard's
-- 90-day window is served from raw (which is kept for exactly that window), and the rollup serves
-- long-term retention and spend. The rollup table is itself bounded: the retention job deletes
-- rolled-up days older than `retention.rollup_days` (default 365), so this table does not grow
-- without bound either.
--
-- ## Money semantics preserved
--
-- `usage_events.total_cost` is `NOT NULL DEFAULT 0` (since `20260320000001`), and ingest collapses
-- an unknown cost to `0.0` at write time, so `SUM(total_cost)` over raw rows is never NULL. The
-- rollup column is nullable only defensively (a rolled-up day with no raw rows would be NULL); the
-- rollup insert uses `SUM(total_cost)` (not `COALESCE(..., 0)`), so a rolled-up day with no cost
-- data stays NULL and `spend_for_account`'s `Spend::Known`/`Spend::Unavailable` split is unchanged
-- across the boundary. The `ON CONFLICT DO UPDATE` fold-in adds costs with a NULL-safe `COALESCE`
-- so a late row never turns a known sum into NULL.
--
-- ## The unique index and NULLs
--
-- The natural key is `(bucket_start, <dimensions>)`, and every dimension column is nullable. A
-- plain unique index on nullable columns would treat NULLs as distinct, so the same (day,
-- dimensions) group with a NULL dimension could be inserted twice. The unique index therefore
-- uses `NULLS NOT DISTINCT`, which makes NULLs compare equal for uniqueness purposes -- so a group
-- whose dimensions are all NULL is still unique per `bucket_start`. This prevents partial-day or
-- duplicate insertions if the job is interrupted or modified.
CREATE TABLE IF NOT EXISTS usage_events_daily (
    bucket_start TIMESTAMPTZ NOT NULL,
    account_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    user_id TEXT,
    user_name TEXT,
    model TEXT,
    metric_name TEXT,
    signal_type TEXT,
    azp TEXT,
    operation TEXT,
    billing_plan TEXT,
    requests BIGINT NOT NULL DEFAULT 0,
    usage_value DOUBLE PRECISION NOT NULL DEFAULT 0,
    prompt_tokens BIGINT,
    completion_tokens BIGINT,
    total_tokens BIGINT,
    total_cost DOUBLE PRECISION,
    latency_samples BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS usage_events_daily_natural_key
    ON usage_events_daily (
        bucket_start,
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
        billing_plan
    ) NULLS NOT DISTINCT;

CREATE INDEX IF NOT EXISTS idx_usage_events_daily_bucket_start
    ON usage_events_daily (bucket_start);

CREATE INDEX IF NOT EXISTS idx_usage_events_daily_account_time
    ON usage_events_daily (account_id, bucket_start);

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
-- long-term retention and spend.
--
-- ## Money semantics preserved
--
-- `total_cost` is nullable here, exactly as in `usage_events`: `SUM(total_cost)` over all-NULL
-- rows is NULL ("unknown"), never 0. The rollup insert uses `SUM(total_cost)` (not
-- `COALESCE(..., 0)`), so a rolled-up day with no cost data stays NULL and `spend_for_account`'s
-- `Spend::Known`/`Spend::Unavailable` split is unchanged across the boundary.
--
-- ## The unique index and NULLs
--
-- The natural key is `(bucket_start, <dimensions>)`, and every dimension column is nullable. A
-- plain unique index on nullable columns would treat NULLs as distinct. The unique index therefore 
-- maps NULL to the empty string via `COALESCE` -- safe because every real dimension value is 
-- non-empty (CUID2 ids, model names, the closed `operation` vocabulary). This prevents partial-day 
-- or duplicate insertions if the job is interrupted or modified.
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
        COALESCE(account_id, ''),
        COALESCE(project_id, ''),
        COALESCE(api_key_id, ''),
        COALESCE(user_id, ''),
        COALESCE(user_name, ''),
        COALESCE(model, ''),
        COALESCE(metric_name, ''),
        COALESCE(signal_type, ''),
        COALESCE(azp, ''),
        COALESCE(operation, ''),
        COALESCE(billing_plan, '')
    );

CREATE INDEX IF NOT EXISTS idx_usage_events_daily_bucket_start
    ON usage_events_daily (bucket_start);

CREATE INDEX IF NOT EXISTS idx_usage_events_daily_account_time
    ON usage_events_daily (account_id, bucket_start);

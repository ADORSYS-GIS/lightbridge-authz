-- #549 P2: persist the last successful retention purge cutoff so `/usage/v1/usage/query` can
-- report `truncated` from what the retention job actually purged, not from the wall clock at query
-- time.
--
-- A single-row table (id is always TRUE, CHECK-enforced) holding the day-truncated cutoff of the
-- most recent successful rollup+purge run. It is empty until the job first runs; `last_purge_cutoff`
-- is the `date_trunc('day', now() - raw_days)` boundary the run actually purged up to. The query
-- handler reads this row and flags a range truncated only when its `start_time` predates this
-- persisted cutoff -- which eliminates the daily false-positive window where a cutoff recomputed
-- from `Utc::now()` at query time has advanced past what the job has actually purged.
CREATE TABLE usage_retention_state (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    last_purge_cutoff TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A3 (#648): the usage dimensions bridge -- step 3 of 3, the indexes.
--
-- Deliberately LAST, after `20260902000002`'s backfill: an index built before the backfill would
-- be maintained row-by-row through every one of those UPDATEs and then be bloated by them, so it
-- is built once, over final data, instead.
--
-- Shape `(<dimension>, observed_at DESC)`, matching the four dimension indexes this table already
-- carries (`idx_usage_events_account_time` and friends, `20260223000001` / `20260506000001`):
-- every query this store serves is time-bounded first (`observed_at >= $1 AND observed_at < $2`)
-- and then grouped or filtered by a dimension, so the dimension leads and the time column orders
-- within it.
--
-- NOT `CONCURRENTLY`, stated rather than quietly skipped. Two reasons, both structural:
-- (1) sqlx applies a migration file as one multi-statement simple query, which Postgres wraps in
-- an implicit transaction block -- `CREATE INDEX CONCURRENTLY` is rejected outright there, and
-- splitting into three one-statement `-- no-transaction` files would only buy it at the cost of
-- (2): a `CONCURRENTLY` build that fails leaves behind an INVALID index that a re-run's
-- `IF NOT EXISTS` then silently skips, so the migration reports success while the index it
-- promised never comes into service. That is exactly the silent-wrongness failure mode this
-- store's migration doctrine (#581: "no `EXCEPTION WHEN OTHERS`; the migration fails loudly")
-- exists to refuse. A plain build takes a SHARE lock that blocks writes for the seconds it needs
-- on a ~1.3M-row table, and the only writer is an OTLP exporter that retries.
CREATE INDEX IF NOT EXISTS idx_usage_events_azp_time ON usage_events (azp, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_operation_time ON usage_events (operation, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_billing_plan_time ON usage_events (billing_plan, observed_at DESC);

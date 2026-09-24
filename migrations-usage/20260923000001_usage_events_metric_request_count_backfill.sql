-- no-transaction
-- Data repair for the `request_count` bug fixed alongside this migration in
-- `crates/lightbridge-authz-usage/src/handlers/ingest.rs` (`number_data_point_to_event`):
-- every Gauge/Sum metric data point had its `request_count` derived from the metric's own raw
-- VALUE (`request_count_from_metric_value`) instead of counting one per data point, the way the
-- histogram/summary/exponential-histogram paths in the same file already did (`count.max(1)`).
--
-- Found live 2026-09-23 via the Console's Usage page: the "Unassigned" channel (rows with no
-- `azp`, i.e. local CLI-tool telemetry that never goes through an OAuth client) showed 31.2
-- BILLION "requests". Traced to `claude_code.token.usage` -- a TOKEN COUNTER, not a request
-- counter -- whose (apparently cumulative) raw value was summed straight into `request_count` on
-- every ~30s export tick. `usage_value`/`total_cost` were never affected: this is purely a
-- `request_count` data-integrity bug, on the `metric` signal only.
--
-- Verified against production before writing this file (see the PR body for the exact queries):
-- EVERY `usage_events` row with `signal_type = 'metric'` comes from exactly three CLI-tool
-- integrations (`claude-code`, `opencode`, `github-copilot`); the real, billed API-gateway traffic
-- (`source = 'eaig'`) is 100% `signal_type = 'log'` and carries none of this corruption --
-- `log`-signal rows already hardcode `request_count: 1` at ingest and are untouched here. None of
-- the three CLI tools' metric names correspond to a genuine OTel Histogram/Summary in this data
-- (every one is a plain Gauge/Sum counter or duration reading), so there is no legitimate
-- per-bucket sample count anywhere in the `metric` signal that this backfill could be flattening
-- by mistake -- resetting every `metric`-signal row to `request_count = 1` is not a heuristic
-- guess here, it is what EVERY one of these rows should already say.
--
-- BATCHED, ONE TRANSACTION PER BATCH, same shape as
-- `migrations-usage/20260902000002_usage_event_dimensions_backfill.sql` (authz-migration skill
-- Rule 4): `-- no-transaction` so the `DO` block's internal `COMMIT`s are legal, 10 000 rows of
-- `id` range per batch so autovacuum can reclaim dead tuples as it goes instead of holding them
-- until one giant UPDATE finishes, and a killed/resumed run is free because the `WHERE` clause
-- only ever touches rows still needing the fix.
DO $$
DECLARE
    batch_size CONSTANT bigint := 10000;
    lo bigint;
    hi bigint;
    max_id bigint;
BEGIN
    SELECT COALESCE(MIN(id), 0), COALESCE(MAX(id), -1)
    INTO lo, max_id
    FROM usage_events
    WHERE signal_type = 'metric';

    WHILE lo <= max_id LOOP
        hi := lo + batch_size;

        UPDATE usage_events
        SET request_count = 1
        WHERE id >= lo
          AND id < hi
          AND signal_type = 'metric'
          AND request_count <> 1;

        COMMIT;

        lo := hi;
    END LOOP;
END $$;

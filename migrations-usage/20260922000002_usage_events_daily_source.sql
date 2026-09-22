-- Companion to 20260922000001 (request dedup) for the same governance#358 gap: the daily
-- rollup (20260903000004_usage_event_rollup.sql) predates `usage_events.source`
-- (20260908000003) and never carries it forward, so once IDE-sourced rows exist and age past
-- `raw_days`, a rolled-up day silently merges EAIG spend with Claude Code / Codex / OpenCode
-- spend into one row -- exactly the double-billing risk ADR-0028 flags and governance#358 calls
-- out ("without duplicating gateway/IDE billing"). Today this is latent, not yet triggered: the
-- IDE ingest leg is not live, so every existing rollup row is 100% EAIG in substance.
--
-- Column is added nullable, matching `usage_events.source`'s own precedent -- a rolled-up day
-- from before source-tracking existed carries no source identity, and NULL is the honest value
-- for that (never backfilled to 'eaig', for the same reason `usage_events.source` isn't
-- backfilled: that would assert data the table never actually recorded). `spend_for_account`
-- (see the same-day code change) treats NULL as EAIG-equivalent for exactly this reason -- it is
-- the only source that ever existed before source-tracking shipped, so "unknown" and "eaig" are
-- the same population for every pre-existing row.
--
-- The unique index is replaced (not just extended) because a nullable column is already part of
-- the natural key and `NULLS NOT DISTINCT` must cover it identically to every other dimension --
-- see the original migration's "The unique index and NULLs" note. Take the SHARE lock, same as
-- 20260922000001: CONCURRENTLY is incompatible with the migrator transaction and this table is
-- the small daily aggregate, not the high-volume raw table.
ALTER TABLE usage_events_daily ADD COLUMN IF NOT EXISTS source TEXT;

DROP INDEX IF EXISTS usage_events_daily_natural_key;

CREATE UNIQUE INDEX IF NOT EXISTS usage_events_daily_natural_key
    ON usage_events_daily (
        bucket_start,
        source,
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

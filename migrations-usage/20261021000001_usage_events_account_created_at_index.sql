-- ADR-0035 D6 (lightbridge-authz): settlement reads an account's spend by INGESTION time,
-- `created_at`, so a late-arriving event can never land behind the settlement watermark. Every
-- existing index is keyed on `observed_at`, so without this a settlement window query would scan
-- the account's whole raw retention window. The window query also bounds `observed_at` from
-- below, so a Timescale-partitioned table can still skip old chunks.
CREATE INDEX IF NOT EXISTS idx_usage_events_account_created_at
    ON usage_events (account_id, created_at);

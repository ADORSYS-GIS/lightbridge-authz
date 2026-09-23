-- Expand-only request dedup prerequisite for governance#358 / ADR-0028 D22.
-- Existing rows deliberately remain NULL: their request IDs were never persisted,
-- so a trustworthy historical key cannot be reconstructed from aggregate measures.
-- Deploy this schema before a receiver that writes dedup_key (ADR-0031).
-- Same ADR-0038 exception as usage_events: composite time-series upserts are not
-- expressible through the generated CRUD client. No new persistence dependency.
ALTER TABLE usage_events ADD COLUMN dedup_key TEXT;
COMMENT ON COLUMN usage_events.dedup_key IS
    'Natural request key scoped by authenticated account/user. NULL means legacy/no stable key; never a hash of content.';
-- Take the SHARE lock: CONCURRENTLY is incompatible with the migrator transaction
-- and can leave an invalid index after failure. Exporters must retry during the lock.
-- Includes observed_at so the key remains compatible with a Timescale partition.
CREATE UNIQUE INDEX usage_events_request_dedup
    ON usage_events (observed_at, source, dedup_key);

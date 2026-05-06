ALTER TABLE usage_events ADD COLUMN IF NOT EXISTS api_key_id TEXT;
ALTER TABLE usage_events ADD COLUMN IF NOT EXISTS user_name TEXT;

CREATE INDEX IF NOT EXISTS idx_usage_events_api_key_time ON usage_events (api_key_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_user_name_time ON usage_events (user_name, observed_at DESC);

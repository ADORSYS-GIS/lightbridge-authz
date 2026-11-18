-- Additive request-grain extension (ADR-0038 time-series exception).
-- Deploy this migration before the reader/writer release. No historical values are invented.
ALTER TABLE usage_events
    ADD COLUMN cached_tokens BIGINT CHECK (cached_tokens >= 0),
    ADD COLUMN reasoning_tokens BIGINT CHECK (reasoning_tokens >= 0);
ALTER TABLE usage_events_daily
    ADD COLUMN cached_tokens BIGINT CHECK (cached_tokens >= 0),
    ADD COLUMN reasoning_tokens BIGINT CHECK (reasoning_tokens >= 0);
COMMENT ON COLUMN usage_events.cached_tokens IS 'Reported cache-read input tokens, included in prompt_tokens. NULL means unavailable.';
COMMENT ON COLUMN usage_events.reasoning_tokens IS 'Reported reasoning output tokens, included in completion_tokens. NULL means unavailable.';
COMMENT ON COLUMN usage_events_daily.cached_tokens IS 'Sum only when every contributing event reports cached tokens; otherwise NULL.';
COMMENT ON COLUMN usage_events_daily.reasoning_tokens IS 'Sum only when every contributing event reports reasoning tokens; otherwise NULL.';

-- Additive request-grain extension (ADR-0038 time-series exception).
-- Deploy this migration before the reader/writer release. No historical values are invented.
-- The checks are NOT VALID: they bind every row written from now on, and the rows that exist are
-- all NULL, so validating them would only hold an exclusive lock over a full scan of the table
-- while ingest waits.
ALTER TABLE usage_events
    ADD COLUMN cached_tokens BIGINT,
    ADD COLUMN reasoning_tokens BIGINT;
ALTER TABLE usage_events
    ADD CONSTRAINT usage_events_cached_tokens_nonnegative CHECK (cached_tokens >= 0) NOT VALID,
    ADD CONSTRAINT usage_events_reasoning_tokens_nonnegative CHECK (reasoning_tokens >= 0) NOT VALID;
ALTER TABLE usage_events_daily
    ADD COLUMN cached_tokens BIGINT,
    ADD COLUMN reasoning_tokens BIGINT;
ALTER TABLE usage_events_daily
    ADD CONSTRAINT usage_events_daily_cached_tokens_nonnegative CHECK (cached_tokens >= 0) NOT VALID,
    ADD CONSTRAINT usage_events_daily_reasoning_tokens_nonnegative CHECK (reasoning_tokens >= 0) NOT VALID;
COMMENT ON COLUMN usage_events.cached_tokens IS 'Reported cache-read input tokens, included in prompt_tokens. NULL means unavailable.';
COMMENT ON COLUMN usage_events.reasoning_tokens IS 'Reported reasoning output tokens, included in completion_tokens. NULL means unavailable.';
COMMENT ON COLUMN usage_events_daily.cached_tokens IS 'Sum over the events that report input tokens, only when each of them also reports cached tokens; otherwise NULL.';
COMMENT ON COLUMN usage_events_daily.reasoning_tokens IS 'Sum over the events that report output tokens, only when each of them also reports reasoning tokens; otherwise NULL.';

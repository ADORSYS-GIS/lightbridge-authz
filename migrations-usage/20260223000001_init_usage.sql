CREATE TABLE IF NOT EXISTS usage_events (
    id BIGSERIAL PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    signal_type TEXT NOT NULL,
    account_id TEXT,
    project_id TEXT,
    user_id TEXT,
    model TEXT,
    metric_name TEXT,
    usage_value DOUBLE PRECISION NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 1,
    prompt_tokens BIGINT,
    completion_tokens BIGINT,
    total_tokens BIGINT,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_events_observed_at ON usage_events (observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_account_time ON usage_events (account_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_project_time ON usage_events (project_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_user_time ON usage_events (user_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_events_model_time ON usage_events (model, observed_at DESC);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;

        BEGIN
            PERFORM create_hypertable('usage_events', 'observed_at', if_not_exists => TRUE, migrate_data => TRUE);
        EXCEPTION
            WHEN undefined_function THEN
                BEGIN
                    PERFORM create_hypertable('usage_events', by_range('observed_at'), if_not_exists => TRUE, migrate_data => TRUE);
                EXCEPTION
                    WHEN OTHERS THEN
                        RAISE NOTICE 'Unable to create usage_events hypertable (new signature): %', SQLERRM;
                END;
            WHEN OTHERS THEN
                RAISE NOTICE 'Unable to create usage_events hypertable (legacy signature): %', SQLERRM;
        END;

        BEGIN
            PERFORM add_retention_policy('usage_events', INTERVAL '30 days', if_not_exists => TRUE);
        EXCEPTION
            WHEN undefined_function THEN
                BEGIN
                    PERFORM add_retention_policy('usage_events', INTERVAL '30 days');
                EXCEPTION
                    WHEN duplicate_object THEN
                        NULL;
                    WHEN OTHERS THEN
                        RAISE NOTICE 'Unable to configure usage_events retention policy (legacy signature): %', SQLERRM;
                END;
            WHEN OTHERS THEN
                RAISE NOTICE 'Unable to configure usage_events retention policy: %', SQLERRM;
        END;
    END IF;
END $$;

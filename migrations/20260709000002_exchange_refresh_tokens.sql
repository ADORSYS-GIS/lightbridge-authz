CREATE TABLE exchange_refresh_tokens (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    account_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_exchange_refresh_tokens_subject_project
    ON exchange_refresh_tokens (subject, project_id);
CREATE INDEX idx_exchange_refresh_tokens_expires_at
    ON exchange_refresh_tokens (expires_at);

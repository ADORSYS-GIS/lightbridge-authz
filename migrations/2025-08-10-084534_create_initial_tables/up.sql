-- Migration: create acls, api_keys and acl_models tables used by lightbridge-authz-api-key
CREATE TABLE acls (
    id TEXT PRIMARY KEY,
    rate_limit_requests INTEGER NOT NULL,
    rate_limit_window INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    metadata JSONB,
    status TEXT NOT NULL,
    acl_id TEXT NOT NULL,
    CONSTRAINT fk_acl FOREIGN KEY (acl_id) REFERENCES acls(id) ON DELETE CASCADE
);

CREATE TABLE acl_models (
    acl_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    token_limit BIGINT NOT NULL,
    PRIMARY KEY (acl_id, model_name),
    CONSTRAINT fk_acl_model FOREIGN KEY (acl_id) REFERENCES acls(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at);

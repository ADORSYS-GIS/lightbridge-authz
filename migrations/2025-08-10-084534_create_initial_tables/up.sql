-- Migration: create acls, api_keys and acl_models tables used by lightbridge-authz-api-key
CREATE TABLE acls (
    id TEXT PRIMARY KEY,
    api_key_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    metadata JSONB
);

CREATE TABLE acl_models (
    id TEXT PRIMARY KEY,
    model TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_acl_models_model ON acl_models(model);

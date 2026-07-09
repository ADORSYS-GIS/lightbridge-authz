CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'RS256',
    private_key_pem TEXT NOT NULL,
    public_jwk JSONB NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_signing_keys_single_active ON signing_keys (status) WHERE status = 'active';
CREATE INDEX idx_signing_keys_created_at ON signing_keys (created_at);

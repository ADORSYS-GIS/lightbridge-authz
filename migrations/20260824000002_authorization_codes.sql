-- ADR-0019 / #425: short-lived, single-use authorization codes for the browser authorization
-- code flow. This is an ADR-0038 persistence exception: redemption requires a single-statement
-- CAS so concurrent requests can never both obtain the same grant.
CREATE TABLE authorization_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    identity JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT authorization_codes_pkce_pair CHECK (
        (code_challenge IS NULL AND code_challenge_method IS NULL) OR
        (code_challenge IS NOT NULL AND code_challenge_method = 'S256')
    )
);

CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes (expires_at);

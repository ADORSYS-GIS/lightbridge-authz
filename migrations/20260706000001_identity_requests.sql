CREATE TABLE identity_requests (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    client_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_identity_requests_subject ON identity_requests(subject);
CREATE INDEX IF NOT EXISTS idx_identity_requests_project_id ON identity_requests(project_id);

ALTER TABLE signing_keys ADD COLUMN purpose TEXT NOT NULL DEFAULT 'access';

DROP INDEX idx_signing_keys_single_active;
CREATE UNIQUE INDEX idx_signing_keys_single_active ON signing_keys (status, purpose) WHERE status = 'active';

-- GHSA-9pc6-965v-2c44 / #538: single-use, subject-bound claims for handing an API key secret to
-- a human without routing it through a model's context.
--
-- This is an ADR-0038 persistence exception, for the same reason `authorization_codes` is one:
-- redemption requires a single-statement CAS so that concurrent requests can never both obtain
-- the same secret. Generated CRUD cannot express "claim exactly once".
--
-- Postgres rather than Redis deliberately. `lightbridge-mcp` is the component that issues these
-- claims, and it is explicitly and permanently freed from the Redis requirement (AGENTS.md,
-- "Redis is a mandatory dependency for authz-api / authz-idp / authz-budget" -- `-mcp` and `-opa`
-- take no `redis` parameter at all). It already holds a database handle, so the claim lives where
-- the issuer can reach it without reintroducing the dependency that rule exists to keep out.
--
-- `subject` is stored so redemption can filter on it IN THE SAME STATEMENT that consumes the row
-- (see `consume_secret_claim`). That is what makes a wrong-subject attempt fail WITHOUT burning
-- the claim: the row never matches, so `consumed_at` is never set, and the legitimate owner can
-- still collect. Checking the subject after consuming would let anyone holding the token --
-- including the model it was handed through -- destroy the owner's one chance at their key.
--
-- `sealed_secret` is an AES-256-GCM envelope whose associated data is the same `subject`, so the
-- SQL filter is backed by a cryptographic binding rather than replacing it.
CREATE TABLE secret_claims (
    id TEXT PRIMARY KEY,
    -- SHA-256 of the claim token, never the token itself: a dump of this table must not be a
    -- dump of usable claim tokens, exactly as `api_keys` stores only `key_hash`.
    token_hash TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    sealed_secret TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

-- Supports both the expiry predicate in `consume_secret_claim` and any periodic purge of
-- long-dead rows.
CREATE INDEX idx_secret_claims_expires_at ON secret_claims (expires_at);

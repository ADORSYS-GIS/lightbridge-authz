-- Take migration ownership of the two tables cratestack bootstraps lazily at runtime:
-- `cratestack_audit` and `cratestack_idempotency`.
--
-- WHY: `CREATE TABLE IF NOT EXISTS` is NOT atomic across sessions. The existence check and the
-- creation are separate steps, so two backends can both pass the check and the loser fails on the
-- system catalog's own unique index instead of skipping. Captured from a real Postgres 17 server
-- log while reproducing lightbridge-authz#684 (see that ticket for the full repro loop):
--
--     ERROR:  23505: duplicate key value violates unique constraint "pg_type_typname_nsp_index"
--     DETAIL:  Key (typname, typnamespace)=(cratestack_audit, 2200) already exists.
--     STATEMENT:  CREATE TABLE IF NOT EXISTS cratestack_audit ( ... );
--
-- That error reaches the caller as `CratestackError::Database`, which the RPC surface renders as an
-- opaque `500 {code: "internal", message: "internal error"}` with the cause discarded — nothing on
-- the create path logs it.
--
-- WHO RACES:
--
-- * `cratestack_audit` — `ensure_audit_table` (cratestack-sqlx 0.11.0 `src/audit/schema.rs:53-69`)
--   runs the DDL on the FIRST audited write of each `SqlxRuntime`, cached on a per-instance
--   `AtomicBool`. Every `@@audit` model's create/update/delete goes through it, so on a fresh
--   database any two concurrent first writes race. In this repo that is `Account`, `Project` and
--   `ApiKey`. The crate's own comment (`src/audit/schema.rs:58-62`) claims the block "stays safe
--   under concurrent first-runs" because the sub-statements are `IF NOT EXISTS`; the log above is
--   that claim failing. Not reported upstream from here -- cratestack is pinned from crates.io at
--   `=0.11.0` and nothing in this repo can patch it, so this migration is the fix that is available.
--
-- * `cratestack_idempotency` — `SqlxIdempotencyStore::ensure_schema()` (same crate,
--   `src/idempotency.rs:34-43`) runs the identical shape at server startup. `authz-api` and
--   `authz-budget` each call it, so two replicas coming up together against a fresh database race
--   the same way, and a loser fails to start rather than serving a 500.
--
-- Once these tables exist, both DDL blocks are permanent no-ops and there is nothing left to race.
-- Both call sites are therefore removed in the same change: the startup `ensure_schema()` calls in
-- `crates/lightbridge-authz-rest/src/lib.rs`, and the per-binary `OnceCell` guards the it-tests
-- carried to work around the idempotency half. `ensure_audit_table` is `pub(crate)` upstream and
-- cannot be removed from here; it stays, and is now always a no-op.
--
-- OWNERSHIP: this is ADR-0003's "Migration ownership — REVISED after the spike" applied to the two
-- tables it did not name. cratestack does not own DDL in this repo; hand-written SQLx does. The
-- statements below are copied VERBATIM from the crate's own `AUDIT_TABLE_DDL` and
-- `IDEMPOTENCY_TABLE_DDL` constants, and `app/lightbridge-authz/tests/cratestack_bootstrap_ddl_sync_tests.rs`
-- fails the build if a cratestack bump changes the audit constant out from under this file.
--
-- DRIFT is not a new risk introduced here: `IF NOT EXISTS` already skipped a changed definition on
-- every database where the table was created by an earlier cratestack version. Owning the DDL only
-- moves that silent skip somewhere a test can see it.
--
-- Idempotent on every existing database: each statement is `IF NOT EXISTS`, so a deployment whose
-- tables were already bootstrapped at runtime applies this as a no-op.

-- Verbatim from `cratestack_sqlx::AUDIT_TABLE_DDL` (cratestack-sqlx 0.11.0).
CREATE TABLE IF NOT EXISTS cratestack_audit (
    event_id UUID PRIMARY KEY,
    schema_name TEXT NOT NULL,
    model TEXT NOT NULL,
    operation TEXT NOT NULL,
    primary_key JSONB NOT NULL,
    actor JSONB NOT NULL,
    tenant TEXT,
    before JSONB,
    after JSONB,
    request_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    attempts BIGINT NOT NULL DEFAULT 0,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS cratestack_audit_model_idx
    ON cratestack_audit (schema_name, model, occurred_at DESC);

CREATE INDEX IF NOT EXISTS cratestack_audit_tenant_idx
    ON cratestack_audit (tenant, occurred_at DESC)
    WHERE tenant IS NOT NULL;

CREATE INDEX IF NOT EXISTS cratestack_audit_undelivered_idx
    ON cratestack_audit (occurred_at)
    WHERE delivered_at IS NULL;

-- Verbatim from `cratestack_sql::IDEMPOTENCY_TABLE_DDL` (cratestack-sql 0.11.0, reached through
-- cratestack-sqlx 0.11.0). Unlike the audit constant this one is not re-exported through
-- `cratestack-pg`, so the sync test below cannot assert on it -- see that file's own comment.
CREATE TABLE IF NOT EXISTS cratestack_idempotency (
    principal_fingerprint TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    reservation_id UUID NOT NULL,
    response_status INT,
    response_headers BYTEA,
    response_body BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (principal_fingerprint, key)
);

CREATE INDEX IF NOT EXISTS cratestack_idempotency_expires_idx
    ON cratestack_idempotency (expires_at);

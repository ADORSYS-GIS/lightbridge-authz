-- Refresh-token reuse GRACE WINDOW (bounded idempotent replay), added in direct response to a
-- real production incident: 2026-08-30, the console (2 replicas, each running its own in-memory,
-- per-pod refresh single-flight) raced its own token refresh -- one pod rotated the refresh token
-- it was presented, the other pod replayed the very same, now-superseded, pre-rotation token
-- seconds later. `revoke_chain_on_reuse` (this table's strict RFC 6819 §5.2.2.3 reuse-detection
-- cascade, added by `20260815000001_exchange_refresh_tokens_add_chain.sql`) treated that replay
-- exactly like a stolen token and revoked the WHOLE chain -- the user's own session died with
-- intermittent 401s, even though nothing was actually stolen; both pods were the same
-- already-authenticated client. Log line observed in production:
-- "refresh token reuse detected (an already-rotated token was replayed); revoking its chain".
--
-- Standard OAuth practice for exactly this race (Keycloak's "revoke refresh token: max reuse",
-- Auth0's reuse interval) is a short grace window after rotation during which a replay of the
-- token just rotated is NOT treated as theft. See
-- `TokenExchangeOpStore::classify_replayed_refresh_token`'s doc comment in
-- `crates/lightbridge-authz-rest/src/oauth2_op/store.rs` for the full design -- in particular why
-- a graced replay mints a BRAND NEW successor rather than replaying the first rotation's response:
-- only `token_hash` is ever persisted (never plaintext), so the first successor's plaintext
-- refresh token cannot be reconstructed and reissued to the second caller.
ALTER TABLE exchange_refresh_tokens
    -- When this row's single-use CAS consume (`consume_exchange_refresh_token`) flipped it from
    -- `active` to `rotated`. NULL for a row that has never been rotated, and for every row already
    -- `rotated` before this migration runs (no truthful value to backfill -- their rotation
    -- moment was never recorded). `classify_replayed_refresh_token` treats a NULL `rotated_at` as
    -- OUTSIDE the grace window (fail closed: cascade, exactly today's pre-migration behavior),
    -- never as "always graced".
    ADD COLUMN rotated_at TIMESTAMPTZ,
    -- The id of the row this one was rotated into, written atomically with `rotated_at` in the
    -- same `UPDATE ... SET status = 'rotated', rotated_at = $2, successor_id = $3` statement (the
    -- caller generates that id BEFORE calling `consume_exchange_refresh_token`, specifically so it
    -- can be recorded here instead of only existing after a second, separate `INSERT`).
    --
    -- Deliberately NOT a foreign key: `consume_exchange_refresh_token` (this UPDATE) and
    -- `create_exchange_refresh_token` (the INSERT that actually creates the row `successor_id`
    -- names) are two separate, non-transactional statements -- see
    -- `TokenExchangeOpStore::handle_refresh_token`'s doc comment -- so at the instant the UPDATE
    -- commits, the row `successor_id` points at does not exist yet, and a FK would reject the
    -- write outright. Informational lineage only (audit/tracing); no reuse-detection logic reads
    -- it back today. A graced replay mints its OWN new successor as a second live leaf off the
    -- replayed row without overwriting this column, so within the grace window this may name only
    -- the FIRST of more than one successor a chain briefly has.
    ADD COLUMN successor_id TEXT;

-- The grace-window read is `status = 'rotated' AND rotated_at > now() - grace_interval`, always
-- keyed off the same `token_hash` lookup `find_exchange_refresh_token_by_hash` already does (that
-- column is already UNIQUE, so this adds no new hot-path index). This index exists for
-- operator/audit queries ("which rotated tokens are still inside their grace window right now")
-- without a sequential scan.
CREATE INDEX idx_exchange_refresh_tokens_status_rotated_at
    ON exchange_refresh_tokens (status, rotated_at);

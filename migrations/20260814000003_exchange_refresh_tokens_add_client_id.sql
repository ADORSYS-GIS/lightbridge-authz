-- ADR-0011 phase 2: refresh tokens are now issued to a specific registered client
-- (authkestra-op's RefreshTokenStore binds client_id at issuance and checks it again at refresh
-- time), so a refresh token presented by a different client than the one it was issued to must be
-- rejected -- the same `old_rt.client_id != client_id` check authkestra-op's own
-- default_handle_refresh_token hard-codes upstream.
--
-- Existing rows predate the client concept entirely, so there is no meaningful value to backfill.
-- Defaulting them to '' (never a valid registered client_id, since real client ids are
-- operator-configured strings) makes any pre-phase-2 refresh token fail the client-binding check
-- on its next use rather than being silently attributable to whichever client happens to ask --
-- a safe, self-invalidating cutover, not a backfill.
ALTER TABLE exchange_refresh_tokens
    ADD COLUMN client_id TEXT NOT NULL DEFAULT '';

ALTER TABLE exchange_refresh_tokens
    ALTER COLUMN client_id DROP DEFAULT;

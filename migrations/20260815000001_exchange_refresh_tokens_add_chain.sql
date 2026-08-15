-- Refresh-token family (RFC 6819 §5.2.2.3 reuse-detection cascade) + an absolute session cap.
--
-- chain_id: shared by every token minted across one rotation chain, starting at the
-- offline_access exchange grant that gave birth to it and inherited unchanged by every
-- subsequent rotation. Lets a replay of a superseded (already-rotated) token revoke the WHOLE
-- chain in one UPDATE, not just the replayed row -- closing the gap where a stolen-and-rotated
-- refresh token left its live successor untouched.
--
-- chain_expires_at: an absolute deadline set once, when the chain is born, and inherited
-- unchanged by every rotation thereafter. Without this, refreshing before every individual
-- token's `expires_at` gives an unbounded session -- each rotation only ever resets the
-- per-token TTL, never a session-level ceiling. This is that ceiling.
--
-- ADR-0038 exception note: `exchange_refresh_tokens` is already a documented hand-written-SQL
-- exception (CAS rotation via `UPDATE ... WHERE status = 'active' ... RETURNING`, not migratable
-- to cratestack -- see AGENTS.md's "Persistence" section). Extending it here with more
-- hand-written SQL is consistent with that existing, scoped exception, not a new one.
--
-- Prod blast radius: this runs against a live database carrying real, still-refreshable
-- sessions. The backfill below gives every existing row its own single-member chain
-- (`chain_id = id`) and a cap dated from its ORIGINAL creation, not from today
-- (`chain_expires_at = created_at + 90 days`) -- an old session is exactly as close to its cap as
-- it always implicitly should have been; it simply had no cap enforced until now. No existing
-- session is invalidated by running this migration alone. Some may already be past their
-- (backdated) cap and will fail their next refresh with invalid_grant -- that is the intended
-- effect of adding a cap, not a migration bug.
ALTER TABLE exchange_refresh_tokens
    ADD COLUMN chain_id TEXT,
    ADD COLUMN chain_expires_at TIMESTAMPTZ;

UPDATE exchange_refresh_tokens
SET chain_id = id,
    chain_expires_at = created_at + INTERVAL '90 days'
WHERE chain_id IS NULL;

ALTER TABLE exchange_refresh_tokens
    ALTER COLUMN chain_id SET NOT NULL,
    ALTER COLUMN chain_expires_at SET NOT NULL;

-- The cascade-revoke-on-reuse query is `UPDATE ... WHERE chain_id = $1 AND status = 'active'`.
CREATE INDEX idx_exchange_refresh_tokens_chain_id_status
    ON exchange_refresh_tokens (chain_id, status);

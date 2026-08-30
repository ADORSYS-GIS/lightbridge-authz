-- Sibling of `20260814000002_exchange_refresh_tokens_add_identity_snapshot.sql`, which added
-- `email`/`email_verified`/`auth_time` so the refresh grant could re-mint symmetrically with the
-- original exchange grant instead of dropping them. `preferred_username`/`name` are the same
-- profile-claim snapshot, just added a cycle later (they were only just wired into `KeyOwner` --
-- see `signing::KeyOwner`): without these two columns a refresh-token rotation would silently
-- drop `preferred_username`/`name` even though the *initial* token in the chain carried them,
-- reintroducing the exact "mint_from_refresh drops claims the original grant had" class of bug
-- that migration's own doc comment describes for email.
--
-- Nullable, no backfill -- same reasoning as the email/email_verified/auth_time columns already
-- on this table: every pre-existing row predates these claims being captured at all, and there is
-- no truthful value to invent for them.
ALTER TABLE exchange_refresh_tokens
    ADD COLUMN preferred_username TEXT,
    ADD COLUMN name TEXT;

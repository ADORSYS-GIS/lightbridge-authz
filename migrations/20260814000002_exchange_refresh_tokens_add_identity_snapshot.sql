-- ADR-0011: the refresh grant re-mints access + id_token symmetrically with the original
-- exchange grant, which requires a snapshot of the upstream subject_token's email/email_verified/
-- auth_time at the moment the refresh-token session was created (mint_from_refresh previously
-- hardcoded these to None on every refresh -- the bug this migration lets the code fix).
--
-- nonce is deliberately NOT added here: it binds an id_token to the authorization request that
-- produced it, and a refresh presents no such request to bind a re-minted id_token to.
ALTER TABLE exchange_refresh_tokens
    ADD COLUMN email TEXT,
    ADD COLUMN email_verified BOOLEAN,
    ADD COLUMN auth_time BIGINT;

-- ADR-0024 Q2 already establishes that "plaintext, queryable metadata sits alongside the sealed
-- blob" (`issuer`, `subject`, `scope`, `access_expires_at`, `refresh_expires_at`,
-- `token_sealed_at`, `last_authenticated_at`) -- none of that is a bearer-equivalent credential,
-- so none of it needs AES-256-GCM sealing. `email`/`email_verified`/`preferred_username`/`name`
-- are exactly the same class of data: identity claims about the person, not secrets. Today they
-- are captured off Keycloak's id-token (`relying_party::persist_federated_identity`) and sealed
-- INSIDE `token_envelope` as part of `IdTokenClaimsSnapshot` -- fine for `end_upstream_session`
-- (the envelope's only production reader so far, which already holds the decryption key), but
-- useless for token *minting*: `oauth2_op::store::TokenExchangeOpStore` (the browser
-- `authorization_code` grant's minting path) holds no `token_encryption_key` and has no reason to
-- gain one just to read four non-secret display strings on every token issuance. That gap is why
-- a browser-flow-minted token has carried no `name`/`preferred_username`/`email` at all (the
-- `authorization_code` grant's `KeyOwner` was hardcoded `email: None` -- see `oauth2_op::store`'s
-- `mint_from_authorization_code`, fixed alongside this migration).
--
-- Plain, nullable, unindexed columns -- same shape as `accounts.name`
-- (`20260829000001_accounts_add_name.sql`) and for the same reason: there is no truthful value to
-- backfill an existing row with, so every pre-existing `federated_identities` row reads back NULL
-- here until its subject's next successful login re-populates it (`upsert_federated_identity`'s
-- UPDATE branch, unconditionally, on every login -- unlike `token_envelope`, which is skipped
-- when a fresh Keycloak token set was not sealed, these four columns are always refreshed from
-- whatever the id-token carried, including back to NULL if a claim disappears upstream).
--
-- Adding a nullable column with no default is catalog-only in Postgres (no table rewrite, no
-- backfill statement), so this is safe to apply to a live, populated `federated_identities` table.
ALTER TABLE federated_identities
    ADD COLUMN email TEXT,
    ADD COLUMN email_verified BOOLEAN,
    ADD COLUMN preferred_username TEXT,
    ADD COLUMN name TEXT;

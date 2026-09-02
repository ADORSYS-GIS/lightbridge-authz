-- Supporting indexes for `searchUsers` (#647), the bounded free-text user search over
-- `federated_identities`' three display columns. Without them every search is a sequential scan of
-- the whole table -- fine at today's row count, not fine as a permanent property of a surface an
-- admin console calls on every keystroke.
--
-- `lower(<col>)` because the search is case-insensitive: a plain index on the raw column cannot
-- serve `lower(col) LIKE ...`, only an expression index on the exact same expression can.
--
-- `text_pattern_ops` because the default `text` btree operator class orders by the database's
-- collation, and Postgres can only turn `LIKE 'prefix%'` into an index range scan when the index
-- uses a byte-ordering operator class. With the default class these indexes would be built,
-- reported in `\d`, and never used -- the exact failure mode where "an index exists" is true and
-- meaningless.
--
-- What these DO NOT cover, stated plainly rather than left to be discovered: the substring arm of
-- the search (`lower(col) LIKE '%needle%'`). No btree index of any operator class can serve a
-- leading-wildcard match; that needs a `pg_trgm` GIN index, and `CREATE EXTENSION pg_trgm`
-- requires privileges this deployment's migration role is not guaranteed to hold -- a failed
-- `CREATE EXTENSION` fails the whole migration and therefore every service's init container
-- (ADR-0031), which is a far worse outcome than a scan on a table with one row per human who has
-- ever logged in. The substring arm stays a scan, bounded by the `LIMIT` the procedure always
-- applies and reachable only with the admin-only `user:read` permission. Revisit if
-- `federated_identities` ever grows past the point where that is a real cost.
--
-- Partial (`WHERE <col> IS NOT NULL`) because every one of these columns is nullable and NULL can
-- never match a `LIKE` predicate: indexing the NULLs would only make the index bigger. Rows
-- predating `20260830000001_federated_identities_add_profile_claims.sql` read back NULL until
-- their subject's next login, so this is not a marginal saving today.
--
-- Plain `CREATE INDEX` (not CONCURRENTLY): sqlx applies each migration file inside a transaction,
-- and `CREATE INDEX CONCURRENTLY` cannot run in one. These take ShareLock on
-- `federated_identities`, which blocks writes (logins) to that table for the duration but not
-- reads; at this table's size that is milliseconds.
SET LOCAL lock_timeout = '5s';

CREATE INDEX idx_federated_identities_name_lower
    ON federated_identities (lower(name) text_pattern_ops)
    WHERE name IS NOT NULL;

CREATE INDEX idx_federated_identities_email_lower
    ON federated_identities (lower(email) text_pattern_ops)
    WHERE email IS NOT NULL;

CREATE INDEX idx_federated_identities_preferred_username_lower
    ON federated_identities (lower(preferred_username) text_pattern_ops)
    WHERE preferred_username IS NOT NULL;

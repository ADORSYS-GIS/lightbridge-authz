-- no-transaction
-- A3 (#648): the usage dimensions bridge -- step 2 of 3, the backfill.
--
-- Every historical row already carries `azp` / `billing_plan` / the request path inside its
-- `attributes` JSONB blob (that is exactly the problem this story fixes), so the three new columns
-- can be filled from the blob rather than left NULL until the next ingest. The blob itself is
-- LEFT UNTOUCHED: this reads `attributes`, it never rewrites it.
--
-- BATCHED, ONE TRANSACTION PER BATCH. `BATCH_SIZE = 10000` rows of `id` range per `UPDATE`,
-- committed immediately. This file is `-- no-transaction` (sqlx runs it outside a transaction) and
-- holds exactly ONE statement -- the `DO` block -- which is what makes `COMMIT` inside the loop
-- legal: Postgres refuses `COMMIT` in a procedural block that is already inside a transaction
-- block, and a multi-statement simple query is one. The point of committing per batch is not
-- statement duration but dead tuples: an `UPDATE` rewrites every row it touches, and at this
-- table's production shape (~43k rows/day against a 30-day retention, ~1.3M rows, ~1.5 GB) a
-- single-transaction backfill would keep every one of those dead tuples unvacuumable until the
-- very end -- on the table whose growth already exhausted a production volume once (#549).
-- Committing per batch lets autovacuum reclaim as it goes, and makes a killed migration resumable
-- rather than a full rollback of hours of work.
--
-- The `WHERE` clause is what makes a re-run cheap and idempotent: a row is touched only when all
-- three columns are still NULL AND the blob actually yields at least one of them, so a re-run (or
-- a resumed run) rewrites nothing it already did, and a row whose attributes carry none of the
-- three is never rewritten at all.
--
-- The derivation MUST stay bit-identical to ingest's
-- (`crates/lightbridge-authz-usage/src/handlers/ingest.rs`: `AZP_KEYS`, `BILLING_PLAN_KEYS`,
-- `PATH_KEYS`, `operation_from_path`) -- backfilled rows and freshly-ingested rows have to be the
-- same fact or every "cost by channel" chart silently steps at the migration timestamp. Key
-- precedence is first-match, in the same order, and `NULLIF(..., '')` mirrors ingest's rule that
-- an empty string is an absent value, not a value of "".
--
-- `operation` vocabulary (closed; #581's PR-1b reuses it verbatim -- see the plan doc):
--   /v1/chat/completions -> chat_completions
--   /v1/responses        -> responses
--   /v1/messages         -> messages
--   /v1/embeddings       -> embeddings
--   any other path       -> other
--   NO path key present  -> NULL (absent, never 'other' -- "we don't know" is not "something else")
-- Prefix match, not equality: the gateway's `x-envoy-origin-path` carries the full request target,
-- query string included.
DO $$
DECLARE
    -- Documented batch size. Rows of `id` range per UPDATE + COMMIT.
    batch_size CONSTANT bigint := 10000;
    lo bigint;
    hi bigint;
    max_id bigint;
BEGIN
    SELECT COALESCE(MIN(id), 0), COALESCE(MAX(id), -1) INTO lo, max_id FROM usage_events;

    WHILE lo <= max_id LOOP
        hi := lo + batch_size;

        UPDATE usage_events AS e
        SET azp = src.azp,
            billing_plan = src.billing_plan,
            operation = src.operation
        FROM (
            SELECT
                id,
                COALESCE(
                    NULLIF(attributes ->> 'azp', ''),
                    NULLIF(attributes ->> 'x-oidc-azp', ''),
                    NULLIF(attributes ->> 'oauth.azp', ''),
                    NULLIF(attributes ->> 'client_id', '')
                ) AS azp,
                COALESCE(
                    NULLIF(attributes ->> 'billing_plan', ''),
                    NULLIF(attributes ->> 'x-billing-plan', '')
                ) AS billing_plan,
                CASE
                    WHEN COALESCE(
                             NULLIF(attributes ->> 'x-envoy-origin-path', ''),
                             NULLIF(attributes ->> 'http.route', ''),
                             NULLIF(attributes ->> 'url.path', ''),
                             NULLIF(attributes ->> 'route_name', '')
                         ) LIKE '/v1/chat/completions%' THEN 'chat_completions'
                    WHEN COALESCE(
                             NULLIF(attributes ->> 'x-envoy-origin-path', ''),
                             NULLIF(attributes ->> 'http.route', ''),
                             NULLIF(attributes ->> 'url.path', ''),
                             NULLIF(attributes ->> 'route_name', '')
                         ) LIKE '/v1/responses%' THEN 'responses'
                    WHEN COALESCE(
                             NULLIF(attributes ->> 'x-envoy-origin-path', ''),
                             NULLIF(attributes ->> 'http.route', ''),
                             NULLIF(attributes ->> 'url.path', ''),
                             NULLIF(attributes ->> 'route_name', '')
                         ) LIKE '/v1/messages%' THEN 'messages'
                    WHEN COALESCE(
                             NULLIF(attributes ->> 'x-envoy-origin-path', ''),
                             NULLIF(attributes ->> 'http.route', ''),
                             NULLIF(attributes ->> 'url.path', ''),
                             NULLIF(attributes ->> 'route_name', '')
                         ) LIKE '/v1/embeddings%' THEN 'embeddings'
                    WHEN COALESCE(
                             NULLIF(attributes ->> 'x-envoy-origin-path', ''),
                             NULLIF(attributes ->> 'http.route', ''),
                             NULLIF(attributes ->> 'url.path', ''),
                             NULLIF(attributes ->> 'route_name', '')
                         ) IS NOT NULL THEN 'other'
                    ELSE NULL
                END AS operation
            FROM usage_events
            WHERE id >= lo AND id < hi
        ) AS src
        WHERE e.id = src.id
          AND e.azp IS NULL
          AND e.billing_plan IS NULL
          AND e.operation IS NULL
          AND (src.azp IS NOT NULL OR src.billing_plan IS NOT NULL OR src.operation IS NOT NULL);

        COMMIT;

        lo := hi;
    END LOOP;
END $$;

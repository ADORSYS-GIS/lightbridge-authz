-- Synthetic `usage_events` fixture shaped like PRODUCTION, for query-plan work on the usage store.
--
-- Why this file exists: the usage query hot path (`crates/lightbridge-authz-usage/src/repo.rs`)
-- is dominated by how many HEAP PAGES a time-range scan has to touch, and that is a function of
-- row WIDTH, not row count. A fixture seeded with `attributes = '{}'` is ~100 bytes/row and makes
-- every query look instant; production's `attributes` averages 1,464 bytes/row (measured
-- 2026-09-03 on `lightbridge-main-db`/`usage`, 932,531 rows, 3,267 MB heap), which is what turns
-- an estate-wide 30-day scan into gigabytes of I/O. Reproducing that width is the whole point.
--
-- Production shape this mirrors (measured 2026-09-03, read-only, on the `-ro` replica):
--   rows                     932,531 over ~20 days (~46k rows/day, 30-day retention)
--   pg_relation_size         3,267 MB heap  +  625 MB indexes  +  19 MB toast
--   avg pg_column_size(attributes)  1,464 bytes   (max 2,084 -- below the 2 KB TOAST threshold,
--                                                  so it stays INLINE and widens the heap)
--   rows carrying latency_ms        ~29%
--   accounts / models / projects    a few hundred / tens / a few per account
--
-- Usage:
--   psql "$DATABASE_URL" -v rows=2000000 -v days=120 -f .docker/it/seed-usage-perf-fixture.sql
--
-- Requires `migrations-usage/` to have been applied first. Seeds in 100k-row batches so a long
-- run is observable and so no single statement builds a multi-GB tuplestore.
\set ON_ERROR_STOP on
\timing on

\if :{?rows}
\else
\set rows 2000000
\endif
\if :{?days}
\else
\set days 120
\endif

-- psql does NOT interpolate `:vars` inside a dollar-quoted body, so the two knobs are handed to
-- the DO block as session GUCs instead of textually substituted into it.
SELECT set_config('seed.rows', :'rows', false), set_config('seed.days', :'days', false);

DO $seed$
DECLARE
    -- Kept in sync with the psql `-v` variables by the caller; defaults match the documented
    -- "prod-shaped" fixture (2M rows over 120 days).
    target_rows  bigint := current_setting('seed.rows')::bigint;
    span_days    int    := current_setting('seed.days')::int;
    batch        bigint := 100000;
    done         bigint := 0;
    accounts     int    := 200;
    models       int    := 30;
    -- A HIGH-ENTROPY filler pool. This is not decoration: `pg_column_size` reports the STORED
    -- size, and Postgres pglz-compresses a wide jsonb before deciding whether it fits inline. A
    -- filler of repeated text compresses ~2x and produced a 753-byte fixture against production's
    -- measured 1,464 -- i.e. a heap only half as wide as the thing being reproduced, which is
    -- exactly the variable the query work turns on. A pool of concatenated md5 digests does not
    -- compress, so each row's 1.2 KB slice of it is stored at ~its raw size, like production's
    -- real attribute blobs (request ids, trace ids, headers) are.
    filler       text;
BEGIN
    SELECT string_agg(md5(random()::text), '') INTO filler FROM generate_series(1, 250);

    WHILE done < target_rows LOOP
        INSERT INTO usage_events (
            observed_at, signal_type, account_id, project_id, api_key_id, user_id, user_name,
            model, metric_name, azp, operation, billing_plan,
            usage_value, request_count, prompt_tokens, completion_tokens, total_tokens,
            total_cost, latency_ms, attributes
        )
        SELECT
            -- Append-ordered in time, like a real OTLP ingest stream: row N is not older than row
            -- N-1 beyond a small jitter. This is what makes BRIN on `observed_at` even worth
            -- measuring, and it is how production actually writes.
            TIMESTAMPTZ '2026-05-06 00:00:00+00'
              + ((done + g) * (span_days * 86400.0) / target_rows) * INTERVAL '1 second'
              + (random() * 30) * INTERVAL '1 second'                          AS observed_at,
            (ARRAY['metric','trace','log'])[1 + ((done + g) % 3)]              AS signal_type,
            'acct_' || lpad((((done + g) * 7919) % accounts)::text, 4, '0')    AS account_id,
            'proj_' || lpad((((done + g) * 7919) % (accounts * 3))::text, 5, '0') AS project_id,
            'akey_' || lpad((((done + g) * 104729) % (accounts * 2))::text, 5, '0') AS api_key_id,
            'user_' || lpad((((done + g) * 15485863) % (accounts * 10))::text, 6, '0') AS user_id,
            'User '  || (((done + g) * 15485863) % (accounts * 10))::text      AS user_name,
            'model-' || lpad((((done + g) * 65537) % models)::text, 2, '0')    AS model,
            (ARRAY['gen_ai.client.token.usage','gen_ai.client.operation.duration','http.server.request.duration'])[1 + ((done + g) % 3)] AS metric_name,
            (ARRAY['librechat','opencode','console-ui','cli','n8n'])[1 + ((done + g) % 5)] AS azp,
            (ARRAY['chat_completions','responses','messages','embeddings','other'])[1 + ((done + g) % 5)] AS operation,
            (ARRAY['free','team','enterprise'])[1 + ((done + g) % 3)]          AS billing_plan,
            (random() * 1000)::double precision                                AS usage_value,
            1                                                                  AS request_count,
            (random() * 4000)::bigint                                          AS prompt_tokens,
            (random() * 2000)::bigint                                          AS completion_tokens,
            (random() * 6000)::bigint                                          AS total_tokens,
            (random() * 0.05)::double precision                                AS total_cost,
            -- ~29% of production rows carry a per-request duration (aggregate metric points carry
            -- none -- see `UsageEvent::latency_ms`). Log-normal-ish so percentiles are not uniform.
            CASE WHEN ((done + g) % 100) < 29
                 THEN (30 + 900 * power(random(), 3))::double precision
                 ELSE NULL END                                                 AS latency_ms,
            jsonb_build_object(
                'x-envoy-origin-path', '/v1/chat/completions',
                'azp', (ARRAY['librechat','opencode','console-ui','cli','n8n'])[1 + ((done + g) % 5)],
                'billing_plan', (ARRAY['free','team','enterprise'])[1 + ((done + g) % 3)],
                'http.request.method', 'POST',
                'http.response.status_code', 200,
                'server.address', 'gateway.converse.example',
                'url.scheme', 'https',
                'user_agent.original', 'librechat/0.7.9 (node 22)',
                'net.peer.ip', '10.42.' || ((done + g) % 255) || '.' || ((done + g) % 97),
                'request_id', md5((done + g)::text),
                'trace_id', md5((done + g)::text || 'trace'),
                'span_id', substr(md5((done + g)::text || 'span'), 1, 16),
                'gen_ai.system', 'openai',
                'gen_ai.request.model', 'model-' || lpad((((done + g) * 65537) % models)::text, 2, '0'),
                'gen_ai.response.model', 'model-' || lpad((((done + g) * 65537) % models)::text, 2, '0'),
                'gen_ai.request.temperature', 0.7,
                'gen_ai.request.max_tokens', 4096,
                'k8s.pod.name', 'core-gateway-' || substr(md5((done + g)::text), 1, 10),
                'k8s.namespace.name', 'converse',
                'service.name', 'core-gateway',
                'service.version', '1.42.0',
                'deployment.environment', 'production',
                'telemetry.sdk.language', 'rust',
                'response_headers', substr(filler, 1 + ((done + g) % 6000)::int, 450),
                'request_headers', substr(filler, 1 + ((done + g) % 5000)::int, 110)
            )                                                                  AS attributes
        FROM generate_series(1, LEAST(batch, target_rows - done)) AS g;

        done := done + LEAST(batch, target_rows - done);
        RAISE NOTICE 'seeded % / % rows', done, target_rows;
    END LOOP;
END
$seed$;

ANALYZE usage_events;

//! The hand-written rollup/purge SQL statements for `usage_events` retention (#549 AC2).
//!
//! Split out of `retention.rs` by the LoC gate (`.github/actions/loc-gate`): the statements and
//! their load-bearing doc comments are a cohesive unit that does not belong to the loop logic, and
//! keeping them here lets `retention.rs` stay under the 200-line ceiling. The pairing is unchanged
//! -- `retention.rs` is the only consumer, and the two files move together.

/// Rolls raw rows older than the cutoff into `usage_events_daily` and deletes them from
/// `usage_events`, in ONE statement. The cutoff is computed in SQL from the database clock
/// (`now()`), so it stays consistent with the data regardless of any clock skew between the app
/// and the database. `date_trunc('day', observed_at)` is the bucket key, matching the cutoff's day
/// boundary; both are pinned to UTC by the transaction's `SET LOCAL TimeZone = 'UTC'`. `$2` bounds
/// the batch (see [`super::BATCH_SIZE`]) so a large backlog is processed in bounded chunks.
///
/// The `DELETE ... RETURNING` and the `INSERT ... SELECT` share one statement snapshot, so a row
/// is never deleted without being rolled up (no READ COMMITTED race). `ON CONFLICT DO UPDATE`
/// folds a late-arriving row for an already-rolled-up day into the existing rollup row with a
/// NULL-safe `COALESCE` add, so spend for a closed period is stable. The trailing `SELECT COUNT(*)`
/// returns the number of raw rows deleted.
pub const ROLLUP_AND_PURGE_SQL: &str = r#"
WITH deleted AS (
    DELETE FROM usage_events
    WHERE ctid IN (
        SELECT ctid FROM usage_events
        WHERE observed_at < date_trunc('day', now() - ($1 * interval '1 day'))
        LIMIT $2
    )
    RETURNING *
),
rolled AS (
    INSERT INTO usage_events_daily (
        bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
        signal_type, azp, operation, billing_plan, requests, usage_value, prompt_tokens,
        completion_tokens, total_tokens, total_cost, latency_samples
    )
    SELECT
        date_trunc('day', observed_at) AS bucket_start,
        account_id, project_id, api_key_id, user_id, user_name, model, metric_name, signal_type,
        azp, operation, billing_plan,
        SUM(request_count)::bigint AS requests,
        SUM(usage_value)::double precision AS usage_value,
        SUM(prompt_tokens)::bigint AS prompt_tokens,
        SUM(completion_tokens)::bigint AS completion_tokens,
        SUM(total_tokens)::bigint AS total_tokens,
        SUM(total_cost)::double precision AS total_cost,
        COUNT(latency_ms)::bigint AS latency_samples
    FROM deleted
    GROUP BY bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
             signal_type, azp, operation, billing_plan
    ON CONFLICT (bucket_start, account_id, project_id, api_key_id, user_id, user_name, model, metric_name,
                 signal_type, azp, operation, billing_plan)
    DO UPDATE SET
        requests = COALESCE(usage_events_daily.requests, 0) + COALESCE(EXCLUDED.requests, 0),
        usage_value = COALESCE(usage_events_daily.usage_value, 0) + COALESCE(EXCLUDED.usage_value, 0),
        prompt_tokens = COALESCE(usage_events_daily.prompt_tokens, 0) + COALESCE(EXCLUDED.prompt_tokens, 0),
        completion_tokens = COALESCE(usage_events_daily.completion_tokens, 0) + COALESCE(EXCLUDED.completion_tokens, 0),
        total_tokens = COALESCE(usage_events_daily.total_tokens, 0) + COALESCE(EXCLUDED.total_tokens, 0),
        total_cost = COALESCE(usage_events_daily.total_cost, 0) + COALESCE(EXCLUDED.total_cost, 0),
        latency_samples = COALESCE(usage_events_daily.latency_samples, 0) + COALESCE(EXCLUDED.latency_samples, 0)
)
SELECT COUNT(*) FROM deleted
"#;

/// Deletes rollup rows older than `rollup_days`, bounding the long-term store so it does not grow
/// without bound. Same day-boundary cutoff shape as [`ROLLUP_AND_PURGE_SQL`], and pinned to UTC by
/// the transaction's `SET LOCAL TimeZone = 'UTC'`.
pub const ROLLUP_PURGE_SQL: &str = r#"
DELETE FROM usage_events_daily
WHERE bucket_start < date_trunc('day', now() - ($1 * interval '1 day'))
"#;

#![cfg(feature = "it-tests")]

use sqlx::PgPool;

/// Replays 20260922000002 over a table already carrying pre-existing rollup rows (recreating the
/// pre-migration shape first), proving: the column and index both existed columns without
/// disturbing existing rows -- and existing rows land with `source IS NULL`, never a fabricated
/// `'eaig'` (see the migration's own comment for why backfilling would be dishonest here).
#[sqlx::test(migrations = "../../migrations-usage")]
async fn expansion_preserves_legacy_rows_and_enforces_the_new_key(pool: PgPool) {
    sqlx::raw_sql(
        "DROP INDEX usage_events_daily_natural_key;
        ALTER TABLE usage_events_daily DROP COLUMN source;
        CREATE UNIQUE INDEX usage_events_daily_natural_key
            ON usage_events_daily (
                bucket_start, account_id, project_id, api_key_id, user_id, user_name, model,
                metric_name, signal_type, azp, operation, billing_plan
            ) NULLS NOT DISTINCT;
        INSERT INTO usage_events_daily (bucket_start, account_id, total_cost)
        VALUES ('2026-09-22T00:00:00Z', 'acct_legacy', 10.0);",
    )
    .execute(&pool)
    .await
    .expect("recreate the pre-expansion shape");

    sqlx::raw_sql(include_str!(
        "../../../migrations-usage/20260922000002_usage_events_daily_source.sql"
    ))
    .execute(&pool)
    .await
    .expect("replay the source-expansion migration");

    let source: Option<String> = sqlx::query_scalar(
        "SELECT source FROM usage_events_daily WHERE account_id = 'acct_legacy'",
    )
    .fetch_one(&pool)
    .await
    .expect("query the legacy row");
    assert_eq!(
        source, None,
        "a pre-existing rollup row must stay source=NULL, never be backfilled to 'eaig'"
    );

    let valid: bool = sqlx::query_scalar(
        "SELECT indisvalid AND indisunique FROM pg_index \
         WHERE indexrelid = 'usage_events_daily_natural_key'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("check the recreated index");
    assert!(valid);

    // The new key includes `source`: the same (bucket_start, account_id, ...) pair with two
    // different sources must now coexist as two rows, where the pre-expansion key would have
    // forced them into one.
    let inserted = sqlx::query(
        "INSERT INTO usage_events_daily (bucket_start, account_id, source, total_cost)
         VALUES ('2026-09-22T00:00:00Z', 'acct_legacy', 'claude-code', 5.0)
         ON CONFLICT (bucket_start, source, account_id, project_id, api_key_id, user_id,
             user_name, model, metric_name, signal_type, azp, operation, billing_plan)
         DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("insert a second row distinguished only by source");
    assert_eq!(inserted.rows_affected(), 1);

    let row_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM usage_events_daily WHERE account_id = 'acct_legacy'",
    )
    .fetch_one(&pool)
    .await
    .expect("count rows for the account");
    assert_eq!(row_count, 2);
}

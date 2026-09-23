#![cfg(feature = "it-tests")]

use sqlx::PgPool;

#[sqlx::test(migrations = "../../migrations-usage")]
async fn expansion_preserves_legacy_duplicates_and_enforces_new_keys(pool: PgPool) {
    // This database belongs only to this sqlx test. Recreate the pre-expansion shape,
    // then exercise the actual migration over existing rows instead of an empty table.
    sqlx::raw_sql(
        "ALTER TABLE usage_events DROP COLUMN dedup_key;
        INSERT INTO usage_events (observed_at, signal_type, source)
        VALUES ('2026-09-22T00:00:00Z', 'log', 'eaig'),
               ('2026-09-22T00:00:00Z', 'log', 'eaig');",
    )
    .execute(&pool)
    .await
    .expect("synthetic fixture operation must succeed");
    sqlx::raw_sql(include_str!(
        "../../../migrations-usage/20260922000001_usage_request_dedup.sql"
    ))
    .execute(&pool)
    .await
    .expect("synthetic fixture operation must succeed");
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM usage_events WHERE dedup_key IS NULL")
            .fetch_one(&pool)
            .await
            .expect("synthetic fixture operation must succeed");
    assert_eq!(retained, 2);
    let valid: bool = sqlx::query_scalar("SELECT indisvalid AND indisunique FROM pg_index WHERE indexrelid = 'usage_events_request_dedup'::regclass")
        .fetch_one(&pool).await.expect("synthetic fixture operation must succeed");
    assert!(valid);
    let result = sqlx::query(
        "INSERT INTO usage_events (observed_at, signal_type, source, dedup_key)
        VALUES ('2026-09-22T00:00:00Z', 'log', 'eaig', 'natural-key'),
               ('2026-09-22T00:00:00Z', 'log', 'eaig', 'natural-key')
        ON CONFLICT (observed_at, source, dedup_key) DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("synthetic fixture operation must succeed");
    assert_eq!(result.rows_affected(), 1);
}

// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! Live-database coverage for `20260823000001_backfill_projects_model_policy_allowlist`: the
//! ADR-0018 sequencing fix that moves an `allow_all` project with a genuinely non-empty
//! `allowed_models` to `allowlist`, while leaving `deny_all`, already-`allowlist`, and every
//! shape of "no restriction" (`NULL`, jsonb `null` literal, empty array) untouched.
//!
//! This is the one file in this crate that cannot go through
//! `#[sqlx::test(migrations = "../../migrations")]`: that helper applies every migration,
//! including the backfill under test, before the test body gets to insert a single row, so there
//! would be nothing left to backfill by the time the test runs. Mirrors the shape
//! `token_exchange_tests.rs::migration_backfill_gives_existing_rows_a_chain_and_a_backdated_cap`
//! already uses in `lightbridge-authz-rest` for the same reason: run migrations up to (and
//! including) `20260821000001_projects_model_policy` -- the migration that adds the
//! `model_policy` column this backfill depends on -- seed rows directly with raw SQL in every
//! state the backfill must tell apart, then run the remaining migrations and inspect the result.

use lightbridge_authz_core::cuid::cuid2;
use sqlx::PgPool;
use sqlx::types::Json;

async fn insert_account(pool: &PgPool, account_id: &str) {
    sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a test account must succeed");
}

async fn insert_project(
    pool: &PgPool,
    project_id: &str,
    account_id: &str,
    model_policy: &str,
    allowed_models_json: Option<&str>,
) {
    let billing_identity = format!("bill-{}", cuid2());
    match allowed_models_json {
        Some(raw) => {
            let value: serde_json::Value =
                serde_json::from_str(raw).expect("literal fixture JSON must parse");
            sqlx::query(
                "INSERT INTO projects
                    (id, account_id, name, allowed_models, billing_plan, billing_identity, model_policy)
                 VALUES ($1, $2, 'proj', $3, 'free', $4, $5)",
            )
            .bind(project_id)
            .bind(account_id)
            .bind(Json(value))
            .bind(&billing_identity)
            .bind(model_policy)
            .execute(pool)
            .await
            .expect("inserting a project with an explicit allowed_models value must succeed");
        }
        None => {
            sqlx::query(
                "INSERT INTO projects
                    (id, account_id, name, allowed_models, billing_plan, billing_identity, model_policy)
                 VALUES ($1, $2, 'proj', NULL, 'free', $3, $4)",
            )
            .bind(project_id)
            .bind(account_id)
            .bind(&billing_identity)
            .bind(model_policy)
            .execute(pool)
            .await
            .expect("inserting a project with a SQL NULL allowed_models must succeed");
        }
    }
}

async fn model_policy_of(pool: &PgPool, project_id: &str) -> String {
    sqlx::query_scalar("SELECT model_policy FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_one(pool)
        .await
        .expect("the seeded row must still exist after the migration runs")
}

#[sqlx::test(migrations = false)]
async fn backfill_moves_only_allow_all_rows_with_a_genuinely_non_empty_list(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    migrator
        .run_to(20260821000001, &pool)
        .await
        .expect("migrations up to and including projects_model_policy apply");

    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let non_empty_allow_all = cuid2();
    insert_project(
        &pool,
        &non_empty_allow_all,
        &account_id,
        "allow_all",
        Some(r#"["gpt-4", "gpt-3.5"]"#),
    )
    .await;

    let empty_array_allow_all = cuid2();
    insert_project(
        &pool,
        &empty_array_allow_all,
        &account_id,
        "allow_all",
        Some("[]"),
    )
    .await;

    let null_allow_all = cuid2();
    insert_project(&pool, &null_allow_all, &account_id, "allow_all", None).await;

    let jsonb_null_literal_allow_all = cuid2();
    insert_project(
        &pool,
        &jsonb_null_literal_allow_all,
        &account_id,
        "allow_all",
        Some("null"),
    )
    .await;

    let already_allowlist = cuid2();
    insert_project(
        &pool,
        &already_allowlist,
        &account_id,
        "allowlist",
        Some(r#"["gpt-4"]"#),
    )
    .await;

    let deny_all_with_list = cuid2();
    insert_project(
        &pool,
        &deny_all_with_list,
        &account_id,
        "deny_all",
        Some(r#"["gpt-4"]"#),
    )
    .await;

    migrator
        .run(&pool)
        .await
        .expect("the backfill migration applies on top of the seeded rows");

    assert_eq!(
        model_policy_of(&pool, &non_empty_allow_all).await,
        "allowlist",
        "a non-empty allowed_models on an allow_all project must be backfilled to allowlist"
    );
    assert_eq!(
        model_policy_of(&pool, &empty_array_allow_all).await,
        "allow_all",
        "an empty allowed_models array means no restriction and must NOT be touched"
    );
    assert_eq!(
        model_policy_of(&pool, &null_allow_all).await,
        "allow_all",
        "SQL NULL allowed_models means no restriction and must NOT be touched"
    );
    assert_eq!(
        model_policy_of(&pool, &jsonb_null_literal_allow_all).await,
        "allow_all",
        "the jsonb null literal also means no restriction and must NOT be touched"
    );
    assert_eq!(
        model_policy_of(&pool, &already_allowlist).await,
        "allowlist",
        "an already-allowlist row is deliberate operator state and must be left exactly as-is"
    );
    assert_eq!(
        model_policy_of(&pool, &deny_all_with_list).await,
        "deny_all",
        "a deny_all row must never be overwritten by this backfill, non-empty list or not"
    );
}

#[sqlx::test(migrations = false)]
async fn backfill_is_idempotent_on_a_second_run(pool: PgPool) {
    let migrator = sqlx::migrate::Migrator::new(std::path::Path::new("../../migrations"))
        .await
        .expect("migrator loads from the workspace migrations directory");
    migrator
        .run_to(20260821000001, &pool)
        .await
        .expect("migrations up to and including projects_model_policy apply");

    let account_id = cuid2();
    insert_account(&pool, &account_id).await;

    let project_id = cuid2();
    insert_project(
        &pool,
        &project_id,
        &account_id,
        "allow_all",
        Some(r#"["gpt-4"]"#),
    )
    .await;

    migrator
        .run(&pool)
        .await
        .expect("the backfill migration applies on top of the seeded row");
    assert_eq!(
        model_policy_of(&pool, &project_id).await,
        "allowlist",
        "sanity check: the row must have actually moved on the first application"
    );

    // Simulate the migration's own UPDATE running a second time (e.g. a re-deploy replaying the
    // same migration file, or a manual re-run) directly against the now-already-backfilled row.
    let second_run = sqlx::query(
        "UPDATE projects
            SET model_policy = 'allowlist'
          WHERE model_policy = 'allow_all'
            AND (CASE WHEN jsonb_typeof(allowed_models) = 'array'
                      THEN jsonb_array_length(allowed_models)
                      ELSE 0
                 END) > 0",
    )
    .execute(&pool)
    .await
    .expect("re-running the backfill's UPDATE against an already-migrated row must succeed");

    assert_eq!(
        second_run.rows_affected(),
        0,
        "a second application must match zero rows: the WHERE clause requires model_policy = \
         'allow_all', and the row is already 'allowlist' after the first application"
    );
    assert_eq!(
        model_policy_of(&pool, &project_id).await,
        "allowlist",
        "the row must remain allowlist after the idempotent second run"
    );
}

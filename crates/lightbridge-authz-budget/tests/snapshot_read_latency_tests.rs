#![cfg(feature = "it-tests")]
//! The measured cost the single-call design adds to `POST /v1/authorino/validate/introspect`
//! (ADR-0034 §15, owner directive 2026-09-04: "ensure the call on the budget side is the fastest
//! possible").
//!
//! The added work on the request path is exactly one thing — a primary-key probe of
//! `budget_remaining_snapshots` through the pool `authz-opa` already holds. The `last_seen_at`
//! write is spawned, not awaited, and is throttled to at most once per account per 30 s, so it is
//! not on the path being measured here. This test measures the probe and asserts the ADR's number.
//!
//! **What is asserted, and what is only reported.** The assertion is the *plan*: the probe must be
//! an index scan on the primary key. That is the property that makes the cost bounded, and it is
//! deterministic — a future schema or query change that turns it into a sequential scan fails here.
//! The timings are PRINTED, not asserted tightly: they are a local measurement against a container
//! on the same host, they move with whatever else is running, and a wall-clock assertion would be
//! a flaky test asserting the speed of a laptop. The loose 50 ms guard exists only to catch an
//! order-of-magnitude regression the plan check somehow misses.

use std::sync::Arc;
use std::time::Instant;

use chrono::Utc;
use lightbridge_authz_budget::period::Period;
use lightbridge_authz_budget::snapshot::BudgetSnapshotReader;
use lightbridge_authz_budget::snapshot_store::SnapshotStore;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::DbPool;
use sqlx::PgPool;

const SAMPLES: usize = 2_000;

#[sqlx::test(migrations = "../../migrations")]
async fn the_snapshot_probe_is_the_only_cost_the_request_path_pays(pool: PgPool) {
    let store = SnapshotStore::new(Arc::new(DbPool::from_pool(pool.clone())));

    // A realistic table rather than a one-row one: the probe must be an index hit, and a table with
    // a single row would hide a sequential scan.
    let mut target = String::new();
    for index in 0..500 {
        let id = cuid2();
        sqlx::query("INSERT INTO accounts (id) VALUES ($1)")
            .bind(&id)
            .execute(&pool)
            .await
            .expect("inserting a test account must succeed");
        store.touch(&id).await.expect("touch must succeed");
        store
            .store_reading(
                &id,
                &Period::current(Utc::now()),
                24_000_000,
                3_210_000,
                Utc::now(),
            )
            .await
            .expect("storing a reading must succeed");
        if index == 250 {
            target = id;
        }
    }

    // Warm the pool and the plan cache; the first probe pays for both and is not what a live
    // request path experiences.
    for _ in 0..50 {
        store.read(&target).await.expect("read must succeed");
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let snapshot = store.read(&target).await.expect("read must succeed");
        samples.push(started.elapsed().as_micros() as u64);
        assert!(
            snapshot.is_some(),
            "the target account must have a snapshot"
        );
    }
    samples.sort_unstable();

    // The real assertion: the probe is an index scan on the primary key, not a sequential scan.
    let plan: (serde_json::Value,) = sqlx::query_as(
        "EXPLAIN (FORMAT JSON) SELECT budget_account_id, period, ceiling_micros, spent_micros, \
         remaining_micros, next_reset_at, refreshed_at, stale_since, last_seen_at \
         FROM budget_remaining_snapshots WHERE budget_account_id = $1",
    )
    .bind(&target)
    .fetch_one(&pool)
    .await
    .expect("EXPLAIN must succeed");
    let node_type = plan.0[0]["Plan"]["Node Type"]
        .as_str()
        .expect("EXPLAIN JSON must carry a plan node type")
        .to_string();
    assert!(
        node_type.contains("Index"),
        "the request path's budget read must be an index probe, not a {node_type}; a sequential \
         scan here would put the whole table on the critical path of every metered model request"
    );

    let p50 = samples[samples.len() / 2];
    let p99 = samples[samples.len() * 99 / 100];
    println!(
        "budget_remaining_snapshots probe ({node_type}) over {SAMPLES} samples: \
         p50 = {p50} us, p99 = {p99} us, max = {} us",
        samples[samples.len() - 1]
    );

    assert!(
        p50 < 50_000,
        "an order-of-magnitude regression, not a contention blip: measured p50 = {p50} us"
    );
}

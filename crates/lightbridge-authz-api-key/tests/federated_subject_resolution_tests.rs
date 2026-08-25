// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "it-tests")]

//! ADR-0025 Stage 1: pins `StoreRepo::resolve_account_for_federated_subject`, the one seam every
//! ingress translates a remote IdP `(issuer, subject)` through into an id this service owns.
//!
//! Prove-fail-first (see `/tmp/prove-fail-subjects.md` for the verbatim log): each test below was
//! run once against a deliberately broken implementation (the specific break is named in that
//! test's own comment) to confirm it fails for the PREDICTED reason, then re-run green against the
//! real implementation.

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::CreateAccount;
use lightbridge_authz_core::db::DbPool;
use lightbridge_authz_core::error::Error;
use sqlx::PgPool;
use std::sync::Arc;

const ISSUER: &str = "https://issuer.example";
const OTHER_ISSUER: &str = "https://other-issuer.example";

fn build_repo(pool: PgPool) -> StoreRepo {
    StoreRepo::new(Arc::new(DbPool::from_pool(pool)))
}

/// t1: existing_fi_row_resolves_to_its_account_id
/// Prove-fail break: step 1's SELECT swapped to return the raw subject instead of the row's
/// account_id -- proves the method resolves through the federated_identities row rather than
/// echoing back whatever subject string it was handed.
#[sqlx::test(migrations = "../../migrations")]
async fn existing_fi_row_resolves_to_its_account_id(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let account_id = "owning-account";
    repo.create_account(
        account_id,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation must succeed");

    let fi_id = lightbridge_authz_core::cuid::cuid2();
    sqlx::query(
        "INSERT INTO federated_identities (id, issuer, subject, account_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(&fi_id)
    .bind(ISSUER)
    .bind("a-different-remote-sub")
    .bind(account_id)
    .execute(&pool)
    .await
    .expect("seeding the federated identity row must succeed");

    let resolved = repo
        .resolve_account_for_federated_subject(ISSUER, "a-different-remote-sub", ISSUER)
        .await
        .expect("an existing federated identity row must resolve");
    assert_eq!(
        resolved, account_id,
        "must resolve to the row's own account_id, not the presented subject"
    );

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(
        fi_count, 1,
        "resolving an already-adopted identity must not write a second row"
    );
}

/// t2: grandfathered_account_is_adopted_on_first_resolution_and_the_row_persists
/// Prove-fail break: drop the INSERT in the grandfather branch -- proves the self-healing adoption
/// actually persists a federated_identities row, not just returns the right id once.
#[sqlx::test(migrations = "../../migrations")]
async fn grandfathered_account_is_adopted_on_first_resolution_and_the_row_persists(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "grandfathered-subject";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("a pre-ADR-0024 account has accounts.id == subject");

    let resolved = repo
        .resolve_account_for_federated_subject(ISSUER, subject, ISSUER)
        .await
        .expect("a grandfathered account presented by the trusted issuer must be adopted");
    assert_eq!(resolved, subject);

    let row: (String,) = sqlx::query_as(
        "SELECT account_id FROM federated_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(ISSUER)
    .bind(subject)
    .fetch_one(&pool)
    .await
    .expect("the self-healed row must persist");
    assert_eq!(row.0, subject);

    // Second resolution must hit the persisted row (step 1), not adopt again.
    let resolved_again = repo
        .resolve_account_for_federated_subject(ISSUER, subject, ISSUER)
        .await
        .expect("a second resolution must succeed via the persisted row");
    assert_eq!(resolved_again, subject);

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(fi_count, 1, "adoption must happen exactly once");
}

/// t3: a_second_issuer_presenting_the_same_subject_is_refused_not_merged
/// THE security test. Prove-fail break: remove the `issuer != grandfather_issuer` guard -- proves
/// a subject value alone can never adopt a grandfathered account from an untrusted issuer.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_issuer_presenting_the_same_subject_is_refused_not_merged(pool: PgPool) {
    let repo = build_repo(pool.clone());
    let subject = "shared-subject-value";
    repo.create_account(
        subject,
        CreateAccount {
            default_quota: None,
        },
    )
    .await
    .expect("account creation must succeed");

    let err = repo
        .resolve_account_for_federated_subject(OTHER_ISSUER, subject, ISSUER)
        .await
        .expect_err("an untrusted issuer presenting the grandfathered subject must be refused");
    assert!(
        matches!(err, Error::Forbidden(_)),
        "expected Error::Forbidden, got {err:?}"
    );

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(
        fi_count, 0,
        "a refused cross-issuer resolution must leave no federated_identities row behind"
    );
}

/// t4: a_subject_with_no_account_is_refused
/// Prove-fail break: the None-account branch returns Ok(subject) instead of Err -- proves an
/// unknown subject can never silently become its own account id.
#[sqlx::test(migrations = "../../migrations")]
async fn a_subject_with_no_account_is_refused(pool: PgPool) {
    let repo = build_repo(pool.clone());

    let err = repo
        .resolve_account_for_federated_subject(ISSUER, "no-such-account", ISSUER)
        .await
        .expect_err("a subject with no accounts row must be refused");
    assert!(
        matches!(err, Error::Forbidden(_)),
        "expected Error::Forbidden, got {err:?}"
    );

    let fi_count: i64 = sqlx::query_scalar("SELECT count(*) FROM federated_identities")
        .fetch_one(&pool)
        .await
        .expect("counting federated_identities must succeed");
    assert_eq!(fi_count, 0);
}

/// t5: adoption_is_idempotent_under_concurrency
/// Prove-fail break: drop FOR UPDATE (or the ON CONFLICT DO NOTHING re-read) -- proves two
/// concurrent first-time resolutions of the SAME grandfathered subject both succeed with the same
/// account id and only ever write one row, rather than racing into an error or a duplicate.
#[sqlx::test(migrations = "../../migrations")]
async fn adoption_is_idempotent_under_concurrency(pool: PgPool) {
    let repo_a = build_repo(pool.clone());
    let repo_b = build_repo(pool.clone());
    let subject = "concurrently-adopted-subject";
    repo_a
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
            },
        )
        .await
        .expect("account creation must succeed");

    let issuer_a = ISSUER.to_string();
    let issuer_b = ISSUER.to_string();
    let subject_a = subject.to_string();
    let subject_b = subject.to_string();
    let (result_a, result_b) = tokio::join!(
        async move {
            repo_a
                .resolve_account_for_federated_subject(&issuer_a, &subject_a, &issuer_a)
                .await
        },
        async move {
            repo_b
                .resolve_account_for_federated_subject(&issuer_b, &subject_b, &issuer_b)
                .await
        }
    );

    let account_a = result_a.expect("the first concurrent resolution must succeed");
    let account_b = result_b.expect("the second concurrent resolution must succeed");
    assert_eq!(account_a, subject);
    assert_eq!(account_b, subject);

    let fi_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM federated_identities WHERE issuer = $1 AND subject = $2",
    )
    .bind(ISSUER)
    .bind(subject)
    .fetch_one(&pool)
    .await
    .expect("counting federated_identities must succeed");
    assert_eq!(
        fi_count, 1,
        "two concurrent first-time resolutions must adopt exactly once, never twice"
    );
}

/// t6: db_unreachable_refuses_rather_than_falling_through
/// Prove-fail break: wrap the lookup in `.unwrap_or(...)`/swallow the error -- proves an
/// unavailable database routes to a hard error, never a permissive default.
#[sqlx::test(migrations = "../../migrations")]
async fn db_unreachable_refuses_rather_than_falling_through(pool: PgPool) {
    // Close the pool so every subsequent query fails with a connection error -- the cheapest
    // reliable way to simulate "database unreachable" against a real sqlx::PgPool in-process,
    // without standing up a second Postgres just to shut it down mid-test.
    pool.close().await;
    let repo = build_repo(pool);

    let result = repo
        .resolve_account_for_federated_subject(ISSUER, "irrelevant-subject", ISSUER)
        .await;
    assert!(
        result.is_err(),
        "an unreachable database must refuse (Err), never fall through to Ok"
    );
    assert!(
        !matches!(result, Err(Error::Forbidden(_)) | Err(Error::Conflict(_))),
        "a DB-unreachable failure must not be misreported as an authorization decision, got \
         {result:?}"
    );
}

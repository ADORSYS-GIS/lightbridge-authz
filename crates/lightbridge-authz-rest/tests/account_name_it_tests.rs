// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Live-database coverage for `Account.name` (`migrations/20260829000001_accounts_add_name.sql`):
//! the human-facing display label an account had no way to carry before, so a console could only
//! ever render the opaque id.
//!
//! Four properties are worth a live database rather than a unit test, because each of them lives
//! in the seam between the handler, the SQL, and the column's own constraints:
//!
//! 1. **Unnamed is a real, representable state.** Every account that predates the column reads
//!    back `None`, and nothing invents a placeholder on the way out. This is what lets a console
//!    tell "the user named this" apart from "nobody has yet"; a backfilled id would have made the
//!    two indistinguishable forever.
//! 2. **`NULL` is the *only* representation of unnamed.** The handler normalises blank/whitespace
//!    input to `None`, and the column's `CHECK` makes that true regardless of code path.
//! 3. **A name is a label, never an identifier.** Two accounts may carry the same one; nothing
//!    resolves an account by it.
//! 4. **The tenant boundary holds on the write path.** `updateAccountName` is `WHERE id = $3 AND
//!    id = $4`, so another subject's account is an indistinguishable `NotFound`, not a rename.
//!
//! Gated behind `it-tests` / `just it-tests` (needs a migrated Postgres via `DATABASE_URL`), same
//! as `quota_tier_it_tests.rs`, whose harness this mirrors.
#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::Error;
use lightbridge_authz_core::{Account, CreateAccount};
use lightbridge_authz_rest::handlers::AuthzStoreImpl;
use sqlx::PgPool;
use std::sync::Arc;

fn core_pool(pool: PgPool) -> Arc<dyn DbPoolTrait> {
    Arc::new(DbPool::from_pool(pool))
}

async fn create(store: &AuthzStoreImpl, subject: &str, name: Option<&str>) -> Account {
    store
        .create_account(
            subject,
            CreateAccount {
                default_quota: None,
                name: name.map(str::to_owned),
            },
        )
        .await
        .expect("createAccount should succeed")
}

// ---------------------------------------------------------------------------------------------
// createAccount
// ---------------------------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_persists_a_supplied_name_and_reads_it_back(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone());
    let subject = format!("subj-{}", cuid2());

    let created = create(&store, &subject, Some("Acme Corp")).await;
    assert_eq!(created.name.as_deref(), Some("Acme Corp"));

    // Read back through the repo, not just the create response: the name has to survive the round
    // trip through the column and the `SELECT` list, which is exactly what a console reads.
    let fetched = StoreRepo::new(core)
        .get_account_by_id(&subject)
        .await
        .expect("lookup should succeed")
        .expect("the account should exist");
    assert_eq!(fetched.name.as_deref(), Some("Acme Corp"));
}

/// Property 1. An account created without a name is *unnamed*, not named after its id — which is
/// the entire reason the column is nullable rather than `NOT NULL` with an id backfill.
#[sqlx::test(migrations = "../../migrations")]
async fn an_account_created_without_a_name_is_unnamed_not_named_after_its_id(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));
    let subject = format!("subj-{}", cuid2());

    let account = create(&store, &subject, None).await;

    assert_eq!(
        account.name, None,
        "an unnamed account must read back as None so a console can offer a name-me affordance"
    );
    assert_ne!(
        account.name.as_deref(),
        Some(account.id.as_str()),
        "the id must never be smuggled in as a name"
    );
}

/// Property 2, handler half: blank and whitespace-only input collapse to unnamed rather than
/// becoming an empty-string "name" that a console would render as a blank label.
#[sqlx::test(migrations = "../../migrations")]
async fn create_account_normalises_blank_and_whitespace_names_to_unnamed(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));

    for blank in ["", "   ", "\t\n "] {
        let subject = format!("subj-{}", cuid2());
        let account = create(&store, &subject, Some(blank)).await;
        assert_eq!(
            account.name, None,
            "a blank name ({blank:?}) must normalise to unnamed, not to an empty-string name"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn create_account_trims_surrounding_whitespace_but_keeps_the_name(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));
    let subject = format!("subj-{}", cuid2());

    let account = create(&store, &subject, Some("  Acme Corp  ")).await;

    assert_eq!(account.name.as_deref(), Some("Acme Corp"));
}

/// Property 3. No unique index, no lookup-by-name: two unrelated people may both call their
/// account "Personal". A unique constraint here would also leak other tenants' names through
/// conflict errors.
#[sqlx::test(migrations = "../../migrations")]
async fn two_accounts_may_carry_the_same_name(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));
    let first = format!("subj-{}", cuid2());
    let second = format!("subj-{}", cuid2());

    let a = create(&store, &first, Some("Personal")).await;
    let b = create(&store, &second, Some("Personal")).await;

    assert_eq!(a.name.as_deref(), Some("Personal"));
    assert_eq!(b.name.as_deref(), Some("Personal"));
    assert_ne!(a.id, b.id, "the id is still the only thing that identifies");
}

// ---------------------------------------------------------------------------------------------
// updateAccountName
// ---------------------------------------------------------------------------------------------

/// The rename path an already-existing (and therefore nameless) production account needs: without
/// it, every account that predates this migration would be permanently unnamed, since
/// `Account.name` is `@readonly` and `model.Account.update` does not exist.
#[sqlx::test(migrations = "../../migrations")]
async fn update_account_name_names_a_previously_unnamed_account(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));
    let subject = format!("subj-{}", cuid2());
    let created = create(&store, &subject, None).await;
    assert_eq!(created.name, None);

    let renamed = store
        .update_account_name(&subject, &subject, Some("Acme Corp"))
        .await
        .expect("the account's own subject may rename it");

    assert_eq!(renamed.name.as_deref(), Some("Acme Corp"));
}

/// A set, not a PATCH: `None` clears rather than leaving the previous value untouched, matching
/// `updateAccountDefaultQuota`'s established contract. A blank string clears identically —
/// property 2 again, on the update path this time.
#[sqlx::test(migrations = "../../migrations")]
async fn update_account_name_clears_on_none_and_on_blank(pool: PgPool) {
    let store = AuthzStoreImpl::with_pool(core_pool(pool));

    for clearing in [None, Some(""), Some("   ")] {
        let subject = format!("subj-{}", cuid2());
        create(&store, &subject, Some("Acme Corp")).await;

        let cleared = store
            .update_account_name(&subject, &subject, clearing)
            .await
            .expect("clearing should succeed");

        assert_eq!(
            cleared.name, None,
            "{clearing:?} must clear the name back to unnamed"
        );
    }
}

/// Property 4. The `WHERE id = $3 AND id = $4` clause is the whole authorization check (ADR-0006:
/// one account is one person), so a caller pointing at somebody else's account gets the same
/// `NotFound` as one pointing at an account that does not exist — no probe, no rename.
#[sqlx::test(migrations = "../../migrations")]
async fn update_account_name_refuses_another_subjects_account_as_not_found(pool: PgPool) {
    let core = core_pool(pool);
    let store = AuthzStoreImpl::with_pool(core.clone());
    let owner = format!("subj-{}", cuid2());
    let stranger = format!("subj-{}", cuid2());
    create(&store, &owner, Some("Owned")).await;
    create(&store, &stranger, None).await;

    let err = store
        .update_account_name(&stranger, &owner, Some("Hijacked"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::NotFound),
        "a foreign account must be NotFound, not a successful rename: {err}"
    );

    let unknown = store
        .update_account_name(&stranger, &format!("subj-{}", cuid2()), Some("Hijacked"))
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, Error::NotFound),
        "an unknown account must be indistinguishable from a foreign one: {unknown}"
    );

    let still = StoreRepo::new(core)
        .get_account_by_id(&owner)
        .await
        .expect("lookup should succeed")
        .expect("the owner's account should still exist");
    assert_eq!(
        still.name.as_deref(),
        Some("Owned"),
        "the foreign rename must not have landed"
    );
}

// ---------------------------------------------------------------------------------------------
// The column's own constraints
// ---------------------------------------------------------------------------------------------

/// Property 2, database half. The handler is the primary normalisation, but the `CHECK` is what
/// keeps "NULL is the only unnamed" true for any future write path that forgets to normalise —
/// so it has to actually be enforced, not merely written down in the migration.
#[sqlx::test(migrations = "../../migrations")]
async fn the_column_check_refuses_a_blank_name_written_around_the_handler(pool: PgPool) {
    let subject = format!("subj-{}", cuid2());
    sqlx::query(
        "INSERT INTO accounts (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())",
    )
    .bind(&subject)
    .bind("   ")
    .execute(&pool)
    .await
    .expect_err("a whitespace-only name must violate the CHECK constraint");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id = $1")
        .bind(&subject)
        .fetch_one(&pool)
        .await
        .expect("count should succeed");
    assert_eq!(count, 0, "the rejected insert must leave no row behind");
}

/// The same constraint must not get in the way of the states that ARE legal: `NULL`, and any
/// non-blank name (including one with interior whitespace).
#[sqlx::test(migrations = "../../migrations")]
async fn the_column_check_allows_null_and_any_non_blank_name(pool: PgPool) {
    for (suffix, name) in [("null", None), ("named", Some("Acme  Corp"))] {
        let subject = format!("subj-{suffix}-{}", cuid2());
        sqlx::query(
            "INSERT INTO accounts (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())",
        )
        .bind(&subject)
        .bind(name)
        .execute(&pool)
        .await
        .expect("a NULL or non-blank name must be accepted");
    }
}

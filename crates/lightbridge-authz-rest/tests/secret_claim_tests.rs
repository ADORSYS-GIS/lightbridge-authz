//! Behaviour tests for the single-use, subject-bound secret claim store
//! (`lightbridge_authz_rest::secret_claim`, GHSA-9pc6-965v-2c44, #538).
//!
//! Postgres-backed via `sqlx::test`, which gives every test its own migrated database. That
//! isolation matters here more than usual: these tests deliberately race concurrent redemptions
//! against one another, and a shared database would turn a real exactly-once violation into an
//! intermittent failure someone would eventually paper over with a retry.
//!
//! The properties under test, in order of how much damage their absence does:
//!
//! 1. A subject that does not own a claim cannot redeem it, **and cannot burn it either**.
//! 2. A claim is redeemable exactly once, including under concurrent redemption.
//! 3. An expired claim is unredeemable.
//! 4. An unknown token is a miss, not an error.

#![cfg(feature = "it-tests")]

use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::secret_claim::SecretClaimStore;
use sqlx::PgPool;
use std::sync::Arc;

const KEY: [u8; 32] = [7u8; 32];
const SECRET: &str = "lbk_the_secret";

fn store(pool: PgPool, ttl_seconds: i64) -> SecretClaimStore {
    let core: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
    SecretClaimStore::new(Arc::new(StoreRepo::new(core)), KEY, ttl_seconds)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_owning_subject_redeems_the_secret_exactly_once(pool: PgPool) {
    let store = store(pool, 300);
    let claim = store.issue(SECRET, "subject-a").await.expect("issue");

    let first = store
        .redeem(&claim.token, "subject-a")
        .await
        .expect("redeem");
    assert_eq!(
        first.as_deref(),
        Some(SECRET),
        "the owning subject must get the secret back"
    );

    let second = store
        .redeem(&claim.token, "subject-a")
        .await
        .expect("redeem");
    assert_eq!(
        second, None,
        "a claim is single-use: the second redemption must be a miss"
    );
}

/// The security property the entire design rests on. A model that holds the claim token -- which
/// it always does, since handing it over is the point -- must be able to do nothing with it: not
/// redeem it, and not destroy it.
///
/// The second assertion is the one that is easy to get wrong. Consuming the row before checking
/// the subject would still block the wrong redeemer, so it *looks* correct, while quietly handing
/// every token-holder a denial of service against the legitimate owner.
#[sqlx::test(migrations = "../../migrations")]
async fn a_different_subject_cannot_redeem_and_does_not_consume_the_claim(pool: PgPool) {
    let store = store(pool, 300);
    let claim = store.issue(SECRET, "subject-a").await.expect("issue");

    let attacker = store
        .redeem(&claim.token, "subject-b")
        .await
        .expect("redeem");
    assert_eq!(
        attacker, None,
        "possession of the token must not be sufficient to redeem it"
    );

    let owner = store
        .redeem(&claim.token, "subject-a")
        .await
        .expect("redeem");
    assert_eq!(
        owner.as_deref(),
        Some(SECRET),
        "a refused attempt must NOT consume the claim -- otherwise anyone holding the token can \
         destroy the owner's one chance to collect their key"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_token_is_a_miss_not_an_error(pool: PgPool) {
    let store = store(pool, 300);
    let result = store
        .redeem("definitely-not-a-real-token", "subject-a")
        .await
        .expect("an unknown token is a normal miss, not a store failure");
    assert_eq!(result, None);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_is_unredeemable_once_it_has_expired(pool: PgPool) {
    // Negative TTL: already expired at the moment it is written, so the test asserts the expiry
    // predicate rather than waiting on a clock.
    let store = store(pool, -1);
    let claim = store.issue(SECRET, "subject-a").await.expect("issue");
    let result = store
        .redeem(&claim.token, "subject-a")
        .await
        .expect("redeem");
    assert_eq!(result, None, "an expired claim must not be redeemable");
}

/// Concurrent redemptions by the legitimate owner. The consuming `UPDATE` is the exactly-once
/// boundary; without it a double-submit would hand out the secret twice and leave no trace.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_redemptions_by_the_owner_yield_exactly_one_winner(pool: PgPool) {
    let store = Arc::new(store(pool, 300));
    let claim = store.issue(SECRET, "subject-a").await.expect("issue");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        let token = claim.token.clone();
        handles.push(tokio::spawn(async move {
            store.redeem(&token, "subject-a").await.expect("redeem")
        }));
    }
    let mut winners = 0;
    for handle in handles {
        if handle.await.expect("task").is_some() {
            winners += 1;
        }
    }
    assert_eq!(
        winners, 1,
        "exactly one concurrent redemption may return the secret, got {winners}"
    );
}

/// The token is a bearer credential in transit, so it must not be recoverable from the table.
/// Storing only its hash is the same discipline `api_keys` applies to `key_hash`.
#[sqlx::test(migrations = "../../migrations")]
async fn the_claim_token_and_the_secret_are_never_stored_in_the_clear(pool: PgPool) {
    let store = store(pool.clone(), 300);
    let claim = store.issue(SECRET, "subject-a").await.expect("issue");

    let (token_hash, sealed): (String, String) =
        sqlx::query_as("SELECT token_hash, sealed_secret FROM secret_claims")
            .fetch_one(&pool)
            .await
            .expect("row");

    assert_ne!(
        token_hash, claim.token,
        "the claim token must be stored hashed, never verbatim"
    );
    assert!(
        !sealed.contains(SECRET),
        "the secret must be sealed at rest, never stored in the clear"
    );
}

//! Behaviour tests for the single-use, subject-bound secret claim store
//! (`crate::secret_claim`, GHSA-9pc6-965v-2c44, #538).
//!
//! The two fail-closed tests run unconditionally -- they need no Redis, because "Redis is
//! unreachable" is exactly what they assert. Everything else is gated behind `it-tests` and needs
//! a real Redis on `localhost:6379` (`just it-tests` brings one up), for the same reason the rest
//! of this repo prefers a real container over a mock: the bugs that matter live in the seam, and
//! `GETDEL`'s exactly-once semantics are precisely such a seam.
//!
//! Every test uses a per-test key prefix. Shared-store tests that collide on keys have already
//! caused real flakes in this repo; the prefix, not a retry budget, is the fix.

use lightbridge_authz_rest::secret_claim::RedisSecretClaimStore;

const KEY: [u8; 32] = [7u8; 32];
/// A port nothing listens on, so the connection attempt fails rather than hanging.
const UNREACHABLE: &str = "redis://127.0.0.1:1/";

fn unreachable_store() -> RedisSecretClaimStore {
    RedisSecretClaimStore::connect(UNREACHABLE, None, "test:", KEY, 300)
        .expect("construction is lazy and must succeed even against an unreachable server")
}

/// The whole point of the design is that a secret never reaches the model. If the claim store is
/// down, the only safe answer is to refuse the operation -- an `Ok` here would push the caller
/// toward returning the secret inline, which is the exposure this module exists to remove.
#[tokio::test]
async fn issue_refuses_rather_than_succeeding_when_the_store_is_unreachable() {
    let result = unreachable_store()
        .issue("lbk_the_secret", "subject-a")
        .await;
    assert!(
        result.is_err(),
        "an unreachable claim store must refuse to issue, never report success: {result:?}"
    );
}

/// Redemption must distinguish "no such claim" (`Ok(None)`) from "the store is broken" (`Err`).
/// Collapsing the second into the first would let an outage read as a clean miss.
#[tokio::test]
async fn redeem_errors_rather_than_reporting_a_clean_miss_when_the_store_is_unreachable() {
    let result = unreachable_store().redeem("some-token", "subject-a").await;
    assert!(
        result.is_err(),
        "an unreachable claim store must error, not report Ok(None): {result:?}"
    );
}

#[cfg(feature = "it-tests")]
mod with_redis {
    use super::{KEY, RedisSecretClaimStore};

    const URL: &str = "redis://127.0.0.1:6379/";

    fn store(prefix: &str, ttl_seconds: u64) -> RedisSecretClaimStore {
        RedisSecretClaimStore::connect(URL, None, prefix, KEY, ttl_seconds)
            .expect("store construction")
    }

    #[tokio::test]
    async fn the_owning_subject_redeems_the_secret_exactly_once() {
        let store = store("t_once:", 300);
        let claim = store
            .issue("lbk_the_secret", "subject-a")
            .await
            .expect("issue");

        let first = store
            .redeem(&claim.token, "subject-a")
            .await
            .expect("redeem");
        assert_eq!(
            first.as_deref(),
            Some("lbk_the_secret"),
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

    /// The security property the entire design rests on. A model that holds the claim URL --
    /// which it always does, since handing it over is the point -- must not be able to redeem it,
    /// and must not be able to destroy it either.
    #[tokio::test]
    async fn a_different_subject_cannot_redeem_and_does_not_consume_the_claim() {
        let store = store("t_wrong_subject:", 300);
        let claim = store
            .issue("lbk_the_secret", "subject-a")
            .await
            .expect("issue");

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
            Some("lbk_the_secret"),
            "a refused attempt must NOT consume the claim -- otherwise anyone holding the token \
             can destroy the owner's one chance to collect their key"
        );
    }

    #[tokio::test]
    async fn an_unknown_token_is_a_miss_not_an_error() {
        let store = store("t_unknown:", 300);
        let result = store
            .redeem("definitely-not-a-real-token", "subject-a")
            .await
            .expect("an unknown token is a normal miss, not a store failure");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn a_claim_is_unredeemable_once_its_ttl_has_elapsed() {
        let store = store("t_ttl:", 1);
        let claim = store
            .issue("lbk_the_secret", "subject-a")
            .await
            .expect("issue");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let result = store
            .redeem(&claim.token, "subject-a")
            .await
            .expect("redeem");
        assert_eq!(result, None, "an expired claim must not be redeemable");
    }

    /// Two concurrent redemptions by the legitimate owner: `GETDEL` is the exactly-once boundary,
    /// so exactly one must win. Without it, a double-submit would hand out the secret twice and
    /// leave no record that it happened.
    #[tokio::test]
    async fn concurrent_redemptions_by_the_owner_yield_exactly_one_winner() {
        let store = std::sync::Arc::new(store("t_race:", 300));
        let claim = store
            .issue("lbk_the_secret", "subject-a")
            .await
            .expect("issue");

        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = std::sync::Arc::clone(&store);
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
}

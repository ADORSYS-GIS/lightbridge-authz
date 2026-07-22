use lightbridge_authz_rest::ratelimit_redis::{RedisRateLimitStore, build_redis_rate_limit_store};

#[test]
fn rejects_an_unparseable_redis_url() {
    let result = build_redis_rate_limit_store("not-a-redis-url", "lightbridge");
    assert!(result.is_err());
}

#[test]
fn accepts_a_well_formed_redis_url_without_connecting() {
    let result = build_redis_rate_limit_store("redis://127.0.0.1:6379", "lightbridge");
    assert!(result.is_ok());
}

#[test]
fn bucket_keys_for_the_same_input_are_stable_and_namespaced() {
    let store = RedisRateLimitStore::open("redis://127.0.0.1:6379", "lightbridge-authz")
        .expect("well-formed redis url should construct a store without connecting");

    let key_a = store.bucket_key("auth:some-fingerprint");
    let key_b = store.bucket_key("auth:some-fingerprint");
    let key_c = store.bucket_key("auth:another-fingerprint");

    assert_eq!(key_a, key_b, "same input must hash to the same bucket key");
    assert_ne!(
        key_a, key_c,
        "different inputs must hash to different bucket keys"
    );
    assert!(
        key_a.starts_with("lightbridge-authz:rl:"),
        "bucket key must be namespaced under the configured prefix, got: {key_a}"
    );
}

#[test]
fn empty_key_prefix_falls_back_to_the_cratestack_default() {
    let store = RedisRateLimitStore::open("redis://127.0.0.1:6379", "")
        .expect("well-formed redis url should construct a store without connecting");
    assert_eq!(store.key_prefix(), "cratestack");
}

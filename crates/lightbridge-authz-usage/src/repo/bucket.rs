//! Shared bucket-interval validation for the usage query endpoints (#726). Split out of
//! `repo.rs` to satisfy the LoC gate (lightbridge-governance#172); the pairing with the query
//! builders in `repo.rs`/`repo/execution.rs` is unchanged.

use lightbridge_authz_core::{Error, Result};
use std::sync::LazyLock;

pub(super) fn validate_bucket_interval(bucket: &str) -> Result<()> {
    static BUCKET_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\d+\s+(second|seconds|minute|minutes|hour|hours|day|days)$")
            .expect("bucket regex should be valid")
    });

    if BUCKET_RE.is_match(bucket.trim()) {
        Ok(())
    } else {
        Err(Error::BadRequest(
            "bucket must look like `5 minutes`, `1 hour`, or `1 day`".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bucket_interval_accepts_supported_units() {
        assert!(validate_bucket_interval("1 minute").is_ok());
        assert!(validate_bucket_interval("15 minutes").is_ok());
        assert!(validate_bucket_interval("2 hours").is_ok());
        assert!(validate_bucket_interval("1 day").is_ok());
    }

    #[test]
    fn validate_bucket_interval_rejects_unexpected_values() {
        assert!(validate_bucket_interval("hour").is_err());
        assert!(validate_bucket_interval("1month").is_err());
        assert!(validate_bucket_interval("1 week").is_err());
    }
}

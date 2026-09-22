//! Shared bucket-interval validation for the usage query endpoints (#726). Split out of
//! `repo.rs` to satisfy the LoC gate (lightbridge-governance#172); the pairing with the query
//! builders in `repo.rs`/`repo/execution.rs` is unchanged.

use lightbridge_authz_core::{Error, Result};
use std::sync::LazyLock;

pub(super) fn validate_bucket_interval(bucket: &str) -> Result<()> {
    static BUCKET_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^(\d+)\s+(second|seconds|minute|minutes|hour|hours|day|days)$")
            .expect("bucket regex should be valid")
    });

    let trimmed = bucket.trim();
    let Some(caps) = BUCKET_RE.captures(trimmed) else {
        return Err(Error::BadRequest(
            "bucket must look like `5 minutes`, `1 hour`, or `1 day`".to_string(),
        ));
    };

    // A zero interval is degenerate for EVERY grain: `date_bin(CAST('0 days' AS interval), ...)`
    // fails server-side with a Postgres error, so a zero bucket would 500 instead of 400. Reject it
    // here, the shared format gate every query path calls first (execution, day-facts, seat, and
    // the legacy `query_usage`), so `0 days`/`0 seconds`/... never reach `date_bin`.
    // The regex guarantees a digit string, but not a `u64`-sized one: an oversized bucket (e.g. a
    // 29-digit count) passes the format gate yet overflows on parse. That must be a 400, never a
    // panic reachable from one authenticated request.
    let count: u64 = caps[1]
        .parse()
        .map_err(|_| Error::BadRequest("bucket count is too large".to_string()))?;
    if count == 0 {
        return Err(Error::BadRequest(
            "bucket must be a positive interval (e.g. `5 minutes`, `1 hour`, `1 day`)".to_string(),
        ));
    }

    Ok(())
}

/// Rejects sub-day buckets for the day/seat grains (#727/#728). The day and seat grains are daily
/// (`usage_day_facts.day`, `usage_seat_snapshots.snapshot_day` are `DATE`s), so a sub-day bucket
/// would collapse every row into the midnight bucket -- degenerate and misleading. Call AFTER
/// [`validate_bucket_interval`], which has already guaranteed the format.
pub(super) fn validate_day_grain_bucket(bucket: &str) -> Result<()> {
    static SUB_DAY_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^\d+\s+(second|seconds|minute|minutes|hour|hours)$")
            .expect("sub-day bucket regex should be valid")
    });
    if SUB_DAY_RE.is_match(bucket.trim()) {
        Err(Error::BadRequest(
            "the day/seat grain is daily; bucket must be at least 1 day (e.g. `1 day`, `7 days`)"
                .to_string(),
        ))
    } else {
        Ok(())
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

    #[test]
    fn validate_bucket_interval_rejects_zero_interval() {
        // A zero interval passes the format regex but would make `date_bin(CAST('0 days' AS
        // interval), ...)` fail server-side with a Postgres error (500 instead of 400) -- it must
        // be rejected here, the shared gate every query path calls first.
        assert!(validate_bucket_interval("0 days").is_err());
        assert!(validate_bucket_interval("0 seconds").is_err());
        assert!(validate_bucket_interval("0 hours").is_err());
        assert!(validate_bucket_interval("0 minutes").is_err());
    }

    #[test]
    fn validate_bucket_interval_rejects_oversized_count() {
        // A 29-digit count passes the format regex but overflows `u64` on parse. It must be a 400
        // (BadRequest), never a panic reachable from one authenticated request.
        let oversized = format!("{} days", "9".repeat(29));
        let err = validate_bucket_interval(&oversized).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)));
    }

    #[test]
    fn validate_day_grain_bucket_rejects_sub_day_units() {
        assert!(validate_day_grain_bucket("1 second").is_err());
        assert!(validate_day_grain_bucket("30 minutes").is_err());
        assert!(validate_day_grain_bucket("2 hours").is_err());
    }

    #[test]
    fn validate_day_grain_bucket_accepts_day_and_coarser() {
        assert!(validate_day_grain_bucket("1 day").is_ok());
        assert!(validate_day_grain_bucket("7 days").is_ok());
    }
}

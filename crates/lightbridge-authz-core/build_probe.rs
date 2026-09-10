// Pure resolution logic for the compile-time build stamp, shared by two consumers that cannot
// `use` each other:
//
// * `build.rs` (`include!`s this file, runs before the crate exists), and
// * `src/build_info.rs`'s `#[cfg(test)] mod build_probe` (`include!`s it again so the fallback
//   ladder below is covered by `cargo test`).
//
// Everything here is deliberately side-effect free and takes its inputs as parameters — no
// `std::process::Command`, no `std::env` reads. The build script does the I/O and hands the
// results in; the tests hand in fixtures. That is the only way a build script's decision table
// can be tested at all, and this ladder has three real branches per field.
//
// The ladder, in order, for every field: **git → environment → `unknown`.**
// `unknown` is the honest answer, never a fabricated or empty value: `/version` reporting an
// empty SHA reads as "we have no idea", which is exactly what it means, whereas a plausible-
// looking fake would be worse than no answer at all.

/// Placeholder written into the binary when neither git nor the environment could answer.
///
/// Deliberately a non-empty sentinel rather than `""`: it survives a round trip through JSON,
/// through a log line, and through a console table cell without collapsing into "field missing".
/// The frontend maps this exact string back to "unknown" for display.
pub const UNKNOWN: &str = "unknown";

/// Trims a captured command's stdout, returning `None` for anything blank.
///
/// A `git` invocation that fails is expected to arrive here as `None` already; this additionally
/// rejects the "succeeded but printed nothing" case, which is indistinguishable from failure for
/// our purposes and would otherwise bake an empty string into the binary.
pub fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// git → env → `unknown`, for any single field.
///
/// `git_value` is what the build script's `git` invocation produced (already `None` when git is
/// absent, when `.git` is not in the build context, or when the command failed);
/// `env_value` is the escape hatch an image build sets when it stripped `.git` out of the context.
pub fn resolve(git_value: Option<String>, env_value: Option<String>) -> String {
    non_empty(git_value)
        .or_else(|| non_empty(env_value))
        .unwrap_or_else(|| UNKNOWN.to_owned())
}

/// The first 7 characters of a full SHA, or the value unchanged when it is shorter (including the
/// `unknown` sentinel, which must not be sliced into `unknow`).
pub fn short_sha(sha: &str) -> String {
    if sha == UNKNOWN {
        return sha.to_owned();
    }
    sha.chars().take(7).collect()
}

/// Renders a Unix timestamp as RFC 3339 in UTC, or `None` when the input is not a valid timestamp.
///
/// This exists for `SOURCE_DATE_EPOCH`, the reproducible-builds standard an image build sets when
/// it has no `.git` to ask for a commit date. Every other date this crate handles is already
/// RFC 3339 (`git show -s --format=%cI`).
pub fn rfc3339_from_epoch(epoch: &str) -> Option<String> {
    let seconds: i64 = epoch.trim().parse().ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Resolves the commit date: git's own RFC 3339 output, else `SOURCE_DATE_EPOCH` converted, else
/// `unknown`.
///
/// Note the asymmetry with [`resolve`]: the environment value here is an epoch, not an RFC 3339
/// string, so it needs converting before it can stand in. A malformed `SOURCE_DATE_EPOCH` is
/// treated as absent rather than propagated — a build stamp saying `not-a-number` helps nobody.
pub fn resolve_commit_date(git_value: Option<String>, source_date_epoch: Option<String>) -> String {
    if let Some(value) = non_empty(git_value) {
        return value;
    }
    non_empty(source_date_epoch)
        .and_then(|epoch| rfc3339_from_epoch(&epoch))
        .unwrap_or_else(|| UNKNOWN.to_owned())
}

/// The build's own wall-clock timestamp, pinned to `SOURCE_DATE_EPOCH` when the caller set one so
/// a reproducible build stays reproducible, and only otherwise read off the clock.
pub fn resolve_build_time(source_date_epoch: Option<String>, now: chrono::DateTime<chrono::Utc>) -> String {
    non_empty(source_date_epoch)
        .and_then(|epoch| rfc3339_from_epoch(&epoch))
        .unwrap_or_else(|| now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

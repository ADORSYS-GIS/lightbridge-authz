//! The build stamp every `lightbridge-authz` service reports about itself (#573).
//!
//! One struct, four surfaces, all reading this same value — so they cannot disagree about what is
//! running:
//!
//! | surface | who may read it | where |
//! |---|---|---|
//! | `GET /version` | anyone (unauthenticated, like `/healthz`) | every service listener |
//! | `getBuildInfo()` RPC | any authenticated caller | `authz-api` + `authz-budget` |
//! | `lightbridge-authz version` / `--version` | the operator at a shell | CLI |
//! | `service.build` log line | whoever reads the logs | once, at startup |
//!
//! # Where each field comes from
//!
//! Two clocks, deliberately kept apart:
//!
//! * **Compile time** (`build.rs` → `env!`): crate version, git SHA, git commit date, dirty flag,
//!   rustc version, build timestamp. These are frozen into the binary and can never drift from
//!   the code that is executing.
//! * **Run time** (`std::env::var`): `imageBuildSha`, `imageTag`, `imageBuildTime`. These describe
//!   the *container*, which does not exist yet while the binary is being compiled — CI builds the
//!   binaries in one job (`.github/actions/build-binaries`) and the image in a later one
//!   (`.github/actions/container-build`). Both Dockerfiles declare them as `ARG`s and promote them
//!   to `ENV`, so the running process reads the image's own identity out of its environment.
//!
//! # `None` means unknown, and unknown is said out loud
//!
//! The three image fields are `Option<String>`: a binary run outside a container (a local
//! `cargo run`, a test) genuinely has no image identity, and the honest answer is `null`, not `""`
//! and not a fabricated placeholder. The compile-time fields cannot be `None` — `build.rs` always
//! produces *something* — so they carry the string `"unknown"` (see [`UNKNOWN`]) when neither git
//! nor the environment could answer.
//!
//! # Not a secret
//!
//! Everything here is a version string, a commit id, or a toolchain name. `/version` is therefore
//! unauthenticated, on purpose and by the same reasoning as `/healthz`: an operator, a probe, or a
//! support engineer must be able to ask "what are you running?" without holding a credential.
//! Nothing here discloses configuration, topology, or data.

use serde::{Deserialize, Serialize};

/// Reported when neither git nor the environment could name a value at compile time.
///
/// Kept in lockstep with `build_probe.rs`'s constant of the same name (that file cannot be
/// imported from here — it is `include!`d by the build script, which runs before this crate
/// exists), and re-asserted by a test below.
pub const UNKNOWN: &str = "unknown";

/// Environment variable carrying the container image's own build SHA, set as `ENV` from the
/// `IMAGE_BUILD_SHA` build-arg by both Dockerfiles.
pub const IMAGE_BUILD_SHA_ENV: &str = "IMAGE_BUILD_SHA";
/// Environment variable carrying the container image's tag (`ENV` from the `IMAGE_TAG` build-arg).
pub const IMAGE_TAG_ENV: &str = "IMAGE_TAG";
/// Environment variable carrying when the container image was built (`ENV` from the
/// `IMAGE_BUILD_TIME` build-arg).
pub const IMAGE_BUILD_TIME_ENV: &str = "IMAGE_BUILD_TIME";

/// What one `lightbridge-authz` process is: which service, built from which commit, by which
/// toolchain, shipped in which image.
///
/// Field names are `camelCase` on the wire because both consumers are TypeScript — the console's
/// `/settings/info` screen reads this over plain JSON (`GET /version`) and over the cratestack RPC
/// client (`getBuildInfo`), and the two must deserialize into the same shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    /// Which listener answered: `authz-api`, `authz-idp`, `authz-opa`, `authz-budget`,
    /// `authz-usage`, `authz-usage-query` or `lightbridge-mcp`. Supplied by the caller, because a
    /// single binary serves several of these.
    pub service: String,
    /// The workspace crate version (release-please owns this number).
    pub version: String,
    /// Full 40-character commit SHA, or [`UNKNOWN`].
    pub git_sha: String,
    /// First 7 characters of [`BuildInfo::git_sha`], or [`UNKNOWN`].
    pub git_short_sha: String,
    /// Committer date of that commit, RFC 3339, or [`UNKNOWN`].
    pub git_commit_date: String,
    /// Whether the working tree had uncommitted changes when this binary was compiled. Always
    /// `false` for anything CI built; `true` locally is the point of the flag.
    pub git_dirty: bool,
    /// `rustc --version` of the compiler that produced this binary.
    pub rustc_version: String,
    /// When this binary was compiled, RFC 3339 (pinned to `SOURCE_DATE_EPOCH` when one was set).
    pub build_time: String,
    /// The image's own build SHA, or `None` when not running from an image built by our pipeline.
    pub image_build_sha: Option<String>,
    /// The image tag, or `None`. Note this is the tag the build was *pushed as*, which is not
    /// necessarily the tag it was *pulled by* (argocd-image-updater resolves by digest).
    pub image_tag: Option<String>,
    /// When the image was built, RFC 3339, or `None`.
    pub image_build_time: Option<String>,
}

/// Reads an environment variable, treating "set but blank" as unset.
///
/// Docker writes `ENV FOO=` for an `ARG` that was declared with an empty default and never passed,
/// so an empty string reaching here means "the pipeline did not supply this", not "the pipeline
/// supplied an empty value".
fn env_opt(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The build stamp for `service`, assembled from the compile-time constants and the runtime image
/// environment.
///
/// Cheap enough to call per request (three `getenv`s and a handful of `&'static str` clones), so
/// there is no cache to invalidate and no startup ordering to get wrong.
pub fn build_info(service: &str) -> BuildInfo {
    BuildInfo {
        service: service.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        git_sha: env!("LB_GIT_SHA").to_owned(),
        git_short_sha: env!("LB_GIT_SHORT_SHA").to_owned(),
        git_commit_date: env!("LB_GIT_COMMIT_DATE").to_owned(),
        git_dirty: env!("LB_GIT_DIRTY") == "true",
        rustc_version: env!("LB_RUSTC_VERSION").to_owned(),
        build_time: env!("LB_BUILD_TIME").to_owned(),
        image_build_sha: env_opt(IMAGE_BUILD_SHA_ENV),
        image_tag: env_opt(IMAGE_TAG_ENV),
        image_build_time: env_opt(IMAGE_BUILD_TIME_ENV),
    }
}

impl BuildInfo {
    /// The stamp WITHOUT the leading service name: what `--version` prints.
    ///
    /// clap already prefixes its output with the binary name, so repeating the service there reads
    /// as a stutter (`lightbridge-authz lightbridge-authz 0.8.1 …`). Everything after the name is
    /// identical to [`BuildInfo::summary`], which is the form the startup log wants.
    ///
    /// Unknown image fields are omitted rather than printed as `none` — a shell reader scanning
    /// this wants the fields that mean something, and their absence already says "not from an
    /// image".
    pub fn stamp(&self) -> String {
        let mut line = format!(
            "{} ({}{}, {}) built {} with {}",
            self.version,
            self.git_short_sha,
            if self.git_dirty { "-dirty" } else { "" },
            self.git_commit_date,
            self.build_time,
            self.rustc_version,
        );
        if let Some(tag) = &self.image_tag {
            line.push_str(&format!(" image {tag}"));
        }
        if let Some(sha) = &self.image_build_sha {
            line.push_str(&format!(" image-sha {sha}"));
        }
        line
    }

    /// One dense line for a human, service name first: what the `service.build` startup log line
    /// carries as its message.
    pub fn summary(&self) -> String {
        format!("{} {}", self.service, self.stamp())
    }
}

/// Emits the `service.build` startup line, once, from every server entry point.
///
/// Structured fields, not just the summary string: an operator grepping logs for "which commit is
/// this pod on" filters on `git_sha`, and a log aggregator can facet on `service`. The summary
/// rides along as the human-readable message.
pub fn log_build_info(service: &str) {
    let info = build_info(service);
    tracing::info!(
        target: "service.build",
        service = %info.service,
        version = %info.version,
        git_sha = %info.git_sha,
        git_commit_date = %info.git_commit_date,
        git_dirty = info.git_dirty,
        rustc_version = %info.rustc_version,
        build_time = %info.build_time,
        image_build_sha = info.image_build_sha.as_deref().unwrap_or(UNKNOWN),
        image_tag = info.image_tag.as_deref().unwrap_or(UNKNOWN),
        image_build_time = info.image_build_time.as_deref().unwrap_or(UNKNOWN),
        "{}",
        info.summary()
    );
}

#[cfg(test)]
mod build_probe {
    //! The build script's decision table, compiled a second time into the test binary.
    //!
    //! `build.rs` `include!`s the same file, so these tests exercise the exact code that stamps
    //! the binary rather than a re-implementation of it. Without this, the git → env → `unknown`
    //! ladder would be the one piece of logic in the workspace that no test can reach.
    #![allow(dead_code)]
    include!("../build_probe.rs");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_sentinel_matches_the_build_scripts() {
        assert_eq!(UNKNOWN, build_probe::UNKNOWN);
    }

    #[test]
    fn resolve_prefers_git_over_the_environment() {
        assert_eq!(
            build_probe::resolve(Some("  abc123\n".to_owned()), Some("env-sha".to_owned())),
            "abc123"
        );
    }

    #[test]
    fn resolve_falls_back_to_the_environment_when_git_is_absent() {
        assert_eq!(
            build_probe::resolve(None, Some("env-sha".to_owned())),
            "env-sha"
        );
    }

    #[test]
    fn resolve_treats_blank_git_output_as_absent() {
        assert_eq!(
            build_probe::resolve(Some("   \n".to_owned()), Some("env-sha".to_owned())),
            "env-sha"
        );
    }

    #[test]
    fn resolve_reports_unknown_when_nothing_answers() {
        assert_eq!(build_probe::resolve(None, None), UNKNOWN);
        assert_eq!(build_probe::resolve(None, Some(String::new())), UNKNOWN);
    }

    #[test]
    fn short_sha_takes_seven_characters_but_never_truncates_the_sentinel() {
        assert_eq!(
            build_probe::short_sha("0123456789abcdef0123456789abcdef01234567"),
            "0123456"
        );
        assert_eq!(build_probe::short_sha(UNKNOWN), UNKNOWN);
        assert_eq!(build_probe::short_sha("abc"), "abc");
    }

    #[test]
    fn source_date_epoch_becomes_rfc3339_utc() {
        assert_eq!(
            build_probe::rfc3339_from_epoch("1700000000"),
            Some("2023-11-14T22:13:20Z".to_owned())
        );
        assert_eq!(build_probe::rfc3339_from_epoch("not-a-number"), None);
    }

    #[test]
    fn commit_date_falls_back_to_source_date_epoch_then_unknown() {
        assert_eq!(
            build_probe::resolve_commit_date(
                Some("2026-09-03T10:00:00+02:00".to_owned()),
                Some("1700000000".to_owned())
            ),
            "2026-09-03T10:00:00+02:00"
        );
        assert_eq!(
            build_probe::resolve_commit_date(None, Some("1700000000".to_owned())),
            "2023-11-14T22:13:20Z"
        );
        // A malformed epoch is not propagated as a bogus date.
        assert_eq!(
            build_probe::resolve_commit_date(None, Some("garbage".to_owned())),
            UNKNOWN
        );
        assert_eq!(build_probe::resolve_commit_date(None, None), UNKNOWN);
    }

    #[test]
    fn build_time_honours_source_date_epoch_over_the_clock() {
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp(1, 0).expect("valid timestamp");
        assert_eq!(
            build_probe::resolve_build_time(Some("1700000000".to_owned()), now),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            build_probe::resolve_build_time(None, now),
            "1970-01-01T00:00:01Z"
        );
    }

    #[test]
    fn build_info_reports_the_compiled_in_stamp() {
        let info = build_info("authz-api");
        assert_eq!(info.service, "authz-api");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        // Whatever the build context was, every compile-time field is non-empty — the whole point
        // of the `unknown` sentinel is that no field is ever blank.
        assert!(!info.git_sha.is_empty());
        assert!(!info.git_short_sha.is_empty());
        assert!(!info.git_commit_date.is_empty());
        assert!(!info.rustc_version.is_empty());
        assert!(!info.build_time.is_empty());
    }

    #[test]
    fn serialization_is_camel_case_and_keeps_unknown_image_fields_null() {
        let info = BuildInfo {
            service: "authz-idp".to_owned(),
            version: "1.2.3".to_owned(),
            git_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_short_sha: "0123456".to_owned(),
            git_commit_date: "2026-09-03T08:00:00Z".to_owned(),
            git_dirty: false,
            rustc_version: "rustc 1.90.0".to_owned(),
            build_time: "2026-09-03T09:00:00Z".to_owned(),
            image_build_sha: None,
            image_tag: None,
            image_build_time: None,
        };
        let json = serde_json::to_value(&info).expect("serializes");
        assert_eq!(json["service"], "authz-idp");
        assert_eq!(json["gitShortSha"], "0123456");
        assert_eq!(json["gitDirty"], false);
        assert_eq!(json["rustcVersion"], "rustc 1.90.0");
        assert!(json["imageBuildSha"].is_null());
        assert!(json["imageTag"].is_null());
        assert!(json["imageBuildTime"].is_null());
        // Round-trips: the console deserializes this exact shape.
        let back: BuildInfo = serde_json::from_value(json).expect("deserializes");
        assert_eq!(back, info);
    }

    #[test]
    fn summary_names_the_service_commit_and_image() {
        let info = BuildInfo {
            service: "authz-budget".to_owned(),
            version: "1.2.3".to_owned(),
            git_sha: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            git_short_sha: "0123456".to_owned(),
            git_commit_date: "2026-09-03T08:00:00Z".to_owned(),
            git_dirty: true,
            rustc_version: "rustc 1.90.0".to_owned(),
            build_time: "2026-09-03T09:00:00Z".to_owned(),
            image_build_sha: Some("deadbeef".to_owned()),
            image_tag: Some("ghcr.io/adorsys-gis/lightbridge-authz:main".to_owned()),
            image_build_time: Some("2026-09-03T09:30:00Z".to_owned()),
        };
        let summary = info.summary();
        assert!(summary.starts_with("authz-budget 1.2.3 (0123456-dirty, 2026-09-03T08:00:00Z)"));
        assert!(summary.contains("rustc 1.90.0"));
        assert!(summary.contains("image ghcr.io/adorsys-gis/lightbridge-authz:main"));
        assert!(summary.contains("image-sha deadbeef"));
        // `--version` drops the leading service name, because clap already printed the binary name.
        assert_eq!(summary, format!("authz-budget {}", info.stamp()));
        assert!(info.stamp().starts_with("1.2.3 ("));
    }

    #[test]
    fn summary_omits_image_fields_when_there_is_no_image() {
        let mut info = build_info("authz-opa");
        info.image_tag = None;
        info.image_build_sha = None;
        let summary = info.summary();
        assert!(!summary.contains("image "));
        assert!(summary.starts_with("authz-opa "));
    }
}

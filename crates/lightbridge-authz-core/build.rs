//! Bakes the build stamp (#573) into every binary in this workspace.
//!
//! Every service crate depends on `lightbridge-authz-core`, so stamping it here — once — is what
//! makes `authz-api`, `authz-opa`, `authz-idp`, `authz-budget`, `authz-usage` and `lightbridge-mcp`
//! all report the same commit without six copies of this script.
//!
//! # Two build contexts, one answer
//!
//! * **CI and local dev** compile with the repository checked out, so `git` answers directly.
//!   (`.github/actions/build-binaries` builds the musl binaries on the runner, inside the
//!   `actions/checkout` tree — `.git` is present there.)
//! * **`Dockerfile`'s in-container build** bind-mounts only `Cargo.toml`, `Cargo.lock`, `app/`,
//!   `crates/` and the migration dirs. There is no `.git`, so `git` fails and the environment
//!   answers instead: `GIT_SHA`, `GIT_COMMIT_DATE`, `SOURCE_DATE_EPOCH`.
//!
//! The decision table itself lives in `build_probe.rs`, `include!`d below, so it can be unit
//! tested from `src/build_info.rs` (a build script is otherwise untestable).
//!
//! # What this script does NOT stamp
//!
//! The Docker image's own SHA and tag. Those are not knowable while compiling: CI builds the
//! binaries in one job and the image in a later one, so the image identity does not exist yet.
//! They arrive at RUNTIME through `IMAGE_BUILD_SHA` / `IMAGE_TAG` / `IMAGE_BUILD_TIME`, set as
//! `ENV` from `ARG`s by both Dockerfiles — see `src/build_info.rs`.

include!("build_probe.rs");

use std::process::Command;

/// Runs a `git` command in the crate directory, returning its trimmed stdout on success.
///
/// Any failure — git not installed, `.git` absent, a non-zero exit, non-UTF-8 output — collapses
/// to `None`, which is the signal for the environment fallback. Failing the build because a
/// version string could not be computed would be absurd.
fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn emit(key: &str, value: &str) {
    println!("cargo:rustc-env={key}={value}");
}

fn main() {
    // Overriding the default "rerun when any file in the package changed" is intentional: this
    // script's output depends on git state and environment, not on the crate's sources. The crate
    // still recompiles normally on source edits; only the script's re-execution is narrowed.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_probe.rs");
    // `.git/HEAD` moves on every checkout/commit; the ref file it points at moves when the current
    // branch advances. Both are relative to the crate dir, hence the `../../` hops.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    for key in ["GIT_SHA", "GIT_COMMIT_DATE", "SOURCE_DATE_EPOCH"] {
        println!("cargo:rerun-if-env-changed={key}");
    }

    let sha = resolve(git(&["rev-parse", "HEAD"]), std::env::var("GIT_SHA").ok());
    emit("LB_GIT_SHA", &sha);
    emit("LB_GIT_SHORT_SHA", &short_sha(&sha));

    let commit_date = resolve_commit_date(
        git(&["show", "-s", "--format=%cI", "HEAD"]),
        std::env::var("SOURCE_DATE_EPOCH")
            .ok()
            .or_else(|| std::env::var("GIT_COMMIT_DATE").ok()),
    );
    emit("LB_GIT_COMMIT_DATE", &commit_date);

    // `--porcelain` prints one line per modified path and nothing at all for a clean tree, so
    // "has output" IS "dirty". A tree we could not inspect is reported as clean rather than
    // guessed dirty: the SHA is already `unknown` in that case, which carries the same warning
    // without a second misleading flag.
    let dirty = git(&["status", "--porcelain"])
        .map(|out| !out.trim().is_empty())
        .unwrap_or(false);
    emit("LB_GIT_DIRTY", if dirty { "true" } else { "false" });

    // `$RUSTC` is what cargo itself is invoking, which is not necessarily the `rustc` on `PATH`
    // (rustup shims, cross-compiles, a pinned toolchain). Ask the compiler actually in use.
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rustc_version = resolve(
        Command::new(rustc)
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok()),
        None,
    );
    emit("LB_RUSTC_VERSION", &rustc_version);

    emit(
        "LB_BUILD_TIME",
        &resolve_build_time(std::env::var("SOURCE_DATE_EPOCH").ok(), chrono::Utc::now()),
    );
}

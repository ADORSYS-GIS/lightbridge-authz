//! `lightbridge-authz idp jwk {list,new,rotate}` -- explicit signing-key management for operators
//! (via `kubectl debug` or an init container), alongside the existing 30-day age-based
//! auto-rotation (`lightbridge_authz_rest::signing::bootstrap_signing_key`,
//! `oauth2_op::refresh_signing::bootstrap_idp_signing_keys`).
//!
//! `list` never selects `signing_keys.private_key_pem` at all (see
//! [`SigningKeyMeta`](lightbridge_authz_api_key::entities::signing_key_row::SigningKeyMeta)) --
//! there is no code path through which it could reach stdout or logs.
//!
//! `new` refuses to rotate a purpose that already has an active key: surprising an operator with a
//! silent rotation is worse than an error telling them to use `rotate` instead. `rotate` always
//! forces a fresh key via the same advisory-lock-serialized
//! [`StoreRepo::ensure_active_signing_key`], so both are safe to run concurrently across replicas.
//!
//! Exposed from the crate's lib target (`pub mod jwk_cmd;` in `lib.rs`) rather than kept
//! bin-private like `main.rs`'s `utils`/`migrate`/`idp_cmd` modules, purely so integration tests
//! (`tests/jwk_cmd_tests.rs`) can call it directly instead of spawning the built binary.

use std::sync::Arc;

use chrono::Utc;
use clap::ValueEnum;
use lightbridge_authz_api_key::entities::signing_key_row::{
    NewSigningKey, SigningKeyMeta, SigningKeyRow,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::error::{Error, Result};
use lightbridge_authz_rest::oauth2_op::refresh_signing::mint_path_cutoff;
use lightbridge_authz_rest::signing::generate_rs256_key;

/// `--type access|refresh`. Named after, and matching verbatim, `signing_keys.purpose`'s two
/// values (AGENTS.md: "one name per thing" -- do not invent a second vocabulary here).
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyPurpose {
    Access,
    Refresh,
}

impl KeyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyPurpose::Access => "access",
            KeyPurpose::Refresh => "refresh",
        }
    }
}

/// The three `jwk` operations, decoupled from `cli.rs`'s clap `Subcommand` shape so this module's
/// public API does not depend on how the binary happens to parse its arguments.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum JwkAction {
    List,
    New(KeyPurpose),
    /// The `bool` is `--yes`; see [`rotate_key`] for why rotation alone requires it.
    Rotate(KeyPurpose, bool),
}

/// Entry point: loads config, connects to Postgres (no Redis -- signing keys are DB-only), and
/// dispatches. Mirrors the connection setup every other `Commands` arm in `main.rs` already does.
pub async fn run(config_path: &str, action: JwkAction) -> Result<()> {
    let config = load_from_path(config_path)?;
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);
    let repo = StoreRepo::new(pool);
    dispatch(&repo, action).await
}

/// The part of [`run`] that touches `signing_keys`, taking an already-built [`StoreRepo`] rather
/// than a config path -- split out so integration tests can exercise it directly against a real
/// (test-provisioned) database without round-tripping through a config file on disk.
pub async fn dispatch(repo: &StoreRepo, action: JwkAction) -> Result<()> {
    match action {
        JwkAction::List => list(repo).await,
        JwkAction::New(purpose) => new_key(repo, purpose).await,
        JwkAction::Rotate(purpose, confirmed) => rotate_key(repo, purpose, confirmed).await,
    }
}

async fn active_for(repo: &StoreRepo, purpose: KeyPurpose) -> Result<Option<SigningKeyRow>> {
    match purpose {
        KeyPurpose::Access => repo.get_active_signing_key().await,
        KeyPurpose::Refresh => repo.get_active_refresh_signing_key().await,
    }
}

/// Pure formatter, split out from [`list`] so it can be tested without a database -- the hard
/// requirement is that `signing_keys.private_key_pem` never reaches this output, and
/// [`SigningKeyMeta`] structurally cannot carry it (the query behind it never selects the column).
pub fn format_signing_keys(keys: &[SigningKeyMeta]) -> String {
    if keys.is_empty() {
        return "No signing keys found.".to_string();
    }
    let mut out = format!("{:<26}{:<9}{:<8}CREATED_AT\n", "KID", "PURPOSE", "STATUS");
    for key in keys {
        out.push_str(&format!(
            "{:<26}{:<9}{:<8}{}\n",
            key.kid, key.purpose, key.status, key.created_at
        ));
    }
    out
}

async fn list(repo: &StoreRepo) -> Result<()> {
    let keys = repo.list_signing_keys().await?;
    println!("{}", format_signing_keys(&keys).trim_end());
    Ok(())
}

fn candidate(purpose: KeyPurpose, created_at: chrono::DateTime<Utc>) -> Result<NewSigningKey> {
    let generated = generate_rs256_key()?;
    Ok(NewSigningKey {
        kid: generated.kid,
        algorithm: "RS256".to_string(),
        private_key_pem: generated.private_key_pem,
        public_jwk: generated.public_jwk,
        purpose: purpose.as_str().to_string(),
        created_at,
    })
}

/// Creates an active key for `purpose` only if none exists yet. Refuses (`Error::Conflict`,
/// non-zero exit) rather than silently rotating when one is already active -- the operator asked
/// for `new`, not `rotate`. The far-past cutoff from `mint_path_cutoff` means the underlying
/// `ensure_active_signing_key` call itself can also never rotate a live key, so a race against a
/// concurrent `new`/bootstrap on another replica still lands on exactly one active key, never two.
async fn new_key(repo: &StoreRepo, purpose: KeyPurpose) -> Result<()> {
    if let Some(existing) = active_for(repo, purpose).await? {
        return Err(Error::Conflict(format!(
            "an active {} signing key already exists (kid={}, created_at={}); use `rotate` to replace it",
            purpose.as_str(),
            existing.kid,
            existing.created_at
        )));
    }
    let now = Utc::now();
    let created = repo
        .ensure_active_signing_key(candidate(purpose, now)?, mint_path_cutoff())
        .await?;
    println!(
        "created new {} signing key: kid={}",
        purpose.as_str(),
        created.kid
    );
    Ok(())
}

/// Forces rotation for `purpose`: retires the current active key (if any) and activates a fresh
/// one, via the same advisory-lock `ensure_active_signing_key` path the age-based auto-rotation
/// uses -- passing `now` as the cutoff means any existing active key (necessarily created before
/// `now`) is always due for rotation.
/// `confirmed` is `--yes`. Refused without it: `list` and `new` are safe to fat-finger, this is
/// not -- it retires the key currently signing tokens. Already-issued tokens keep validating
/// (retired keys stay in the verification set), so the blast radius is bounded, but an accidental
/// rotation is still a real event and there is no interactive prompt available in the `kubectl
/// exec`/init-container contexts this command exists for.
async fn rotate_key(repo: &StoreRepo, purpose: KeyPurpose, confirmed: bool) -> Result<()> {
    if !confirmed {
        return Err(Error::Conflict(format!(
            "refusing to rotate the {} signing key without --yes: this retires the key currently \
             signing tokens",
            purpose.as_str()
        )));
    }
    let old = active_for(repo, purpose).await?;
    let now = Utc::now();
    let new = repo
        .ensure_active_signing_key(candidate(purpose, now)?, now)
        .await?;
    match old {
        Some(old) => println!(
            "rotated {} signing key: old_kid={} new_kid={}",
            purpose.as_str(),
            old.kid,
            new.kid
        ),
        None => println!(
            "no existing {} signing key; created kid={}",
            purpose.as_str(),
            new.kid
        ),
    }
    Ok(())
}

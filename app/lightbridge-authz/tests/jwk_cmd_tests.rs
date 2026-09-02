// Integration tests are their own crates, so clippy's `allow-unwrap-in-tests`
// (clippy.toml) does not reach their free helper functions. Unwrapping in a test
// is a deliberate assertion that the setup held; the workspace gate stays `deny`
// for shipping code.
#![allow(clippy::unwrap_used)]

//! Tests for `lightbridge-authz idp jwk {list,new,rotate}` (`app/lightbridge-authz/src/jwk_cmd.rs`).
//!
//! `format_signing_keys_never_contains_pem_material` runs unconditionally (no database needed):
//! it exercises the hard "never print `signing_keys.private_key_pem`" requirement directly.
//! Everything that exercises `jwk_cmd::dispatch` against a real `signing_keys` table lives in the
//! `db` module, gated behind `it-tests` like every other Postgres-backed test in this workspace
//! (see `crates/lightbridge-authz-rest/tests/signing_tests.rs`'s own `db` module for the same
//! pattern).

use chrono::Utc;
use lightbridge_authz::jwk_cmd::format_signing_keys;
use lightbridge_authz_api_key::entities::signing_key_row::SigningKeyMeta;

fn meta(kid: &str, purpose: &str, status: &str) -> SigningKeyMeta {
    SigningKeyMeta {
        kid: kid.to_string(),
        purpose: purpose.to_string(),
        status: status.to_string(),
        created_at: Utc::now(),
        retired_at: None,
    }
}

/// The hard requirement from the task: `list`'s output must never contain private key material.
/// `SigningKeyMeta` structurally has no `private_key_pem` field (the query behind it never
/// selects the column -- see `crates/lightbridge-authz-api-key/src/signing_keys_admin.rs`), so
/// this also guards against a future edit that adds one back and wires it into the formatter.
#[test]
fn format_signing_keys_never_contains_pem_material() {
    let keys = vec![
        meta("key1access0000000000000a", "access", "active"),
        meta("key2access0000000000000b", "access", "stale"),
        meta("key1refresh000000000000c", "refresh", "active"),
    ];
    let out = format_signing_keys(&keys);
    assert!(
        !out.to_uppercase().contains("PRIVATE KEY"),
        "list output must never contain private key material, got: {out}"
    );
    assert!(out.contains("key1access0000000000000a"));
    assert!(out.contains("access"));
    assert!(out.contains("refresh"));
    assert!(out.contains("active"));
    assert!(out.contains("stale"));
}

#[test]
fn format_signing_keys_reports_empty_state() {
    assert_eq!(format_signing_keys(&[]), "No signing keys found.");
}

#[cfg(feature = "it-tests")]
mod db {
    use super::*;
    use lightbridge_authz::jwk_cmd::{JwkAction, KeyPurpose, dispatch};
    use lightbridge_authz_api_key::repo::StoreRepo;
    use lightbridge_authz_core::Error;
    use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
    use sqlx::PgPool;
    use std::sync::Arc;

    fn repo(pool: PgPool) -> StoreRepo {
        let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::from_pool(pool));
        StoreRepo::new(pool)
    }

    /// `new` creates an active key when none exists; running `new` again for the SAME purpose
    /// must refuse (never silently rotate) and leave the original key active and unchanged.
    #[sqlx::test(migrations = "../../migrations")]
    async fn new_creates_once_then_conflicts_without_rotating(pool: PgPool) {
        let repo = repo(pool);
        assert!(repo.get_active_signing_key().await.unwrap().is_none());

        dispatch(&repo, JwkAction::New(KeyPurpose::Access))
            .await
            .expect("first new must create a key");
        let first = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("active key after first new");

        let err = dispatch(&repo, JwkAction::New(KeyPurpose::Access))
            .await
            .expect_err("new must refuse when a key is already active");
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Error::Conflict, got: {err:?}"
        );

        let second = repo
            .get_active_signing_key()
            .await
            .unwrap()
            .expect("still exactly one active key");
        assert_eq!(
            first.kid, second.kid,
            "a refused `new` must never rotate the existing key"
        );
        assert_eq!(repo.list_signing_keys().await.unwrap().len(), 1);
    }

    /// `access` and `refresh` are independent purposes (the `(status, purpose)` unique index is
    /// what makes this legal) -- creating one must never conflict with, or affect, the other.
    #[sqlx::test(migrations = "../../migrations")]
    async fn new_is_scoped_per_purpose(pool: PgPool) {
        let repo = repo(pool);

        dispatch(&repo, JwkAction::New(KeyPurpose::Access))
            .await
            .expect("access key creation must succeed");
        dispatch(&repo, JwkAction::New(KeyPurpose::Refresh))
            .await
            .expect("refresh key creation must succeed independently of access");

        let access = repo.get_active_signing_key().await.unwrap().unwrap();
        let refresh = repo
            .get_active_refresh_signing_key()
            .await
            .unwrap()
            .unwrap();
        assert_ne!(access.kid, refresh.kid);
        assert_eq!(repo.list_signing_keys().await.unwrap().len(), 2);
    }

    /// `rotate` on an empty table creates the first key for that purpose (no prior key to
    /// retire).
    #[sqlx::test(migrations = "../../migrations")]
    async fn rotate_creates_a_key_when_none_exists_yet(pool: PgPool) {
        let repo = repo(pool);
        assert!(
            repo.get_active_refresh_signing_key()
                .await
                .unwrap()
                .is_none()
        );

        dispatch(&repo, JwkAction::Rotate(KeyPurpose::Refresh))
            .await
            .expect("rotate must succeed even with no prior key");

        assert!(
            repo.get_active_refresh_signing_key()
                .await
                .unwrap()
                .is_some()
        );
    }

    /// `rotate` on a purpose with an existing active key retires it (status `stale`) and
    /// activates a genuinely new key -- the core "force rotation" behavior the task requires.
    #[sqlx::test(migrations = "../../migrations")]
    async fn rotate_retires_the_old_key_and_activates_a_new_one(pool: PgPool) {
        let repo = repo(pool);
        dispatch(&repo, JwkAction::New(KeyPurpose::Access))
            .await
            .expect("seed an active access key");
        let old = repo.get_active_signing_key().await.unwrap().unwrap();

        dispatch(&repo, JwkAction::Rotate(KeyPurpose::Access))
            .await
            .expect("rotate must succeed against an existing active key");

        let new = repo.get_active_signing_key().await.unwrap().unwrap();
        assert_ne!(old.kid, new.kid, "rotate must activate a genuinely new key");

        let all = repo.list_signing_keys().await.unwrap();
        let old_row = all
            .iter()
            .find(|k| k.kid == old.kid)
            .expect("old key still listed");
        assert_eq!(
            old_row.status, "stale",
            "the previously active key must be retired, not deleted"
        );
        let new_row = all
            .iter()
            .find(|k| k.kid == new.kid)
            .expect("new key listed");
        assert_eq!(new_row.status, "active");
    }

    /// `list` surfaces every key across both purposes and every status, and -- structurally, via
    /// `SigningKeyMeta` -- never the private key.
    #[sqlx::test(migrations = "../../migrations")]
    async fn list_surfaces_every_key_across_purposes_and_statuses(pool: PgPool) {
        let repo = repo(pool);
        dispatch(&repo, JwkAction::New(KeyPurpose::Access))
            .await
            .unwrap();
        dispatch(&repo, JwkAction::New(KeyPurpose::Refresh))
            .await
            .unwrap();
        dispatch(&repo, JwkAction::Rotate(KeyPurpose::Access))
            .await
            .unwrap();

        let keys = repo.list_signing_keys().await.unwrap();
        assert_eq!(
            keys.len(),
            3,
            "2 access (1 stale, 1 active) + 1 active refresh"
        );
        assert_eq!(keys.iter().filter(|k| k.purpose == "access").count(), 2);
        assert_eq!(keys.iter().filter(|k| k.purpose == "refresh").count(), 1);
        assert_eq!(keys.iter().filter(|k| k.status == "active").count(), 2);
        assert_eq!(keys.iter().filter(|k| k.status == "stale").count(), 1);

        // Also drive it through jwk_cmd's own formatter, the same output the CLI prints.
        let rendered = format_signing_keys(&keys);
        assert!(!rendered.to_uppercase().contains("PRIVATE KEY"));
    }
}

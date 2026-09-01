//! `authkestra_op::device::DeviceCodeStore` backed by the `device_authorizations` table
//! (ADR-0012 Decision 7, #423) -- replaces `NoDeviceCodeStore`
//! (`crates/lightbridge-authz-rest/src/oauth2_op/noop_stores.rs`), which was a permanent no-op.
//!
//! Two representational gaps between the upstream trait and this repo's storage, both handled
//! here so the rest of the codebase never has to think about them:
//!
//! - **No room for `id`/`interval_secs` on the wire type.** `DeviceCodeSession` (upstream) has no
//!   `id` field at all -- [`DbDeviceCodeStore::store_device_code`] mints one via `cuid2()`
//!   (ADR-0039) on every fresh insert. It also has no `interval_secs` field, even though
//!   ADR-0012 Decision 7's table carries one -- the trait-level `store_device_code`/
//!   `update_device_code` path (which nothing in this codebase invokes yet: no client is
//!   registered for the `device_code` grant type today, so the whole flow is unreachable in
//!   production regardless) always persists [`DEFAULT_INTERVAL_SECS`], matching
//!   `authkestra_op::handlers::device_authorization::handle_device_authorization`'s own hardcoded
//!   `interval: 5`. [`create_pending_device_authorization`] below, the entry point a future
//!   `/device_authorization` endpoint ticket is expected to call directly instead of going through
//!   the generic trait method, takes an explicit `interval_secs` argument.
//! - **`store_device_code` is called twice per session, not once.** Per
//!   `authkestra_op::handlers::token::handle_device_code`'s own polling arm, a `Pending` session
//!   is re-passed to `store_device_code` on every poll purely to bump `last_polled_at` -- the
//!   upstream KV-store blanket impl this trait ships treats that as an ordinary overwrite.
//!   Overwriting the whole row here would let a stale re-store race an approval/denial CAS
//!   transition and clobber it, so this implementation instead: inserts on the first call (no
//!   existing row for that `device_code`), and on every subsequent call for the same
//!   `device_code`, CAS-touches only `last_polled_at` via
//!   [`StoreRepo::touch_device_authorization_poll`] -- silently leaving `status`/`subject` alone.
//!   See that method's own doc comment for why the guard exists.

use std::collections::HashMap;
use std::sync::Arc;

use authkestra_engine::auth::state::Identity;
use authkestra_op::OpError;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use chrono::{Duration, Utc};
use cratestack_axum::ratelimit::{RateLimitConfig, RateLimitDecision, RateLimitStore};
use lightbridge_authz_api_key::entities::device_authorization_row::{
    DeviceAuthorizationRow, NewDeviceAuthorization,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::async_trait;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::error::Error as RepoError;

/// [`Identity::provider_id`] stamped on every device-authorization identity, mirroring
/// `refresh_store::IDENTITY_PROVIDER_ID` -- every subject here is a snapshot of an upstream
/// Keycloak login (once the verification page ticket lands), never an identity this service
/// authenticated itself.
const IDENTITY_PROVIDER_ID: &str = "keycloak";

/// Matches `handle_device_authorization`'s own hardcoded `interval: 5` -- see this module's doc
/// comment for why the trait-level path has no way to receive a caller-supplied value.
const DEFAULT_INTERVAL_SECS: i32 = 5;

/// Crockford-style base32 (RFC 8628 §6.1): excludes `I`, `L`, `O`, `U` to avoid characters a user
/// could visually confuse when transcribing a short code by hand. 32 symbols, so `byte % 32` on a
/// uniformly random byte introduces no modulo bias (256 is evenly divisible by 32).
const USER_CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const USER_CODE_LEN: usize = 8;
const DEVICE_CODE_ENTROPY_BYTES: usize = 32;

/// How many fresh `(device_code, user_code)` pairs [`create_pending_device_authorization`] will
/// generate before giving up. Per the ticket's own risk mitigation ("unique index +
/// retry-on-conflict at insert time, not a pre-check-then-insert race"): a collision is only
/// possible on `user_code` in practice (`device_code`'s 256-bit entropy makes a collision there
/// astronomically unlikely) and is expected, not exceptional, given the charset's small size --
/// this is not a sign of a broken system, just birthday-bound collisions on a short code.
const MAX_GENERATION_ATTEMPTS: u32 = 5;

/// Generates a short, RFC 8628 §6.1-shaped end-user verification code: 8 characters from
/// [`USER_CODE_ALPHABET`], always upper-case. Not hyphenated -- display formatting (e.g.
/// "ABCD-1234") is a verification-page presentation concern, out of scope for this data layer.
pub fn generate_user_code() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; USER_CODE_LEN];
    OsRng.fill_bytes(&mut buf);
    buf.iter()
        .map(|b| USER_CODE_ALPHABET[(*b as usize) % USER_CODE_ALPHABET.len()] as char)
        .collect()
}

/// Generates the opaque, high-entropy device-verification code the CLI polls with. Never shown
/// to a human, so no readability constraint applies (unlike [`generate_user_code`]).
pub fn generate_device_code() -> String {
    super::random_urlsafe(DEVICE_CODE_ENTROPY_BYTES)
}

/// Strips anything that is not an ASCII alphanumeric and upper-cases the rest -- the store's own
/// last line of defense against a verification-page submission carrying stray whitespace or a
/// display hyphen the future endpoint didn't already strip, and the sole place case-insensitivity
/// (RFC 8628 §6.1) is enforced, since `generate_user_code`'s output and the table's unique index
/// are both already upper-case.
fn normalize_user_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

fn row_to_session(row: DeviceAuthorizationRow) -> Result<DeviceCodeSession, OpError> {
    let status = match row.status.as_str() {
        "pending" => DeviceCodeStatus::Pending,
        "approved" => {
            let subject = row.subject.ok_or_else(|| {
                tracing::error!(
                    device_code = %row.device_code,
                    "approved device_authorizations row has no subject, refusing to build a \
                     session for it"
                );
                OpError::Storage
            })?;
            DeviceCodeStatus::Approved(Identity {
                provider_id: IDENTITY_PROVIDER_ID.to_string(),
                external_id: subject,
                email: None,
                username: None,
                attributes: HashMap::new(),
            })
        }
        "denied" => DeviceCodeStatus::Denied,
        other => {
            // Every read path this module drives (`find_active_device_authorization_by_*`)
            // already filters out `consumed`/`expired` rows, so reaching this arm means an
            // invariant was violated elsewhere -- fail closed rather than guess.
            tracing::error!(
                status = other,
                device_code = %row.device_code,
                "unexpected device_authorizations status for a row a read path should already \
                 have filtered out"
            );
            return Err(OpError::Storage);
        }
    };
    let mut session = DeviceCodeSession::new(
        row.device_code,
        row.user_code,
        row.client_id,
        row.scope.unwrap_or_default(),
        row.expires_at,
        status,
    );
    session.last_polled_at = row.last_polled_at;
    Ok(session)
}

/// Real, Postgres-backed [`DeviceCodeStore`]. See this module's doc comment for the two
/// representational gaps this implementation papers over.
#[derive(Clone)]
pub struct DbDeviceCodeStore {
    repo: Arc<StoreRepo>,
}

impl DbDeviceCodeStore {
    pub fn new(repo: Arc<StoreRepo>) -> Self {
        Self { repo }
    }

    /// Transitions exactly one live pending device authorization to approved. Unlike the upstream
    /// trait's `update_device_code` method, this exposes the CAS result to the browser callback so
    /// it never claims success when a concurrent consume, expiry, or deny won the race.
    pub async fn approve_pending(&self, device_code: &str, subject: &str) -> Result<bool, OpError> {
        // ADR-0025: `subject` here is already the ADR-0025-resolved acting account id -- this
        // method's only production caller, `relying_party::complete`'s `Completion::Device`
        // branch, passes `identity.account_id` (the `FederatedIdentityRow` returned by
        // `persist_federated_identity`, which resolves/adopts through
        // `StoreRepo::upsert_federated_identity` before ever reaching this call). Not
        // `verify_submit`, which only looks up the pending session by `user_code` and never
        // touches subject resolution.
        self.repo
            .approve_device_authorization(
                device_code,
                &lightbridge_authz_core::identity::AccountId::assert_already_resolved(subject),
                Utc::now(),
            )
            .await
            .map(|row| row.is_some())
            .map_err(|e| {
                tracing::error!(error = %e, "failed to approve device authorization");
                OpError::Storage
            })
    }
}

#[async_trait]
impl DeviceCodeStore for DbDeviceCodeStore {
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        if !matches!(session.status, DeviceCodeStatus::Pending) {
            // Every real call site in this codebase (none reachable in production today -- see
            // this module's doc comment) only ever re-stores a `Pending` session; approving or
            // denying goes through `update_device_code`. Refuse anything else rather than accept
            // a status this method has no safe way to persist for a brand-new row.
            tracing::error!(
                device_code = %session.device_code,
                "store_device_code called with a non-Pending status, refusing"
            );
            return Err(OpError::Storage);
        }

        let scope = if session.scope.is_empty() {
            None
        } else {
            Some(session.scope.clone())
        };
        let new = NewDeviceAuthorization {
            id: cuid2(),
            device_code: session.device_code.clone(),
            user_code: session.user_code.clone(),
            client_id: session.client_id.clone(),
            project_id: None,
            scope,
            interval_secs: DEFAULT_INTERVAL_SECS,
            expires_at: session.expires_at,
        };

        match self.repo.create_device_authorization(new).await {
            Ok(_) => Ok(()),
            Err(RepoError::Conflict(_)) => {
                // The row already exists -- this is the polling re-store described in this
                // module's doc comment, not a real conflict. Touch `last_polled_at` only; a
                // no-op (`Ok(None)`) if the row has since moved past `pending` is intentionally
                // swallowed here too, mirroring how `authkestra_op`'s own polling call site
                // ignores this method's result entirely (`let _ = op_store.store_device_code(...)`).
                let now = session.last_polled_at.unwrap_or_else(Utc::now);
                self.repo
                    .touch_device_authorization_poll(&session.device_code, now)
                    .await
                    .map(|_| ())
                    .map_err(|e| {
                        tracing::error!(error = %e, "failed to touch device code last_polled_at");
                        OpError::Storage
                    })
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to persist device authorization");
                Err(OpError::Storage)
            }
        }
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        let row = self
            .repo
            .find_active_device_authorization_by_device_code(device_code, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to look up device code");
                OpError::Storage
            })?;
        row.map(row_to_session).transpose()
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        let normalized = normalize_user_code(user_code);
        let row = self
            .repo
            .find_active_device_authorization_by_user_code(&normalized, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to look up device code by user code");
                OpError::Storage
            })?;
        row.map(row_to_session).transpose()
    }

    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        let now = Utc::now();
        let result = match &session.status {
            DeviceCodeStatus::Pending => {
                self.repo
                    .touch_device_authorization_poll(
                        &session.device_code,
                        session.last_polled_at.unwrap_or(now),
                    )
                    .await
            }
            DeviceCodeStatus::Approved(identity) => {
                // Not reachable in production today (see this impl's module doc comment) --
                // `approve_pending` above is the real path. `identity.external_id` is treated the
                // same way `approve_pending` treats its own `subject`: already an ADR-0025-resolved
                // account id, not a raw upstream claim.
                self.repo
                    .approve_device_authorization(
                        &session.device_code,
                        &lightbridge_authz_core::identity::AccountId::assert_already_resolved(
                            identity.external_id.clone(),
                        ),
                        now,
                    )
                    .await
            }
            DeviceCodeStatus::Denied => {
                self.repo
                    .deny_device_authorization(&session.device_code, now)
                    .await
            }
        };
        // `Ok(None)` (the CAS guard didn't match -- the row already moved on, expired, or is
        // gone) is folded into success here, same "fire and forget" contract the trait's own
        // callers already treat this method with; nothing in this codebase inspects the return
        // value.
        result.map(|_| ()).map_err(|e| {
            tracing::error!(error = %e, "failed to update device authorization");
            OpError::Storage
        })
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
        self.repo
            .delete_device_authorization(device_code)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to delete device authorization");
                OpError::Storage
            })
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        let row = self
            .repo
            .consume_device_authorization(device_code, Utc::now())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to consume device authorization");
                OpError::Storage
            })?;
        row.map(row_to_session).transpose()
    }
}

/// Generates a fresh `(device_code, user_code)` pair and persists a `pending` row, retrying with
/// new values on a unique-constraint collision (see [`MAX_GENERATION_ATTEMPTS`]'s doc comment).
/// This is the entry point a future `/device_authorization` endpoint ticket is expected to call
/// directly -- unlike [`DeviceCodeStore::store_device_code`], which accepts a pre-built session
/// verbatim and has no room to retry with different generated values on its own, this owns the
/// whole "generate, try, regenerate on conflict" loop the ticket's Risks table calls for.
pub async fn create_pending_device_authorization(
    repo: &StoreRepo,
    client_id: &str,
    project_id: Option<&str>,
    scope: &str,
    ttl: Duration,
    interval_secs: i32,
) -> Result<DeviceCodeSession, OpError> {
    let expires_at = Utc::now() + ttl;
    let scope_owned = if scope.is_empty() {
        None
    } else {
        Some(scope.to_string())
    };

    for attempt in 0..MAX_GENERATION_ATTEMPTS {
        let new = NewDeviceAuthorization {
            id: cuid2(),
            device_code: generate_device_code(),
            user_code: generate_user_code(),
            client_id: client_id.to_string(),
            project_id: project_id.map(str::to_string),
            scope: scope_owned.clone(),
            interval_secs,
            expires_at,
        };
        match repo.create_device_authorization(new).await {
            Ok(row) => return row_to_session(row),
            Err(RepoError::Conflict(_)) => {
                tracing::warn!(
                    attempt,
                    "device_code/user_code collision generating a fresh device authorization, \
                     retrying with new values"
                );
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to persist a new device authorization");
                return Err(OpError::Storage);
            }
        }
    }
    tracing::error!(
        attempts = MAX_GENERATION_ATTEMPTS,
        "exhausted retries generating a unique device_code/user_code pair"
    );
    Err(OpError::Storage)
}

/// Rate-limits `user_code` lookups (the verification-page submission path) via the SAME
/// `RateLimitStore` infrastructure `authz-api`/`authz-budget` already use for HTTP rate limiting
/// (`crate::ratelimit_redis`) -- reused here rather than a second mechanism, per the ticket's own
/// instruction. `caller_key` is the caller-supplied rate-limit bucket key (e.g. a per-IP or
/// per-session identity from the future verification-page HTTP handler) -- this function has no
/// way to derive one itself, since `DeviceCodeStore::get_by_user_code` (the trait method this
/// deliberately does NOT implement, staying a free function instead) carries no caller-identity
/// parameter. A future verification-page ticket wires a real per-request key in; until then this
/// is dead code exercised only by this crate's own tests, exactly like
/// [`create_pending_device_authorization`] above.
///
/// Fails CLOSED on any rate-limiter error (e.g. Redis unreachable) -- refuses the lookup rather
/// than silently bypassing throttling, matching this repo's general "an unavailable dependency
/// must never become the permissive branch" rule. The database is never touched when the caller
/// is throttled or the limiter itself is unavailable -- the rate-limit check runs strictly before
/// [`StoreRepo::find_active_device_authorization_by_user_code`].
pub async fn get_by_user_code_rate_limited(
    repo: &StoreRepo,
    rate_limiter: &dyn RateLimitStore,
    rate_limit_config: RateLimitConfig,
    caller_key: &str,
    user_code: &str,
) -> Result<Option<DeviceCodeSession>, OpError> {
    match rate_limiter.consume(caller_key, rate_limit_config).await {
        Ok(RateLimitDecision::Allowed { .. }) => {}
        Ok(RateLimitDecision::Throttled { retry_after_secs }) => {
            tracing::warn!(
                caller_key,
                retry_after_secs,
                "device verification user_code lookup refused: rate limit exceeded"
            );
            return Err(OpError::Storage);
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "rate limit store unavailable, refusing device code lookup fail-closed"
            );
            return Err(OpError::Storage);
        }
    }

    let normalized = normalize_user_code(user_code);
    let row = repo
        .find_active_device_authorization_by_user_code(&normalized, Utc::now())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to look up device code by user code");
            OpError::Storage
        })?;
    row.map(row_to_session).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_user_code_uses_only_the_crockford_alphabet() {
        for _ in 0..200 {
            let code = generate_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(
                code.chars()
                    .all(|c| USER_CODE_ALPHABET.contains(&(c as u8)))
            );
            assert_eq!(code, code.to_uppercase());
        }
    }

    #[test]
    fn generated_user_code_excludes_visually_ambiguous_characters() {
        for _ in 0..200 {
            let code = generate_user_code();
            assert!(!code.contains(['I', 'L', 'O', 'U']));
        }
    }

    #[test]
    fn normalize_user_code_upper_cases_and_strips_separators() {
        assert_eq!(normalize_user_code("abcd-2345"), "ABCD2345");
        assert_eq!(normalize_user_code(" AbCd 2345 "), "ABCD2345");
    }

    #[test]
    fn generated_device_codes_are_unique_across_many_calls() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(generate_device_code()));
        }
    }
}

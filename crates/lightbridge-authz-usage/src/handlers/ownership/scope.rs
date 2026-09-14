//! Grain-scoped scope authorization for the shared ownership gate. Split out of
//! `handlers::ownership` to satisfy the LoC gate (lightbridge-governance#172); the pairing with
//! `auth.rs`/`validate.rs` is unchanged. The scope-authorization tests live in
//! `tests/ownership_scope_tests.rs` -- the integration-test tree, which the LoC gate reports but
//! never fails -- because the scope × permission matrix is too large to keep this file under the
//! 200-line ceiling with its tests inline.

use super::auth::forbidden;
use crate::models::UsageScope;
use crate::scope_authority::ScopeAuthority;
use axum::response::Response;
use lightbridge_authz_bearer::TokenInfo;
use lightbridge_authz_core::{Error, Permission};
use tracing::{info, warn};

/// The grain-specific scope model: which `UsageScope` variants a grain endpoint supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrainScope {
    /// The legacy `usage_events` grain: all five scopes (`user`, `api_key`, `project`, `account`,
    /// `all`) are supported with their existing semantics.
    Legacy,
    /// The day/seat grain (`usage_day_facts`, `usage_seat_snapshots`): only `user` (self-ownership
    /// via JWT subject) and `all` (`usage:read-all` permission) are supported. `account`,
    /// `project`, and `api_key` are rejected with `400`.
    DaySeat,
    /// The execution grain (`usage_executions` + `usage_model_calls` + `usage_tool_calls`, #726):
    /// only `user` (self-ownership via JWT subject, resolved through `usage_identities`) and `all`
    /// (`usage:read-all` permission) are supported. `account`, `project`, and `api_key` are
    /// rejected with `400` -- this grain has no per-account/per-project/per-key ownership
    /// authority.
    Execution,
}

/// Outcome of scope authorization. The caller matches on this to decide whether to proceed with
/// the query, return a `403`, or return a `400`.
#[derive(Debug)]
pub enum ScopeAuthOutcome {
    /// Authorized to proceed with the query.
    Authorized,
    /// Not authorized. The contained `Response` is a `403` ready to return.
    Forbidden(Response),
    /// The requested scope is invalid for the current grain. The contained `Error` is a
    /// `BadRequest` ready to propagate.
    BadRequest(Error),
}

/// Authorizes the caller's scope for the given grain model.
///
/// For `GrainScope::Legacy`, all five scopes are handled:
/// - `user`: self-ownership only (scope_id == token subject), or `usage:read-all` bypass (#648).
/// - `api_key`: always refused (no ownership authority).
/// - `all`: requires `usage:read-all` permission.
/// - `account`/`project`: remote scope-authority check, or `usage:read-all` bypass (#648).
///
/// For `GrainScope::DaySeat` and `GrainScope::Execution`:
/// - `user`: self-ownership only (scope_id == token subject), or `usage:read-all` bypass.
/// - `all`: requires `usage:read-all` permission.
/// - `account`/`project`/`api_key`: refused with `400`.
///
/// Takes the `scope_authority` as a trait object (rather than the whole `UsageState`) so the gate
/// is testable without constructing a full state, and so future grain handlers that never consult
/// the authority (day/seat/execution) still pass the same interface.
pub async fn authorize_scope(
    scope_authority: &dyn ScopeAuthority,
    token_info: &TokenInfo,
    scope: &UsageScope,
    scope_id: &str,
    grain: GrainScope,
) -> ScopeAuthOutcome {
    let is_usage_admin = token_info.has_permission(Permission::UsageReadAll);

    match grain {
        GrainScope::DaySeat | GrainScope::Execution => match scope {
            UsageScope::User => authorize_user_scope(token_info, scope_id, is_usage_admin),
            UsageScope::All => authorize_all_scope(is_usage_admin),
            UsageScope::Account | UsageScope::Project | UsageScope::ApiKey => {
                warn!(
                    scope = ?scope,
                    "day/seat/execution grain does not support this scope; refusing"
                );
                ScopeAuthOutcome::BadRequest(Error::BadRequest(format!(
                    "this grain does not support scope {}; only user and all are supported",
                    scope_wire_value(scope),
                )))
            }
        },
        GrainScope::Legacy => match scope {
            UsageScope::User => authorize_user_scope(token_info, scope_id, is_usage_admin),
            UsageScope::ApiKey => {
                warn!(
                    scope = ?scope,
                    "scope has no resolvable ownership authority; refusing"
                );
                ScopeAuthOutcome::Forbidden(forbidden())
            }
            UsageScope::All => authorize_all_scope(is_usage_admin),
            UsageScope::Account | UsageScope::Project => {
                if is_usage_admin {
                    info!(
                        scope = ?scope,
                        "usage:read-all holder; skipping the ownership round trip"
                    );
                    ScopeAuthOutcome::Authorized
                } else {
                    let authorized = scope_authority
                        .authorize(&token_info.iss, &token_info.sub, scope, scope_id)
                        .await;
                    match authorized {
                        Ok(true) => ScopeAuthOutcome::Authorized,
                        Ok(false) => {
                            warn!(
                                scope = ?scope,
                                scope_id = %scope_id,
                                "scope authority refused the requested scope"
                            );
                            ScopeAuthOutcome::Forbidden(forbidden())
                        }
                        // Deliberately fail-closed to 403 rather than propagating the `Err` as a
                        // 500 (the pre-extraction behavior): the trait contract is that
                        // implementations resolve authorization failures to `Ok(false)` -- the
                        // real `RemoteScopeAuthority` never returns `Err` -- so an `Err` here is
                        // an implementation bug, and "withhold" (403) is the strictest branch a
                        // caller can act on. A 500 would invite retries and could be cached
                        // differently by intermediaries; a 403 is a definitive refusal.
                        Err(err) => {
                            warn!(error = %err, "scope authority returned an error");
                            ScopeAuthOutcome::Forbidden(forbidden())
                        }
                    }
                }
            }
        },
    }
}

/// `scope=user`: self-ownership (scope_id == token subject) or `usage:read-all` bypass (#648).
fn authorize_user_scope(
    token_info: &TokenInfo,
    scope_id: &str,
    is_usage_admin: bool,
) -> ScopeAuthOutcome {
    if !is_usage_admin && scope_id != token_info.sub {
        warn!(
            scope = "user",
            "scope=user requested for a subject other than the caller's own; refusing"
        );
        ScopeAuthOutcome::Forbidden(forbidden())
    } else {
        ScopeAuthOutcome::Authorized
    }
}

/// `scope=all`: requires `usage:read-all` permission.
fn authorize_all_scope(is_usage_admin: bool) -> ScopeAuthOutcome {
    if !is_usage_admin {
        warn!(scope = "all", "scope=all requires usage:read-all; refusing");
        ScopeAuthOutcome::Forbidden(forbidden())
    } else {
        ScopeAuthOutcome::Authorized
    }
}

/// Maps a `UsageScope` to the wire string `authz-opa`'s `authorize_usage_scope` predicate
/// matches on. Used in error messages.
fn scope_wire_value(scope: &UsageScope) -> &'static str {
    match scope {
        UsageScope::Account => "account",
        UsageScope::Project => "project",
        UsageScope::User => "user",
        UsageScope::ApiKey => "api_key",
        UsageScope::All => "all",
    }
}

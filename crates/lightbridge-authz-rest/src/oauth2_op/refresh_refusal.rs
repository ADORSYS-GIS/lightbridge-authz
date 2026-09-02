//! Server-side-only structured logging for why `handle_refresh_token` refused a presented refresh
//! token. Before this module, only the reuse/replay cascade logged anything -- every other
//! refusal (JWT verification failure, an unknown/expired/revoked token, a client-binding
//! mismatch, a chain past its absolute cap, a suspended account/project) was completely silent
//! server-side, diagnosable only by reading code (two real production incidents, 2026-09).
//!
//! **The WIRE RESPONSE NEVER VARIES by reason** -- every refusal is the same uniform
//! `invalid_grant`/`server_error` `TokenErrorResponse` `handle_refresh_token` always returned.
//! Distinguishing refusal reasons on the wire would be an oracle telling an attacker whether a
//! given presented token ever existed; these helpers exist to make the reason visible in server
//! logs ONLY, bundled with constructing the unchanged wire error so each call site in
//! `store.rs` (tight LoC budget) stays one line.
//!
//! **NEVER pass the token, its hash, or any `jti`/`token_hash`** into [`log_refresh_refusal`] --
//! only `client_id`/`subject`/`chain_id`, matching this repo's existing rule against logging
//! secret-shaped material (see `classify_replayed_refresh_token`'s own doc comment).

use authkestra_op::handlers::token::TokenErrorResponse;

use super::oauth_err;

/// Logs `reason` at INFO -- not `debug!`: production runs `RUST_LOG=info`, so a `debug!` line
/// would never surface in the one environment that needs it. `subject`/`chain_id` are omitted
/// (logged as `"-"`) wherever the refusal happens before either is resolved.
pub(crate) fn log_refresh_refusal(
    reason: &'static str,
    client_id: &str,
    subject: Option<&str>,
    chain_id: Option<&str>,
) {
    tracing::info!(
        reason,
        client_id = %client_id,
        subject = subject.unwrap_or("-"),
        chain_id = chain_id.unwrap_or("-"),
        "refresh token grant refused"
    );
}

/// Logs `reason`, then returns the SAME uniform `invalid_grant` error every such refusal already
/// returned -- see the module doc comment for why the wire text itself never changes.
pub(crate) fn invalid_grant_refusal(
    reason: &'static str,
    client_id: &str,
    subject: Option<&str>,
    chain_id: Option<&str>,
) -> TokenErrorResponse {
    log_refresh_refusal(reason, client_id, subject, chain_id);
    oauth_err(
        "invalid_grant",
        "refresh_token is invalid, expired, or already used",
    )
}

/// Same as [`invalid_grant_refusal`], for the `server_error` branches (JWT verification
/// unavailable, CAS rotation failed, a dependency lookup errored) -- these are availability
/// failures, not an auth decision, but were equally silent before this module and cost nothing
/// extra to log the same way.
pub(crate) fn server_refusal(
    reason: &'static str,
    client_id: &str,
    description: &'static str,
) -> TokenErrorResponse {
    log_refresh_refusal(reason, client_id, None, None);
    oauth_err("server_error", description)
}

/// Classifies why a token found by hash (ignoring status/expiry) is not a live replay --
/// `classify_replayed_refresh_token`'s "not a replay at all" branch, used only to pick a
/// [`log_refresh_refusal`] reason string; never changes control flow. `consume_exchange_refresh_
/// token`'s CAS predicate is `status = 'active' AND expires_at > now`, so a row reachable here
/// with `status == "active"` necessarily failed on the expiry half of that predicate.
pub(crate) fn cas_miss_reason(status: &str) -> &'static str {
    match status {
        "revoked" => "revoked",
        _ => "expired",
    }
}

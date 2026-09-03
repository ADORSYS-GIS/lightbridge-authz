//! `authz-budget`'s mTLS-only internal listener block (ADR-0034, lightbridge-authz#658).
//!
//! Split out of `config/mod.rs` verbatim because that file sits on its LoC-gate ceiling, the same
//! way `claim_mapper.rs` beside it was. Nothing moved but the text: [`BudgetInternalServer`] is
//! re-exported from `crate::config`, so every existing `use` path still resolves.

use serde::Deserialize;

use super::Tls;

/// `authz-budget`'s mTLS-only internal listener (ADR-0034, lightbridge-authz#658) — see
/// [`super::Server::budget_internal`] for why it is a second listener rather than a route on the first.
///
/// A distinct type from [`super::BudgetServer`] rather than a reuse of it: the grace window below is
/// meaningful only for this listener, and a field that half of a shared type's users must ignore
/// is exactly the shape that eventually gets set on the wrong one.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetInternalServer {
    pub address: String,
    pub port: u16,
    /// `client_ca_bundle_path` is **required** here in practice — `start_budget_server` refuses to
    /// start without it. See [`super::Server::budget_internal`].
    pub tls: Tls,
    /// How long (seconds) `GET /budget/v1/remaining` may keep answering from the last known spend
    /// reading after the usage service stops responding, before it starts reporting the balance as
    /// unknowable (`503 budget_unavailable`).
    ///
    /// This is ADR-0034's *cached grace*, and it lives here rather than at the gateway because
    /// neither component downstream can express it: Envoy's Lua filter has no cross-request state,
    /// and Authorino's `metadata` cache drops an entry on a failed fetch rather than serving it
    /// stale. Zero disables stale serving entirely (an unreachable usage service becomes an
    /// immediate `503`); the default is two minutes, comfortably longer than a usage-service
    /// rollout and far shorter than a window in which an account could spend meaningfully more
    /// than the last reading showed.
    ///
    /// Raising this trades enforcement accuracy for availability, in exactly one direction: the
    /// served spend can only be *older* than reality, never newer, so a longer grace can only ever
    /// let an account spend more than it should — never less. Size it against ADR-0034's overspend
    /// window, not against how long the usage service typically takes to come back.
    #[serde(default = "default_remaining_grace_seconds")]
    pub remaining_grace_seconds: u64,
}

/// Two minutes. See [`BudgetInternalServer::remaining_grace_seconds`].
fn default_remaining_grace_seconds() -> u64 {
    120
}

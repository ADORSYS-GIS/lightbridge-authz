//! `authz-budget`'s internal listener block (ADR-0034 + its 2026-09-03 amendment,
//! lightbridge-authz#658).
//!
//! Split out of `config/mod.rs` verbatim because that file sits on its LoC-gate ceiling, the same
//! way `claim_mapper.rs` beside it was. Nothing moved but the text: [`BudgetInternalServer`] is
//! re-exported from `crate::config`, so every existing `use` path still resolves.

use serde::Deserialize;

use super::Tls;

/// `authz-budget`'s internal listener (ADR-0034, lightbridge-authz#658) — see
/// [`super::Server::budget_internal`] for why it is a second listener rather than a route on the first.
///
/// **Access control is a shared secret, not a client certificate.** ADR-0034 originally specified
/// mTLS here, copying `lightbridge-authz-usage`'s query listener (#347). That was checked against
/// the deployed Authorino and does not work: `AuthConfig.spec.metadata.http` on Authorino
/// **v0.24.0** exposes `body`, `bodyParameters`, `contentType`, `credentials`, `headers`,
/// `method`, `oauth2`, `sharedSecretRef`, `url` and `urlExpression` — and nothing that references
/// a client key/certificate pair. The deployed pod mounts only `ca.crt`. An mTLS-only listener is
/// therefore unreachable by the one caller it exists for, so the endpoint takes the credential
/// Authorino *can* send: a `sharedSecretRef` value delivered in a custom header
/// (`credentials.customHeader`, never the `Authorization` header — this route refuses that one
/// outright).
///
/// A distinct type from [`super::BudgetServer`] rather than a reuse of it: the grace window below is
/// meaningful only for this listener, and a field that half of a shared type's users must ignore
/// is exactly the shape that eventually gets set on the wrong one.
#[derive(Debug, Clone, Deserialize)]
pub struct BudgetInternalServer {
    pub address: String,
    pub port: u16,
    /// Server-side TLS for this listener. Authorino verifies this certificate against the
    /// internal CA it already mounts at `/etc/pki/tls/certs/lightbridge-ca.crt`.
    ///
    /// `tls.client_ca_bundle_path` is **optional** and normally unset: see the type-level note on
    /// why mTLS cannot be the access control here. Setting it locks Authorino out.
    pub tls: Tls,
    /// The shared secret this listener requires in [`Self::shared_secret_header`], and the ONLY
    /// access control in front of a cross-account balance read. `start_budget_server` refuses to
    /// start when it is empty — serving the route because someone configured the port and forgot
    /// the credential is precisely the silent degrade this codebase's fail-closed rule forbids.
    ///
    /// Supply it through the config's `${VAR}` interpolation from a Kubernetes Secret; the same
    /// Secret is what the AuthConfig's `metadata.http.sharedSecretRef` points at, so the two ends
    /// cannot drift.
    pub shared_secret: String,
    /// Header the secret arrives in. Must match the AuthConfig's
    /// `metadata.http.credentials.customHeader.name`.
    ///
    /// It is deliberately **not** `Authorization`: this route refuses any request carrying that
    /// header (a misrouted proxy forwarding a user's bearer token must fail loudly rather than
    /// quietly answer a cross-account question), and Authorino's own default for
    /// `sharedSecretRef` is the `Authorization` header — so the AuthConfig must set
    /// `credentials.customHeader` explicitly, and this value is what it has to say.
    #[serde(default = "default_shared_secret_header")]
    pub shared_secret_header: String,
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

/// See [`BudgetInternalServer::shared_secret_header`].
fn default_shared_secret_header() -> String {
    "x-lightbridge-budget-token".to_string()
}

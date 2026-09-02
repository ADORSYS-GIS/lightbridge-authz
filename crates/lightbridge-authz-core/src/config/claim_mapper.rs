//! `oauth2.signing.claim_mappers` — the declared extra claims `authz-idp` stamps onto the tokens
//! it mints, and the closed set of server-side facts a mapper may read.
//!
//! Split out of `config/mod.rs` (which re-exports both types verbatim, so every existing
//! `lightbridge_authz_core::config::{ClaimMapper, ClaimSource}` path still resolves) purely
//! because that file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may
//! be touched but not grown — the same reason `permission_set.rs` is separate from `authz.rs`.
//! [`ClaimSource::PlatformRoles`] (ADR-0033) is the one addition; everything else moved unchanged.

use serde::{Deserialize, Serialize};

/// One declared claim, its source, and how source values become claim values.
///
/// Deliberately data, not code: adding a role tier or renaming the RBAC claim is a values-file
/// edit, not a release. The evaluation is intentionally trivial -- lookup, map, emit -- because a
/// claim that feeds an authorization decision is the wrong place for an expression language.
///
/// # Several mappers, one claim: union, never overwrite (ADR-0033)
///
/// More than one mapper may name the same `claim`. When they do, the emitted value is the
/// DEDUPLICATED UNION of every mapper's own output, in mapper-declaration order -- not
/// last-one-wins. That is the whole mechanism by which
/// [`ClaimSource::ProjectRole`] and [`ClaimSource::PlatformRoles`] coexist on
/// `lightbridge_api_roles`: the project mapper contributes the tenant-shaped role an account owner
/// gets by default (`lightbridge-viewer`, post-cutover) and the platform mapper contributes
/// whatever `platform_role_grants` says, and a person holding both keeps both. Overwrite semantics
/// would make the roles claim depend on YAML ordering, which is exactly the kind of silent
/// authorization surprise a values-file edit must not be able to cause.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClaimMapper {
    /// The claim name to stamp, e.g. `lightbridge_api_roles` (whatever `rbac.roles_claim` names).
    pub claim: String,
    /// Where the value comes from. Server-side resolved data only.
    pub source: ClaimSource,
    /// Source value -> emitted claim values. A source value absent from this map falls through to
    /// [`ClaimMapper::default_values`].
    #[serde(default)]
    pub map: std::collections::HashMap<String, Vec<String>>,
    /// Emitted when the source resolves to a value `map` does not cover, or resolves to nothing.
    ///
    /// Defaults to EMPTY, which for the RBAC roles claim means "no permissions" -- the
    /// default-deny direction. An operator wanting a baseline role must say so explicitly.
    ///
    /// For a [`ClaimSource::PlatformRoles`] mapper this fires only when the subject holds NO
    /// active grants at all, and the sane value is `[]`: "this person was granted nothing" must
    /// contribute nothing, or the table stops being the authority it exists to be.
    #[serde(default, rename = "default")]
    pub default_values: Vec<String>,
}

/// The server-side facts a [`ClaimMapper`] may read. Closed on purpose: every variant must be
/// something this service already resolves while minting, so a mapper can never introduce a new
/// round-trip or read data the token subject does not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSource {
    /// The subject's `project_members.role` on the token's project (`lead` / `member`), or
    /// `owner` when they own the project's account and hold no roster row -- the same
    /// owner-is-implicitly-authorized rule `authorize_project_lead` applies.
    ///
    /// Resolves to exactly ONE source value, so `map` is a plain lookup.
    ProjectRole,
    /// The subject's ACTIVE rows in `platform_role_grants` (ADR-0033): every `role` whose grant
    /// has `revoked_at IS NULL`, for the person (`users.id`) behind the acting account.
    ///
    /// The one source that resolves to a LIST rather than a single value. Each resolved role is
    /// looked up in `map` independently and every hit contributes its values; a role absent from
    /// `map` contributes ITSELF verbatim, because a platform role IS already a role name -- an
    /// operator configuring this mapper wants `platform_role_grants.role` in the claim, not a
    /// translation table they have to keep in sync with the grants they hand out. An empty grant
    /// set falls through to [`ClaimMapper::default_values`] like any other unresolved source; it
    /// is emphatically NOT a lookup failure (see `resolve_mapped_claims`'s fail-closed contract --
    /// only a database error refuses the mint).
    PlatformRoles,
}

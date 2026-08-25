//! ADR-0025 ("lightbridge owns its subjects") Stage 2: the `AccountId` newtype every repository
//! method below the translation seam is typed with, instead of a raw `&str`/`String` copied off a
//! bearer claim.
//!
//! Before this stage, `accounts.id == sub` held only by convention: any `&str` that happened to
//! carry a JWT `sub` value could reach `StoreRepo::resolve_context` (or any of the other ~37
//! `subject: &str`-typed repository methods) and be treated as the acting account id, with
//! nothing at the type level distinguishing "a remote IdP subject, not yet translated" from "an
//! account id this service actually owns." [`AccountId`] closes that gap: a raw token `sub`
//! flowing into a function that now expects an `AccountId` is a compile error, not a runtime
//! authorization bug.

use std::fmt;

/// The acting person's lightbridge account id (ADR-0025). Every repository method below the
/// translation seam (`StoreRepo::resolve_account_for_federated_subject`,
/// `crates/lightbridge-authz-api-key/src/repo.rs`) is typed with this, never a raw `&str`.
///
/// **THE ONLY SANCTIONED CONSTRUCTION SITE** is the `Ok` return of
/// `StoreRepo::resolve_account_for_federated_subject`, wrapped immediately via
/// [`Self::assert_already_resolved`]. This is a documented contract, not a cross-crate-enforced
/// one -- `core` sits beneath `api-key` in this codebase's layering (AGENTS.md, "Rust Workspace
/// and Crates"), so a compiler-enforced capability token is not available here without inverting
/// that layering. Treat `assert_already_resolved` the same way this codebase already treats
/// `cuid2()` as the one chokepoint for minting an id (ADR-0039): the discipline is "call the one
/// function", not "the type system refuses any other origin."
///
/// Never construct one from a raw bearer `sub` claim, a `project.account_id`/`projects.owner`
/// column read directly, or any other string that has not passed through the resolver -- doing
/// so re-opens exactly the class of bug ADR-0025 exists to close.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(String);

impl AccountId {
    /// Escape hatch for pre-resolved seams (`handlers::AuthzStoreImpl`, the `OpaRepoTrait` impl,
    /// and any other caller wrapping a value it did not itself just resolve): calling this
    /// function is a PROMISE, on the caller's own authority, that `id` already flowed out of
    /// `StoreRepo::resolve_account_for_federated_subject` upstream -- e.g. a session row's
    /// `subject` column, an introspected API key's `owner_account_id`, or an already-minted
    /// token's own `sub` claim on its next refresh, all of which trace back to that one seam and
    /// are never re-translated. Named `assert_already_resolved`, not `new` or `from_resolved`, so
    /// a call site reads as an assertion about its own history, not a bare constructor -- see
    /// this type's own doc comment for the full contract. Nothing here checks the promise; it is
    /// exactly the shape of an `unsafe` escape hatch without the keyword. **Any new call site is
    /// review focus**: it must be traceable to an already-resolved value, never to a raw bearer
    /// claim or a foreign-table column read fresh off the wire.
    pub fn assert_already_resolved(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the underlying id, e.g. to bind it into a `sqlx` query.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AccountId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<AccountId> for String {
    fn from(id: AccountId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests {
    use super::AccountId;

    #[test]
    fn round_trips_through_display_as_str_and_into_string() {
        let id = AccountId::assert_already_resolved("acct-123");
        assert_eq!(id.as_str(), "acct-123");
        assert_eq!(id.to_string(), "acct-123");
        assert_eq!(String::from(id), "acct-123");
    }
}

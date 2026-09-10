//! Shared helpers for `lightbridge-authz rbac`: resolving `--user` to a person, and rendering a
//! grant listing.
//!
//! Split from `rbac_cmd.rs` (which holds the command dispatch and the three actions) to keep both
//! files inside the repository's 200-LoC ceiling. Both are pure enough to unit-test on their own —
//! [`format_grants`] needs no database at all, and [`resolve_user`] is the piece whose refusals
//! (`tests/rbac_cmd_tests.rs`) are the security-relevant behaviour of the whole command.

use lightbridge_authz_api_key::entities::platform_role_grant_row::PlatformRoleGrantRow;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::error::{Error, Result};

/// Resolves `--user` to a `users.id`.
///
/// A value containing `@` is treated as an email and resolved through `federated_identities`;
/// anything else is treated as a `users.id` and merely checked for existence. Both refuse rather
/// than guess.
///
/// **Ambiguity is a hard refusal, never a pick.** Two different people can genuinely share an email
/// string: `federated_identities` is unique on `(issuer, subject)`, not on `email`, so the same
/// address logged in through two realms is two rows, two accounts and two `users` rows. Choosing
/// one of them would grant admin to the wrong human, silently, and the operator would have no
/// signal that it happened. The error lists every candidate id so the retry can name one exactly.
pub async fn resolve_user(repo: &StoreRepo, needle: &str) -> Result<String> {
    let needle = needle.trim();
    if needle.is_empty() {
        return Err(Error::BadRequest("--user must not be empty".to_string()));
    }
    if !needle.contains('@') {
        return if repo.user_exists(needle).await? {
            Ok(needle.to_string())
        } else {
            Err(Error::BadRequest(format!(
                "no user with id '{needle}'; pass an email instead if you meant to search by one"
            )))
        };
    }
    let matches = repo.find_users_by_email(needle).await?;
    match matches.len() {
        0 => Err(Error::BadRequest(format!(
            "no federated identity with email '{needle}'"
        ))),
        1 => Ok(matches[0].user_id.clone()),
        _ => Err(Error::Conflict(format!(
            "email '{needle}' matches {} users ({}); pass one of those ids to --user instead",
            matches.len(),
            matches
                .iter()
                .map(|row| row.user_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Pure formatter, split out so it can be tested without a database. Lists ACTIVE grants only
/// (that is what `list_platform_role_grants` defaults to), and renders a NULL `granted_by` as the
/// explicit sentinel `CLI` rather than an empty column — "nobody granted this" and "the granter is
/// unknown" must not look the same.
pub fn format_grants(rows: &[PlatformRoleGrantRow]) -> String {
    if rows.is_empty() {
        return "No active platform role grants.".to_string();
    }
    let mut out = format!(
        "{:<28}{:<28}{:<22}{:<28}REASON\n",
        "GRANT_ID", "USER_ID", "ROLE", "GRANTED_BY"
    );
    for row in rows {
        out.push_str(&format!(
            "{:<28}{:<28}{:<22}{:<28}{}\n",
            row.id,
            row.user_id,
            row.role,
            row.granted_by.as_deref().unwrap_or("CLI"),
            row.reason.as_deref().unwrap_or("-")
        ));
    }
    out
}

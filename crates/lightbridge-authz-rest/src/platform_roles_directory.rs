//! Procedure bodies for the platform-role grant surface (ADR-0033): `listPlatformRoleGrants`,
//! `grantPlatformRole`, `revokePlatformRole` — and, re-exported from [`crate::my_access`], the
//! ungated `getMyAccess` that shares their vocabulary.
//!
//! Free functions here rather than inline in `lib.rs`'s `ProcedureRegistry` impl for the same two
//! reasons `identity_directory.rs` gives: `lib.rs` sits on its committed LoC-gate baseline and may
//! be touched but not grown, and these bodies share a body of reasoning that deserves to be read
//! in one place. The trait impl keeps only the thin, generated-signature wrappers.
//!
//! # What the schema policy does and does not do here
//!
//! Each procedure's `@allow` is the generated coarse gate — `auth() != null && auth().rpcScope ==
//! "crud" && auth().permRbacManage == true` — so a caller without `rbac:manage` is refused before
//! any of this runs, on the unary path by `rpc_authorize`'s middleware and on the `/rpc/batch`
//! path by cratestack's own per-frame policy evaluation. That gate is the WHOLE authorization
//! story: there is no per-tenant ownership relation between an admin and an arbitrary target
//! person for a `@@allow` to check, exactly as with `revokeSubjectSessions`.
//!
//! # Accounts in, people out
//!
//! `auth().id` is an ACCOUNT id; grants are keyed on `users.id`. Everything here that needs the
//! person goes through `StoreRepo::resolve_user_id_for_account` rather than assuming the two are
//! equal — they are byte-identical for every grandfathered account, but ADR-0026 lets one person
//! own several, and a platform role follows the human.

use cratestack::{CratestackContext, CratestackError};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::entities::platform_role_grant_row::{
    NewPlatformRoleGrant, PlatformRoleGrantFilter, PlatformRoleGrantRow,
};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::platform_role::validate_platform_role;

use crate::handlers::AuthzStoreImpl;
use crate::{subject_from_ctx, to_cratestack_error};

/// The caller's subject (`auth().id`). The `@allow` clause already asserts `auth() != null`, so
/// this is defence in depth against a context that somehow carries no subject.
fn require_subject(ctx: &CratestackContext) -> Result<String, CratestackError> {
    subject_from_ctx(ctx).ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))
}

fn to_schema_grant(row: PlatformRoleGrantRow) -> schema::PlatformRoleGrant {
    schema::PlatformRoleGrant {
        id: row.id,
        userId: row.user_id,
        role: row.role,
        grantedBy: row.granted_by,
        grantedAt: row.granted_at,
        revokedAt: row.revoked_at,
        reason: row.reason,
    }
}

/// `listPlatformRoleGrants`: one page of grants, newest first.
pub(crate) async fn list_platform_role_grants(
    repo: &StoreRepo,
    ctx: &CratestackContext,
    args: schema::ListPlatformRoleGrantsInput,
) -> Result<schema::PlatformRoleGrantPage, CratestackError> {
    require_subject(ctx)?;
    let filter = PlatformRoleGrantFilter {
        user_id: args.userId,
        role: args.role,
        include_revoked: args.includeRevoked.unwrap_or(false),
        after: args.after,
        limit: args.limit,
    };
    let page_size = filter.page_size();
    let rows = repo
        .list_platform_role_grants(&filter)
        .await
        .map_err(to_cratestack_error)?;
    // `listBudgetGrants`' own cursor rule: the last entry's sort key when the page came back
    // exactly full (there may be more), `None` when it came back short (nothing further).
    let next_cursor = (rows.len() == usize::try_from(page_size).unwrap_or(usize::MAX))
        .then(|| rows.last().map(|row| row.granted_at))
        .flatten();
    Ok(schema::PlatformRoleGrantPage {
        entries: rows.into_iter().map(to_schema_grant).collect(),
        nextCursor: next_cursor,
    })
}

/// `grantPlatformRole`: idempotent grant of a configured role to a person.
///
/// `known_roles` is this deployment's own `oauth2.rbac.role_permissions` catalogue; an unknown role
/// is refused rather than written, because a row for `lightbridge-admn` confers nothing while
/// looking exactly like a successful grant.
///
/// `granted_by` is the CALLING ADMIN's `users.id`, so the audit row names a person rather than
/// whichever of their accounts the console happened to be scoped to. A caller whose account has no
/// `users` row yet (the ADR-0025 bootstrap window) records `None` — the same value a CLI bootstrap
/// records, which is honest: in both cases nobody identifiable in `users` made this grant.
pub(crate) async fn grant_platform_role(
    repo: &StoreRepo,
    ctx: &CratestackContext,
    known_roles: &[String],
    args: schema::GrantPlatformRoleInput,
) -> Result<schema::PlatformRoleGrant, CratestackError> {
    let subject = require_subject(ctx)?;
    let role = validate_platform_role(&args.role, known_roles).map_err(to_cratestack_error)?;
    let granted_by = repo
        .resolve_user_id_for_account(&subject)
        .await
        .map_err(to_cratestack_error)?;
    let row = repo
        .grant_platform_role(NewPlatformRoleGrant {
            id: cuid2(),
            user_id: args.userId,
            role,
            granted_by,
            reason: args.reason,
        })
        .await
        .map_err(to_cratestack_error)?;
    Ok(to_schema_grant(row))
}

/// `revokePlatformRole`: stamp `revoked_at`, then close the person's sessions so the change bites.
///
/// The session fan-out is the load-bearing half. Stamping `revoked_at` alone would leave the person
/// holding a still-valid access token carrying the revoked role for up to a full access-token TTL,
/// and — worse — a refresh would keep re-minting it from the same live session for as long as the
/// refresh chain lived. Running the existing `revokeSubjectSessions` path for EVERY account the
/// person owns (ADR-0026: one person, many accounts, one `sessions.subject` per account) forces a
/// fresh login instead of a silent re-mint, so the worst case collapses to the remaining lifetime
/// of one already-issued access token.
///
/// Grants deliberately do NOT do this: gaining a capability a few minutes late is not a security
/// event, and logging someone out to hand them a role would be a hostile way to do it.
///
/// An already-revoked grant is REFUSED (`Conflict`) rather than silently re-stamped: the original
/// `revoked_at` is the audit fact this table exists to record.
pub(crate) async fn revoke_platform_role(
    issuer: &AuthzStoreImpl,
    ctx: &CratestackContext,
    args: schema::RevokePlatformRoleInput,
) -> Result<schema::PlatformRoleRevocation, CratestackError> {
    require_subject(ctx)?;
    let repo = &issuer.repo;
    let row = repo
        .revoke_platform_role(&args.grantId, args.reason.as_deref())
        .await
        .map_err(to_cratestack_error)?
        .ok_or_else(|| {
            CratestackError::Conflict(format!(
                "no active platform role grant with id '{}'",
                args.grantId
            ))
        })?;

    let account_ids = repo
        .account_ids_for_user(&row.user_id)
        .await
        .map_err(to_cratestack_error)?;
    let mut revoked_session_count: u64 = 0;
    for account_id in account_ids {
        revoked_session_count += issuer
            .revoke_sessions(&account_id)
            .await
            .map_err(to_cratestack_error)?;
    }

    Ok(schema::PlatformRoleRevocation {
        grant: to_schema_grant(row),
        // `i64`, not `u64`, on the wire; a session count cannot realistically overflow it, and
        // saturating is the right failure mode for a report field either way.
        revokedSessionCount: i64::try_from(revoked_session_count).unwrap_or(i64::MAX),
    })
}

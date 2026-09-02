//! `getMyAccess` (ADR-0033): what the CALLER may do, as the server itself computed it.
//!
//! The one procedure in `authz.cstack` that requires no permission at all — it is the sole entry in
//! `rpc_permission_map::AUTHENTICATED_ONLY_OP_IDS`. See that constant for why gating it would
//! defeat its purpose and why it discloses nothing the caller's own token does not already carry.
//!
//! # Read back, never re-derive
//!
//! Both halves of the answer come out of the very [`CratestackContext`] every `@allow` clause in
//! the schema is evaluated against, built once per request by
//! [`crate::auth_provider::build_context`] from the caller's real `TokenInfo::has_permission`
//! verdicts:
//!
//! - `roles` from the `roles` context extension (the raw claim strings, whatever
//!   `oauth2.rbac.roles_claim` names);
//! - `permissions` from the `auth().perm*` booleans — one per [`Permission::ALL`] variant, read
//!   back through the SAME `permission_field_name` mapping that wrote them.
//!
//! Nothing here consults `oauth2.rbac.role_permissions` a second time. That is the whole point: a
//! console that re-implemented the role → permission map would drift from the server's, and the
//! drift surfaces as a screen offering an action the backend then refuses — or, worse, hiding one
//! it would have allowed. There is exactly one map, and this reads it rather than copying it.

use cratestack::{CratestackContext, CratestackError, Value};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::Permission;

use crate::auth_provider::ROLES_CONTEXT_KEY;
use crate::rpc_authorize::permission_field_name;
use crate::{subject_from_ctx, to_cratestack_error};

/// The caller's raw role strings, or an empty list.
///
/// Absent is not an error: `build_context` inserts this extension only when the token carried a
/// non-empty roles claim, so "no roles" and "no extension" are the same fact and both mean the same
/// thing — a caller whose token grants them nothing.
fn roles_from_ctx(ctx: &CratestackContext) -> Vec<String> {
    match ctx.extensions.get(ROLES_CONTEXT_KEY) {
        Some(Value::List(values)) => values
            .iter()
            .filter_map(|value| match value {
                Value::String(role) => Some(role.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Every permission whose `auth().perm*` boolean is `true` on this context, as canonical
/// `resource:action` strings, in [`Permission::ALL`] declaration order.
///
/// A field that is missing or non-boolean counts as NOT held — fail-closed, so a context built by
/// some future path that forgot a field under-reports rather than over-reports.
fn permissions_from_ctx(ctx: &CratestackContext) -> Vec<String> {
    Permission::ALL
        .into_iter()
        .filter(|permission| {
            matches!(
                ctx.auth_field(&permission_field_name(*permission)),
                Some(Value::Bool(true))
            )
        })
        .map(|permission| permission.as_str().to_owned())
        .collect()
}

/// `getMyAccess`: `{ userId, roles, permissions }` for the authenticated caller.
///
/// `userId` is the PERSON (`users.id`) behind the acting account, not `auth().id` itself — the
/// console needs it to line the answer up against `platform_role_grants`, which is keyed on people
/// (ADR-0026: one person may own several accounts). A subject with no `accounts` row at all falls
/// back to the subject itself: that is the ADR-0025 bootstrap window, and the `accounts_set_user`
/// trigger will provision `users.id = accounts.id` the moment `createAccount` runs, so the fallback
/// is the value this will return one call later, not a guess.
pub(crate) async fn get_my_access(
    repo: &StoreRepo,
    ctx: &CratestackContext,
) -> Result<schema::MyAccess, CratestackError> {
    let subject = subject_from_ctx(ctx)
        .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))?;
    let user_id = repo
        .resolve_user_id_for_account(&subject)
        .await
        .map_err(to_cratestack_error)?
        .unwrap_or(subject);
    Ok(schema::MyAccess {
        userId: user_id,
        roles: roles_from_ctx(ctx),
        permissions: permissions_from_ctx(ctx),
    })
}

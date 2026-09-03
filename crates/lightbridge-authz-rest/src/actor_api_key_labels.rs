//! `resolveActorLabels`' fourth kind: API-key labels, row-scoped rather than permission-scoped
//! (#647, owner feedback 2026-09-03 — "can we use names on the 'Spend by API key' panel? API keys
//! do have names").
//!
//! # The problem this closes
//!
//! Every "spend by API key" panel in the console printed a raw cuid2, because the only key names
//! the console could reach were a PROJECT-scoped `listApiKeys` — so a panel that had one
//! `projectId` could label its rows and a panel that spanned several (the account-family lens at
//! `/settings/overview/usage`, the account overview's own breakdown) could not. Widening the
//! console's listing would have been an N+1 across projects; widening `resolveActorLabels`'
//! `user:read` gate would have handed every reader of a spend panel the estate-wide identity
//! surface. Neither is acceptable, so the authorization got FINER instead of looser.
//!
//! # Two callers, two authorizations, one SQL shape
//!
//! * A caller holding `user:read` resolves ANY key. That is the same estate-wide reach they
//!   already have over users, accounts and projects; a key's name adds nothing they could not
//!   already read.
//! * Everyone else resolves only the keys they can already read, and "can already read" is decided
//!   by reading the ids back through the generated `db.api_key()` delegate — the
//!   `listMyExpiringApiKeys` idiom. That means the isolation rule here IS `ApiKey`'s own compiled
//!   `@@allow("read", …)` clause (account owner OR project member, plus `apikey:read`), folded into
//!   the SQL `WHERE` by cratestack-pg with no bypass, rather than a second hand-written ownership
//!   join that could drift from the model's policy. It also means the model's `@@soft_delete`
//!   filter applies for free.
//!
//! Both paths then go through ONE query, [`StoreRepo::resolve_api_key_labels`], for the label shape
//! itself (the `projects` join the `ApiKey` model cannot express). Two round trips on the member
//! path, one on the admin path; see that function's own doc comment.
//!
//! # A stranger gets an empty list, never a 403
//!
//! An id the caller may not see is ABSENT, exactly like an id that does not exist — the same rule
//! the rest of this surface holds ("never fabricate an identity", and its mirror: never confirm
//! one). Refusing the call instead would make key existence probeable by anyone who can read the
//! difference between `403` and `200 { apiKeys: [] }`, and would take the caller's OWN resolvable
//! keys down with it in a batch that happened to contain someone else's id.

use cratestack::{CratestackContext, CratestackError};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::entities::identity_label_row::{MAX_IDENTITY_BATCH, check_batch};
use lightbridge_authz_api_key::repo::StoreRepo;
use lightbridge_authz_core::Permission;

use crate::rpc_permission_map::permission_field_name;
use crate::{has_permission, to_cratestack_error};

/// Whether this caller resolves API-key labels estate-wide (`user:read`) or only through
/// `ApiKey`'s own read policy. Derived from [`Permission::UserRead`] rather than a literal
/// `"permUserRead"` so a rename of the permission string cannot silently turn this into a field
/// nobody holds — which would fail closed to the row-scoped branch, but silently.
pub(crate) fn resolves_labels_estate_wide(ctx: &CratestackContext) -> bool {
    has_permission(ctx, &permission_field_name(Permission::UserRead))
}

/// The `apiKeys` half of `resolveActorLabels`. See this module's doc comment for the two paths.
pub(crate) async fn resolve_api_key_labels(
    db: &schema::Cratestack,
    repo: &StoreRepo,
    ctx: &CratestackContext,
    api_key_ids: &[String],
) -> Result<Vec<schema::ActorApiKeyLabel>, CratestackError> {
    // Checked BEFORE the visibility query, not only inside the repo call: the member path would
    // otherwise hand an unbounded `IN (…)` list to `db.api_key()` and get its rejection second-hand
    // — or not at all. Reject, never truncate (`identity_label_row.rs`).
    check_batch("apiKeyIds", api_key_ids).map_err(to_cratestack_error)?;
    if api_key_ids.is_empty() {
        return Ok(Vec::new());
    }

    let visible: Vec<String> = if resolves_labels_estate_wide(ctx) {
        api_key_ids.to_vec()
    } else {
        db.api_key()
            .find_many()
            .where_(schema::api_key::id().in_(api_key_ids.to_vec()))
            // Bounded even though `check_batch` already bounds the input: `limit` is what the
            // generated query carries, and stating it here means a future caller that reaches this
            // with a longer list gets a bounded query rather than an unbounded one.
            .limit(MAX_IDENTITY_BATCH as i64)
            .run(ctx)
            .await?
            .into_iter()
            .map(|key| key.id)
            .collect()
    };
    if visible.is_empty() {
        return Ok(Vec::new());
    }

    let rows = repo
        .resolve_api_key_labels(&visible)
        .await
        .map_err(to_cratestack_error)?;
    Ok(rows
        .into_iter()
        .map(|row| schema::ActorApiKeyLabel {
            apiKeyId: row.api_key_id,
            name: row.name,
            projectId: row.project_id,
            accountId: row.account_id,
            revoked: row.revoked,
        })
        .collect())
}

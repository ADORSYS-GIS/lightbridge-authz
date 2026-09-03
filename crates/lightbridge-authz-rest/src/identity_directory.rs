//! Procedure bodies for admin identity resolution (#647): `resolveUserProfiles`,
//! `resolveActorLabels` and `searchUsers`.
//!
//! Free functions here rather than inline in `lib.rs`'s `ProcedureRegistry` impl for two reasons:
//! `lib.rs` sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be
//! touched but not grown, and these three share a body of reasoning that deserves to be read in
//! one place. The trait impl keeps only the three thin, generated-signature wrappers that hand off
//! to these.
//!
//! # What the schema policy does and does not do here
//!
//! `resolveUserProfiles`' and `searchUsers`' `@allow` in `authz.cstack` is the generated coarse
//! gate — `auth() != null && auth().rpcScope == "crud" && auth().permUserRead == true` — so a
//! caller without `user:read` is refused before either runs, on the unary path by
//! `rpc_authorize`'s middleware and on the `/rpc/batch` path by cratestack's own per-frame policy
//! evaluation. That gate is the WHOLE authorization story for those two: the SQL underneath
//! applies no ownership filter whatsoever, which is exactly what "estate-wide admin labels"
//! means. There is deliberately no per-tenant second check to add.
//!
//! `resolveActorLabels` is the exception, and [`require_user_read_for_admin_kinds`] below is why.
//! Since the owner's 2026-09-03 feedback it also answers `apiKeyIds`, a kind that is NOT
//! admin-only and is row-scoped through `ApiKey`'s own `@@allow("read", …)` clause
//! (`actor_api_key_labels.rs`). A coarse op-id/`@allow` gate cannot say "these three lists need a
//! permission, that one needs a row check", so its clause is bare `auth() != null` and the
//! `user:read` requirement for the other three kinds is enforced HERE — moved, not dropped. The
//! op-id moved to `AUTHENTICATED_ONLY_OP_IDS` in the same change; see that constant.
//!
//! # Never fabricate an identity
//!
//! An unknown id is simply absent from the result. Nothing here emits a placeholder row, and the
//! batch caps REJECT rather than truncate — see `identity_label_row.rs` for why.

use cratestack::{CratestackContext, CratestackError};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::entities::identity_label_row::UserProfileRow;
use lightbridge_authz_api_key::repo::StoreRepo;

use crate::actor_api_key_labels::{resolve_api_key_labels, resolves_labels_estate_wide};
use crate::{subject_from_ctx, to_cratestack_error};

/// Every procedure here requires an authenticated caller. The `@allow` clause already asserts
/// `auth() != null`, so this is defence in depth against a context that somehow carries no
/// subject, matching every other procedure in `lib.rs`.
fn require_subject(ctx: &CratestackContext) -> Result<(), CratestackError> {
    subject_from_ctx(ctx)
        .map(|_| ())
        .ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))
}

fn to_schema_user_profile(row: UserProfileRow) -> schema::UserProfile {
    schema::UserProfile {
        userId: row.user_id,
        displayName: row.display_name,
        email: row.email,
        username: row.username,
    }
}

/// `resolveUserProfiles`: display claims for a batch of user ids.
pub(crate) async fn resolve_user_profiles(
    repo: &StoreRepo,
    ctx: &CratestackContext,
    user_ids: Vec<String>,
) -> Result<schema::UserProfiles, CratestackError> {
    require_subject(ctx)?;
    let rows = repo
        .resolve_user_profiles(&user_ids)
        .await
        .map_err(to_cratestack_error)?;
    Ok(schema::UserProfiles {
        profiles: rows.into_iter().map(to_schema_user_profile).collect(),
    })
}

/// The three ESTATE-WIDE kinds still require `user:read`, and say so rather than answering empty.
///
/// Silently returning `[]` for a caller who may not ask would be the one confusion this whole
/// surface exists to prevent: an empty list already means "no row for that id", so reusing it for
/// "you may not ask" would make an unknown id and a forbidden one indistinguishable. `apiKeyIds`
/// is different and empties on purpose — see `actor_api_key_labels.rs`'s own doc comment: there,
/// absence is a ROW-level fact about ids the caller has no relationship with, and a refusal would
/// leak that the id exists.
///
/// The check is skipped entirely when all three lists are empty, so an `apiKeyIds`-only call —
/// which is exactly what an ordinary member's spend panel sends — is served rather than refused.
fn require_user_read_for_admin_kinds(
    ctx: &CratestackContext,
    args: &schema::ResolveActorLabelsInput,
) -> Result<(), CratestackError> {
    let asks_admin_kinds =
        !args.userIds.is_empty() || !args.accountIds.is_empty() || !args.projectIds.is_empty();
    if asks_admin_kinds && !resolves_labels_estate_wide(ctx) {
        return Err(CratestackError::Forbidden(
            "userIds, accountIds and projectIds require the user:read permission; apiKeyIds does              not — send only apiKeyIds"
                .to_owned(),
        ));
    }
    Ok(())
}

/// `resolveActorLabels`: one call, four kinds, one query per kind (two for `apiKeyIds` on the
/// row-scoped path).
///
/// The queries run sequentially rather than concurrently: they hit the same pool, each is a
/// single indexed `= ANY($1)` lookup capped at 200 ids, and `join!`-ing them would buy the round
/// trips' latency at the cost of holding a pool connection per kind per call. Sequential is the
/// right trade at this size; revisit only with a measurement.
pub(crate) async fn resolve_actor_labels(
    db: &schema::Cratestack,
    repo: &StoreRepo,
    ctx: &CratestackContext,
    args: schema::ResolveActorLabelsInput,
) -> Result<schema::ActorLabels, CratestackError> {
    require_subject(ctx)?;
    require_user_read_for_admin_kinds(ctx, &args)?;
    let api_keys = resolve_api_key_labels(db, repo, ctx, &args.apiKeyIds).await?;
    let users = repo
        .resolve_user_profiles(&args.userIds)
        .await
        .map_err(to_cratestack_error)?;
    let accounts = repo
        .resolve_account_labels(&args.accountIds)
        .await
        .map_err(to_cratestack_error)?;
    let projects = repo
        .resolve_project_labels(&args.projectIds)
        .await
        .map_err(to_cratestack_error)?;

    Ok(schema::ActorLabels {
        // `ActorUserLabel` deliberately carries no `username`: an actor lens shows a name and an
        // email, and `resolveUserProfiles` is right there for the caller that needs the third
        // claim. Narrower payload, same query.
        users: users
            .into_iter()
            .map(|row| schema::ActorUserLabel {
                userId: row.user_id,
                displayName: row.display_name,
                email: row.email,
            })
            .collect(),
        accounts: accounts
            .into_iter()
            .map(|row| schema::ActorAccountLabel {
                accountId: row.account_id,
                name: row.name,
                ownerUserId: row.owner_user_id,
            })
            .collect(),
        projects: projects
            .into_iter()
            .map(|row| schema::ActorProjectLabel {
                projectId: row.project_id,
                name: row.name,
                accountId: row.account_id,
            })
            .collect(),
        apiKeys: api_keys,
    })
}

/// `searchUsers`: bounded free-text search over the three display columns.
pub(crate) async fn search_users(
    repo: &StoreRepo,
    ctx: &CratestackContext,
    args: schema::SearchUsersInput,
) -> Result<schema::UserSearchResults, CratestackError> {
    require_subject(ctx)?;
    let rows = repo
        .search_user_profiles(&args.query, args.limit)
        .await
        .map_err(to_cratestack_error)?;
    Ok(schema::UserSearchResults {
        users: rows.into_iter().map(to_schema_user_profile).collect(),
    })
}

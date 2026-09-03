//! Procedure bodies for the sessions read/revoke surface (ADR-0020 Follow-up 4, #649):
//! `querySessions` and `revokeSession`.
//!
//! Free functions here rather than inline in `lib.rs`'s `ProcedureRegistry` impl, matching
//! [`crate::identity_directory`]: `lib.rs` sits on its committed LoC-gate baseline and may be
//! touched but not grown, and these two share one authorization story that deserves to be read in
//! one place. The pure helpers live in [`crate::session_query`].
//!
//! # Where authorization actually happens
//!
//! Neither procedure's schema `@allow` clause is the whole story, and they are asymmetric on
//! purpose:
//!
//! - **`querySessions`** is gated at `session:read-own` — the floor that decides who may CALL it.
//!   Which ROWS come back is decided by the `Session` model's `@@allow("read", ...)` clause, which
//!   cratestack folds into the SQL `WHERE` of the `db.session()` read below
//!   (`push_scoped_conditions`). `session:read` widens it from `subject == auth().id` to every
//!   row. There is deliberately NO handler-side subject clamp: an own-scope caller passing
//!   `subject: <someone else>` intersects the policy predicate to nothing and gets an empty page
//!   from the database itself. That is the property #649 asks for, and it holds for every filter
//!   combination because it is not a filter — it is the read policy.
//! - **`revokeSession`** is gated at `session:revoke-own`, and the widening to someone else's
//!   session IS checked here, in [`revoke_session`]. It has to be: `Session` carries no
//!   `@@allow("update", ...)` (adding one would light up the generic `model.Session.update` verb,
//!   i.e. a way to flip `status` back to `active`), and a procedure `@allow` clause can only see
//!   `auth()`, never the row a caller-supplied id names.
//!
//! # The enrichment split
//!
//! The page's rows come from the policy-scoped generated client; `subjectUserId`/`offline` are
//! annotated afterwards by one batch query (`StoreRepo::session_listing_facts`) over the ids that
//! read already released. The annotation query applies no ownership filter, by design — it is
//! never given an id the policy did not hand back.

use std::collections::HashMap;

use chrono::Utc;
use cratestack::{CratestackContext, CratestackError, FilterExpr};
use lightbridge_authz_api::schema;
use lightbridge_authz_api_key::entities::session_row::SessionFactsRow;
use lightbridge_authz_api_key::repo::StoreRepo;

use crate::session_query::{
    STATUS_ACTIVE, STATUS_REVOKED, SessionCursor, SessionStatusFilter, decode_cursor,
    encode_cursor, parse_status_filter, resolve_limit, to_schema_session_row,
};
use crate::{has_permission, subject_from_ctx, to_cratestack_error};

/// The caller's own subject, or `Unauthorized`. The `@allow` clause already asserts
/// `auth() != null`; this is defence in depth against a context carrying no subject, matching
/// every other procedure in `lib.rs`.
fn require_subject(ctx: &CratestackContext) -> Result<String, CratestackError> {
    subject_from_ctx(ctx).ok_or_else(|| CratestackError::Unauthorized("missing subject".to_owned()))
}

/// `querySessions`: one policy-scoped page, annotated with the two facts the row cannot answer.
pub(crate) async fn query_sessions(
    db: &schema::Cratestack,
    repo: &StoreRepo,
    ctx: &CratestackContext,
    args: schema::QuerySessionsInput,
) -> Result<schema::SessionPage, CratestackError> {
    require_subject(ctx)?;
    let status = parse_status_filter(args.status.as_deref())?;
    let limit = resolve_limit(args.limit);
    // ONE `now` for the whole call: the same instant decides which rows the `expired`/`active`
    // filters select and what `status`/`expired` report on the way out, so a page can never
    // contain a row that contradicts the filter that selected it.
    let now = Utc::now();

    let mut query = db
        .session()
        .find_many()
        .where_optional(args.kind.map(|kind| schema::session::kind().eq(kind)))
        .where_optional(
            args.accountId
                .map(|account_id| schema::session::accountId().eq(account_id)),
        )
        .where_optional(
            args.subject
                .map(|subject| schema::session::subject().eq(subject)),
        )
        .where_optional(
            args.clientId
                .map(|client_id| schema::session::clientId().eq(client_id)),
        )
        .order_by(schema::session::createdAt().desc())
        .order_by(schema::session::id().desc())
        .limit(limit);

    query = match status {
        SessionStatusFilter::Active => query
            .where_(schema::session::status().eq(STATUS_ACTIVE.to_owned()))
            .where_(schema::session::expiresAt().gt(now)),
        SessionStatusFilter::Expired => query
            .where_(schema::session::status().eq(STATUS_ACTIVE.to_owned()))
            .where_(schema::session::expiresAt().lte(now)),
        SessionStatusFilter::Revoked => {
            query.where_(schema::session::status().eq(STATUS_REVOKED.to_owned()))
        }
        SessionStatusFilter::All => query,
    };

    if let Some(after) = args.after.as_deref() {
        let cursor = decode_cursor(after)?;
        // `(created_at, id) < (cursor)` spelled out, because a row-value comparison is not part of
        // the filter DSL. Strictly-older OR same-instant-lower-id: the tie arm is what makes the
        // boundary total, so no row is served twice or skipped when several share a timestamp.
        query = query.where_expr(FilterExpr::any([
            FilterExpr::from(schema::session::createdAt().lt(cursor.created_at)),
            FilterExpr::all([
                FilterExpr::from(schema::session::createdAt().eq(cursor.created_at)),
                FilterExpr::from(schema::session::id().lt(cursor.id)),
            ]),
        ]));
    }

    let sessions = query.run(ctx).await?;

    let ids: Vec<String> = sessions.iter().map(|s| s.id.clone()).collect();
    let facts: HashMap<String, SessionFactsRow> = repo
        .session_listing_facts(&ids)
        .await
        .map_err(to_cratestack_error)?
        .into_iter()
        .map(|row| (row.session_id.clone(), row))
        .collect();

    // A full page always carries a cursor, a short page never does. Proving a full page is
    // actually the last one would cost an extra row read on every page; an empty final fetch is
    // the cheaper way to learn it.
    let next = (sessions.len() as i64 == limit)
        .then(|| {
            sessions.last().map(|last| {
                encode_cursor(&SessionCursor {
                    created_at: last.createdAt,
                    id: last.id.clone(),
                })
            })
        })
        .flatten();

    let rows = sessions
        .into_iter()
        .map(|session| {
            let fact = facts.get(&session.id);
            to_schema_session_row(session, fact, now)
        })
        .collect();

    Ok(schema::SessionPage { rows, next })
}

/// `revokeSession`: close one session and the refresh chain hanging off it.
///
/// Reads the target's owner first and decides, in this order: unknown id -> `NotFound`; someone
/// else's session without `session:revoke` -> `Forbidden`; otherwise revoke. The two refusals stay
/// distinct because a session id is an opaque CUID2 nobody can enumerate, so a `403` only confirms
/// existence to a caller who already held the id.
pub(crate) async fn revoke_session(
    repo: &StoreRepo,
    ctx: &CratestackContext,
    args: schema::RevokeSessionInput,
) -> Result<schema::RevokeSessionResult, CratestackError> {
    let caller = require_subject(ctx)?;
    let target = repo
        .find_session_owner(&args.id)
        .await
        .map_err(to_cratestack_error)?
        .ok_or_else(|| CratestackError::NotFound("session not found".to_owned()))?;

    // A `None` subject (a session minted before the column existed) is owned by nobody, so it
    // falls to the `session:revoke` branch rather than matching whoever is asking.
    let is_own = target.subject.as_deref() == Some(caller.as_str());
    if !is_own && !has_permission(ctx, "permSessionRevoke") {
        return Err(CratestackError::Forbidden(
            "session:revoke is required to revoke another subject's session".to_owned(),
        ));
    }

    let revoked = repo
        .revoke_session_by_id(&args.id)
        .await
        .map_err(to_cratestack_error)?;
    Ok(schema::RevokeSessionResult { revoked })
}

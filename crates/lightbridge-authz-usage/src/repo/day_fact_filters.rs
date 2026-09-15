//! Scope/time/filter predicates for the day-facts grain query (#727). Split out of
//! `repo/day_fact_query.rs` to satisfy the LoC gate (lightbridge-governance#172).

use crate::models::UsageScope;
use crate::models::day_fact::DayFactQueryRequest;
use sqlx::{Postgres, QueryBuilder};

/// Appends the time-range/scope/filter predicates for the day-facts grain query.
///
/// `scope=user` matches `df.provider_user_id = $scope_id` -- only per-user facts (org/repo-level
/// facts have `NULL` `provider_user_id` and are excluded by the equality). `scope=all` adds no
/// entity filter. The `account`/`project`/`api_key` arms are rejected with `400` at the handler
/// before this is ever called, but are fail-closed here (`AND false`) so a future caller that
/// bypasses the gate can never widen the query.
///
/// `day` is a `DATE` column, so the request's `DateTime<Utc>` bounds are converted to `NaiveDate`
/// for the half-open `[start, end)` range.
pub(super) fn push_day_fact_scope_filters(
    builder: &mut QueryBuilder<Postgres>,
    input: &DayFactQueryRequest,
) {
    builder.push("df.day >= ");
    builder.push_bind(input.start_time.date_naive());
    builder.push(" AND df.day < ");
    builder.push_bind(input.end_time.date_naive());

    match input.scope {
        UsageScope::User => {
            // `scope=user` matches `provider_user_id = $scope_id`. The gate (`authorize_user_scope`)
            // only admits `scope=user` when `scope_id == token.sub` (the Keycloak JWT subject), so
            // this assumes `provider_user_id` is written in the SAME namespace as the JWT subject.
            // The migration documents `provider_user_id` as "the join key per governance#185" and
            // the table's ids as "never joined across providers except through usage_identities" --
            // if ingest instead writes a provider-scoped id (e.g. a GitHub numeric id), this direct
            // match would return empty for every non-admin self-query and the resolution would need
            // to route through `usage_identities` like the execution grain does. There is no
            // day-facts ingest yet (#727 ships the query surface only), so this assumption is
            // unverified and MUST be settled by the ingest story before self-service scope=user is
            // relied on.
            builder.push(" AND df.provider_user_id = ");
            builder.push_bind(&input.scope_id);
        }
        UsageScope::All => {}
        _ => {
            builder.push(" AND false");
        }
    }

    if let Some(source) = &input.filters.source {
        builder.push(" AND df.source = ");
        builder.push_bind(source);
    }
    if let Some(subject_kind) = &input.filters.subject_kind {
        builder.push(" AND df.subject_kind = ");
        builder.push_bind(subject_kind.as_str());
    }
    if let Some(is_aggregate_only) = input.filters.is_aggregate_only {
        builder.push(" AND df.is_aggregate_only = ");
        builder.push_bind(is_aggregate_only);
    }
    if let Some(language) = &input.filters.language {
        builder.push(" AND df.language = ");
        builder.push_bind(language);
    }
    if let Some(editor) = &input.filters.editor {
        builder.push(" AND df.editor = ");
        builder.push_bind(editor);
    }
    if let Some(model) = &input.filters.model {
        builder.push(" AND df.model = ");
        builder.push_bind(model);
    }
}

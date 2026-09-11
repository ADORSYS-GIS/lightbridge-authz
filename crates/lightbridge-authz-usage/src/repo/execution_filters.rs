//! Scope/time/filter predicates for the execution-grain query (#726). Split out of
//! `repo/execution.rs` to satisfy the LoC gate (lightbridge-governance#172).

use crate::models::UsageScope;
use crate::models::execution::ExecutionQueryRequest;
use sqlx::{Postgres, QueryBuilder};

/// Appends the time-range/scope/filter predicates for the execution-grain query.
///
/// `scope=user` resolves self-ownership through `usage_identities` (`e.identity_id IN (SELECT id
/// FROM usage_identities WHERE subject_id = $scope_id)`); `scope=all` adds no entity filter. The
/// `account`/`project`/`api_key` arms are rejected with `400` at the handler before this is ever
/// called, but are fail-closed here (`AND false`) so a future caller that bypasses the gate can
/// never widen the query.
pub(super) fn push_execution_scope_filters(
    builder: &mut QueryBuilder<Postgres>,
    input: &ExecutionQueryRequest,
) {
    builder.push("e.observed_at >= ");
    builder.push_bind(input.start_time);
    builder.push(" AND e.observed_at < ");
    builder.push_bind(input.end_time);

    match input.scope {
        UsageScope::User => {
            builder
                .push(" AND e.identity_id IN (SELECT id FROM usage_identities WHERE subject_id = ");
            builder.push_bind(&input.scope_id);
            builder.push(")");
        }
        UsageScope::All => {}
        _ => {
            builder.push(" AND false");
        }
    }

    if let Some(source) = &input.filters.source {
        builder.push(" AND e.source = ");
        builder.push_bind(source);
    }
    if let Some(provider) = &input.filters.provider {
        builder.push(" AND e.provider = ");
        builder.push_bind(provider);
    }
    if let Some(model) = &input.filters.model {
        builder.push(" AND mc.model = ");
        builder.push_bind(model);
    }
}

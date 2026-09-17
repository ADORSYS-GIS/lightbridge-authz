//! Execution-grain repo upserts (#588, AC2): transactional insert of executions, model calls,
//! tool calls and identity minting, with stub-before-parent and `(source, trace_id, span_id)`
//! dedup.
//!
//! ADR-0038 persistence exception, same class as `usage_events` and the day-grain upserts: a
//! natural-key upsert with `ON CONFLICT` that generated CRUD cannot express.

use std::collections::{HashMap, HashSet};

use lightbridge_authz_core::cuid::cuid2;
use lightbridge_authz_core::{Error, Result};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};

use crate::models::execution_ingest::{
    ExecutionGrainBatch, ExecutionRecord, execution_id, model_call_id, tool_call_id,
};

/// Upsert an execution-grain batch in ONE transaction.
///
/// The single transaction is load-bearing: the `usage_executions`/`usage_model_calls`/
/// `usage_tool_calls` FKs are `DEFERRABLE INITIALLY DEFERRED`, so a child may reference a parent
/// (real or stub) inserted later in the same transaction. Identity minting, execution upserts
/// and child inserts all commit together — a partial batch never lands.
pub async fn upsert_execution_grain(pool: &PgPool, batch: &ExecutionGrainBatch) -> Result<usize> {
    let mut tx = pool.begin().await?;

    let identity_ids = mint_identities(&mut tx, batch).await?;

    let mut accepted = 0usize;
    accepted += upsert_executions(&mut tx, batch, &identity_ids).await?;
    accepted += upsert_model_calls(&mut tx, batch).await?;
    accepted += upsert_tool_calls(&mut tx, batch).await?;

    tx.commit().await?;
    Ok(accepted)
}

/// Mint (or reuse) a `usage_identities` row per distinct `(source, provider_user_id)` and return
/// the `(source, subject_id) -> id` map. Provider user ids are preserved verbatim (AC3 — no
/// shape validation). Minted in ONE batched statement (not one round-trip per identity), with
/// `ON CONFLICT (source, subject_kind, subject_id) DO UPDATE ... RETURNING id` reusing existing ids.
async fn mint_identities(
    tx: &mut Transaction<'_, Postgres>,
    batch: &ExecutionGrainBatch,
) -> Result<HashMap<(String, String), String>> {
    let mut distinct: Vec<(String, String, String)> = Vec::new();
    let mut seen = HashSet::new();
    for exec in &batch.executions {
        let Some(subject_id) = &exec.provider_user_id else {
            continue;
        };
        let key = (exec.source.clone(), subject_id.clone());
        if seen.insert(key) {
            distinct.push((exec.source.clone(), subject_id.clone(), cuid2()));
        }
    }
    if distinct.is_empty() {
        return Ok(HashMap::new());
    }

    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_identities (id, source, subject_kind, subject_id) ",
    );
    builder.push_values(&distinct, |mut row, (source, subject_id, id)| {
        row.push_bind(id)
            .push_bind(source)
            .push_bind("user")
            .push_bind(subject_id);
    });
    builder.push(
        " ON CONFLICT (source, subject_kind, subject_id) \
         DO UPDATE SET subject_id = EXCLUDED.subject_id \
         RETURNING source, subject_id, id",
    );

    let rows = builder.build().fetch_all(&mut **tx).await?;

    let mut map = HashMap::new();
    for row in rows {
        let source: String = row.try_get("source")?;
        let subject_id: String = row.try_get("subject_id")?;
        let id: String = row.try_get("id")?;
        map.insert((source, subject_id), id);
    }
    Ok(map)
}

async fn upsert_executions(
    tx: &mut Transaction<'_, Postgres>,
    batch: &ExecutionGrainBatch,
    identity_ids: &HashMap<(String, String), String>,
) -> Result<usize> {
    if batch.executions.is_empty() {
        return Ok(0);
    }
    // Dedup by derived id before the multi-row statement: a single export can carry the same
    // (source, trace_id, span_id) twice, and a multi-row `ON CONFLICT DO UPDATE` refuses a row
    // that appears twice in the SAME statement (Postgres 21000). Keeping the first is safe.
    let mut seen = HashSet::new();
    let mut deduped: Vec<ExecutionRecord> = Vec::with_capacity(batch.executions.len());
    for e in &batch.executions {
        if seen.insert(execution_id(&e.source, &e.trace_id, &e.span_id)) {
            deduped.push(e.clone());
        }
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_executions \
         (id, observed_at, source, provider, trace_id, span_id, identity_id, duration_ms, \
          estimated_cost_micro_usd, raw_backend, raw_schema_version) ",
    );
    builder.push_values(&deduped, |mut row, e| {
        let identity_id = e.provider_user_id.as_ref().and_then(|uid| {
            identity_ids
                .get(&(e.source.clone(), uid.clone()))
                .map(|s| s.as_str())
        });
        row.push_bind(execution_id(&e.source, &e.trace_id, &e.span_id))
            .push_bind(e.observed_at)
            .push_bind(&e.source)
            .push_bind(&e.provider)
            .push_bind(&e.trace_id)
            .push_bind(&e.span_id)
            .push_bind(identity_id)
            .push_bind(e.duration_ms)
            .push_bind(e.estimated_cost_micro_usd)
            .push_bind(&e.raw_backend)
            .push_bind(e.raw_schema_version);
    });
    builder.push(
        " ON CONFLICT (source, trace_id, span_id) DO UPDATE SET \
         observed_at = EXCLUDED.observed_at, \
         provider = COALESCE(EXCLUDED.provider, usage_executions.provider), \
         identity_id = COALESCE(EXCLUDED.identity_id, usage_executions.identity_id), \
         duration_ms = COALESCE(EXCLUDED.duration_ms, usage_executions.duration_ms), \
         estimated_cost_micro_usd = COALESCE(EXCLUDED.estimated_cost_micro_usd, usage_executions.estimated_cost_micro_usd), \
         raw_backend = COALESCE(EXCLUDED.raw_backend, usage_executions.raw_backend), \
         raw_schema_version = COALESCE(EXCLUDED.raw_schema_version, usage_executions.raw_schema_version), \
         updated_at = now()",
    );
    let result = builder.build().execute(&mut **tx).await?;
    usize::try_from(result.rows_affected())
        .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
}

async fn upsert_model_calls(
    tx: &mut Transaction<'_, Postgres>,
    batch: &ExecutionGrainBatch,
) -> Result<usize> {
    if batch.model_calls.is_empty() {
        return Ok(0);
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_model_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, model, input_tokens, \
          output_tokens, cost_micro_usd) ",
    );
    builder.push_values(&batch.model_calls, |mut row, m| {
        row.push_bind(model_call_id(&m.source, &m.trace_id, &m.span_id))
            .push_bind(m.observed_at)
            .push_bind(&m.source)
            .push_bind(&m.execution_id)
            .push_bind(&m.trace_id)
            .push_bind(&m.span_id)
            .push_bind(&m.model)
            .push_bind(m.input_tokens)
            .push_bind(m.output_tokens)
            .push_bind(m.cost_micro_usd);
    });
    builder.push(" ON CONFLICT (source, trace_id, span_id) DO NOTHING");
    let result = builder.build().execute(&mut **tx).await?;
    usize::try_from(result.rows_affected())
        .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
}

async fn upsert_tool_calls(
    tx: &mut Transaction<'_, Postgres>,
    batch: &ExecutionGrainBatch,
) -> Result<usize> {
    if batch.tool_calls.is_empty() {
        return Ok(0);
    }
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO usage_tool_calls \
         (id, observed_at, source, execution_id, trace_id, span_id, tool_name, duration_ms) ",
    );
    builder.push_values(&batch.tool_calls, |mut row, t| {
        row.push_bind(tool_call_id(&t.source, &t.trace_id, &t.span_id))
            .push_bind(t.observed_at)
            .push_bind(&t.source)
            .push_bind(&t.execution_id)
            .push_bind(&t.trace_id)
            .push_bind(&t.span_id)
            .push_bind(&t.tool_name)
            .push_bind(t.duration_ms);
    });
    builder.push(" ON CONFLICT (source, trace_id, span_id) DO NOTHING");
    let result = builder.build().execute(&mut **tx).await?;
    usize::try_from(result.rows_affected())
        .map_err(|_| Error::Database("rows_affected overflowed usize".to_string()))
}

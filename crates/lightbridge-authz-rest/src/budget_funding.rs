//! ADR-0035 D11: `POST /budget/v1/fund`, mounted on the budget-internal listener beside (not
//! behind) the shared-secret remaining read. Callers present an authz-idp `client_credentials`
//! access token (ADR-0030: `sub = svc:<client_id>`); its `aud` must contain the configured
//! funding audience and its `sub` must map, in `funding.principals`, to the source it writes. The
//! shared secret is never accepted here: it identifies no principal, so it cannot scope sources.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::post};
use chrono::{DateTime, Utc};
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_budget::{BudgetError, CreditPool, CreditRepo, FundRequest, GrantSource};
use lightbridge_authz_core::config::FundingConfig;
use serde::{Deserialize, Serialize};

pub const BUDGET_FUND_PATH: &str = "/budget/v1/fund";

pub struct FundingState {
    pub credit: Arc<CreditRepo>,
    pub bearer: Arc<dyn BearerTokenServiceTrait>,
    pub audience: String,
    pub principals: HashMap<String, HashSet<GrantSource>>,
    /// The pool-aware ledger is on (`server.budget.settlement_seconds > 0`). Funding with it off
    /// would book credit no snapshot or reset knows how to treat, so the port refuses.
    pub settlement_on: bool,
}

/// Validates `funding.principals` at startup: every source must parse and be a funding source.
pub fn principals_from_config(
    config: &FundingConfig,
) -> Result<HashMap<String, HashSet<GrantSource>>, String> {
    let mut principals = HashMap::new();
    for (subject, sources) in &config.principals {
        let mut allowed = HashSet::new();
        for raw in sources {
            let source: GrantSource = raw.parse().map_err(|e| format!("{subject}: {e}"))?;
            if CreditPool::for_funding_source(source).is_none() {
                return Err(format!("{subject}: '{raw}' is not a funding source"));
            }
            allowed.insert(source);
        }
        principals.insert(subject.clone(), allowed);
    }
    Ok(principals)
}

pub fn funding_router(state: Arc<FundingState>) -> Router {
    Router::new()
        .route(BUDGET_FUND_PATH, post(fund))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct FundBody {
    pub budget_account_id: String,
    pub source: String,
    pub amount_micros: i64,
    pub idempotency_key: String,
    pub external_ref: Option<String>,
    pub reverses_idempotency_key: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FundResponse {
    pub grant_id: String,
    pub lot_id: String,
    pub pool: String,
    pub amount_micros: i64,
    pub lot_remaining_micros: i64,
    pub replayed: bool,
}

fn refuse(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn fund(
    State(state): State<Arc<FundingState>>,
    headers: HeaderMap,
    Json(body): Json<FundBody>,
) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        return refuse(StatusCode::UNAUTHORIZED, "a bearer token is required");
    };
    let info = match state.bearer.validate_bearer_token(token).await {
        Ok(info) if info.active => info,
        _ => return refuse(StatusCode::UNAUTHORIZED, "invalid bearer token"),
    };
    if !info.aud.iter().any(|aud| aud == &state.audience) {
        return refuse(
            StatusCode::FORBIDDEN,
            "token audience does not include the funding port",
        );
    }
    let Ok(source) = body.source.parse::<GrantSource>() else {
        return refuse(
            StatusCode::BAD_REQUEST,
            format!("unknown source '{}'", body.source),
        );
    };
    if !state
        .principals
        .get(&info.sub)
        .is_some_and(|allowed| allowed.contains(&source))
    {
        return refuse(
            StatusCode::FORBIDDEN,
            format!("'{}' may not write '{source}'", info.sub),
        );
    }
    if !state.settlement_on {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "settlement is off; funding is disabled",
        );
    }
    if source == GrantSource::Purchase && body.expires_at.is_some() {
        // ADR-0035 *Not decided here*: paid credit does not expire until counsel says it may.
        return refuse(
            StatusCode::BAD_REQUEST,
            "a purchase cannot carry expires_at",
        );
    }

    let request = FundRequest {
        budget_account_id: body.budget_account_id,
        source,
        amount_micros: body.amount_micros,
        idempotency_key: body.idempotency_key,
        external_ref: body.external_ref,
        reverses_idempotency_key: body.reverses_idempotency_key,
        expires_at: body.expires_at,
        actor_id: Some(info.sub.clone()),
        reason: body.reason,
    };
    match state.credit.fund(request).await {
        Ok(outcome) => {
            let status = if outcome.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            tracing::info!(principal = %info.sub, %source, grant_id = %outcome.grant_id,
                replayed = outcome.replayed, "funding port booked");
            let response = FundResponse {
                grant_id: outcome.grant_id,
                lot_id: outcome.lot_id,
                pool: outcome.pool.to_string(),
                amount_micros: outcome.amount_micros,
                lot_remaining_micros: outcome.lot_remaining_micros,
                replayed: outcome.replayed,
            };
            (status, Json(response)).into_response()
        }
        Err(err) => {
            let status = match &err {
                BudgetError::InvalidAmount(_) => StatusCode::BAD_REQUEST,
                BudgetError::NotFound(_) => StatusCode::NOT_FOUND,
                BudgetError::ReversalExceedsLot { .. } | BudgetError::IdempotencyConflict(_) => {
                    StatusCode::CONFLICT
                }
                BudgetError::FundingRefused(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            if status == StatusCode::INTERNAL_SERVER_ERROR {
                tracing::error!(error = %err, "funding port failed");
            }
            refuse(status, err.to_string())
        }
    }
}

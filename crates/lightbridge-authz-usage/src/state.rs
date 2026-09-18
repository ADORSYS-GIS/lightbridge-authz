//! Shared application state and the repository trait for the usage service.
//!
//! Split out of `lib.rs` by the LoC gate (`.github/actions/loc-gate`): `UsageState` and the
//! `UsageRepoTrait`/`StoreRepo` impl are a self-contained unit that does not belong to the server
//! wiring, and keeping it here lets `lib.rs` stay under its ceiling. The pairing is unchanged --
//! `lib.rs` re-exports [`UsageState`] and [`UsageRepoTrait`] so every existing `use` path still
//! resolves, and the two files move together.

use chrono::{DateTime, Utc};
use lightbridge_authz_bearer::BearerTokenServiceTrait;
use lightbridge_authz_core::{Result, async_trait};
use std::sync::Arc;

use crate::models::day_fact::{DayFactQueryRequest, DayFactSeriesPoint};
use crate::models::day_seat::{DayFact, SeatSnapshot};
use crate::models::execution::{ExecutionQueryRequest, ExecutionSeriesPoint};
use crate::models::execution_ingest::ExecutionGrainBatch;
use crate::models::seat::{SeatSnapshotQueryRequest, SeatSnapshotSeriesPoint};
use crate::models::{UsageQueryRequest, UsageSeriesPoint};
use crate::repo::{StoreRepo, UsageEvent};
use crate::scope_authority::ScopeAuthority;

/// Shared between both listeners `start_usage_server` binds (#347): the unauthenticated ingest
/// listener (`UsageServerGroup::usage`) and the mTLS-required query listener
/// (`UsageServerGroup::query`, `/usage/v1/usage/query` + `/usage/v1/spend/query`).
///
/// The ingest listener carries no auth gate of its own beyond the ClusterIP-only mitigation
/// (`AGENTS.md`'s Security Notes) -- it never reads `bearer`/`scope_authority`. The query
/// listener's mTLS requirement is enforced at the TLS layer (`Tls::client_ca_bundle_path`) before
/// any handler here runs, but `/usage/v1/usage/query` additionally requires and validates an
/// end-user bearer token (#570, `handlers::query::query_usage`) -- `bearer`/`scope_authority`
/// below back that check. `/usage/v1/spend/query` (`handlers::spend::query_spend`) stays exempt
/// (mTLS-only, no bearer -- it is `authz-budget`'s legitimate cross-account service reader).
pub struct UsageState {
    pub repo: Arc<dyn UsageRepoTrait>,
    /// Validates the end-user bearer token `/usage/v1/usage/query` requires (#570).
    pub bearer: Arc<dyn BearerTokenServiceTrait>,
    /// Ownership authority for `/usage/v1/usage/query`'s `account`/`project` scopes (#570).
    pub scope_authority: Arc<dyn ScopeAuthority>,
    /// The raw `usage_events` retention window in days (#549). `/usage/v1/usage/query` reads raw
    /// only (the rollup does not carry latency percentiles), so a request whose `start_time` is
    /// older than this window silently has no data -- the handler ORs a range-truncation flag into
    /// `truncated` so the API never reports `truncated: false` for a range it cannot answer (P1-5).
    ///
    /// `None` when the retention job is disabled (`retention.enabled: false`): nothing is ever
    /// purged, so `usage_events` holds everything ingested and no range is truncated by retention
    /// -- the handler must not stamp `truncated: true` on a complete answer (P2).
    pub raw_days: Option<i64>,
    /// The credential-binding rules for the authenticated ingest surface (#585): the strict
    /// `sub` -> `X-Source` map and the required audience.
    ///
    /// `None` means `ingest_auth` was absent from config, and is the single source of truth for
    /// whether the `/auth/v1/otel/*` routes are mounted at all -- `build_ingest_router` derives
    /// that decision from this field rather than taking a parallel flag, so the two can never
    /// disagree. See that call site for why the surface is config-conditional today.
    ///
    /// Deny-by-default regardless: an empty `principals` map authorizes nobody, so a route that
    /// somehow stayed mounted would refuse rather than admit.
    pub ingest_auth: Option<crate::config::IngestAuthConfig>,
}

#[async_trait]
pub trait UsageRepoTrait: Send + Sync {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize>;
    /// Upserts day-grain facts into `usage_day_facts` on the natural key (#588).
    async fn upsert_day_facts(&self, facts: &[DayFact]) -> Result<usize>;
    /// Upserts seat snapshots into `usage_seat_snapshots` on the natural key (#588).
    async fn upsert_seat_snapshots(&self, snapshots: &[SeatSnapshot]) -> Result<usize>;
    /// Upserts an execution-grain batch (executions + model calls + tool calls + identities) in
    /// one transaction (#588, AC2).
    async fn upsert_execution_grain(&self, batch: &ExecutionGrainBatch) -> Result<usize>;
    /// Returns `(points, truncated)` -- see `StoreRepo::query_usage`'s doc comment for the #578
    /// truncation contract `truncated` documents.
    async fn query_usage(&self, input: &UsageQueryRequest)
    -> Result<(Vec<UsageSeriesPoint>, bool)>;
    /// Returns `(points, truncated)` for the execution grain (#726) -- see
    /// `StoreRepo::query_executions`'s doc comment for the #578 truncation contract `truncated`
    /// documents.
    async fn query_executions(
        &self,
        input: &ExecutionQueryRequest,
    ) -> Result<(Vec<ExecutionSeriesPoint>, bool)>;
    /// Returns `(points, truncated)` for the seat grain (#728) -- see
    /// `StoreRepo::query_seat_snapshots`'s doc comment for the #578 truncation contract `truncated`
    /// documents.
    async fn query_seat_snapshots(
        &self,
        input: &SeatSnapshotQueryRequest,
    ) -> Result<(Vec<SeatSnapshotSeriesPoint>, bool)>;
    /// Returns `(points, truncated)` for the day-facts grain (#727) -- see
    /// `StoreRepo::query_day_facts`'s doc comment for the #578 truncation contract `truncated`
    /// documents.
    async fn query_day_facts(
        &self,
        input: &DayFactQueryRequest,
    ) -> Result<(Vec<DayFactSeriesPoint>, bool)>;
    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>>;
    /// Reads the last successful retention purge cutoff (P2) -- `None` when the job has never run,
    /// so no range is truncated by retention. See `StoreRepo::last_purge_cutoff`.
    async fn last_purge_cutoff(&self) -> Result<Option<DateTime<Utc>>>;
}

#[async_trait]
impl UsageRepoTrait for StoreRepo {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        StoreRepo::insert_usage_events(self, events).await
    }

    async fn upsert_day_facts(&self, facts: &[DayFact]) -> Result<usize> {
        crate::repo::day_grain::upsert_day_facts(self.pool(), facts).await
    }

    async fn upsert_seat_snapshots(&self, snapshots: &[SeatSnapshot]) -> Result<usize> {
        crate::repo::day_grain::upsert_seat_snapshots(self.pool(), snapshots).await
    }

    async fn upsert_execution_grain(&self, batch: &ExecutionGrainBatch) -> Result<usize> {
        crate::repo::execution_ingest::upsert_execution_grain(self.pool(), batch).await
    }

    async fn query_usage(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        StoreRepo::query_usage(self, input).await
    }

    async fn query_executions(
        &self,
        input: &ExecutionQueryRequest,
    ) -> Result<(Vec<ExecutionSeriesPoint>, bool)> {
        StoreRepo::query_executions(self, input).await
    }

    async fn query_seat_snapshots(
        &self,
        input: &SeatSnapshotQueryRequest,
    ) -> Result<(Vec<SeatSnapshotSeriesPoint>, bool)> {
        StoreRepo::query_seat_snapshots(self, input).await
    }

    async fn query_day_facts(
        &self,
        input: &DayFactQueryRequest,
    ) -> Result<(Vec<DayFactSeriesPoint>, bool)> {
        StoreRepo::query_day_facts(self, input).await
    }

    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>> {
        StoreRepo::spend_for_account(self, account_id, start, end).await
    }

    async fn last_purge_cutoff(&self) -> Result<Option<DateTime<Utc>>> {
        StoreRepo::last_purge_cutoff(self).await
    }
}

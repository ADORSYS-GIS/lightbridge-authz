//! The `UsageRepoTrait` seam between the usage service and its persistence.
//!
//! Split out of `lib.rs` rather than left beside `UsageState`/`start_usage_server` purely because
//! that file sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be
//! touched but not grown — the same reason `lightbridge-authz-api-key`'s `session_revocation.rs`
//! is separate from its `repo.rs`. Moved verbatim, and `lib.rs` re-exports the trait, so every
//! existing `lightbridge_authz_usage_rest::UsageRepoTrait` path still resolves. The impl for
//! `StoreRepo` moves with it; the pairing with `StoreRepo` is unchanged.

use chrono::{DateTime, Utc};
use lightbridge_authz_core::{Result, async_trait};

use crate::models::{UsageQueryRequest, UsageSeriesPoint};
use crate::repo::{StoreRepo, UsageEvent};

#[async_trait]
pub trait UsageRepoTrait: Send + Sync {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize>;
    /// Returns `(points, truncated)` -- see `StoreRepo::query_usage`'s doc comment for the #578
    /// truncation contract `truncated` documents.
    async fn query_usage(&self, input: &UsageQueryRequest)
    -> Result<(Vec<UsageSeriesPoint>, bool)>;
    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>>;
}

#[async_trait]
impl UsageRepoTrait for StoreRepo {
    async fn insert_usage_events(&self, events: &[UsageEvent]) -> Result<usize> {
        StoreRepo::insert_usage_events(self, events).await
    }

    async fn query_usage(
        &self,
        input: &UsageQueryRequest,
    ) -> Result<(Vec<UsageSeriesPoint>, bool)> {
        StoreRepo::query_usage(self, input).await
    }

    async fn spend_for_account(
        &self,
        account_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Option<f64>> {
        StoreRepo::spend_for_account(self, account_id, start, end).await
    }
}

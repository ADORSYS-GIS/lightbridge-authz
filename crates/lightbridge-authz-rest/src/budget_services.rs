//! The budget-domain service graph every server that constructs a [`crate::Procedures`] registry
//! needs: `authz-api`, `authz-budget`, and (since the MCP parity work, lightbridge-authz#645)
//! `lightbridge-mcp`.
//!
//! Extracted from `lib.rs`, where `start_api_server` and `start_budget_server` each carried a
//! byte-for-byte copy of this wiring. A third copy in `app/lightbridge-authz/src/mcp.rs` — a
//! different crate, where a divergence would be invisible to anyone reading either server — is
//! what made the duplication worth removing rather than tolerating: the fail-closed spend-reader
//! degrade below is a security property, and "three hand-maintained copies of a fail-closed
//! default" is the shape that eventually ships two of them agreeing and one not.
//!
//! What this does NOT do is spawn the [`ResetScheduler`]'s interval task. That stays in
//! `start_budget_server` and only there: `authz-budget` owns the budget domain's background work,
//! and `authz-api`/`lightbridge-mcp` hold an inert scheduler purely because
//! [`crate::Procedures::new`] takes one unconditionally.
//!
//! ADR-0034 §15/§15.6's snapshot refresher is started from
//! [`crate::budget_snapshot_refresher::spawn_snapshot_refresher`], a sibling module rather than a
//! function here, purely to keep both files under this repo's 200-LoC ceiling.
//!
//! [`ResetScheduler`]: lightbridge_authz_budget::ResetScheduler

use std::sync::Arc;

use lightbridge_authz_core::{Error, Result, config::UsageServiceClient, db::DbPoolTrait};

/// The single policy set every deployment activates budget revisions against (ADR-0007).
pub const BUDGET_POLICY_SET_ID: &str = "budget-refill";

/// Evaluation step ceiling for one budget policy decision — a runaway rule set fails the decision
/// rather than the process.
pub const BUDGET_POLICY_EVALUATION_BUDGET: usize = 10_000;

/// Everything [`crate::Procedures::new`] needs from the budget domain, built once per process.
///
/// Fields are `pub` because the sole consumers are the three `start_*_server` functions that
/// immediately destructure them into a `Procedures::new` call; there is no invariant between them
/// worth an accessor, and every one of them is itself an `Arc` handle onto shared state.
pub struct BudgetServices {
    pub policy_store: Arc<lightbridge_authz_budget::PolicyStore>,
    pub refill_service: Arc<lightbridge_authz_budget::RefillService>,
    pub review_service: Arc<lightbridge_authz_budget::ReviewService>,
    pub budget_repo: Arc<lightbridge_authz_budget::repo::BudgetRepo>,
    pub reset_scheduler: Arc<lightbridge_authz_budget::ResetScheduler>,
    /// The same fail-closed spend reader `refill_service`/`reset_scheduler` above were built
    /// with, handed back so `start_budget_server` can assemble ADR-0034's `RemainingService` over
    /// it with that server's configured grace window. Exposed rather than pre-assembled here
    /// because the grace window is `server.budget_internal` config that only `authz-budget` reads
    /// -- and because sharing this exact reader is the point: the number the gateway enforces on
    /// can never disagree with the number a refill decision or a reset tick would compute from
    /// identical state.
    pub spend_reader: Arc<dyn lightbridge_authz_budget::SpendReader>,
    /// ADR-0034 §15: the store behind `budget_remaining_snapshots`, built here because the same
    /// `BudgetRepo`/`SpendReader`/`ResetScheduler` graph is what fills it — a second graph over
    /// the same pool is exactly how two components come to disagree about a number.
    pub snapshots: Arc<lightbridge_authz_budget::SnapshotStore>,
}

/// The spend reader for `usage_service`, or the fail-closed stand-in when it is unconfigured.
///
/// `usage_service` (`Config.usage_service`) is optional. When it is not set this degrades to
/// [`UnavailableSpendReader`] rather than failing startup: every spend-dependent policy fact then
/// reads `Spend::Unavailable`, which the rule-data evaluator already treats as a fail-closed
/// signal (routes to `manual_review`, never `auto_approve`). Degrading rather than hard-failing is
/// deliberate — unlike the policy load below, which DOES fail startup loudly: a missing
/// `usage_service` narrows what self-service refill can decide automatically, it does not make the
/// RPC surface unsafe to serve.
///
/// When it IS configured, [`UsageServiceSpendReader`] calls the usage service's
/// `/usage/v1/spend/query` over HTTP instead of opening a second database connection (see
/// `lightbridge-authz-budget/src/spend.rs`). Every way that call can fail — unreachable, timeout,
/// non-2xx, unparseable body — also resolves to `Spend::Unavailable`, never a hard error, so a
/// flaky usage service degrades refill decisions exactly the way a missing config does.
///
/// [`UnavailableSpendReader`]: lightbridge_authz_budget::UnavailableSpendReader
/// [`UsageServiceSpendReader`]: lightbridge_authz_budget::UsageServiceSpendReader
fn build_spend_reader(
    usage_service: &Option<UsageServiceClient>,
) -> Result<Arc<dyn lightbridge_authz_budget::SpendReader>> {
    let Some(usage_service) = usage_service else {
        tracing::warn!(
            "usage_service is not configured -- budget refill spend facts will report \
             Unavailable, and self-service refill decisions that depend on them will fail \
             closed to manual review"
        );
        return Ok(Arc::new(lightbridge_authz_budget::UnavailableSpendReader));
    };
    Ok(Arc::new(
        lightbridge_authz_budget::UsageServiceSpendReader::new(
            usage_service.base_url.clone(),
            usage_service.insecure_skip_verify,
            usage_service.ca_bundle_path.as_deref(),
            usage_service.client_cert_path.as_deref(),
            usage_service.client_key_path.as_deref(),
            std::time::Duration::from_millis(usage_service.timeout_ms),
        )
        .map_err(|e| Error::Server(format!("failed to build usage-service spend reader: {e}")))?,
    ))
}

/// Build the budget-domain service graph over `pool`.
///
/// ADR-0007: the policy store loads whatever is genuinely active in the database right now, so a
/// fresh startup always agrees with the last successful activation — this is what proves "no
/// restart needed to see a policy change AND still correct if you do restart" holds for the real
/// running server, not just at the `PolicyStore` unit level. A bad load fails startup loudly,
/// unlike the spend reader above.
///
/// `policy_store.engine()` handed to the refill service is the SAME live, hot-swappable engine
/// `activateBudgetPolicy`/`getBudgetPolicyStatus` read and write, so a policy activated at runtime
/// takes effect for refills immediately, with no restart.
pub async fn build_budget_services(
    pool: Arc<dyn DbPoolTrait>,
    usage_service: &Option<UsageServiceClient>,
) -> Result<BudgetServices> {
    let policy_store = Arc::new(
        lightbridge_authz_budget::PolicyStore::load_active_from_db(
            pool.clone(),
            BUDGET_POLICY_SET_ID,
            BUDGET_POLICY_EVALUATION_BUDGET,
        )
        .await
        .map_err(|e| Error::Server(format!("failed to load active budget policy: {e}")))?,
    );

    let budget_repo = Arc::new(lightbridge_authz_budget::repo::BudgetRepo::new(
        pool.clone(),
    ));
    let augmentation_repo = Arc::new(lightbridge_authz_budget::AugmentationRepo::new(
        pool.clone(),
    ));
    let policy_engine: Arc<dyn lightbridge_authz_budget::PolicyEngine> = policy_store.engine();
    let spend_reader = build_spend_reader(usage_service)?;

    let refill_service = Arc::new(lightbridge_authz_budget::RefillService::new(
        budget_repo.clone(),
        augmentation_repo.clone(),
        policy_engine,
        spend_reader.clone(),
    ));
    let review_service = Arc::new(lightbridge_authz_budget::ReviewService::new(
        budget_repo.clone(),
        augmentation_repo,
    ));
    // ADR-0032. Shares the SAME fail-closed `spend_reader` the refill path uses, so an unreachable
    // usage service degrades a reset the same way it degrades a refill: never a grant on unknown
    // spend.
    let spend_reader_for_remaining = spend_reader.clone();
    let reset_scheduler = Arc::new(lightbridge_authz_budget::ResetScheduler::new(
        pool.clone(),
        budget_repo.clone(),
        spend_reader,
    ));

    let snapshots = Arc::new(lightbridge_authz_budget::SnapshotStore::new(pool.clone()));

    Ok(BudgetServices {
        policy_store,
        refill_service,
        review_service,
        budget_repo,
        reset_scheduler,
        spend_reader: spend_reader_for_remaining,
        snapshots,
    })
}

//! `budget` command dispatch: translates `cli.rs`'s clap shape into
//! [`lightbridge_authz::budget_cmd::BudgetAction`] and runs it.
//!
//! Split out of `main.rs` for the same reason `rbac_dispatch.rs` and `idp_cmd.rs` were: that file
//! sits on its committed LoC-gate baseline (`.github/loc-baseline.json`) and may be touched but not
//! grown. The actual work lives in the crate's lib target so integration tests can call it without
//! spawning the binary.

use std::sync::Arc;

use lightbridge_authz::budget_cmd::{self, BudgetAction};
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_core::{Error, Result};
use lightbridge_authz_rest::start_budget_server;
use tracing::info;

use crate::utils::cli::BudgetSubcommand;

/// `budget` with no subcommand starts the server; with one, it runs that one-shot and exits.
/// Both arms live here rather than in `main.rs` so that file stays under its committed LoC-gate
/// baseline.
pub async fn run(config_path: String, command: Option<BudgetSubcommand>) -> Result<()> {
    match command {
        Some(command) => dispatch(config_path, command).await,
        None => serve(config_path).await,
    }
}

async fn serve(config_path: String) -> Result<()> {
    info!("{}", crate::utils::banner::BANNER);

    let config = load_from_path(&config_path)?;

    info!("Connecting to DB...");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

    let budget = config.server.budget.as_ref().ok_or_else(|| {
        Error::Server("server.budget config is required to run the budget command".into())
    })?;
    start_budget_server(
        budget,
        config.server.budget_internal.as_ref(),
        pool,
        &config.oauth2,
        &config.billing,
        &config.quota_tiers,
        &config.models,
        &config.api_key_expiry,
        &config.redis,
        &config.usage_service,
    )
    .await?;
    Ok(())
}

async fn dispatch(config_path: String, command: BudgetSubcommand) -> Result<()> {
    let action = match command {
        BudgetSubcommand::Grant {
            account,
            amount_micros,
            period,
            source,
            reason,
            idempotency_key,
        } => BudgetAction::Grant {
            account,
            amount_micros,
            period,
            source,
            reason,
            idempotency_key,
        },
    };
    budget_cmd::run(&config_path, action).await
}

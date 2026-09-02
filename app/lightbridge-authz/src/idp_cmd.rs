//! `idp` command dispatch: no subcommand starts the IdP server exactly as before (the Helm chart's
//! container command is `lightbridge-authz idp --config-path /etc/lightbridge/config.yaml`, so
//! this path must never change shape); `jwk {list,new,rotate}` instead manages signing keys
//! directly, without starting the server at all.
//!
//! Split out of `main.rs` purely to keep that file under its LoC-gate baseline
//! (`.github/loc-baseline.json`) -- the server-start body below is the Idp arm's PRE-EXISTING
//! logic, moved verbatim, not a behavior change.

use std::sync::Arc;

use lightbridge_authz::jwk_cmd::{self, JwkAction};
use lightbridge_authz_core::Result;
use lightbridge_authz_core::config::load_from_path;
use lightbridge_authz_core::db::{DbPool, DbPoolTrait};
use lightbridge_authz_rest::start_idp_server;
use tracing::info;

use crate::utils::banner::BANNER;
use crate::utils::cli::{IdpSubcommand, JwkCommand};

pub async fn run(config_path: String, command: Option<IdpSubcommand>) -> Result<()> {
    match command {
        None => start_server(config_path).await,
        Some(IdpSubcommand::Jwk { command }) => {
            let action = match command {
                JwkCommand::List => JwkAction::List,
                JwkCommand::New { r#type } => JwkAction::New(r#type),
                JwkCommand::Rotate { r#type, yes } => JwkAction::Rotate(r#type, yes),
            };
            jwk_cmd::run(&config_path, action).await
        }
    }
}

async fn start_server(config_path: String) -> Result<()> {
    info!("{}", BANNER);

    let config = load_from_path(&config_path)?;

    info!("Connecting to DB...");
    let pool: Arc<dyn DbPoolTrait> = Arc::new(DbPool::new(&config.database).await?);

    let idp = config.server.idp.as_ref().ok_or_else(|| {
        lightbridge_authz_core::Error::Server(
            "server.idp config is required to run the idp command".to_string(),
        )
    })?;
    start_idp_server(
        idp,
        pool,
        &config.oauth2,
        &config.redis,
        &config.secret_claim,
    )
    .await?;
    Ok(())
}

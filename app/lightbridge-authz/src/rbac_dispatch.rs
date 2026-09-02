//! `rbac` command dispatch: translates `cli.rs`'s clap shape into
//! [`lightbridge_authz::rbac_cmd::RbacAction`] and runs it.
//!
//! Split out of `main.rs` for the same reason `idp_cmd.rs` was: that file sits on its committed
//! LoC-gate baseline (`.github/loc-baseline.json`) and may be touched but not grown. The actual
//! work lives in the crate's lib target so integration tests can call it without spawning the
//! binary.

use lightbridge_authz::rbac_cmd::{self, RbacAction};
use lightbridge_authz_core::Result;

use crate::utils::cli::RbacCommand;

pub async fn run(config_path: String, command: RbacCommand) -> Result<()> {
    let action = match command {
        RbacCommand::Grant { user, role, reason } => RbacAction::Grant { user, role, reason },
        RbacCommand::Revoke { user, role, reason } => RbacAction::Revoke { user, role, reason },
        RbacCommand::List { user, role } => RbacAction::List { user, role },
    };
    rbac_cmd::run(&config_path, action).await
}

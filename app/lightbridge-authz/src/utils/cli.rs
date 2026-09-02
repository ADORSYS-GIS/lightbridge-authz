use clap::{Parser, Subcommand};
use lightbridge_authz::jwk_cmd::KeyPurpose;

#[derive(Parser)]
#[command(name = "lightbridge-authz", author, version, about = "LightBridge Authz CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Serve {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Api {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Opa {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Idp {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
        /// Manage signing keys directly instead of starting the server (kubectl-debug/init-container
        /// operator surface, alongside the existing 30-day age-based auto-rotation).
        #[command(subcommand)]
        command: Option<IdpSubcommand>,
    },
    Budget {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Migrate {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
}

#[derive(Subcommand)]
pub enum IdpSubcommand {
    /// Manage signing keys explicitly (list/create/rotate), instead of relying solely on
    /// age-based auto-rotation.
    Jwk {
        #[command(subcommand)]
        command: JwkCommand,
    },
}

#[derive(Subcommand)]
pub enum JwkCommand {
    /// List every signing key (both purposes, active and stale). Never prints private key
    /// material.
    List,
    /// Create an active key for `--type` if none exists yet. Refuses (non-zero exit) if one is
    /// already active -- use `rotate` for that instead.
    New {
        #[arg(long, value_enum)]
        r#type: KeyPurpose,
    },
    /// Force-rotate the active key for `--type`: retires the current one and activates a fresh
    /// one. Requires `--yes`: unlike `list` and `new`, this changes live signing state, and the
    /// operator typing it is the only confirmation an `exec`/init-container context can offer.
    Rotate {
        #[arg(long, value_enum)]
        r#type: KeyPurpose,
        /// Required. Rotation retires the currently active key; without this flag the command
        /// refuses and exits non-zero, so a mistyped or scripted invocation cannot rotate.
        #[arg(long)]
        yes: bool,
    },
}

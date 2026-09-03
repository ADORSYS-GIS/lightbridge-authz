use clap::{Parser, Subcommand};
use std::sync::LazyLock;

/// The service name this CLI stamps its own build with (#573). See the authz CLI's `SERVICE_CLI`
/// for why this names the binary rather than one of the two listeners `serve` binds.
pub const SERVICE_CLI: &str = "lightbridge-authz-usage";

/// What `--version` prints: the full build stamp on one line. See the authz CLI's `LONG_VERSION`
/// for why the bare crate version is not enough.
static LONG_VERSION: LazyLock<String> =
    LazyLock::new(|| lightbridge_authz_core::build_info(SERVICE_CLI).stamp());

#[derive(Parser)]
#[command(
    name = "lightbridge-authz-usage",
    author,
    version,
    long_version = LONG_VERSION.as_str(),
    about = "LightBridge Authz Usage CLI",
    long_about = None
)]
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
    Migrate {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    /// Print this binary's build stamp as JSON (#573) -- the same struct both usage listeners
    /// serve at `GET /version`. Reads no config and touches no database.
    Version,
}

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "lightbridge-mcp",
    author,
    version,
    about = "LightBridge MCP CLI",
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
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
}

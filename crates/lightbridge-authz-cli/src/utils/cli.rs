use clap::{Parser, Subcommand};

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
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Migrate {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
}

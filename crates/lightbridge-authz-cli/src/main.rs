use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "lightbridge-authz")]
#[command(about = "Lightbridge Authz CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(long)]
        config: String,
        #[arg(long)]
        rest: bool,
        #[arg(long)]
        grpc: bool,
    },
    Config {
        #[arg(long)]
        config: String,
        #[arg(long)]
        check_config: bool,
    },
    Client {
        #[arg(long)]
        config: String,
        #[arg(long, default_value = "rest")]
        transport: String,
        #[arg(long)]
        health: bool,
    },
}

fn main() {
    let _ = Cli::parse();
}

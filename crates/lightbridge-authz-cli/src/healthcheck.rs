use clap::Parser;
use lightbridge_authz_core::error::Result;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Parser, Clone)]
pub struct HealthCheckCli {
    #[arg(value_name = "PATH", default_value = "0.0.0.0")]
    pub http_host: String,

    #[arg(value_name = "PORT", default_value = "50051")]
    pub http_port: u64,

    #[arg(value_name = "TIMEOUT", default_value = "5")]
    pub http_timeout: u64,
}

fn main() -> Result<()> {
    let cli = HealthCheckCli::parse();
    let address = format!("{}:{}", cli.http_host, cli.http_port);

    let socket_addr: SocketAddr = address.parse()?;

    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(cli.http_timeout)) {
        Ok(_) => {
            println!("Health check is successful");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Health check failed: {}", e);
            std::process::exit(1);
        }
    }
}

use clap::Parser;
use lightbridge_authz_core::error::Result;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Parser, Clone)]
pub struct HealthCheckCli {
    #[arg(value_name = "HOST", short = 'g', long, default_value = "0.0.0.0")]
    pub grpc_host: String,

    #[arg(value_name = "PORT", short = 'p', long, default_value = "3001")]
    pub grpc_port: u16,

    #[arg(value_name = "HOST", short = 'r', long, default_value = "0.0.0.0")]
    pub rest_host: String,

    #[arg(value_name = "PORT", short = 'P', long, default_value = "3000")]
    pub rest_port: u16,

    #[arg(value_name = "TIMEOUT", short = 't', long, default_value = "5")]
    pub timeout: u64,
}

fn check_endpoint(host: &str, port: u16, timeout_secs: u64, name: &str) -> Result<bool> {
    let address = format!("{}:{}", host, port);
    let socket_addr: SocketAddr = address.parse()?;
    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs)) {
        Ok(_) => {
            println!("{} health check successful on {}", name, address);
            Ok(true)
        }
        Err(e) => {
            eprintln!("{} health check failed on {}: {}", name, address, e);
            Ok(false)
        }
    }
}

fn main() -> Result<()> {
    let cli = HealthCheckCli::parse();

    let grpc_ok = check_endpoint(&cli.grpc_host, cli.grpc_port, cli.timeout, "gRPC")?;
    let rest_ok = check_endpoint(&cli.rest_host, cli.rest_port, cli.timeout, "REST")?;

    if grpc_ok && rest_ok {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

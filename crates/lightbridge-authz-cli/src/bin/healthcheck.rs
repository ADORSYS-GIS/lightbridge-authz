use clap::Parser;
use lightbridge_authz_core::error::Result;
use std::net::TcpStream;
use std::time::Duration;

#[derive(Parser, Clone)]
pub struct HealthCheckCli {
    #[arg(value_name = "HOST", short = 's', long, default_value = "0.0.0.0")]
    pub server_host: String,

    #[arg(value_name = "PORT", short = 'g', long, default_value = "3001")]
    pub grpc_port: u16,

    #[arg(value_name = "PORT", short = 'r', long, default_value = "3000")]
    pub rest_port: u16,

    #[arg(value_name = "TIMEOUT", short = 't', long, default_value = "5")]
    pub timeout: u64,
}

fn check_endpoint(host: &str, port: u16, timeout_secs: u64, name: &str) -> Result<bool> {
    let address = format!("{}:{}", host, port);
    let socket_addr = address.parse()?;
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
    let HealthCheckCli {
        timeout,
        rest_port,
        grpc_port,
        server_host,
    } = HealthCheckCli::parse();

    let grpc_ok = check_endpoint(&server_host, grpc_port, timeout, "gRPC")?;
    let rest_ok = check_endpoint(&server_host, rest_port, timeout, "REST")?;

    std::process::exit(if grpc_ok && rest_ok { 0 } else { 1 });
}

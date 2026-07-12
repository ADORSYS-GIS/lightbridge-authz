use clap::Parser;
use std::net::TcpStream;
use std::time::Duration;

#[derive(Parser, Clone)]
struct HealthCheckCli {
    #[arg(value_name = "HOST", short = 's', long, default_value = "0.0.0.0")]
    server_host: String,

    #[arg(value_name = "PORT", short = 'r', long, default_value = "3000")]
    api_port: u16,

    #[arg(value_name = "PORT", short = 'o', long)]
    opa_port: Option<u16>,

    #[arg(value_name = "TIMEOUT", short = 't', long, default_value = "5")]
    timeout: u64,
}

fn check_endpoint(host: &str, port: u16, timeout_secs: u64, name: &str) -> Result<bool, ()> {
    let address = format!("{host}:{port}");
    let socket_addr = address.parse().expect("Wrong address provided");
    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(timeout_secs)) {
        Ok(_) => {
            println!("{name} health check successful on {address}");
            Ok(true)
        }
        Err(error) => {
            eprintln!("{name} health check failed on {address}: {error}");
            Ok(false)
        }
    }
}

fn main() -> Result<(), ()> {
    let HealthCheckCli {
        timeout,
        api_port,
        opa_port,
        server_host,
    } = HealthCheckCli::parse();

    let api_ok = check_endpoint(&server_host, api_port, timeout, "API")?;
    let opa_ok = if let Some(port) = opa_port {
        check_endpoint(&server_host, port, timeout, "OPA")?
    } else {
        true
    };

    std::process::exit(if api_ok && opa_ok { 0 } else { 1 });
}

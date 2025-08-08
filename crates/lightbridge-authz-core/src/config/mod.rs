use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub logging: Logging,
    pub auth: Auth,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub grpc: Grpc,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Grpc {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Logging {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Auth {
    pub api_keys: Vec<String>,
}

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;
    let cfg: Config = serde_yaml::from_str(&content)?;
    Ok(cfg)
}

use crate::error::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub logging: Logging,
    pub auth: Auth,
    pub database: Database,
    pub oauth2: Oauth2,
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
pub struct Database {
    pub url: String,
    pub pool_size: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Oauth2 {
    pub introspection: Introspection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Introspection {
    pub url: String,
    pub timeout_ms: u64,
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

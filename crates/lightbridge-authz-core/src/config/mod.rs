use crate::error::Result;
use serde::Deserialize;
use serde_yaml::from_str;
use std::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: Server,
    pub logging: Logging,
    pub database: Database,
    pub oauth2: Oauth2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub rest: Option<Rest>,
    pub grpc: Option<Grpc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rest {
    pub address: String,
    pub port: u16,
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
    pub jwks_url: String,
}

pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Config> {
    let content = read_to_string(path)?;
    let cfg: Config = from_str(&content)?;
    Ok(cfg)
}

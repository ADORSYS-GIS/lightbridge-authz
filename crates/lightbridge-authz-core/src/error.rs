use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error")]
    Yaml(#[from] serde_yaml::Error),

    /// Error originating from I/O operations.
    #[error("Any: {0}")]
    Any(#[from] anyhow::Error),
}

use axum::{http::StatusCode, response::IntoResponse};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Not found")]
    NotFound,

    /// Error originating from I/O operations.
    #[error("Any: {0}")]
    Any(#[from] anyhow::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self {
            Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Yaml(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Any(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status_code, self.to_string()).into_response()
    }
}

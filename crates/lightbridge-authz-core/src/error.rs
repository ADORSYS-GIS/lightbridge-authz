use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Not found")]
    NotFound,

    #[error("Any: {0}")]
    Any(#[from] anyhow::Error),

    #[error("Rand: {0}")]
    RandError(#[from] rand_core::OsError),

    #[error("Address parse error error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Migration error: {0}")]
    Migration(String),
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::Error;
    use axum::{http::StatusCode, response::IntoResponse};

    impl IntoResponse for Error {
        fn into_response(self) -> axum::response::Response {
            let status_code = match self {
                Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::RandError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Yaml(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::NotFound => StatusCode::NOT_FOUND,
                Error::Any(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::AddrParseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Migration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (status_code, self.to_string()).into_response()
        }
    }
}

use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

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

    #[error("Server Error: {0}")]
    Server(String),

    #[error("Rand: {0}")]
    RandError(#[from] rand_core::OsError),

    #[error("Address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("Database error: {0}")]
    Database(String),

    #[cfg(feature = "db")]
    #[error("DieselError error: {0}")]
    DieselError(#[from] diesel::result::Error),

    #[cfg(feature = "db")]
    #[error("ConnectionError error: {0}")]
    ConnectionError(#[from] diesel::result::ConnectionError),
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
                Error::Server(_) => StatusCode::INTERNAL_SERVER_ERROR,

                #[cfg(feature = "db")]
                Error::DieselError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                #[cfg(feature = "db")]
                Error::ConnectionError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            (status_code, self.to_string()).into_response()
        }
    }
}

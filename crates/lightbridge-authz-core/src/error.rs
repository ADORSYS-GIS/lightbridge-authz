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

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Any: {0}")]
    Any(#[from] anyhow::Error),

    #[error("Server Error: {0}")]
    Server(String),

    #[error("Address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),
}

#[cfg(feature = "axum")]
mod axum_impl {
    use super::Error;
    use axum::{http::StatusCode, response::IntoResponse};
    use sqlx::error::{Error as SqlxError, ErrorKind};

    fn sqlx_status_code(err: &SqlxError) -> StatusCode {
        match err {
            SqlxError::RowNotFound => StatusCode::NOT_FOUND,
            SqlxError::PoolTimedOut | SqlxError::PoolClosed | SqlxError::WorkerCrashed => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            SqlxError::Database(db_err) => match db_err.kind() {
                ErrorKind::UniqueViolation => StatusCode::CONFLICT,
                ErrorKind::ForeignKeyViolation
                | ErrorKind::NotNullViolation
                | ErrorKind::CheckViolation => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    impl IntoResponse for Error {
        fn into_response(self) -> axum::response::Response {
            let status_code = match &self {
                Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Yaml(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::NotFound => StatusCode::NOT_FOUND,
                Error::Conflict(_) => StatusCode::CONFLICT,
                Error::Any(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::AddrParseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
                Error::Server(_) => StatusCode::INTERNAL_SERVER_ERROR,

                Error::SqlxError(err) => sqlx_status_code(err),
            };

            (status_code, self.to_string()).into_response()
        }
    }
}

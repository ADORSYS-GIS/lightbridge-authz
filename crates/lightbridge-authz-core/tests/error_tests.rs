#![cfg(feature = "axum")]

use axum::http::StatusCode;
use axum::response::IntoResponse;
use lightbridge_authz_core::Error;
use sqlx::error::{DatabaseError, ErrorKind};
use std::fmt;

#[derive(Debug)]
struct FakeDbError {
    kind: ErrorKind,
}

impl fmt::Display for FakeDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fake database error")
    }
}

impl std::error::Error for FakeDbError {}

impl DatabaseError for FakeDbError {
    fn message(&self) -> &str {
        "fake database error"
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> ErrorKind {
        match self.kind {
            ErrorKind::UniqueViolation => ErrorKind::UniqueViolation,
            ErrorKind::ForeignKeyViolation => ErrorKind::ForeignKeyViolation,
            ErrorKind::NotNullViolation => ErrorKind::NotNullViolation,
            ErrorKind::CheckViolation => ErrorKind::CheckViolation,
            ErrorKind::ExclusionViolation => ErrorKind::ExclusionViolation,
            _ => ErrorKind::Other,
        }
    }
}

fn sqlx_database_error(kind: ErrorKind) -> sqlx::Error {
    sqlx::Error::Database(Box::new(FakeDbError { kind }))
}

fn status_of(err: Error) -> StatusCode {
    err.into_response().status()
}

#[test]
fn not_found_maps_to_404() {
    assert_eq!(status_of(Error::NotFound), StatusCode::NOT_FOUND);
}

#[test]
fn forbidden_maps_to_403() {
    assert_eq!(
        status_of(Error::Forbidden("nope".to_string())),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn conflict_maps_to_409() {
    assert_eq!(
        status_of(Error::Conflict("dup".to_string())),
        StatusCode::CONFLICT
    );
}

#[test]
fn bad_request_maps_to_400() {
    assert_eq!(
        status_of(Error::BadRequest("bad".to_string())),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn server_error_maps_to_500() {
    assert_eq!(
        status_of(Error::Server("boom".to_string())),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn database_error_maps_to_500() {
    assert_eq!(
        status_of(Error::Database("boom".to_string())),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn io_error_maps_to_500() {
    let io_err = std::io::Error::other("disk on fire");
    assert_eq!(
        status_of(Error::Io(io_err)),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn yaml_error_maps_to_500() {
    let yaml_err = serde_yaml::from_str::<serde_yaml::Value>("[").unwrap_err();
    assert_eq!(
        status_of(Error::Yaml(yaml_err)),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn any_error_maps_to_500() {
    assert_eq!(
        status_of(Error::Any(anyhow::anyhow!("catastrophe"))),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn addr_parse_error_maps_to_500() {
    let parse_err = "not-an-address"
        .parse::<std::net::SocketAddr>()
        .unwrap_err();
    assert_eq!(
        status_of(Error::AddrParseError(parse_err)),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn sqlx_row_not_found_maps_to_404() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx::Error::RowNotFound)),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn sqlx_pool_timed_out_maps_to_503() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx::Error::PoolTimedOut)),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn sqlx_pool_closed_maps_to_503() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx::Error::PoolClosed)),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn sqlx_worker_crashed_maps_to_503() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx::Error::WorkerCrashed)),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn sqlx_unique_violation_maps_to_409() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx_database_error(
            ErrorKind::UniqueViolation
        ))),
        StatusCode::CONFLICT
    );
}

#[test]
fn sqlx_foreign_key_violation_maps_to_400() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx_database_error(
            ErrorKind::ForeignKeyViolation
        ))),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn sqlx_not_null_violation_maps_to_400() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx_database_error(
            ErrorKind::NotNullViolation
        ))),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn sqlx_check_violation_maps_to_400() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx_database_error(
            ErrorKind::CheckViolation
        ))),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn sqlx_other_database_error_kind_maps_to_500() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx_database_error(ErrorKind::Other))),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[test]
fn sqlx_uncategorized_error_maps_to_500() {
    assert_eq!(
        status_of(Error::SqlxError(sqlx::Error::Protocol(
            "unexpected byte".to_string()
        ))),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

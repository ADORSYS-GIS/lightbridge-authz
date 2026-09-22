//! The session-scoped advisory-lock guard for the KPI aggregate refresh (#587).
//!
//! Split out of `aggregate_refresh.rs` by the LoC gate (lightbridge-governance#172): the guard is a
//! self-contained unit built ON TOP OF `refresh_all_aggregates`, which acquires the session lock
//! and hands it to this guard so it is released even if the refresh future is cancelled or panics.
//! The pairing is unchanged -- `aggregate_refresh.rs` re-exports [`RefreshLockGuard`] so every
//! existing `use` path still resolves.

use sqlx::Postgres;
use sqlx::pool::PoolConnection;
use sqlx::postgres::PgConnection;
use tracing::warn;

/// Guards the session-scoped advisory lock for the aggregate refresh.
///
/// `REFRESH MATERIALIZED VIEW CONCURRENTLY` cannot run inside an explicit transaction, so the
/// refresh lock must be session-scoped (`pg_try_advisory_lock`), not transaction-scoped like the
/// budget refresher's (`pg_try_advisory_xact_lock`, which releases on rollback -- including the
/// rollback `sqlx::Transaction`'s `Drop` issues on cancellation or panic). A session lock is
/// released only by `pg_advisory_unlock` on the SAME session or by that session ending. If the
/// refresh future were cancelled or panicked before the explicit unlock, the pooled connection
/// would return to the pool with the lock still held on its session -- silently freezing every
/// replica's refresh (the exact bug class `snapshot_refresher.rs` fixed with a transaction-scoped
/// lock). This guard guarantees the unlock runs on drop, even on cancellation or panic.
///
/// The normal path calls [`RefreshLockGuard::release`], which runs the unlock and consumes the
/// connection so `Drop` does nothing. The abnormal path (cancellation/panic) drops the guard with
/// the connection still held, and `Drop` releases the lock on a dedicated thread with its own
/// runtime -- robust even if the current runtime is shutting down.
pub struct RefreshLockGuard {
    conn: Option<PoolConnection<Postgres>>,
    key: i64,
}

impl RefreshLockGuard {
    pub fn new(conn: PoolConnection<Postgres>, key: i64) -> Self {
        Self {
            conn: Some(conn),
            key,
        }
    }

    /// The connection the refresh runs on. Always present until [`RefreshLockGuard::release`] or
    /// `Drop` takes it.
    pub(crate) fn conn_mut(&mut self) -> &mut PgConnection {
        self.conn
            .as_mut()
            .expect("refresh lock guard connection present")
    }

    /// Releases the session lock on the normal path, consuming the connection so `Drop` does
    /// nothing. Logs (does not propagate) an unlock failure -- a held lock on a pooled connection
    /// would block future refreshes, but the refresh result is the more important signal.
    pub(crate) async fn release(mut self) {
        if let Some(mut conn) = self.conn.take()
            && let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.key)
                .execute(&mut *conn)
                .await
        {
            warn!("usage aggregate refresh: failed to release advisory lock: {e}");
        }
    }
}

impl Drop for RefreshLockGuard {
    fn drop(&mut self) {
        // Abnormal path: the refresh future was cancelled or panicked before `release` ran. The
        // connection is still here, so release the lock on a dedicated thread with its own runtime
        // before the connection returns to the pool. This is robust even during runtime shutdown
        // (the pool teardown would also close the session, but we do not rely on that).
        if let Some(conn) = self.conn.take() {
            let key = self.key;
            std::thread::spawn(move || {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        warn!(
                            "usage aggregate refresh: failed to build runtime to release advisory \
                             lock on drop: {e}"
                        );
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut conn = conn;
                    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(key)
                        .execute(&mut *conn)
                        .await
                    {
                        warn!(
                            "usage aggregate refresh: failed to release advisory lock on drop: {e}"
                        );
                    }
                });
            });
        }
    }
}

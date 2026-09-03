//! The bounded last-known-good spend cache behind ADR-0034's *fail-closed with cached grace*.
//!
//! Split out of `remaining_service.rs` (code moved, not rewritten) under the LoC gate, and it is a
//! coherent piece on its own: everything here is about one question — may this reading still be
//! served, and how old is it — with no knowledge of ledgers, HTTP or budgets.
//!
//! It lives in this crate, rather than at the gateway, because neither component downstream can
//! express it. Envoy's Lua filter has no cross-request state to cache in, and Authorino's
//! `metadata` cache is a plain TTL cache that DROPS an entry rather than serving it stale when the
//! fetch fails (prod's own AuthConfig commentary records this from reading Authorino's source: a
//! failed metadata fetch leaves the value absent). So this is the only place that can ride out a
//! short usage-service outage — and the only place that knows the reading it served was stale.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Duration, Utc};

use crate::period::Period;

/// One cached spend reading. Only `spent_micros` is ever cached, never a whole answer: the ceiling
/// is re-read from the ledger on every request even while serving stale spend, so a refill that
/// lands DURING a usage-service outage takes effect immediately instead of being masked.
#[derive(Debug, Clone, Copy)]
struct CachedSpend {
    micros: i64,
    observed_at: DateTime<Utc>,
}

/// Last-known-good spend per `(budget account, period)`, valid for `grace` after it was observed.
///
/// `grace` of zero disables the cache entirely — nothing is stored and nothing is recalled — which
/// is the default for every construction path except `authz-budget`'s configured internal listener.
///
/// Per-process by design. N replicas hold N independent caches, which only affects whether a
/// request during an outage finds a warm entry; it can never make two replicas disagree about a
/// *fresh* reading. Deduplicating into Redis was considered and rejected: it would add a second
/// network dependency inside the one code path whose entire job is surviving a network dependency
/// being down.
#[derive(Debug)]
pub(crate) struct SpendCache {
    grace: Duration,
    entries: Mutex<HashMap<(String, Period), CachedSpend>>,
}

impl SpendCache {
    pub(crate) fn new(grace: Duration) -> Self {
        Self {
            grace,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Records a fresh reading and drops every entry that has aged past `grace` — the only
    /// eviction this cache has, and enough: an entry past `grace` can never be served again, so
    /// keeping it would be pure leak. Bounded by the number of accounts seen in one grace window.
    pub(crate) fn remember(&self, key: (String, Period), micros: i64, now: DateTime<Utc>) {
        if self.grace <= Duration::zero() {
            return;
        }
        let mut entries = self.lock();
        entries.retain(|_, cached| now.signed_duration_since(cached.observed_at) <= self.grace);
        entries.insert(
            key,
            CachedSpend {
                micros,
                observed_at: now,
            },
        );
    }

    /// The reading for `key` if one exists and is still inside `grace`, with its age.
    pub(crate) fn recall(
        &self,
        key: &(String, Period),
        now: DateTime<Utc>,
    ) -> Option<(i64, Duration)> {
        if self.grace <= Duration::zero() {
            return None;
        }
        let cached = *self.lock().get(key)?;
        let age = now.signed_duration_since(cached.observed_at);
        // A negative age means the clock went backwards between two reads; treat it as fresh
        // rather than as expired -- refusing service over a clock adjustment would be a worse
        // outcome than serving a reading that is, if anything, newer than we think.
        (age <= self.grace).then_some((cached.micros, age.max(Duration::zero())))
    }

    /// A poisoned mutex here means a previous caller panicked while holding a map of plain
    /// `i64`/timestamp values -- there is no invariant to have been broken, so the guard is
    /// recovered rather than propagated as a panic that would take the endpoint down for every
    /// subsequent request.
    fn lock(&self) -> MutexGuard<'_, HashMap<(String, Period), CachedSpend>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

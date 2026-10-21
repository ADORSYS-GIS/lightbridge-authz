//! The spend query for one account over a half-open interval (#549 AC3).
//!
//! Split out of `repo.rs` by the LoC gate (`.github/actions/loc-gate`): the spend query is a
//! self-contained unit that does not belong to the ingest/query repo, and keeping it here lets
//! `repo.rs` stay under its ceiling. The pairing is unchanged -- `StoreRepo::spend_for_account`
//! delegates here, and the two files move together.

use chrono::{DateTime, Utc};
use lightbridge_authz_core::Result;
use sqlx::PgPool;
use tracing::debug;

/// Sums `usage_events.total_cost` for one account over a half-open `[start, end)` interval.
/// This is the exact query `lightbridge-authz-budget`'s (now-removed) `TimescaleSpendReader`
/// ran directly against this same table before the spend-query dependency was inverted onto
/// this HTTP endpoint -- see `crates/lightbridge-authz-budget/src/spend.rs`. `None` means SQL
/// `SUM` over zero matching rows (`NULL`), never collapsed to `0.0` here: that distinction is
/// load-bearing for the budget domain's `Spend::Known`/`Spend::Unavailable` split.
///
/// ## Reads raw UNION ALL rollup (#549 AC2)
///
/// Since the retention job rolls rows older than `raw_days` out of `usage_events` into
/// `usage_events_daily`, a spend query must read both or it would silently under-count once
/// data ages past the boundary. The two arms are `UNION ALL`ed and summed as one set, which
/// preserves the exact `SUM`-over-NULL semantics: an empty combined set, or one where every
/// `total_cost` is NULL, yields `None`; any non-NULL cost yields `Some(sum)`. The current
/// billing period is always within the raw window, so for the queries budget actually issues
/// the rollup arm is empty and the result is identical to the pre-rollup query (AC3).
///
/// ## Day-granularity of the rollup arm
///
/// The rollup arm matches on `bucket_start` (the truncated day), not `observed_at`, because a
/// rolled-up day is stored as a single row keyed by its day boundary. A day is either entirely
/// raw or entirely rolled up (only complete days are rolled up), so there is no double-count
/// between the arms. The consequence is that a spend query whose `[start, end)` boundary falls
/// MID-DAY on a day that has aged into the rollup is **day-granular**: the rollup row for that
/// day is included only if its `bucket_start` is within `[start, end)`, so a sub-day slice of a
/// rolled-up day is not answered exactly. This never manifests for budget's real queries --
/// billing periods are month-aligned (day boundaries) and always within the raw window, so the
/// rollup arm is empty -- but callers should treat spend over a rolled-up period as
/// day-granular, not sub-day-exact.
///
/// ## EAIG is the sole spend authority (governance#358, ADR-0028 D8)
///
/// Public IDE collectors (Claude Code, Codex, OpenCode) may write request-grain observations of
/// the *same* model calls EAIG already bills through the gateway. Summing both would double the
/// account's spend, so both arms restrict to `source IS NULL OR source = 'eaig'`. `NULL` is
/// deliberately treated as EAIG, not excluded: every row written before `usage_events.source`
/// existed (20260908000003) and every row rolled up before `usage_events_daily.source` existed
/// (20260922000002) is `NULL` there and is, in substance, 100% EAIG traffic -- excluding `NULL`
/// would silently undercount that legacy spend. Only a row *affirmatively* tagged with a non-eaig
/// source (`claude-code`, `codex`, `opencode`, ...) is excluded. This is a restriction, not a
/// join, so it costs nothing when no non-eaig source has ever been written -- the common case
/// today.
pub async fn spend_for_account(
    pool: &PgPool,
    account_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Option<f64>> {
    debug!(
        "querying spend for account_id={} start={} end={}",
        account_id, start, end
    );
    let total_cost: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(total_cost)::double precision FROM ( \
             SELECT total_cost FROM usage_events \
             WHERE account_id = $1 AND observed_at >= $2 AND observed_at < $3 \
                 AND (source IS NULL OR source = 'eaig') \
             UNION ALL \
             SELECT total_cost FROM usage_events_daily \
             WHERE account_id = $1 AND bucket_start >= $2 AND bucket_start < $3 \
                 AND (source IS NULL OR source = 'eaig') \
         ) AS spend_rows",
    )
    .bind(account_id)
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await?;

    Ok(total_cost)
}

/// lightbridge-authz ADR-0035 D6: the account's spend INGESTED in `(after, until]`, by
/// `created_at`, so an event that arrives late can never fall behind the settlement watermark.
/// Raw rows only: a settlement window is minutes old, far inside raw retention, so the daily
/// rollup is never needed. The `observed_at` bound only lets a partitioned table skip chunks.
pub async fn spend_ingested_for_account(
    pool: &PgPool,
    account_id: &str,
    observed: (DateTime<Utc>, DateTime<Utc>),
    ingested: (DateTime<Utc>, DateTime<Utc>),
) -> Result<Option<f64>> {
    let total_cost: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(total_cost)::double precision FROM usage_events \
         WHERE account_id = $1 AND created_at > $2 AND created_at <= $3 \
             AND observed_at >= $4 AND observed_at < $5 \
             AND (source IS NULL OR source = 'eaig')",
    )
    .bind(account_id)
    .bind(ingested.0)
    .bind(ingested.1)
    .bind(observed.0)
    .bind(observed.1)
    .fetch_one(pool)
    .await?;
    Ok(total_cost)
}

//! The statements ADR-0035's granted/paid write paths run (`credit_repo.rs` for funding,
//! `settlement_book.rs` for settlement). Kept apart so each caller stays inside the 200-line
//! house rule; every statement here runs inside a caller's transaction.

/// A lot-opening credit row (purchase / promotion / referral). No period: only allowance has one
/// (D2). Idempotent on `idempotency_key`, like `BudgetRepo::grant`.
pub(crate) const INSERT_CREDIT_SQL: &str = "INSERT INTO budget_grants \
    (id, budget_account_id, account_id, pool, period, amount_micros, source, actor_id, reason, \
     idempotency_key, external_ref, expires_at) \
    VALUES ($1, $2, $2, $3, NULL, $4, $5, $6, $7, $8, $9, $10) \
    ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING \
    RETURNING id, created_at";

/// A debit row. `period` is set for allowance draws and NULL for lot draws; `lot_id` the reverse
/// (the CHECKs reject any other combination). Idempotent on `trigger_key` for settlement, and on
/// `idempotency_key` for a reversal.
pub(crate) const INSERT_DEBIT_SQL: &str = "INSERT INTO budget_grants \
    (id, budget_account_id, account_id, pool, period, amount_micros, source, lot_id, actor_id, \
     reason, idempotency_key, trigger_key, external_ref) \
    VALUES ($1, $2, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
    ON CONFLICT DO NOTHING \
    RETURNING id";

/// The row an idempotency key already names: a funding replay returns it rather than booking
/// twice, after checking it is the SAME request.
pub(crate) const SELECT_BY_IDEMPOTENCY_KEY_SQL: &str = "SELECT g.id, g.budget_account_id, \
    g.pool, g.source, g.amount_micros, g.lot_id, COALESCE(l.remaining_micros, 0) AS remaining \
    FROM budget_grants g LEFT JOIN credit_lots l ON l.lot_id = COALESCE(g.lot_id, g.id) \
    WHERE g.idempotency_key = $1";

pub(crate) const INSERT_LOT_SQL: &str = "INSERT INTO credit_lots \
    (lot_id, budget_account_id, pool, amount_micros, remaining_micros, expires_at, opened_at) \
    VALUES ($1, $2, $3, $4, $4, $5, $6)";

/// Locks one lot for a debit against it. The account and pool are part of the predicate, so a
/// debit can never draw on another account's lot or another pool's (D3).
pub(crate) const LOCK_LOT_SQL: &str = "SELECT remaining_micros FROM credit_lots \
    WHERE lot_id = $1 AND budget_account_id = $2 AND pool = $3 FOR UPDATE";

/// Applies a debit to a lot; closes it when it reaches zero. `$2` is the NEGATIVE amount.
pub(crate) const DEBIT_LOT_SQL: &str = "UPDATE credit_lots SET \
    remaining_micros = remaining_micros + $2, \
    closed_at = CASE WHEN remaining_micros + $2 = 0 THEN now() ELSE closed_at END \
    WHERE lot_id = $1";

/// Moves the gateway's snapshot by a granted/paid credit or debit in the same transaction, so a
/// purchase is visible on the very next request (D9). Unlike the allowance delta there is no
/// period guard: these pools have no period. NULL columns stay NULL ("not computed yet").
pub(crate) const SNAPSHOT_GRANTED_DELTA_SQL: &str = "UPDATE budget_remaining_snapshots SET \
    ceiling_micros = ceiling_micros + $2, remaining_micros = remaining_micros + $2, \
    granted_remaining_micros = granted_remaining_micros + $2, refreshed_at = now() \
    WHERE budget_account_id = $1 AND remaining_micros IS NOT NULL";

pub(crate) const SNAPSHOT_PAID_DELTA_SQL: &str = "UPDATE budget_remaining_snapshots SET \
    ceiling_micros = ceiling_micros + $2, remaining_micros = remaining_micros + $2, \
    paid_remaining_micros = paid_remaining_micros + $2, refreshed_at = now() \
    WHERE budget_account_id = $1 AND remaining_micros IS NOT NULL";

pub(crate) const ACCOUNT_EXISTS_SQL: &str = "SELECT 1 FROM accounts WHERE id = $1";

//! ADR-0035 D6's spending order, as a pure function: given what an account owes and the credit it
//! has, decide which credit pays for it. No I/O, so every ordering rule is unit-testable without
//! a database (`tests/settlement_alloc_tests.rs`); `settlement.rs` books the result.
//!
//! The order is: allowance, then granted lots (soonest `expires_at` first, a lot without one last,
//! oldest `opened_at` breaking ties), then paid lots (oldest `opened_at` first). Whatever no credit
//! covers is debt (D7). Expiring credit goes first because it is the customer-friendly order and
//! it keeps the paid liability honest.

use chrono::{DateTime, Utc};

use crate::pool::CreditPool;

/// One open granted/paid lot, as settlement sees it under its row lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenLot {
    pub lot_id: String,
    pub pool: CreditPool,
    pub remaining_micros: i64,
    pub expires_at: Option<DateTime<Utc>>,
    pub opened_at: DateTime<Utc>,
}

/// Where one draw's credit came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrawTarget {
    Allowance,
    Lot { lot_id: String, pool: CreditPool },
}

/// One `consumption` row to book: `amount_micros` is POSITIVE here (the credit used); the ledger
/// row stores it negated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draw {
    pub target: DrawTarget,
    pub amount_micros: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allocation {
    pub draws: Vec<Draw>,
    /// What no credit covered: the account's debt after this allocation.
    pub debt_micros: i64,
}

/// Sorts lots into spending order: granted before paid; within granted, soonest expiry first
/// (no expiry last), then oldest; within paid, oldest first.
pub fn sort_spending_order(lots: &mut [OpenLot]) {
    lots.sort_by(|a, b| {
        let pool_rank = |lot: &OpenLot| u8::from(lot.pool == CreditPool::Paid);
        pool_rank(a)
            .cmp(&pool_rank(b))
            .then_with(|| match (a.pool, a.expires_at, b.expires_at) {
                (CreditPool::Granted, Some(x), Some(y)) => x.cmp(&y),
                (CreditPool::Granted, Some(_), None) => std::cmp::Ordering::Less,
                (CreditPool::Granted, None, Some(_)) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.opened_at.cmp(&b.opened_at))
    });
}

/// Pays `owed_micros` from `allowance_available_micros` first, then `lots` in the order given
/// (call [`sort_spending_order`] first). Negative inputs are treated as zero: a negative owed is
/// nothing to pay, and a negative allowance (an operator correction overshooting) is no credit.
pub fn allocate(owed_micros: i64, allowance_available_micros: i64, lots: &[OpenLot]) -> Allocation {
    let mut left = owed_micros.max(0);
    let mut draws = Vec::new();

    let from_allowance = left.min(allowance_available_micros.max(0));
    if from_allowance > 0 {
        draws.push(Draw {
            target: DrawTarget::Allowance,
            amount_micros: from_allowance,
        });
        left -= from_allowance;
    }

    for lot in lots {
        if left == 0 {
            break;
        }
        let take = left.min(lot.remaining_micros.max(0));
        if take > 0 {
            draws.push(Draw {
                target: DrawTarget::Lot {
                    lot_id: lot.lot_id.clone(),
                    pool: lot.pool,
                },
                amount_micros: take,
            });
            left -= take;
        }
    }

    Allocation {
        draws,
        debt_micros: left,
    }
}

/// Per-pool remaining balances after charging `owed_micros` in spending order -- the refresher's
/// estimate between settlements (D9). Only the totals per pool matter here, so the lots inside a
/// pool are summed rather than ordered.
pub fn remaining_after(
    owed_micros: i64,
    allowance_micros: i64,
    granted_micros: i64,
    paid_micros: i64,
) -> (i64, i64, i64) {
    let mut left = owed_micros.max(0);
    let mut take = |available: i64| {
        let available = available.max(0);
        let used = left.min(available);
        left -= used;
        available - used
    };
    let allowance = take(allowance_micros);
    let granted = take(granted_micros);
    let paid = take(paid_micros);
    (allowance, granted, paid)
}

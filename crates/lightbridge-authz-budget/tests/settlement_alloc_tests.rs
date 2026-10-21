//! ADR-0035 D6's spending order, pinned without a database.
#![allow(clippy::unwrap_used)]

use chrono::{DateTime, TimeZone, Utc};
use lightbridge_authz_budget::pool::CreditPool;
use lightbridge_authz_budget::settlement_alloc::{
    Draw, DrawTarget, OpenLot, allocate, remaining_after, sort_spending_order,
};

fn day(d: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, d, 0, 0, 0).single().unwrap()
}

fn lot(id: &str, pool: CreditPool, remaining: i64, expires: Option<u32>, opened: u32) -> OpenLot {
    OpenLot {
        lot_id: id.to_string(),
        pool,
        remaining_micros: remaining,
        expires_at: expires.map(day),
        opened_at: day(opened),
    }
}

fn ids(lots: &[OpenLot]) -> Vec<&str> {
    lots.iter().map(|lot| lot.lot_id.as_str()).collect()
}

#[test]
fn granted_before_paid_soonest_expiry_first_no_expiry_last_paid_oldest_first() {
    let mut lots = vec![
        lot("paid-new", CreditPool::Paid, 1, None, 9),
        lot("granted-never", CreditPool::Granted, 1, None, 1),
        lot("paid-old", CreditPool::Paid, 1, None, 2),
        lot("granted-late", CreditPool::Granted, 1, Some(30), 1),
        lot("granted-soon", CreditPool::Granted, 1, Some(20), 5),
    ];
    sort_spending_order(&mut lots);
    assert_eq!(
        ids(&lots),
        vec![
            "granted-soon",
            "granted-late",
            "granted-never",
            "paid-old",
            "paid-new"
        ]
    );
}

/// The ADR's worked example: $8 allowance, $5 promotion, $20 purchase, $10 spent.
#[test]
fn allowance_is_drawn_first_then_lots_in_order() {
    let lots = vec![
        lot("promo", CreditPool::Granted, 5_000_000, Some(31), 1),
        lot("purchase", CreditPool::Paid, 20_000_000, None, 3),
    ];
    let allocation = allocate(10_000_000, 8_000_000, &lots);
    assert_eq!(
        allocation.draws,
        vec![
            Draw {
                target: DrawTarget::Allowance,
                amount_micros: 8_000_000
            },
            Draw {
                target: DrawTarget::Lot {
                    lot_id: "promo".into(),
                    pool: CreditPool::Granted
                },
                amount_micros: 2_000_000,
            },
        ]
    );
    assert_eq!(allocation.debt_micros, 0);
}

#[test]
fn spend_beyond_all_credit_becomes_debt() {
    let lots = vec![lot("purchase", CreditPool::Paid, 1_000_000, None, 1)];
    let allocation = allocate(5_000_000, 2_000_000, &lots);
    assert_eq!(allocation.draws.len(), 2);
    assert_eq!(allocation.debt_micros, 2_000_000);
}

#[test]
fn nothing_owed_draws_nothing_and_negative_inputs_are_zero() {
    assert!(allocate(0, 5, &[]).draws.is_empty());
    assert!(allocate(-3, 5, &[]).draws.is_empty());
    let allocation = allocate(4, -10, &[]);
    assert!(allocation.draws.is_empty());
    assert_eq!(allocation.debt_micros, 4);
}

#[test]
fn per_pool_estimate_charges_in_spending_order() {
    assert_eq!(remaining_after(10, 8, 5, 20), (0, 3, 20));
    assert_eq!(remaining_after(0, 8, 5, 20), (8, 5, 20));
    assert_eq!(remaining_after(40, 8, 5, 20), (0, 0, 0));
}

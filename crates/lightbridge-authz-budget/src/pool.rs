//! `budget_grants.pool` (ADR-0035 D1): which of an account's three credit pools a ledger row
//! belongs to. The pool, not the source, decides how a row behaves -- whether resets touch it,
//! whether it carries a period, whether it is tracked per lot.

use std::fmt;
use std::str::FromStr;

use crate::error::BudgetError;
use crate::source::GrantSource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CreditPool {
    /// Free credit: period-scoped, renewed by reset schedules, summed per period (never lots).
    Allowance,
    /// Promotions, referrals, goodwill: lot-tracked, expire per lot, never touched by resets.
    Granted,
    /// Purchased credit: lot-tracked, never expires by default, never touched by resets.
    Paid,
}

impl CreditPool {
    pub fn as_str(&self) -> &'static str {
        match self {
            CreditPool::Allowance => "allowance",
            CreditPool::Granted => "granted",
            CreditPool::Paid => "paid",
        }
    }

    /// Granted and paid credit are lot-tracked (ADR-0035 D3); allowance is period-summed.
    pub fn is_lot_tracked(&self) -> bool {
        !matches!(self, CreditPool::Allowance)
    }

    /// The pool a machine caller's source writes to. The pool is derived from the source and
    /// never read from a request body (D1). `None` for sources a caller does not choose a pool
    /// through: allowance-only sources, `admin` (the one human choice), and the debit sources
    /// whose pool is that of the credit they draw from.
    pub fn for_funding_source(source: GrantSource) -> Option<CreditPool> {
        match source {
            GrantSource::Purchase | GrantSource::PurchaseReversal => Some(CreditPool::Paid),
            GrantSource::Promotion | GrantSource::Referral => Some(CreditPool::Granted),
            _ => None,
        }
    }
}

impl fmt::Display for CreditPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CreditPool {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allowance" => Ok(CreditPool::Allowance),
            "granted" => Ok(CreditPool::Granted),
            "paid" => Ok(CreditPool::Paid),
            other => Err(BudgetError::StorageFailed(format!(
                "unknown budget_grants.pool '{other}'"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pool_round_trips() {
        for pool in [CreditPool::Allowance, CreditPool::Granted, CreditPool::Paid] {
            assert_eq!(pool.as_str().parse::<CreditPool>().unwrap(), pool);
        }
    }

    #[test]
    fn only_allowance_is_period_summed() {
        assert!(!CreditPool::Allowance.is_lot_tracked());
        assert!(CreditPool::Granted.is_lot_tracked());
        assert!(CreditPool::Paid.is_lot_tracked());
    }

    #[test]
    fn funding_sources_map_to_their_pool_and_nothing_else_does() {
        assert_eq!(
            CreditPool::for_funding_source(GrantSource::Purchase),
            Some(CreditPool::Paid)
        );
        assert_eq!(
            CreditPool::for_funding_source(GrantSource::Referral),
            Some(CreditPool::Granted)
        );
        assert_eq!(CreditPool::for_funding_source(GrantSource::Admin), None);
        assert_eq!(
            CreditPool::for_funding_source(GrantSource::Consumption),
            None
        );
    }
}

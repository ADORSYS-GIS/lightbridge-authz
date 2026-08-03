//! Integer micro-USD amounts, matching `gateway_ratelimit_spend_micro_usd` elsewhere on the
//! platform. A float anywhere near a currency amount is a defect (#189) -- this type is the
//! one place that rule is enforced for the budget domain.
//!
//! `AmountMicros` models the *size of a grant* (always positive): a balance, a tier value, a
//! requested top-up. It deliberately does not model a `correction` source's signed ledger
//! delta -- that stays a plain `i64` at the repository layer in a later PR.

use std::fmt;

use crate::error::BudgetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AmountMicros(i64);

impl AmountMicros {
    pub fn new(value: i64) -> Result<Self, BudgetError> {
        if value <= 0 {
            return Err(BudgetError::InvalidAmount(value));
        }
        Ok(Self(value))
    }

    pub fn get(&self) -> i64 {
        self.0
    }
}

impl fmt::Display for AmountMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<AmountMicros> for i64 {
    fn from(value: AmountMicros) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_rejected() {
        assert!(matches!(
            AmountMicros::new(0),
            Err(BudgetError::InvalidAmount(0))
        ));
    }

    #[test]
    fn negative_is_rejected() {
        assert!(matches!(
            AmountMicros::new(-1),
            Err(BudgetError::InvalidAmount(-1))
        ));
    }

    #[test]
    fn positive_succeeds_and_round_trips() {
        let amount = AmountMicros::new(15_000_000).expect("positive amount must succeed");
        assert_eq!(amount.get(), 15_000_000);
        assert_eq!(i64::from(amount), 15_000_000);
    }
}

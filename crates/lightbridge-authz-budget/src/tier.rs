//! The append-only budget-tier ladder from ADR-0008. `x-budget-tier` is stamped on every
//! request; a refill moves an account up one rung. The ladder may grow (`b-2000` may be
//! added later) but existing rungs are never reordered or removed -- the `Ord` derive below
//! relies on the variants staying declared in exactly this ascending order.

use std::fmt;
use std::str::FromStr;

use crate::amount::AmountMicros;
use crate::error::BudgetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BudgetTier {
    B15,
    B30,
    B60,
    B120,
    B250,
    B500,
    B1000,
}

impl BudgetTier {
    pub fn amount(&self) -> AmountMicros {
        let micros = match self {
            BudgetTier::B15 => 15_000_000,
            BudgetTier::B30 => 30_000_000,
            BudgetTier::B60 => 60_000_000,
            BudgetTier::B120 => 120_000_000,
            BudgetTier::B250 => 250_000_000,
            BudgetTier::B500 => 500_000_000,
            BudgetTier::B1000 => 1_000_000_000,
        };
        AmountMicros::new(micros).expect("every budget tier amount is a positive constant")
    }

    pub fn label(&self) -> &'static str {
        match self {
            BudgetTier::B15 => "b-15",
            BudgetTier::B30 => "b-30",
            BudgetTier::B60 => "b-60",
            BudgetTier::B120 => "b-120",
            BudgetTier::B250 => "b-250",
            BudgetTier::B500 => "b-500",
            BudgetTier::B1000 => "b-1000",
        }
    }

    pub fn next(&self) -> Option<BudgetTier> {
        match self {
            BudgetTier::B15 => Some(BudgetTier::B30),
            BudgetTier::B30 => Some(BudgetTier::B60),
            BudgetTier::B60 => Some(BudgetTier::B120),
            BudgetTier::B120 => Some(BudgetTier::B250),
            BudgetTier::B250 => Some(BudgetTier::B500),
            BudgetTier::B500 => Some(BudgetTier::B1000),
            BudgetTier::B1000 => None,
        }
    }
}

impl fmt::Display for BudgetTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl FromStr for BudgetTier {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "b-15" => Ok(BudgetTier::B15),
            "b-30" => Ok(BudgetTier::B30),
            "b-60" => Ok(BudgetTier::B60),
            "b-120" => Ok(BudgetTier::B120),
            "b-250" => Ok(BudgetTier::B250),
            "b-500" => Ok(BudgetTier::B500),
            "b-1000" => Ok(BudgetTier::B1000),
            _ => Err(BudgetError::UnknownTier(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LADDER: [BudgetTier; 7] = [
        BudgetTier::B15,
        BudgetTier::B30,
        BudgetTier::B60,
        BudgetTier::B120,
        BudgetTier::B250,
        BudgetTier::B500,
        BudgetTier::B1000,
    ];

    #[test]
    fn ladder_is_strictly_ascending() {
        for pair in LADDER.windows(2) {
            assert!(pair[0] < pair[1], "{:?} must be < {:?}", pair[0], pair[1]);
        }
        assert!(BudgetTier::B15 < BudgetTier::B30);
        assert!(BudgetTier::B1000 > BudgetTier::B15);
    }

    #[test]
    fn unknown_rung_is_a_typed_error_not_a_default() {
        assert!(matches!(
            "b-2000".parse::<BudgetTier>(),
            Err(BudgetError::UnknownTier(_))
        ));
        assert!("b-20".parse::<BudgetTier>().is_err());
        assert!("garbage".parse::<BudgetTier>().is_err());
        assert!("".parse::<BudgetTier>().is_err());
    }

    #[test]
    fn top_rung_has_no_next() {
        assert_eq!(BudgetTier::B1000.next(), None);
    }

    #[test]
    fn every_other_rung_has_the_expected_next() {
        for pair in LADDER.windows(2) {
            assert_eq!(pair[0].next(), Some(pair[1]));
        }
    }

    #[test]
    fn each_tier_amount_matches_the_dollar_value_table() {
        assert_eq!(
            BudgetTier::B15.amount(),
            AmountMicros::new(15_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B30.amount(),
            AmountMicros::new(30_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B60.amount(),
            AmountMicros::new(60_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B120.amount(),
            AmountMicros::new(120_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B250.amount(),
            AmountMicros::new(250_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B500.amount(),
            AmountMicros::new(500_000_000).expect("valid amount")
        );
        assert_eq!(
            BudgetTier::B1000.amount(),
            AmountMicros::new(1_000_000_000).expect("valid amount")
        );
    }

    #[test]
    fn label_matches_wire_form() {
        assert_eq!(BudgetTier::B15.label(), "b-15");
        assert_eq!(BudgetTier::B1000.label(), "b-1000");
        assert_eq!(BudgetTier::B15.to_string(), "b-15");
    }
}

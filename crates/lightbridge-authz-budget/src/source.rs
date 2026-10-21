//! `budget_grants.source`: the reason a ledger row exists, per ADR-0009, extended by ADR-0035 D4
//! with the paid/granted credit sources and the debits settlement books. Matched verbatim against
//! the DB `CHECK` constraint `budget_grants_source_chk`.

use std::fmt;
use std::str::FromStr;

use crate::error::BudgetError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantSource {
    Base,
    SelfService,
    Admin,
    Automatic,
    ManualApproval,
    Refund,
    Correction,
    Promotion,
    Migration,
    Purchase,
    PurchaseReversal,
    Referral,
    Consumption,
    Expiry,
}

const ALL_SOURCES: [(GrantSource, &str); 14] = [
    (GrantSource::Base, "base"),
    (GrantSource::SelfService, "self_service"),
    (GrantSource::Admin, "admin"),
    (GrantSource::Automatic, "automatic"),
    (GrantSource::ManualApproval, "manual_approval"),
    (GrantSource::Refund, "refund"),
    (GrantSource::Correction, "correction"),
    (GrantSource::Promotion, "promotion"),
    (GrantSource::Migration, "migration"),
    (GrantSource::Purchase, "purchase"),
    (GrantSource::PurchaseReversal, "purchase_reversal"),
    (GrantSource::Referral, "referral"),
    (GrantSource::Consumption, "consumption"),
    (GrantSource::Expiry, "expiry"),
];

impl GrantSource {
    fn as_str(&self) -> &'static str {
        ALL_SOURCES
            .iter()
            .find(|(source, _)| source == self)
            .map(|(_, name)| *name)
            .expect("every GrantSource variant is listed in ALL_SOURCES")
    }

    /// A debit removes credit: its amount must be negative (ADR-0035 D4).
    pub fn is_debit(&self) -> bool {
        matches!(
            self,
            GrantSource::PurchaseReversal | GrantSource::Consumption | GrantSource::Expiry
        )
    }

    /// The sign rule `budget_grants_amount_sign_chk` enforces, for a row in the ALLOWANCE pool:
    /// debits are negative, `correction` is any non-zero amount, everything else is positive.
    /// Granted/paid rows are written by `credit_repo`/`settlement`, which check their own signs.
    pub fn validate_allowance_amount(&self, amount_micros: i64) -> Result<(), BudgetError> {
        let sign_is_valid = match self {
            GrantSource::Correction => amount_micros != 0,
            source if source.is_debit() => amount_micros < 0,
            _ => amount_micros > 0,
        };
        if sign_is_valid {
            Ok(())
        } else {
            Err(BudgetError::InvalidAmount(amount_micros))
        }
    }
}

impl fmt::Display for GrantSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for GrantSource {
    type Err = BudgetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ALL_SOURCES
            .iter()
            .find(|(_, name)| *name == s)
            .map(|(source, _)| *source)
            .ok_or_else(|| BudgetError::UnknownSource(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_round_trips() {
        for (source, _) in ALL_SOURCES {
            let rendered = source.to_string();
            let parsed: GrantSource = rendered.parse().expect("rendered form must parse back");
            assert_eq!(parsed, source);
        }
    }

    #[test]
    fn unrecognized_string_errors() {
        assert!(matches!(
            "not_a_source".parse::<GrantSource>(),
            Err(BudgetError::UnknownSource(_))
        ));
    }

    #[test]
    fn allowance_sign_rule_matches_the_check_constraint() {
        assert!(GrantSource::Base.validate_allowance_amount(1).is_ok());
        assert!(GrantSource::Base.validate_allowance_amount(-1).is_err());
        assert!(
            GrantSource::Correction
                .validate_allowance_amount(-1)
                .is_ok()
        );
        assert!(
            GrantSource::Correction
                .validate_allowance_amount(0)
                .is_err()
        );
        assert!(GrantSource::Expiry.validate_allowance_amount(-1).is_ok());
        assert!(GrantSource::Expiry.validate_allowance_amount(1).is_err());
        assert!(
            GrantSource::Consumption
                .validate_allowance_amount(0)
                .is_err()
        );
    }
}

//! `budget_grants.source`: the reason a grant row exists, per ADR-0009. Exactly the nine
//! variants that migration PR 1.1's DB `CHECK` constraint enforces, matched here verbatim.

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
}

impl GrantSource {
    fn as_str(&self) -> &'static str {
        match self {
            GrantSource::Base => "base",
            GrantSource::SelfService => "self_service",
            GrantSource::Admin => "admin",
            GrantSource::Automatic => "automatic",
            GrantSource::ManualApproval => "manual_approval",
            GrantSource::Refund => "refund",
            GrantSource::Correction => "correction",
            GrantSource::Promotion => "promotion",
            GrantSource::Migration => "migration",
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
        match s {
            "base" => Ok(GrantSource::Base),
            "self_service" => Ok(GrantSource::SelfService),
            "admin" => Ok(GrantSource::Admin),
            "automatic" => Ok(GrantSource::Automatic),
            "manual_approval" => Ok(GrantSource::ManualApproval),
            "refund" => Ok(GrantSource::Refund),
            "correction" => Ok(GrantSource::Correction),
            "promotion" => Ok(GrantSource::Promotion),
            "migration" => Ok(GrantSource::Migration),
            _ => Err(BudgetError::UnknownSource(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [GrantSource; 9] = [
        GrantSource::Base,
        GrantSource::SelfService,
        GrantSource::Admin,
        GrantSource::Automatic,
        GrantSource::ManualApproval,
        GrantSource::Refund,
        GrantSource::Correction,
        GrantSource::Promotion,
        GrantSource::Migration,
    ];

    #[test]
    fn every_variant_round_trips() {
        for source in ALL {
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
}

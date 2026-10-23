//! `budget_grants.source`: the reason a grant row exists, per ADR-0009. The nine variants that
//! migration PR 1.1's DB `CHECK` constraint enforces, matched here verbatim, plus two read-only
//! variants for rows the withdrawn ADR-0035 left behind.

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
    /// Read-only. Spend that ADR-0035's settlement booked as a negative allowance row before the
    /// ADR was withdrawn. `budget_grants` is append-only (ADR-0009), so those rows stay forever,
    /// and they must still list; nothing writes this source any more.
    Consumption,
    /// Read-only. A reset-down that ADR-0035 D8 booked as `expiry` instead of `correction`, kept
    /// for the same reason as [`GrantSource::Consumption`].
    Expiry,
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
            GrantSource::Consumption => "consumption",
            GrantSource::Expiry => "expiry",
        }
    }

    /// Whether a new row may be booked with this source. The read-only variants are also
    /// unbookable through `BudgetRepo::grant` without this check (it demands a positive amount,
    /// the DB `CHECK` demands a negative one for them); this says so up front, with a reason.
    pub fn is_writable(&self) -> bool {
        !matches!(self, GrantSource::Consumption | GrantSource::Expiry)
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
            "consumption" => Ok(GrantSource::Consumption),
            "expiry" => Ok(GrantSource::Expiry),
            _ => Err(BudgetError::UnknownSource(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [GrantSource; 11] = [
        GrantSource::Base,
        GrantSource::SelfService,
        GrantSource::Admin,
        GrantSource::Automatic,
        GrantSource::ManualApproval,
        GrantSource::Refund,
        GrantSource::Correction,
        GrantSource::Promotion,
        GrantSource::Migration,
        GrantSource::Consumption,
        GrantSource::Expiry,
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

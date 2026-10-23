//! The two sources the withdrawn ADR-0035 booked (`consumption`, `expiry`) stay readable, so the
//! append-only ledger rows it left behind still list, and stay unbookable.

use std::str::FromStr;

use lightbridge_authz_budget::GrantSource;

#[test]
fn historical_settlement_sources_parse_but_are_not_writable() {
    for name in ["consumption", "expiry"] {
        let source =
            GrantSource::from_str(name).expect("a historical ledger row's source must still parse");
        assert_eq!(source.to_string(), name);
        assert!(!source.is_writable(), "{name} must not be bookable");
    }
}

#[test]
fn every_bookable_source_stays_writable() {
    for name in [
        "base",
        "self_service",
        "admin",
        "automatic",
        "manual_approval",
        "refund",
        "correction",
        "promotion",
        "migration",
    ] {
        let source = GrantSource::from_str(name).expect("a bookable source must parse");
        assert!(source.is_writable(), "{name} must stay bookable");
    }
}

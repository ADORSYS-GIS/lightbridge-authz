//! A validated calendar-month period (`'YYYY-MM'`, UTC). Per ADR-0008, the period is a
//! calendar month -- this is the corrected representation from ADR-0008 (superseding the old
//! 30-day epoch bucket that used to rotate the same counter a second time, silently).
//!
//! Deliberately clock-free: callers supply `year`/`month` explicitly rather than this type
//! reading the clock itself, the same instinct ADR-0007 records for `now` ("passing `now` in
//! as input rather than calling `time.now_ns()`") applied here for the same testability reason.

use std::fmt;

use crate::error::BudgetError;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Period(String);

impl Period {
    pub fn parse(s: &str) -> Result<Self, BudgetError> {
        let invalid = || BudgetError::InvalidPeriod(s.to_string());

        let bytes = s.as_bytes();
        if bytes.len() != 7 || bytes[4] != b'-' {
            return Err(invalid());
        }

        let is_ascii_digit = |b: u8| b.is_ascii_digit();
        if !bytes[0..4].iter().copied().all(is_ascii_digit)
            || !bytes[5..7].iter().copied().all(is_ascii_digit)
        {
            return Err(invalid());
        }

        let month_str = std::str::from_utf8(&bytes[5..7]).map_err(|_| invalid())?;
        let month: u32 = month_str.parse().map_err(|_| invalid())?;
        if !(1..=12).contains(&month) {
            return Err(invalid());
        }

        Ok(Self(s.to_string()))
    }

    pub fn from_ymd(year: u32, month: u8) -> Result<Self, BudgetError> {
        if !(1..=12).contains(&month) {
            return Err(BudgetError::InvalidPeriod(format!("{year:04}-{month:02}")));
        }
        Ok(Self(format!("{year:04}-{month:02}")))
    }
}

impl fmt::Display for Period {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_period_parses() {
        let period = Period::parse("2026-08").expect("valid period must parse");
        assert_eq!(period.to_string(), "2026-08");
    }

    #[test]
    fn bad_month_is_rejected() {
        assert!(Period::parse("2026-13").is_err());
    }

    #[test]
    fn wrong_width_is_rejected() {
        assert!(Period::parse("2026-8").is_err());
    }

    #[test]
    fn extra_year_digit_is_rejected() {
        assert!(Period::parse("20260-08").is_err());
    }

    #[test]
    fn empty_string_is_rejected() {
        assert!(Period::parse("").is_err());
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(Period::parse("not-a-period").is_err());
    }

    #[test]
    fn from_ymd_builds_matching_period() {
        let period = Period::from_ymd(2026, 8).expect("valid year/month must succeed");
        assert_eq!(period, Period::parse("2026-08").expect("must parse"));
    }

    #[test]
    fn from_ymd_rejects_invalid_month() {
        assert!(Period::from_ymd(2026, 0).is_err());
        assert!(Period::from_ymd(2026, 13).is_err());
    }
}

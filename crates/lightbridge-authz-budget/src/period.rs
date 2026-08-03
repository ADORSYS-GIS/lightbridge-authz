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

    /// The calendar year, e.g. `2026` for `"2026-08"`. Infallible: `Period` only ever holds a
    /// string that already passed `parse`'s digit/width validation, so the first 4 bytes are
    /// always ASCII digits.
    pub fn year(&self) -> u32 {
        self.0[0..4]
            .parse()
            .expect("Period invariant: first 4 chars are always ASCII digits")
    }

    /// The calendar month (`1..=12`), e.g. `8` for `"2026-08"`. Infallible for the same reason as
    /// `year` above.
    pub fn month(&self) -> u8 {
        self.0[5..7]
            .parse()
            .expect("Period invariant: last 2 chars are always ASCII digits in 1..=12")
    }

    /// The calendar month immediately before this one, e.g. `"2026-08"` -> `"2026-07"`, and
    /// `"2026-01"` -> `"2025-12"` (mirroring the December/January rollover already handled by
    /// `spend.rs`'s `period_bounds_utc`). Infallible: `Period` only ever holds an
    /// already-validated `'YYYY-MM'`, and stepping one month back from any valid year/month
    /// always yields another valid year/month.
    pub fn previous(&self) -> Period {
        let year = self.year();
        let month = self.month();

        let (prev_year, prev_month) = if month == 1 {
            (year - 1, 12)
        } else {
            (year, month - 1)
        };

        Period::from_ymd(prev_year, prev_month)
            .expect("Period invariant: stepping one month back always yields a valid period")
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

    #[test]
    fn year_and_month_accessors_roundtrip() {
        let period = Period::parse("2026-08").expect("valid period must parse");
        assert_eq!(period.year(), 2026);
        assert_eq!(period.month(), 8);
    }

    #[test]
    fn previous_steps_back_one_month_within_a_year() {
        let period = Period::parse("2026-08").expect("valid period must parse");
        assert_eq!(
            period.previous(),
            Period::parse("2026-07").expect("valid period must parse")
        );
    }

    #[test]
    fn previous_rolls_january_back_into_december_of_prior_year() {
        let period = Period::parse("2026-01").expect("valid period must parse");
        assert_eq!(
            period.previous(),
            Period::parse("2025-12").expect("valid period must parse")
        );
    }
}

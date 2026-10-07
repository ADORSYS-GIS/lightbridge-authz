//! What one month-start pass reports, per period. Split from [`crate::period_start`] under this
//! repo's 200-LoC ceiling; re-exported from there, so every path still resolves.

use crate::period::Period;

/// What one pass did for ONE period.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodReport {
    pub period: Period,
    /// Accounts without this period's grant when the pass looked.
    pub missing: usize,
    /// Accounts that now hold it — including any a concurrent replica funded first.
    pub funded: usize,
    /// Accounts that could not be funded; the next tick retries them.
    pub failed: usize,
    /// The first failure's message, so a summary log line can name a cause without N lines. Also
    /// set, with `failed = 0`, when the accounts could not even be listed.
    pub first_error: Option<String>,
}

impl PeriodReport {
    pub(crate) fn new(period: Period, missing: usize) -> Self {
        Self {
            period,
            missing,
            funded: 0,
            failed: 0,
            first_error: None,
        }
    }

    /// `true` when some account may still be unfunded, so the summary must be loud.
    pub fn is_incomplete(&self) -> bool {
        self.failed > 0 || self.first_error.is_some()
    }
}

/// One pass: the current period, and the next one while inside [`PREBOOK_WINDOW`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodStartReport {
    pub current: PeriodReport,
    /// `None` outside the pre-book window.
    pub ahead: Option<PeriodReport>,
}

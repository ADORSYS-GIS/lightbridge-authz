//! `budget schedule` subcommands — split from [`super::cli_budget`] so both files stay under this
//! repo's 200-LoC ceiling. Re-exported from `cli_budget`, so
//! `crate::utils::cli::ScheduleSubcommand` still resolves.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum ScheduleSubcommand {
    /// Author one `budget_reset_schedules` row through `ResetScheduleRepo::create` — the same
    /// validated domain write `createBudgetResetSchedule` performs, never a raw `INSERT`.
    ///
    /// Idempotent on `--name`: a re-run finds the schedule that already exists, refuses if its
    /// shape disagrees with the flags, and otherwise converges `enabled` to `--enable`. That makes
    /// a retried Job or a re-applied manifest a no-op rather than a second schedule quietly
    /// firing against the same accounts.
    Create {
        /// The schedule's name, and its idempotency key on this path. Pick one that says what the
        /// row is for; a re-run with the same name will never author a second schedule.
        #[arg(long)]
        name: String,
        /// `global` | `billing_plan` | `account`. Precedence when several enabled schedules match
        /// one account is `account > billing_plan > global` (ADR-0032), so a `global` row is the
        /// FALLBACK for accounts no narrower schedule covers — including every account between
        /// `createAccount` and its first project.
        #[arg(long)]
        scope: String,
        /// A `projects.billing_plan` value for `--scope billing_plan`, an `accounts.id` for
        /// `--scope account`. Must be ABSENT for `--scope global`; supplying it is refused.
        #[arg(long)]
        scope_id: Option<String>,
        /// `daily` | `weekly` | `monthly`.
        #[arg(long)]
        cadence: String,
        /// ISO weekday `1..=7` (Monday = 1) for `weekly`, day-of-month `1..=28` for `monthly`,
        /// absent for `daily`. The bounds are the DB `CHECK`'s, restated so a bad value is a
        /// legible refusal rather than a constraint violation.
        #[arg(long)]
        anchor: Option<i16>,
        /// `HH:MM`, UTC. The column is `TIME`, not `TIMETZ`: there is no second zone here.
        #[arg(long, default_value = "00:00")]
        run_at_utc: String,
        /// Integer micro-USD. For `--mode reset` this is the balance an account is clamped TO
        /// (`0` is meaningful); for `--mode top_up` it is the amount added and must be positive.
        #[arg(long)]
        amount_micros: i64,
        /// `reset` (clamp remaining to exactly `--amount-micros`, booking a negative `correction`
        /// when the account is above it) or `top_up` (add it, whatever the balance).
        #[arg(long)]
        mode: String,
        /// Forces the FIRST window onto this RFC 3339 instant instead of letting the cadence pick
        /// it. Must be strictly in the future. Use it to line a new schedule up with an existing
        /// one's tick, so the outcome does not depend on what time the Job happened to run.
        #[arg(long)]
        next_run_at: Option<String>,
        /// Enable the schedule. The domain layer always creates a schedule DISABLED (ADR-0032 D8),
        /// so this flag is the operator's explicit second step, performed through the same
        /// `ResetScheduleRepo::update` the `updateBudgetResetSchedule` RPC uses. Without it the
        /// row is authored and left inert.
        #[arg(long)]
        enable: bool,
        /// Resolve and print the row that WOULD be written — validation, the derived or forced
        /// `next_run_at`, everything — and exit `0` having written nothing. A `global` schedule
        /// fires against the whole estate; this is the review step, not a convenience.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print every schedule, enabled or not, oldest first — the read-only verification a Job's
    /// second step (or an operator after one) uses to see what is actually configured. Writes
    /// nothing and prints no credential.
    List,
}

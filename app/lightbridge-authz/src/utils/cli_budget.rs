//! `budget` subcommands — split from [`super::cli`] so that file stays under this repo's 200-LoC
//! ceiling. Re-exported from `cli`, so `crate::utils::cli::BudgetSubcommand` still resolves.

use clap::Subcommand;

#[derive(Subcommand)]
pub enum BudgetSubcommand {
    /// Book one grant through `BudgetRepo::grant` — the same transactional ledger write the
    /// `grantBudget` RPC uses, never a direct `budget_balances` update (ADR-0009).
    Grant {
        /// The BUDGET account id (`budget_grants.budget_account_id`, i.e. an `accounts.id`).
        /// Refused unless it resolves through `accounts ⋈ users`, the same predicate
        /// `GET /budget/v1/remaining` applies.
        #[arg(long)]
        account: String,
        /// Integer micro-USD, positive. Must be stated explicitly: the amount an account should
        /// receive is a decision, and this command deliberately has no default to inherit.
        #[arg(long)]
        amount_micros: i64,
        /// `YYYY-MM`, UTC. Required — the month a grant lands in is exactly what an operator
        /// running this near a boundary must state rather than inherit from the clock.
        #[arg(long)]
        period: String,
        /// A `budget_grants.source` (ADR-0009's nine variants). Defaults to `admin`: an operator
        /// ran this. Pass `automatic` when the grant is standing in for a schedule run, so the
        /// balance projection buckets it the way that schedule would have.
        #[arg(long, default_value = "admin")]
        source: String,
        /// Recorded on the row. Write down why — that is most of what the ledger is for.
        #[arg(long)]
        reason: Option<String>,
        /// Makes a re-run return the grant that already exists instead of booking a second one.
        /// Supply it for anything that can be retried, which is every Job.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

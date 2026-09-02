use clap::{Parser, Subcommand};
use lightbridge_authz::jwk_cmd::KeyPurpose;

#[derive(Parser)]
#[command(name = "lightbridge-authz", author, version, about = "LightBridge Authz CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Serve {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Api {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Opa {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Idp {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
        /// Manage signing keys directly instead of starting the server (kubectl-debug/init-container
        /// operator surface, alongside the existing 30-day age-based auto-rotation).
        #[command(subcommand)]
        command: Option<IdpSubcommand>,
    },
    Budget {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    /// Manage PLATFORM role grants (`platform_role_grants`, ADR-0033) directly against the
    /// configured database. One-shot, no server -- the `idp jwk` pattern. This is how the FIRST
    /// admin exists at all: `grantPlatformRole` needs `rbac:manage`, which needs a role, which
    /// after the cutover nobody is minted by default.
    Rbac {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
        #[command(subcommand)]
        command: RbacCommand,
    },
    Config {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
    Migrate {
        #[arg(long, short, env = "CONFIG_PATH")]
        config_path: String,
    },
}

#[derive(Subcommand)]
pub enum RbacCommand {
    /// Grant a platform role. Idempotent: re-granting a role the person already actively holds
    /// reports the existing grant instead of minting a second one. `granted_by` is recorded as
    /// NULL ("CLI bootstrap") on this path, always.
    Grant {
        /// A `users.id` or an email. An email matching more than one user is REFUSED, never
        /// guessed at -- see `rbac_cmd::resolve_user`.
        #[arg(long)]
        user: String,
        /// Must be one of the roles configured in `oauth2.rbac.role_permissions` (or the built-in
        /// defaults when that is unset). An unknown role is refused: the row would confer nothing
        /// while looking exactly like a successful grant.
        #[arg(long)]
        role: String,
        /// Recorded on the row. Write down why -- that is most of what this table is for.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Revoke the active grant of `--role` for `--user`, then close that person's sessions so the
    /// change bites within the access-token TTL instead of the session lifetime.
    Revoke {
        #[arg(long)]
        user: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Print active grants, optionally filtered. Never prints revoked history.
    List {
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        role: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IdpSubcommand {
    /// Manage signing keys explicitly (list/create/rotate), instead of relying solely on
    /// age-based auto-rotation.
    Jwk {
        #[command(subcommand)]
        command: JwkCommand,
    },
}

#[derive(Subcommand)]
pub enum JwkCommand {
    /// List every signing key (both purposes, active and stale). Never prints private key
    /// material.
    List,
    /// Create an active key for `--type` if none exists yet. Refuses (non-zero exit) if one is
    /// already active -- use `rotate` for that instead.
    New {
        #[arg(long, value_enum)]
        r#type: KeyPurpose,
    },
    /// Force-rotate the active key for `--type`: retires the current one and activates a fresh
    /// one. Requires `--yes`: unlike `list` and `new`, this changes live signing state, and the
    /// operator typing it is the only confirmation an `exec`/init-container context can offer.
    Rotate {
        #[arg(long, value_enum)]
        r#type: KeyPurpose,
        /// Required. Rotation retires the currently active key; without this flag the command
        /// refuses and exits non-zero, so a mistyped or scripted invocation cannot rotate.
        #[arg(long)]
        yes: bool,
    },
}

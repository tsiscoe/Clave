//! Clap v4 CLI surface for Loom (`weave`, `unweave`, `clip`, `audit`, `dict`, `tui`).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "loom",
    version,
    about = "Loom: Bidirectional Format-Preserving Cryptographic PII, IP & Secret Pseudonymizer"
)]
pub struct Cli {
    /// Path to the encrypted SQLite token ledger (defaults to %APPDATA%/loom/loom.db or ~/.config/loom/loom.db).
    #[arg(long, env = "LOOM_DB_PATH", global = true)]
    pub db: Option<PathBuf>,

    /// Passphrase used to derive the Argon2id + HKDF-SHA256 key hierarchy.
    #[arg(long, env = "LOOM_PASSPHRASE", global = true)]
    pub passphrase: Option<String>,

    /// Store or load the master passphrase from the OS native keyring (`windows-native`, `apple-native`, `linux-native`).
    #[arg(long, global = true, default_value_t = false)]
    pub keyring: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Weave (pseudonymize) sensitive IPs, emails, keys, paths, UUIDs, and custom terms into sterile synthetic tokens.
    Weave {
        /// Input file path (reads from stdin if omitted).
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file path (writes to stdout if omitted).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Recursively weave all UTF-8 files in a directory in-place (respecting .gitignore).
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Unweave (restore) synthetic tokens back into their exact original values.
    Unweave {
        /// Input file path containing woven synthetic tokens (reads from stdin if omitted).
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file path for restored text (writes to stdout if omitted).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Scrub or restore the current OS system clipboard in-place.
    Clip {
        /// Reverse (`unweave`) the clipboard instead of scrubbing (`weave`).
        #[arg(long, default_value_t = false)]
        restore: bool,
    },

    /// Audit a directory or git repository for PII, internal IPs, API keys, user paths, or custom terms.
    Audit {
        /// Root directory to scan (defaults to current working directory).
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Emit findings as structured JSON.
        #[arg(long, default_value_t = false)]
        json: bool,

        /// Exit with non-zero status code (1) if any findings are detected (CI gate mode).
        #[arg(long, default_value_t = false)]
        fail_on_leak: bool,
    },

    /// Manage custom dictionary terms (hostnames, project codenames, personal names) in the encrypted ledger.
    Dict {
        #[command(subcommand)]
        action: DictAction,
    },

    /// Launch the Ratatui v0.30+ interactive side-by-side Raw vs. Woven diff viewer.
    Tui {
        /// Optional file to preview in the diff viewer.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DictAction {
    /// Add or update a custom sensitive term and its synthetic alias.
    Add {
        /// Sensitive real term (e.g., internal hostname or project codename).
        #[arg(long)]
        term: String,

        /// Optional custom synthetic alias (auto-generates deterministic `alias_<hex>` if omitted).
        #[arg(long)]
        alias: Option<String>,
    },

    /// List all encrypted token mappings currently stored in the ledger.
    List {
        /// Emit mappings as JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

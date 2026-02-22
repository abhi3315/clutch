use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "clutch",
    about = "CLI clipboard sanitizer — redacts secrets before you paste",
    version
)]
pub struct Args {
    /// Show what would be redacted without modifying clipboard
    #[arg(long)]
    pub dry_run: bool,

    /// Print all active rules (defaults + user config)
    #[arg(long)]
    pub list_rules: bool,

    /// Override config file location
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

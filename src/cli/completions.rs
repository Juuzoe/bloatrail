//! `bloatrail completions` — shell completion scripts.
//!
//! Runs before configuration is loaded, so a broken config file can never
//! block a shell from installing its completions at startup.

use anyhow::Result;
use clap::{Args, CommandFactory};
use clap_complete::Shell;

/// Arguments for `bloatrail completions`.
#[derive(Debug, Args)]
#[command(after_help = "\
Install:
  bash:        bloatrail completions bash >> ~/.bashrc
  zsh:         bloatrail completions zsh > \"${fpath[1]}/_bloatrail\"
  fish:        bloatrail completions fish > ~/.config/fish/completions/bloatrail.fish
  powershell:  bloatrail completions powershell >> $PROFILE")]
pub struct CompletionsArgs {
    /// The shell to generate a script for.
    #[arg(value_enum)]
    pub shell: Shell,
}

/// Run the command.
///
/// # Errors
///
/// Fails only if stdout cannot be written. A pipe closed early (`| head`)
/// counts as normal end of output, matching the rest of the CLI.
pub fn run(args: &CompletionsArgs) -> Result<()> {
    let mut command = super::Cli::command();
    // Render into memory first: clap_complete panics on write errors, so a
    // closed pipe must never reach it.
    let mut script = Vec::new();
    clap_complete::generate(args.shell, &mut command, "bloatrail", &mut script);
    let text = String::from_utf8(script)?;
    crate::output::emit(&text)?;
    Ok(())
}

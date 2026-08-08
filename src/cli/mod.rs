//! Command-line interface.
//!
//! The parser lives here; each subcommand's behaviour lives in its own module.
//! Both share a [`Context`], which resolves configuration, colour and the
//! detector registry exactly once so no command can disagree with another about
//! what the settings are.

pub mod clean;
pub mod completions;
pub mod config_cmd;
pub mod diff;
pub mod doctor;
pub mod duplicates;
pub mod explain;
pub mod largest;
pub mod scan;
pub mod tree;

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};

use crate::analysis::Classifier;
use crate::config::{Overrides, Settings};
use crate::output::{ColorMode, Theme};
use crate::pattern::ExcludeSet;
use crate::platform::KnownPaths;
use crate::scanner::{ScanOptions, ScanResult};
use crate::units::ByteSize;

/// Bloatrail's command-line entry point.
#[derive(Debug, Parser)]
#[command(
    name = "bloatrail",
    version,
    about = "Find out where your disk space actually went",
    long_about = "Bloatrail is a developer-aware disk analyser. It identifies dependencies, \
                  build artifacts, caches, Git data and container storage, explains what each \
                  one is, and offers to remove only what your build tools can recreate.",
    arg_required_else_help = true,
    propagate_version = true
)]
pub struct Cli {
    /// The command to run.
    #[command(subcommand)]
    pub command: Command,

    /// Options shared by every command.
    #[command(flatten)]
    pub global: GlobalArgs,
}

/// Options accepted by every subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Levels of directory nesting to display.
    #[arg(long, short = 'd', global = true, value_name = "N")]
    pub depth: Option<usize>,

    /// Number of rows in ranked output.
    #[arg(long, short = 'n', global = true, value_name = "N")]
    pub top: Option<usize>,

    /// Hide entries smaller than this in `tree` and `largest`, e.g. `10MB`.
    /// Never changes the reported totals.
    #[arg(long, global = true, value_name = "SIZE")]
    pub min_size: Option<String>,

    /// Worker threads. Defaults to one per available core.
    #[arg(long, short = 'j', global = true, value_name = "N")]
    pub threads: Option<usize>,

    /// Skip paths matching a pattern. Repeatable.
    #[arg(long, short = 'x', global = true, value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// Traverse dot-directories that are not developer storage.
    ///
    /// Hidden *files* are always counted; this controls directories only.
    #[arg(long, global = true)]
    pub include_hidden: bool,

    /// Emit machine-readable JSON instead of a report.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable colour. `NO_COLOR` is honoured too.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Use ASCII box drawing instead of Unicode.
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Descend into symbolic links and Windows junctions.
    #[arg(long, global = true)]
    pub follow_symlinks: bool,

    /// Do not cross filesystem boundaries.
    #[arg(long, global = true)]
    pub same_filesystem: bool,

    /// Do not draw live scan progress.
    #[arg(long, global = true)]
    pub no_progress: bool,

    /// Use a specific configuration file.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

impl GlobalArgs {
    /// Convert the parsed flags into configuration overrides.
    ///
    /// # Errors
    ///
    /// Fails if `--min-size` cannot be parsed.
    pub fn overrides(&self) -> Result<Overrides> {
        let min_size = match &self.min_size {
            Some(raw) => Some(
                raw.parse::<ByteSize>()
                    .with_context(|| format!("invalid --min-size value `{raw}`"))?,
            ),
            None => None,
        };

        Ok(Overrides {
            exclude: self.exclude.clone(),
            min_size,
            threads: self.threads,
            // Boolean flags can only turn a setting on, so "absent" and "false"
            // are the same thing and `None` preserves the config file's value.
            follow_symlinks: self.follow_symlinks.then_some(true),
            include_hidden: self.include_hidden.then_some(true),
            same_filesystem: self.same_filesystem.then_some(true),
            depth: self.depth,
            top: self.top,
            ascii: self.ascii.then_some(true),
        })
    }
}

/// The available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a directory and show where the space went.
    Scan(scan::ScanArgs),

    /// Show a directory tree annotated with what each entry is.
    Tree(tree::TreeArgs),

    /// Review and remove regenerable storage.
    Clean(clean::CleanArgs),

    /// Explain what a path is and whether it can be removed.
    Explain(explain::ExplainArgs),

    /// Rank the largest directories or files.
    Largest(largest::LargestArgs),

    /// Find files with identical contents.
    Duplicates(duplicates::DuplicatesArgs),

    /// Report notable disk problems without changing anything.
    Doctor(doctor::DoctorArgs),

    /// Compare against the previous scan of the same path.
    Diff(diff::DiffArgs),

    /// Show or generate the configuration file.
    Config(config_cmd::ConfigArgs),

    /// Print a shell completion script.
    Completions(completions::CompletionsArgs),
}

/// Everything the commands share.
pub struct Context {
    /// Resolved settings from defaults, config file and flags.
    pub settings: Settings,
    /// Terminal presentation.
    pub theme: Theme,
    /// Well-known locations on this machine.
    pub known: KnownPaths,
    /// The detector registry.
    pub classifier: Classifier,
    /// Whether to emit JSON.
    pub json: bool,
    /// Whether live progress may be drawn.
    pub progress: bool,
    /// Set by the Ctrl+C handler; scans check it and stop cleanly.
    pub cancel: crate::scanner::CancelToken,
}

impl Context {
    /// Build the shared context from parsed global arguments.
    ///
    /// # Errors
    ///
    /// Fails if the configuration file is unreadable or malformed.
    pub fn new(global: &GlobalArgs) -> Result<Self> {
        let overrides = global.overrides()?;
        let settings = crate::config::load(global.config.as_deref(), &overrides)
            .context("failed to load configuration")?;

        let color = if global.no_color || global.json {
            ColorMode::Never
        } else {
            ColorMode::Auto
        };

        // First Ctrl+C asks the scan to stop and return what it has; the
        // second gives up and exits. Registration can fail when a handler
        // already exists (tests running many Contexts in one process); the
        // scan simply is not interruptible then, which is how it always was.
        let cancel = crate::scanner::CancelToken::new();
        {
            let token = cancel.clone();
            let pressed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let _ = ctrlc::set_handler(move || {
                if pressed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    std::process::exit(130);
                }
                token.cancel();
                // Only the scanner polls the token, so promise no more than
                // that: other commands keep running until their current step
                // finishes or the second press aborts.
                eprintln!("\nStopping as soon as possible. Press Ctrl+C again to abort now.");
            });
        }

        Ok(Context {
            theme: Theme::new(color, settings.ascii),
            known: KnownPaths::discover(),
            classifier: Classifier::with_default_detectors(),
            json: global.json,
            // Progress on stderr would interleave with JSON readers watching
            // both streams, so it is suppressed there as well.
            progress: !global.no_progress && !global.json,
            cancel,
            settings,
        })
    }

    /// Scan options for `root`, derived from the resolved settings.
    #[must_use]
    pub fn scan_options(&self, root: PathBuf) -> ScanOptions {
        ScanOptions {
            root,
            max_depth: None,
            excludes: ExcludeSet::new(&self.settings.exclude),
            include_hidden: self.settings.include_hidden,
            follow_symlinks: self.settings.follow_symlinks,
            same_filesystem: self.settings.same_filesystem,
            threads: self.settings.threads,
            top_files: crate::scanner::DEFAULT_TOP_FILES.max(self.settings.top * 4),
            stale_days: self.settings.stale_days,
            show_progress: self.progress,
            cancel: self.cancel.clone(),
        }
    }

    /// Run a scan with the shared classifier and location registry.
    ///
    /// # Errors
    ///
    /// Fails if the root cannot be scanned at all.
    pub fn scan(&self, root: PathBuf) -> Result<ScanResult> {
        let display = root.display().to_string();
        let options = self.scan_options(root);
        crate::scanner::scan(&options, &self.classifier, &self.known)
            .with_context(|| format!("failed to scan `{display}`"))
    }

    /// Resolve an optional path argument to a directory, defaulting to the
    /// current working directory.
    ///
    /// # Errors
    ///
    /// Fails if the current directory cannot be determined.
    pub fn resolve(&self, path: Option<&PathBuf>) -> Result<PathBuf> {
        match path {
            Some(path) => Ok(path.clone()),
            None => std::env::current_dir().context("could not determine the current directory"),
        }
    }

    /// Write a rendered report to stdout.
    ///
    /// # Errors
    ///
    /// Fails on write errors other than a closed pipe.
    pub fn emit(&self, text: &str) -> Result<()> {
        crate::output::emit(text).context("failed to write output")
    }
}

/// Run the parsed command.
///
/// # Errors
///
/// Propagates whatever the individual command reports.
pub fn run(cli: Cli) -> Result<()> {
    // Completions need no configuration, no colour decisions and no scan
    // setup, so a broken config file cannot block installing them.
    if let Command::Completions(args) = &cli.command {
        return completions::run(args);
    }

    let context = Context::new(&cli.global)?;

    match cli.command {
        Command::Scan(args) => scan::run(&context, &args),
        Command::Tree(args) => tree::run(&context, &args),
        Command::Clean(args) => clean::run(&context, &args),
        Command::Explain(args) => explain::run(&context, &args),
        Command::Largest(args) => largest::run(&context, &args),
        Command::Duplicates(args) => duplicates::run(&context, &args),
        Command::Doctor(args) => doctor::run(&context, &args),
        Command::Diff(args) => diff::run(&context, &args),
        Command::Config(args) => config_cmd::run(&context, &args),
        // Handled above, before the context was built.
        Command::Completions(args) => completions::run(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scan_parses_without_a_path() {
        let cli = Cli::try_parse_from(["bloatrail", "scan"]).expect("parse");
        assert!(matches!(cli.command, Command::Scan(_)));
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli =
            Cli::try_parse_from(["bloatrail", "scan", "--json", "--depth", "3"]).expect("parse");
        assert!(cli.global.json);
        assert_eq!(cli.global.depth, Some(3));
    }

    #[test]
    fn repeated_excludes_accumulate() {
        let cli = Cli::try_parse_from(["bloatrail", "scan", "-x", "a", "-x", "b"]).expect("parse");
        assert_eq!(cli.global.exclude, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn absent_boolean_flags_do_not_override_the_config_file() {
        let cli = Cli::try_parse_from(["bloatrail", "scan"]).expect("parse");
        let overrides = cli.global.overrides().expect("overrides");
        assert_eq!(overrides.follow_symlinks, None);
        assert_eq!(overrides.include_hidden, None);

        let cli = Cli::try_parse_from(["bloatrail", "scan", "--follow-symlinks"]).expect("parse");
        let overrides = cli.global.overrides().expect("overrides");
        assert_eq!(overrides.follow_symlinks, Some(true));
    }

    #[test]
    fn an_invalid_min_size_is_rejected_with_context() {
        let cli =
            Cli::try_parse_from(["bloatrail", "scan", "--min-size", "banana"]).expect("parse");
        let error = cli.global.overrides().unwrap_err();
        assert!(error.to_string().contains("min-size"));
    }

    #[test]
    fn running_with_no_arguments_shows_help() {
        let error = Cli::try_parse_from(["bloatrail"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }
}

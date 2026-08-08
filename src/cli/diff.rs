//! `bloatrail diff` — what changed since the last scan.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::Args;

use crate::cli::Context;
use crate::history;
use crate::output::{json, terminal};

/// Arguments for `bloatrail diff`.
#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Directory to compare. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Compare the two most recent stored scans instead of scanning again.
    #[arg(long)]
    pub stored: bool,

    /// Do not record this scan.
    #[arg(long)]
    pub no_record: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if there is no earlier scan to compare against, or if the path cannot
/// be scanned.
pub fn run(context: &Context, args: &DiffArgs) -> Result<()> {
    let root = crate::scanner::canonical_root(&context.resolve(args.path.as_ref())?)
        .context("the path to compare could not be read")?;

    let (previous, current) = if args.stored {
        let mut snapshots = history::load_all(&root)?;
        let current = snapshots.pop().with_context(|| {
            format!(
                "no scans recorded for `{}` yet — run `bloatrail scan` first",
                root.display()
            )
        })?;
        let previous = snapshots.pop().with_context(|| {
            format!(
                "only one scan recorded for `{}` — run `bloatrail scan` again to compare",
                root.display()
            )
        })?;
        (previous, current)
    } else {
        let stored = history::load_all(&root)?;
        let previous = stored.last().cloned().with_context(|| {
            format!(
                "no previous scan recorded for `{}` — run `bloatrail scan` first",
                root.display()
            )
        })?;

        let scan = context.scan(root.clone())?;
        if scan.cancelled {
            anyhow::bail!(
                "the scan was interrupted, and a partial scan cannot be compared or recorded"
            );
        }
        let current = history::Snapshot::from_scan(&scan, 25);
        if !args.no_record {
            let _ = history::save(&current);
        }
        (previous, current)
    };

    let diff = history::diff(&previous, &current);

    if context.json {
        let document = json::diff_document(&root, &diff);
        return context.emit(&json::to_string(&document)?);
    }

    context.emit(&terminal::diff_report(&diff, &context.theme))
}

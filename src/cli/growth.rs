//! `bloatrail growth` — every recorded scan of a directory as one trajectory.
//!
//! `diff` answers "what changed since last time". This answers the larger
//! questions the whole recorded series can: what has been growing across it,
//! whether the volume underneath is filling, and roughly when it runs out.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::Args;

use crate::cli::Context;
use crate::history;
use crate::output::{json, terminal};

/// Arguments for `bloatrail growth`.
#[derive(Debug, Args)]
pub struct GrowthArgs {
    /// Directory whose recorded scans to analyse. Defaults to the current
    /// directory.
    pub path: Option<PathBuf>,

    /// Use only the recorded scans instead of scanning again first.
    #[arg(long)]
    pub stored: bool,

    /// Also record this scan, adding a point to the series.
    ///
    /// Off by default: reading a trend should not change it. `scan` and `diff`
    /// are what build the record.
    #[arg(long)]
    pub record: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned, or if `--stored` was passed and no
/// scans have ever been recorded for it.
pub fn run(context: &Context, args: &GrowthArgs) -> Result<()> {
    let root = crate::scanner::canonical_root(&context.resolve(args.path.as_ref())?)
        .context("the path to analyse could not be read")?;

    let mut snapshots = history::load_all(&root)?;

    // By default the report ends with a fresh scan, so "now" is genuinely now
    // and the directory rows can be annotated with live classifications.
    // `--stored` skips the scan and reads the record as it stands.
    let scan = if args.stored {
        None
    } else {
        let scan = context.scan(root.clone())?;
        if scan.cancelled {
            anyhow::bail!(
                "the scan was interrupted, and a partial scan cannot be compared or recorded"
            );
        }
        let snapshot = context.snapshot(&scan);
        // Shown as the newest point either way; only `--record` persists it.
        // Recording by default would mean that checking a trend a few times in
        // an afternoon fills the store with near-identical points and thins
        // out the weeks of history that give the trend its meaning.
        if args.record {
            let _ = history::save(&snapshot);
        }
        snapshots.push(snapshot);
        Some(scan)
    };

    let growth = history::growth(&snapshots).with_context(|| {
        format!(
            "no scans recorded for `{}` yet — run `bloatrail scan` first",
            root.display()
        )
    })?;

    if context.json {
        let document = json::growth_document(&root, &growth);
        return context.emit(&json::to_string(&document)?);
    }

    context.emit(&terminal::growth_report(
        &growth,
        &root,
        scan.as_ref(),
        &context.theme,
        &context.known,
    ))
}

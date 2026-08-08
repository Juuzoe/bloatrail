//! `bloatrail scan` — the default view of where space went.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::Context;
use crate::output::{json, terminal, tree as tree_output};

/// Arguments for `bloatrail scan`.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Directory to scan. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Also show the annotated directory tree.
    #[arg(long)]
    pub tree: bool,

    /// Also show what could be reclaimed, and how confidently.
    #[arg(long)]
    pub reclaim: bool,

    /// Do not record this scan in the history used by `bloatrail diff`.
    #[arg(long)]
    pub no_record: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned or the output cannot be written.
pub fn run(context: &Context, args: &ScanArgs) -> Result<()> {
    let root = context.resolve(args.path.as_ref())?;
    let scan = context.scan(root)?;

    // History is best-effort: a read-only home directory should not turn a
    // successful scan into a failure. A cancelled scan is never recorded,
    // because its partial totals would make the next `diff` report phantom
    // growth against a baseline that covered a fraction of the tree.
    if !args.no_record && !scan.cancelled {
        let snapshot = crate::history::Snapshot::from_scan(&scan, 25);
        let _ = crate::history::save(&snapshot);
    }

    if context.json {
        let document = json::scan_document(&scan, context.settings.depth, context.settings.top);
        return context.emit(&json::to_string(&document)?);
    }

    let disk = crate::platform::disk_usage(&scan.root);
    let mut out = terminal::scan_report(&scan, &context.theme, &context.known, disk);

    if args.tree {
        out.push('\n');
        let options = tree_output::TreeOptions {
            max_depth: context.settings.depth.max(1),
            min_size: context.settings.min_size.as_u64(),
            ..tree_output::TreeOptions::default()
        };
        out.push_str(&tree_output::render(
            &scan.tree,
            scan.tree.root(),
            &context.theme,
            &options,
            &context.known.display(&scan.root),
        ));
    }

    if args.reclaim {
        out.push('\n');
        out.push_str(&terminal::reclaim_table(
            &scan,
            &context.theme,
            &context.known,
            context.settings.top,
        ));
    }

    out.push('\n');
    out.push_str(&context.theme.dim(
        "Run `bloatrail clean --dry-run` to see what could be removed, or \
         `bloatrail explain <path>` to ask about one directory.",
    ));
    out.push('\n');

    context.emit(&out)
}

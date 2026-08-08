//! `bloatrail tree` — an annotated directory tree.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::Context;
use crate::output::{json, tree as tree_output};

/// Arguments for `bloatrail tree`.
#[derive(Debug, Args)]
pub struct TreeArgs {
    /// Directory to display. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Maximum children shown per directory.
    #[arg(long, value_name = "N", default_value_t = 12)]
    pub max_children: usize,

    /// Do not draw proportional bars.
    #[arg(long)]
    pub no_bars: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned or the output cannot be written.
pub fn run(context: &Context, args: &TreeArgs) -> Result<()> {
    let root = context.resolve(args.path.as_ref())?;
    let scan = context.scan(root)?;

    if context.json {
        let document = json::scan_document(&scan, context.settings.depth, 0);
        return context.emit(&json::to_string(&document)?);
    }

    let options = tree_output::TreeOptions {
        max_depth: context.settings.depth.max(1),
        min_size: context.settings.min_size.as_u64(),
        max_children: args.max_children,
        bars: !args.no_bars,
    };

    let mut out = tree_output::render(
        &scan.tree,
        scan.tree.root(),
        &context.theme,
        &options,
        &context.known.display(&scan.root),
    );
    out.push_str(&crate::output::terminal::skipped_note(
        &scan,
        &context.theme,
    ));
    context.emit(&out)
}

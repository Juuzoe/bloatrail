//! `bloatrail largest` — ranked directories and files.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use crate::cli::Context;
use crate::output::{json, terminal};

/// Arguments for `bloatrail largest`.
#[derive(Debug, Args)]
pub struct LargestArgs {
    /// Directory to rank. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Rank files instead of directories.
    #[arg(long, conflicts_with = "dirs")]
    pub files: bool,

    /// Rank directories. This is the default.
    #[arg(long)]
    pub dirs: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned or the output cannot be written.
pub fn run(context: &Context, args: &LargestArgs) -> Result<()> {
    let root = context.resolve(args.path.as_ref())?;
    let scan = context.scan(root)?;
    let limit = context.settings.top.max(1);

    if context.json {
        let document = json::largest_document(&scan, limit);
        return context.emit(&json::to_string(&document)?);
    }

    let min_size = context.settings.min_size.as_u64();

    let mut out = String::new();
    if args.files {
        out.push_str(&terminal::largest_files(
            &scan,
            &context.theme,
            &context.known,
            limit,
            min_size,
        ));
    } else {
        out.push_str(&terminal::largest_directories(
            &scan,
            &context.theme,
            &context.known,
            limit,
            min_size,
        ));
        if !args.dirs {
            // Without an explicit `--dirs`, showing both is more useful than
            // making the user run the command twice.
            out.push('\n');
            out.push_str(&terminal::largest_files(
                &scan,
                &context.theme,
                &context.known,
                limit,
                min_size,
            ));
        }
    }

    out.push_str(&terminal::skipped_note(&scan, &context.theme));
    context.emit(&out)
}

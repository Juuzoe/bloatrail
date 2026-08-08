//! `bloatrail duplicates` — files with identical contents.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Args;

use crate::cli::Context;
use crate::duplicates::DuplicateOptions;
use crate::output::{json, terminal};
use crate::scanner::progress::ProgressReporter;
use crate::units::ByteSize;

/// Arguments for `bloatrail duplicates`.
#[derive(Debug, Args)]
pub struct DuplicatesArgs {
    /// Directory to search. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Ignore files smaller than this.
    #[arg(long, value_name = "SIZE", default_value = "1MB")]
    pub min_file_size: String,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the size threshold cannot be parsed or the path cannot be searched.
pub fn run(context: &Context, args: &DuplicatesArgs) -> Result<()> {
    let root = context.resolve(args.path.as_ref())?;
    let min_size: ByteSize = args.min_file_size.parse()?;

    let options = DuplicateOptions {
        root: root.clone(),
        // The global `--min-size` wins when it asks for something stricter.
        min_size: min_size.as_u64().max(context.settings.min_size.as_u64()),
        excludes: crate::pattern::ExcludeSet::new(&context.settings.exclude),
        include_hidden: context.settings.include_hidden,
        limit: context.settings.top.max(1),
    };

    let mut reporter = ProgressReporter::start(context.progress);
    let counters: Arc<_> = reporter.counters();
    // The search is parallel, so it has to honour `--threads` like the scanner.
    let report = match context.settings.threads.filter(|threads| *threads > 0) {
        Some(threads) => rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|index| format!("bloatrail-dup-{index}"))
            .build()
            .context("could not create the worker thread pool")?
            .install(|| crate::duplicates::find(&options, counters)),
        None => crate::duplicates::find(&options, counters),
    };
    reporter.finish();
    let report = report?;

    if context.json {
        let document = json::duplicates_document(&root, &report);
        return context.emit(&json::to_string(&document)?);
    }

    context.emit(&terminal::duplicates(
        &report,
        &context.theme,
        &context.known,
    ))
}

//! `bloatrail clean` — review, select, confirm, remove.
//!
//! The order of operations is the whole point of this command:
//!
//! ```text
//! detect → explain → classify → preview → select → confirm → remove
//! ```
//!
//! Nothing is removed without an explicit selection *and* an explicit
//! confirmation, the confirmation defaults to no, and when stdin is not a
//! terminal the command downgrades itself to a dry run rather than guessing.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

use crate::analysis::CleanupSafety;
use crate::cleanup::executor::{ExecutionOptions, Executor};
use crate::cleanup::planner::{CleanupGroup, CleanupPlan};
use crate::cli::Context;
use crate::output::{json, terminal};
use crate::pattern::ExcludeSet;

/// Arguments for `bloatrail clean`.
#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Directory to clean. Defaults to the current directory.
    pub path: Option<PathBuf>,

    /// Show what would be removed and stop. Nothing is modified.
    #[arg(long)]
    pub dry_run: bool,

    /// Select every group Bloatrail is willing to remove.
    #[arg(long, conflicts_with_all = ["safe", "select"])]
    pub all: bool,

    /// Select only groups classified SAFE.
    #[arg(long, conflicts_with_all = ["all", "select"])]
    pub safe: bool,

    /// Select groups by number, e.g. `1,3` or `1-4`.
    #[arg(long, value_name = "SPEC", conflicts_with_all = ["all", "safe"])]
    pub select: Option<String>,

    /// Skip the confirmation prompt. Requires an explicit selection.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Delete irreversibly instead of moving to the trash.
    #[arg(long)]
    pub permanent: bool,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path cannot be scanned, a selection cannot be parsed, or the
/// output cannot be written. Individual removal failures are reported in the
/// execution summary rather than aborting the run.
pub fn run(context: &Context, args: &CleanArgs) -> Result<()> {
    // Reject a malformed `--select` before spending a whole scan on it.
    if let Some(spec) = &args.select {
        parse_selection(spec)
            .map_err(|message| anyhow::anyhow!("invalid --select value: {message}"))?;
    }

    let root = context.resolve(args.path.as_ref())?;
    let scan = context.scan(root)?;
    // The plan's age-limited figures must use the same threshold the scan used
    // to accumulate them, or the preview and the deletion disagree.
    let plan = CleanupPlan::from_scan_with(&scan, context.settings.stale_days);

    let interactive = std::io::stdin().is_terminal() && !context.json;

    // Anything that is not an explicit, confirmed instruction ends up here.
    let preview_only = args.dry_run
        || plan.is_empty()
        || (!interactive && !args.yes)
        || (args.yes && !args.all && !args.safe && args.select.is_none());

    if context.json {
        return run_json(context, &plan, args, preview_only);
    }

    let mut out = terminal::header(&context.theme);
    out.push_str(&terminal::cleanup_report(
        &plan,
        &context.theme,
        &context.known,
    ));
    context.emit(&out)?;

    if plan.is_empty() {
        return context.emit(&format!(
            "\n{}\n",
            context.theme.dim("Nothing here can be removed safely.")
        ));
    }

    if preview_only {
        return preview(context, &plan, args, interactive);
    }

    let selected = match resolve_selection(context, &plan, args, interactive)? {
        Some(selected) if !selected.is_empty() => selected,
        _ => return context.emit(&format!("\n{}\n", context.theme.dim("Nothing selected."))),
    };

    let summary = terminal::confirmation_summary(&selected, &context.theme);
    context.emit(&summary)?;

    if !args.yes && !confirm(context)? {
        return context.emit(&format!("\n{}\n", context.theme.dim("Cancelled.")));
    }

    let limit = selected
        .iter()
        .map(|group| group.safety)
        .max()
        .unwrap_or(CleanupSafety::Safe);

    let executor = Executor::new(
        &plan.root,
        &context.known,
        &context.classifier,
        ExecutionOptions {
            dry_run: false,
            permanent: args.permanent,
            limit,
            excludes: ExcludeSet::new(&context.settings.exclude),
        },
    );
    let report = executor.run(selected.iter().copied());
    context.emit(&terminal::execution_report(
        &report,
        &context.theme,
        &context.known,
    ))
}

/// Show what a run would do without doing it.
fn preview(
    context: &Context,
    plan: &CleanupPlan,
    args: &CleanArgs,
    interactive: bool,
) -> Result<()> {
    let selected = default_selection(plan, args)?;
    if selected.is_empty() {
        return Ok(());
    }

    let executor = Executor::new(
        &plan.root,
        &context.known,
        &context.classifier,
        ExecutionOptions {
            dry_run: true,
            permanent: false,
            limit: CleanupSafety::Review,
            excludes: ExcludeSet::new(&context.settings.exclude),
        },
    );
    let report = executor.run(selected.iter().copied());
    context.emit(&terminal::execution_report(
        &report,
        &context.theme,
        &context.known,
    ))?;

    if !args.dry_run && !interactive {
        context.emit(&format!(
            "\n{}\n",
            context.theme.review(
                "stdin is not a terminal, so this was a dry run. Pass --yes with --all, --safe \
                 or --select to remove anything."
            )
        ))?;
    }
    Ok(())
}

fn run_json(
    context: &Context,
    plan: &CleanupPlan,
    args: &CleanArgs,
    preview_only: bool,
) -> Result<()> {
    let selected = default_selection(plan, args)?;
    let dry_run = preview_only;

    let executor = Executor::new(
        &plan.root,
        &context.known,
        &context.classifier,
        ExecutionOptions {
            dry_run,
            permanent: args.permanent,
            limit: selected
                .iter()
                .map(|group| group.safety)
                .max()
                .unwrap_or(CleanupSafety::Safe),
            excludes: ExcludeSet::new(&context.settings.exclude),
        },
    );
    let report = executor.run(selected.iter().copied());
    let document = json::clean_document(plan, dry_run, Some(&report));
    context.emit(&json::to_string(&document)?)
}

/// The selection implied by the flags alone, with no prompting.
///
/// # Errors
///
/// A `--select` value that cannot be parsed is an error, never a fallback.
/// Quietly substituting "everything safe" for a typo would mean deleting
/// something the user did not ask for.
fn default_selection<'a>(plan: &'a CleanupPlan, args: &CleanArgs) -> Result<Vec<&'a CleanupGroup>> {
    if args.all {
        return Ok(plan.selectable().collect());
    }
    if let Some(spec) = &args.select {
        let selection = parse_selection(spec)
            .map_err(|message| anyhow::anyhow!("invalid --select value: {message}"))?;
        return Ok(apply(plan, &selection));
    }
    // `--safe`, and the default preview, both mean "only what is unambiguous".
    Ok(plan
        .selectable()
        .filter(|group| group.safety == CleanupSafety::Safe)
        .collect())
}

/// Resolve the selection, prompting when the flags did not decide it.
fn resolve_selection<'a>(
    context: &Context,
    plan: &'a CleanupPlan,
    args: &CleanArgs,
    interactive: bool,
) -> Result<Option<Vec<&'a CleanupGroup>>> {
    if args.all || args.safe || args.select.is_some() {
        return Ok(Some(default_selection(plan, args)?));
    }
    if !interactive {
        bail!("no selection was given and stdin is not a terminal");
    }

    context.emit(&format!(
        "\n{}\n{}\n",
        context.theme.heading("Select:"),
        context
            .theme
            .dim("  all · safe · none · numbers such as `1,3` or `1-4`")
    ))?;
    print!("> ");
    std::io::stdout().flush().ok();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }

    match parse_selection(&line) {
        Ok(selection) => Ok(Some(apply(plan, &selection))),
        Err(message) => {
            context.emit(&format!("\n{}\n", context.theme.review(&message)))?;
            Ok(None)
        }
    }
}

fn apply<'a>(plan: &'a CleanupPlan, selection: &Selection) -> Vec<&'a CleanupGroup> {
    match selection {
        Selection::None => Vec::new(),
        Selection::All => plan.selectable().collect(),
        Selection::Safe => plan
            .selectable()
            .filter(|group| group.safety == CleanupSafety::Safe)
            .collect(),
        Selection::Indexes(indexes) => indexes
            .iter()
            .filter_map(|index| plan.group_by_index(*index))
            .collect(),
    }
}

/// A parsed selection expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Every selectable group.
    All,
    /// Only groups classified SAFE.
    Safe,
    /// Nothing.
    None,
    /// Specific group numbers.
    Indexes(Vec<usize>),
}

/// Parse a selection expression such as `all`, `1,3` or `1-4`.
///
/// # Errors
///
/// Returns a human-readable message for anything it cannot interpret. An
/// unparseable selection always means "select nothing", never "select
/// everything".
pub fn parse_selection(input: &str) -> std::result::Result<Selection, String> {
    let text = input.trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "none" | "n" | "q" | "quit" => return Ok(Selection::None),
        "all" | "a" | "*" => return Ok(Selection::All),
        "safe" | "s" => return Ok(Selection::Safe),
        _ => {}
    }

    let mut indexes = Vec::new();
    for part in text.split([',', ' ']).filter(|p| !p.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start: usize = start
                .trim()
                .parse()
                .map_err(|_| format!("`{part}` is not a valid range"))?;
            let end: usize = end
                .trim()
                .parse()
                .map_err(|_| format!("`{part}` is not a valid range"))?;
            if start == 0 || end < start {
                return Err(format!("`{part}` is not a valid range"));
            }
            indexes.extend(start..=end);
        } else {
            let index: usize = part
                .parse()
                .map_err(|_| format!("`{part}` is not a group number"))?;
            if index == 0 {
                return Err("group numbers start at 1".to_string());
            }
            indexes.push(index);
        }
    }

    if indexes.is_empty() {
        return Err(format!("could not understand `{}`", input.trim()));
    }
    indexes.sort_unstable();
    indexes.dedup();
    Ok(Selection::Indexes(indexes))
}

/// Ask for confirmation. Anything other than an explicit yes means no.
fn confirm(context: &Context) -> Result<bool> {
    context.emit(&format!("\n{} ", context.theme.heading("Continue? [y/N]")))?;
    std::io::stdout().flush().ok();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        return Ok(false);
    }
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_are_recognised() {
        assert_eq!(parse_selection("all").unwrap(), Selection::All);
        assert_eq!(parse_selection(" ALL \n").unwrap(), Selection::All);
        assert_eq!(parse_selection("safe").unwrap(), Selection::Safe);
        assert_eq!(parse_selection("none").unwrap(), Selection::None);
    }

    #[test]
    fn an_empty_answer_selects_nothing() {
        assert_eq!(parse_selection("").unwrap(), Selection::None);
        assert_eq!(parse_selection("   \n").unwrap(), Selection::None);
    }

    #[test]
    fn numbers_and_ranges_are_parsed_and_normalised() {
        assert_eq!(
            parse_selection("3,1,2").unwrap(),
            Selection::Indexes(vec![1, 2, 3])
        );
        assert_eq!(
            parse_selection("1-3").unwrap(),
            Selection::Indexes(vec![1, 2, 3])
        );
        assert_eq!(
            parse_selection("1-2,2,5").unwrap(),
            Selection::Indexes(vec![1, 2, 5])
        );
    }

    #[test]
    fn nonsense_never_becomes_a_selection() {
        for input in ["banana", "0", "3-1", "1-", "-2", "1,x"] {
            assert!(
                parse_selection(input).is_err(),
                "`{input}` must not parse into a selection"
            );
        }
    }
}

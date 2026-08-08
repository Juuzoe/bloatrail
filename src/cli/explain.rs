//! `bloatrail explain` — what is this, and can I delete it?

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::Args;

use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection};
use crate::analysis::{categorize, sensitive};
use crate::cli::Context;
use crate::output::{json, terminal};

/// Arguments for `bloatrail explain`.
#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// The file or directory to explain.
    pub path: PathBuf,
}

/// Run the command.
///
/// # Errors
///
/// Fails if the path does not exist or cannot be inspected.
pub fn run(context: &Context, args: &ExplainArgs) -> Result<()> {
    let metadata = std::fs::symlink_metadata(&args.path)
        .with_context(|| format!("`{}` could not be inspected", args.path.display()))?;

    if !metadata.is_dir() {
        return explain_file(context, args);
    }

    let scan = context.scan(args.path.clone())?;
    // The scan root is deliberately never collapsed, so its own detection is
    // present on the root node and its children are still visible.
    let detection = scan.tree.node(scan.tree.root()).detection.clone();

    if context.json {
        let document = json::explain_document(&scan.root, detection.as_ref(), &scan);
        return context.emit(&json::to_string(&document)?);
    }

    let mut out = terminal::explain(
        &scan.root,
        detection.as_ref(),
        &scan,
        &context.theme,
        &context.known,
    );

    // Show the biggest things inside, which is usually the next question.
    let children = &scan.tree.node(scan.tree.root()).children;
    if !children.is_empty() {
        out.push('\n');
        out.push_str(&context.theme.heading("Largest contents:\n"));
        for id in children.iter().take(5) {
            let node = scan.tree.node(*id);
            out.push_str(&format!(
                "  {}  {}\n",
                crate::output::pad_right(&node.name, 28),
                crate::units::ByteSize(node.total.bytes)
            ));
        }
    }

    context.emit(&out)
}

/// Files get a shorter answer, but the same honesty about what is safe.
fn explain_file(context: &Context, args: &ExplainArgs) -> Result<()> {
    let metadata = std::fs::metadata(&args.path)
        .with_context(|| format!("`{}` could not be inspected", args.path.display()))?;
    let name = args
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    let category = categorize::categorize_file(name);
    let sensitivity = sensitive::classify(name);

    let detection = match sensitivity {
        Some(kind) => Detection::new(
            category,
            Confidence::High,
            CleanupSafety::NeverDelete,
            format!("Protected file — it {}", kind.describe()),
        )
        .with_evidence(
            "Bloatrail never proposes removing keys, credentials, wallets or databases, \
             whatever their size.",
        ),
        None => Detection::new(
            category,
            if category == Category::Unknown {
                Confidence::Low
            } else {
                Confidence::Medium
            },
            CleanupSafety::Review,
            format!("{} file", category.label()),
        )
        .with_evidence(
            "This is a single file, classified by its name. Bloatrail does not propose \
             removing individual files it has not identified as regenerable.",
        ),
    };

    if context.json {
        let document = crate::output::json::ExplainDocument {
            schema_version: crate::output::json::SCHEMA_VERSION,
            path: args.path.to_string_lossy().into_owned(),
            bytes: metadata.len(),
            files: 1,
            detection: Some(crate::output::json::DetectionView::new(&detection)),
            reclaimable: 0,
            reclaim_is_external: false,
        };
        return context.emit(&json::to_string(&document)?);
    }

    let mut out = String::new();
    out.push_str(&context.theme.heading(&context.known.display(&args.path)));
    out.push('\n');
    out.push_str(&format!(
        "Size: {}\n\n",
        crate::units::ByteSize(metadata.len())
    ));
    out.push_str(&context.theme.heading("Detected as:\n"));
    out.push_str(&format!("{}\n\n", detection.reason));
    out.push_str(&context.theme.heading("Why:\n"));
    for line in &detection.evidence {
        out.push_str(&format!("{line}\n"));
    }
    out.push('\n');
    out.push_str(&context.theme.heading("Cleanup:\n"));
    out.push_str(&format!(
        "{}\n",
        context
            .theme
            .by_safety(detection.cleanup, detection.cleanup.label())
    ));

    context.emit(&out)
}

/// Classify a directory without scanning it, using only its immediate context.
///
/// Used by tests and by callers that want the label without the cost of a walk.
#[must_use]
pub fn classify_path(context: &Context, path: &std::path::Path) -> Option<Detection> {
    let name = path.file_name()?.to_str()?;
    let lowered = name.to_lowercase();

    let ctx = DirContext {
        path,
        name,
        name_lower: &lowered,
        parent_name: path
            .parent()
            .and_then(std::path::Path::file_name)
            .and_then(|n| n.to_str()),
        markers: read_markers(path),
        parent_markers: path.parent().map(read_markers).unwrap_or_default(),
        grandparent_markers: path
            .parent()
            .and_then(std::path::Path::parent)
            .map(read_markers)
            .unwrap_or_default(),
        depth: 1,
        subdir_count: 0,
        file_count: 0,
        env: &context.known,
    };
    context.classifier.classify(&ctx)
}

fn read_markers(path: &std::path::Path) -> Markers {
    let mut markers = Markers::empty();
    let Ok(entries) = std::fs::read_dir(path) else {
        return markers;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        match name.to_str() {
            Some(name) => markers.observe(name, is_dir),
            None => markers.observe(&name.to_string_lossy(), is_dir),
        }
    }
    markers
}

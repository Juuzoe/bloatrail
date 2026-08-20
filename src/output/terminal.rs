//! Human-facing renderers for every command.
//!
//! Each function takes finished analysis and returns a `String`. Nothing here
//! performs I/O or makes decisions, which keeps the renderers trivially
//! testable and keeps presentation concerns out of the engine.

use std::fmt::Write as _;
use std::path::Path;

use crate::analysis::domain::{Category, CleanupSafety, Detection};
use crate::analysis::reclaim::{self, Reclaimable};
use crate::cleanup::executor::ExecutionReport;
use crate::cleanup::planner::CleanupPlan;
use crate::docker::{DockerResource, DockerStatus};
use crate::doctor::{DoctorReport, Finding, Severity};
use crate::duplicates::DuplicateReport;
use crate::history::Diff;
use crate::output::{pad_left, pad_right, truncate, Theme, BRAND};
use crate::platform::{DiskUsage, KnownPaths};
use crate::scanner::ScanResult;
use crate::timefmt;
use crate::units::{format_count, ByteSize};

/// Column width used for size figures throughout the reports.
const SIZE_COLUMN: usize = 10;

/// The one-line product header.
#[must_use]
pub fn header(theme: &Theme) -> String {
    format!("{}\n", theme.heading(BRAND))
}

/// The `scan` report.
#[must_use]
pub fn scan_report(
    scan: &ScanResult,
    theme: &Theme,
    known: &KnownPaths,
    disk: Option<DiskUsage>,
) -> String {
    let mut out = String::with_capacity(2_048);
    out.push_str(&header(theme));
    let _ = writeln!(out, "Scanned {}", theme.info(&known.display(&scan.root)));
    let _ = writeln!(out);

    // Usage bar. Without a capacity figure there is nothing meaningful to draw
    // a proportion against, so the bar is simply omitted.
    let bar_width = theme.width.saturating_sub(20).clamp(20, 60);
    if let Some(disk) = disk {
        let fraction = ByteSize(scan.totals.bytes).fraction_of(ByteSize(disk.total));
        let _ = writeln!(
            out,
            "{}  {}",
            theme.bar(fraction, bar_width),
            ByteSize(scan.totals.bytes)
        );
        let _ = writeln!(
            out,
            "{}",
            theme.dim(&format!(
                "{} of {} on this volume is in use; {} free",
                ByteSize(disk.used()),
                ByteSize(disk.total),
                ByteSize(disk.available)
            ))
        );
    } else {
        let _ = writeln!(out, "{}", ByteSize(scan.totals.bytes));
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "{}", theme.heading("Storage breakdown"));
    let _ = writeln!(out);

    let ranked = scan.categories.ranked();
    let label_width = ranked
        .iter()
        .map(|(category, _, _)| category.label().chars().count())
        .max()
        .unwrap_or(10)
        .max(12);

    for (category, bytes, _) in &ranked {
        let _ = writeln!(
            out,
            "  {}{}",
            pad_right(category.label(), label_width + 2),
            pad_left(&ByteSize(*bytes).to_string(), SIZE_COLUMN)
        );
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        theme.dim(&format!(
            "{} files, {} directories in {} ({}/s)",
            format_count(scan.totals.files),
            format_count(scan.totals.dirs),
            format_duration(scan.duration),
            ByteSize(scan.throughput() as u64)
        ))
    );
    out.push_str(&skipped_note(scan, theme));
    if scan.cancelled {
        let _ = writeln!(
            out,
            "{}",
            theme.review("Scan stopped early; totals cover only what was reached.")
        );
    }
    out
}

/// The "reclaimability" table: size next to what is actually recoverable.
#[must_use]
pub fn reclaim_table(scan: &ScanResult, theme: &Theme, known: &KnownPaths, limit: usize) -> String {
    let mut rows: Vec<(String, u64, Reclaimable, Option<&Detection>)> = Vec::new();

    for (id, node) in scan.tree.iter() {
        if id == scan.tree.root() || node.detection.is_none() {
            continue;
        }
        let estimate = reclaim::estimate(node.detection.as_ref(), &node.total);
        rows.push((
            known.display(&scan.tree.path_of(id)),
            node.total.bytes,
            estimate,
            node.detection.as_ref(),
        ));
    }

    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    rows.truncate(limit);

    if rows.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading("Reclaimable storage"));
    let _ = writeln!(out);

    let name_width = theme.width.saturating_sub(40).clamp(20, 46);
    let _ = writeln!(
        out,
        "  {}{}{}{}",
        pad_right("Directory", name_width + 2),
        pad_left("Size", SIZE_COLUMN),
        pad_left("Reclaimable", 14),
        pad_left("Confidence", 12)
    );

    for (label, bytes, estimate, detection) in &rows {
        let reclaimable = if estimate.is_some() {
            ByteSize(estimate.bytes.as_u64()).to_string()
        } else {
            "—".to_string()
        };
        let confidence = reclaim::confidence_label(*detection, *estimate);
        let painted = match detection {
            Some(d) => theme.by_safety(d.cleanup, &reclaimable),
            None => reclaimable.clone(),
        };
        // Colour codes are invisible but not zero-width, so pad the plain text
        // first and colour afterwards.
        let _ = writeln!(
            out,
            "  {}{}{}{}",
            // Elide from the left: every row here shares a long prefix, so the
            // tail is the only part that distinguishes them.
            pad_right(
                &crate::output::elide_start(label, name_width),
                name_width + 2
            ),
            pad_left(&ByteSize(*bytes).to_string(), SIZE_COLUMN),
            pad_left(&painted, 14 + (painted.len() - reclaimable.len())),
            pad_left(confidence, 12)
        );
    }
    out
}

/// The `clean` proposal.
#[must_use]
pub fn cleanup_report(plan: &CleanupPlan, theme: &Theme, known: &KnownPaths) -> String {
    let mut out = String::with_capacity(2_048);
    let _ = writeln!(out, "{}", theme.heading("Potential cleanup"));
    let _ = writeln!(out);

    let sections = [
        (CleanupSafety::Safe, theme.safe("SAFE")),
        (CleanupSafety::ProbablySafe, theme.safe("PROBABLY SAFE")),
        (CleanupSafety::Review, theme.review("REVIEW")),
    ];

    // Wide enough for the longest title the terminal can actually fit; the
    // titles carry the age thresholds, so truncating them loses meaning.
    let ceiling = theme.width.saturating_sub(28).clamp(24, 64);
    let label_width = plan
        .groups
        .iter()
        .map(|g| g.title.chars().count())
        .max()
        .unwrap_or(20)
        .clamp(20, ceiling);

    let mut printed_any = false;
    for (safety, heading) in sections {
        let groups: Vec<_> = plan.by_safety(safety).collect();
        if groups.is_empty() {
            continue;
        }
        printed_any = true;
        let _ = writeln!(out, "{heading}");
        for group in groups {
            let marker = theme.by_safety(safety, theme.safety_glyph(safety));
            let index = match group.index {
                Some(index) => format!("[{index}] "),
                None => "    ".to_string(),
            };
            let _ = writeln!(
                out,
                "{marker} {index}{}{}",
                pad_right(&truncate(&group.title, label_width), label_width + 2),
                pad_left(&ByteSize(group.bytes).to_string(), SIZE_COLUMN)
            );
            if group.external {
                let _ = writeln!(
                    out,
                    "      {}",
                    theme.dim("reclaim with the tool that owns it, not by deleting files")
                );
            }
            if group.location_count() > 1 {
                let _ = writeln!(
                    out,
                    "      {}",
                    theme.dim(&format!("{} locations", group.location_count()))
                );
            } else if let Some(target) = group.targets.first() {
                let _ = writeln!(out, "      {}", theme.dim(&known.display(&target.path)));
            }
        }
        let _ = writeln!(out);
    }

    if !plan.protected.is_empty() {
        let _ = writeln!(out, "{}", theme.danger("DO NOT AUTO DELETE"));
        for row in &plan.protected {
            let _ = writeln!(
                out,
                "{} {}{}",
                theme.danger(theme.safety_glyph(CleanupSafety::NeverDelete)),
                pad_right(&truncate(&row.label, label_width), label_width + 6),
                pad_left(&ByteSize(row.bytes).to_string(), SIZE_COLUMN)
            );
        }
        let _ = writeln!(out);
    }

    if !printed_any {
        let _ = writeln!(out, "{}", theme.dim("Nothing to clean up here."));
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "Potentially recoverable: {}",
        theme.heading(&plan.recoverable().to_string())
    );
    let _ = writeln!(
        out,
        "Safe automatic cleanup:  {}",
        theme.safe(&plan.automatically_safe().to_string())
    );
    out
}

/// The confirmation prompt shown before anything is removed.
#[must_use]
pub fn confirmation_summary(
    groups: &[&crate::cleanup::planner::CleanupGroup],
    theme: &Theme,
) -> String {
    let bytes: u64 = groups.iter().map(|g| g.bytes).sum();
    let locations: usize = groups.iter().map(|g| g.location_count()).sum();
    let mut out = String::new();
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "You are about to remove {} from {} location{}.",
        theme.heading(&ByteSize(bytes).to_string()),
        locations,
        if locations == 1 { "" } else { "s" }
    );
    for group in groups {
        let _ = writeln!(
            out,
            "  {} {}  {}",
            theme.by_safety(group.safety, theme.safety_glyph(group.safety)),
            pad_right(&group.title, 34),
            ByteSize(group.bytes)
        );
    }
    out
}

/// What an execution actually did.
#[must_use]
pub fn execution_report(report: &ExecutionReport, theme: &Theme, known: &KnownPaths) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out);

    if report.dry_run {
        let _ = writeln!(out, "{}", theme.heading("Dry run: nothing was modified"));
    }

    for removal in &report.removed {
        let _ = writeln!(
            out,
            "  {} {}  {}",
            theme.safe(theme.safety_glyph(CleanupSafety::Safe)),
            // Elide from the left: the tail of a path is what identifies it.
            pad_right(
                &crate::output::elide_start(&known.display(&removal.path), 52),
                54
            ),
            pad_left(&ByteSize(removal.bytes).to_string(), SIZE_COLUMN)
        );
    }

    for failure in &report.failures {
        let marker = if failure.refused {
            theme.review("!")
        } else {
            theme.danger("×")
        };
        let _ = writeln!(
            out,
            "  {marker} {}",
            theme.dim(&format!(
                "{}: {}",
                known.display(&failure.path),
                failure.reason
            ))
        );
    }

    let _ = writeln!(out);
    let verb = if report.dry_run {
        "Would free"
    } else {
        "Freed"
    };
    let _ = writeln!(
        out,
        "{verb} {} across {} location{}.",
        theme.heading(&ByteSize(report.bytes_freed).to_string()),
        report.removed.len(),
        if report.removed.len() == 1 { "" } else { "s" }
    );

    if report.refused_count() > 0 {
        let _ = writeln!(
            out,
            "{}",
            theme.review(&format!(
                "{} location(s) were refused by the safety checks.",
                report.refused_count()
            ))
        );
    }
    if report.error_count() > 0 {
        let _ = writeln!(
            out,
            "{}",
            theme.dim(&format!(
                "{} location(s) could not be removed.",
                report.error_count()
            ))
        );
    }
    let trashed = report
        .removed
        .iter()
        .filter(|removal| removal.method == crate::cleanup::RemovalMethod::Trash)
        .count();
    if trashed > 0 {
        let _ = writeln!(
            out,
            "{}",
            theme.dim(&format!(
                "{trashed} item{} moved to the trash and can be restored from there.",
                if trashed == 1 { " was" } else { "s were" }
            ))
        );
    } else if !report.dry_run && !report.removed.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            theme.dim("Removed permanently — these cannot be restored.")
        );
    }
    out
}

/// `largest --dirs`.
#[must_use]
pub fn largest_directories(
    scan: &ScanResult,
    theme: &Theme,
    known: &KnownPaths,
    limit: usize,
    min_size: u64,
) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading("Largest directories"));
    let _ = writeln!(out);

    // `largest` ranks by size, so a minimum-size filter is a floor on the list.
    let rows: Vec<_> = scan
        .largest_directories(usize::MAX)
        .into_iter()
        .filter(|(_, bytes)| *bytes >= min_size)
        .take(limit)
        .collect();
    if rows.is_empty() {
        let _ = writeln!(out, "{}", theme.dim("No directories found."));
        return out;
    }

    let name_width = theme.width.saturating_sub(24).clamp(24, 60);
    for (rank, (id, bytes)) in rows.iter().enumerate() {
        let node = scan.tree.node(*id);
        let path = known.display(&scan.tree.path_of(*id));
        let mut line = format!(
            "{}. {}{}",
            pad_left(&(rank + 1).to_string(), 2),
            pad_right(
                &crate::output::elide_start(&path, name_width),
                name_width + 2
            ),
            pad_left(&ByteSize(*bytes).to_string(), SIZE_COLUMN)
        );
        if let Some(detection) = &node.detection {
            let _ = write!(
                line,
                "   {}",
                theme.by_safety(detection.cleanup, &detection.reason)
            );
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
    out
}

/// `largest --files`.
#[must_use]
pub fn largest_files(
    scan: &ScanResult,
    theme: &Theme,
    known: &KnownPaths,
    limit: usize,
    min_size: u64,
) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading("Largest files"));
    let _ = writeln!(out);

    let rows: Vec<_> = scan
        .largest_files
        .iter()
        .filter(|entry| entry.size >= min_size)
        .take(limit)
        .collect();

    if rows.is_empty() {
        let _ = writeln!(out, "{}", theme.dim("No files found."));
        return out;
    }

    let now = timefmt::now_seconds();
    let name_width = theme.width.saturating_sub(28).clamp(24, 60);
    for (rank, entry) in rows.iter().enumerate() {
        let path = known.display(&entry.path);
        // The age answers the question the size raises: is this still in use?
        let annotation = match entry.modified {
            Some(modified) => format!(
                "{}, modified {}",
                entry.category.label(),
                timefmt::humanize_age(modified, now)
            ),
            None => entry.category.label().to_string(),
        };
        let _ = writeln!(
            out,
            "{}. {}{}   {}",
            pad_left(&(rank + 1).to_string(), 2),
            pad_right(
                &crate::output::elide_start(&path, name_width),
                name_width + 2
            ),
            pad_left(&ByteSize(entry.size).to_string(), SIZE_COLUMN),
            theme.dim(&annotation)
        );
    }
    out
}

/// `explain <path>`.
#[must_use]
pub fn explain(
    path: &Path,
    detection: Option<&Detection>,
    scan: &ScanResult,
    theme: &Theme,
    known: &KnownPaths,
) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading(&known.display(path)));
    let _ = writeln!(out, "Size: {}", ByteSize(scan.totals.bytes));
    let _ = writeln!(
        out,
        "{}",
        theme.dim(&format!(
            "{} {}, {} {}",
            format_count(scan.totals.files),
            plural(scan.totals.files, "file"),
            format_count(scan.totals.dirs),
            plural(scan.totals.dirs, "directory"),
        ))
    );
    let _ = writeln!(out);

    let Some(detection) = detection else {
        let _ = writeln!(out, "{}", theme.heading("Detected as:"));
        let _ = writeln!(out, "Nothing Bloatrail recognises.");
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", theme.heading("Cleanup:"));
        let _ = writeln!(
            out,
            "{}",
            theme
                .danger("NOT OFFERED — Bloatrail never proposes removing what it cannot identify.")
        );
        return out;
    };

    let _ = writeln!(out, "{}", theme.heading("Detected as:"));
    let mut description = detection.reason.to_string();
    if let Some(technology) = detection.technology {
        description = format!("{description} ({technology})");
    }
    let _ = writeln!(out, "{description}");
    let _ = writeln!(
        out,
        "{}",
        theme.dim(&format!(
            "category: {} · confidence: {}",
            detection.category.label(),
            detection.confidence
        ))
    );
    let _ = writeln!(out);

    if !detection.evidence.is_empty() {
        let _ = writeln!(out, "{}", theme.heading("Why:"));
        for line in &detection.evidence {
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "{}", theme.heading("Cleanup:"));
    let _ = writeln!(
        out,
        "{}",
        theme.by_safety(detection.cleanup, detection.cleanup.label())
    );
    let _ = writeln!(
        out,
        "{}",
        crate::cleanup::safety::describe_permission(detection)
    );
    let _ = writeln!(out);

    if let Some(command) = &detection.regenerated_by {
        let _ = writeln!(out, "{}", theme.heading("Regenerated by:"));
        let _ = writeln!(out, "  {command}");
        let _ = writeln!(out);
    }

    let estimate = reclaim::estimate(Some(detection), &scan.totals);

    // Only offer a command when there is genuinely something to recover. A
    // "remove it with" block next to "recoverable: nothing" would be an
    // invitation to do something Bloatrail has just advised against.
    if detection.cleanup.is_deletable() && estimate.is_some() && !estimate.external {
        let _ = writeln!(out, "{}", theme.heading("Remove it with:"));
        // The real path, not the `~`-abbreviated display form: this line is
        // meant to be copied into a shell.
        let _ = writeln!(
            out,
            "  bloatrail clean {} --dry-run",
            quote_path(&path.display().to_string())
        );
        let _ = writeln!(
            out,
            "  {}",
            theme.dim("drop --dry-run once you are happy with the preview")
        );
        let _ = writeln!(out);
    } else if estimate.external {
        if let Some(command) = &detection.regenerated_by {
            let _ = writeln!(out, "{}", theme.heading("Reclaim it with:"));
            let _ = writeln!(out, "  {command}");
            let _ = writeln!(out);
        }
    }

    let _ = writeln!(out, "{}", theme.heading("Recoverable:"));
    if estimate.is_some() {
        let suffix = if estimate.external {
            " (through the tool that owns it)"
        } else {
            ""
        };
        let _ = writeln!(out, "{}{suffix}", ByteSize(estimate.bytes.as_u64()));
    } else {
        let _ = writeln!(out, "nothing; this is not disposable storage");
    }
    out
}

/// `duplicates`.
#[must_use]
pub fn duplicates(report: &DuplicateReport, theme: &Theme, known: &KnownPaths) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading("Duplicate files"));
    let _ = writeln!(out);

    if report.groups.is_empty() {
        let _ = writeln!(out, "{}", theme.dim("No duplicates found."));
        if report.hardlinks > 0 {
            let _ = writeln!(
                out,
                "{}",
                theme.dim(&format!(
                    "Folded {} hardlinked {}: extra names for storage already counted \
                     once. Removing a hardlink frees nothing.",
                    format_count(report.hardlinks),
                    plural(report.hardlinks, "path"),
                ))
            );
        }
        return out;
    }

    for (index, group) in report.groups.iter().enumerate() {
        let _ = writeln!(
            out,
            "{} {} {}",
            theme.heading(&format!("Group {}", index + 1)),
            theme.dim("—"),
            theme.heading(&format!("{} reclaimable", ByteSize(group.reclaimable())))
        );
        for copy in &group.copies {
            let mut names = copy.paths.iter();
            if let Some(first) = names.next() {
                // The head line carries the copy's deletion semantics, so that
                // no listed name reads as freeing space it cannot free.
                if copy.linked_elsewhere() {
                    let _ = writeln!(
                        out,
                        "  {} {}",
                        known.display(first),
                        theme.dim("(more hardlink names than shown — deleting it frees nothing)")
                    );
                } else if copy.paths.len() > 1 {
                    let extras = copy.paths.len() - 1;
                    let note = if extras == 1 {
                        "(also named by the hardlink below — deleting one name frees nothing)"
                            .to_string()
                    } else {
                        format!(
                            "(also named by the {extras} hardlinks below — deleting one name frees nothing)"
                        )
                    };
                    let _ = writeln!(out, "  {} {}", known.display(first), theme.dim(&note));
                } else {
                    let _ = writeln!(out, "  {}", known.display(first));
                }
            }
            for extra in names {
                let _ = writeln!(
                    out,
                    "  {} {}",
                    known.display(extra),
                    theme.dim("(hardlink of the copy above — frees nothing)")
                );
            }
        }
        let _ = writeln!(out);
    }

    let mut tally = format!(
        "{} candidate files compared, {} read in full",
        format_count(report.candidates),
        format_count(report.hashed)
    );
    if report.hardlinks > 0 {
        let _ = write!(
            tally,
            ", {} hardlinked {} folded",
            format_count(report.hardlinks),
            plural(report.hardlinks, "path"),
        );
    }
    let _ = writeln!(out, "{}", theme.dim(&tally));
    let _ = writeln!(
        out,
        "{}",
        theme.review(
            "Bloatrail never deletes duplicates automatically: only you know which copy matters."
        )
    );
    out
}

/// `doctor`.
#[must_use]
pub fn doctor(report: &DoctorReport, theme: &Theme) -> String {
    let mut out = String::with_capacity(1_024);
    out.push_str(&header(theme));
    let _ = writeln!(out, "{}", theme.heading("Bloatrail Doctor"));
    let _ = writeln!(out);

    if report.findings.is_empty() {
        let _ = writeln!(out, "{}", theme.safe("Nothing notable found."));
        return out;
    }

    for finding in &report.findings {
        let tag = match finding.severity {
            Severity::Warn => theme.review("WARN"),
            Severity::Info => theme.info("INFO"),
        };
        // `WARN` and `INFO` are both four columns wide, so the gap is fixed;
        // painting after the fact keeps escape bytes out of the layout maths.
        let _ = writeln!(out, "{tag}  {}", finding.message);
        if let Some(hint) = &finding.hint {
            let _ = writeln!(out, "      {}", theme.dim(hint));
        }
    }

    let _ = writeln!(out);
    if report.recoverable.is_zero() {
        let _ = writeln!(out, "{}", theme.dim("No recoverable space identified."));
    } else {
        let _ = writeln!(
            out,
            "Possible recovery: {}",
            theme.heading(&report.recoverable.to_string())
        );
    }
    out
}

/// `docker` status block, embedded in `doctor` and `scan --docker`.
#[must_use]
pub fn docker_status(status: &DockerStatus, theme: &Theme) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{}", theme.heading("Docker reclaimable storage"));
    let _ = writeln!(out);

    match status {
        DockerStatus::NotInstalled => {
            let _ = writeln!(out, "{}", theme.dim("Docker is not installed."));
        }
        DockerStatus::NotChecked => {
            let _ = writeln!(
                out,
                "{}",
                theme.dim("Docker was not checked (--no-docker).")
            );
        }
        DockerStatus::NotRunning { detail } => {
            let _ = writeln!(
                out,
                "{}",
                theme.dim(&format!("Docker is unavailable: {detail}"))
            );
        }
        DockerStatus::Available { usage } => {
            for row in usage {
                let _ = writeln!(
                    out,
                    "  {}{}{}",
                    pad_right(row.kind.label(), 16),
                    pad_left(&row.size.to_string(), SIZE_COLUMN),
                    pad_left(&format!("{} reclaimable", row.reclaimable), 24)
                );
            }
            let _ = writeln!(out);
            for row in usage {
                if row.reclaimable.is_zero() {
                    continue;
                }
                let line = format!("  {}", row.kind.prune_command());
                if row.kind.holds_persistent_data() {
                    let _ = writeln!(out, "{}", theme.review(&line));
                    let _ = writeln!(
                        out,
                        "      {}",
                        theme.review(
                            "volumes can hold databases and other state you have no second copy of"
                        )
                    );
                } else {
                    let _ = writeln!(out, "{}", theme.dim(&line));
                }
            }
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "{}",
                theme.dim("Bloatrail never deletes Docker's files directly.")
            );
        }
    }
    out
}

/// `diff`.
#[must_use]
pub fn diff_report(diff: &Diff, theme: &Theme) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{}", theme.heading("Disk change since last scan"));
    let _ = writeln!(
        out,
        "{}",
        theme.dim(&format!(
            "{} → {}",
            timefmt::format_timestamp(diff.from),
            timefmt::format_timestamp(diff.to)
        ))
    );
    let _ = writeln!(out);

    if diff.categories.is_empty() && diff.directories.is_empty() {
        let _ = writeln!(out, "{}", theme.dim("Nothing changed."));
        return out;
    }

    for change in diff.categories.iter().take(10) {
        let _ = writeln!(
            out,
            "  {}  {}",
            pad_left(&signed(change.delta), 10),
            change.label
        );
    }

    if !diff.directories.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", theme.heading("By directory"));
        for change in diff.directories.iter().take(10) {
            let _ = writeln!(
                out,
                "  {}  {}",
                pad_left(&signed(change.delta), 10),
                change.label
            );
        }
    }

    let _ = writeln!(out);
    let net = signed(diff.net);
    let painted = if diff.net > 0 {
        theme.review(&net)
    } else {
        theme.safe(&net)
    };
    let _ = writeln!(out, "Net change: {painted}");
    out
}

/// Render a scan duration at a useful precision.
///
/// `0.0s` tells the reader nothing; a fast scan deserves milliseconds and a slow
/// one deserves seconds.
#[must_use]
pub fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 1.0 {
        format!("{} ms", duration.as_millis())
    } else if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        let minutes = (seconds / 60.0).floor();
        format!("{minutes:.0}m {:.0}s", seconds - minutes * 60.0)
    }
}

fn signed(delta: i64) -> String {
    let magnitude = ByteSize(delta.unsigned_abs());
    if delta >= 0 {
        format!("+{magnitude}")
    } else {
        format!("-{magnitude}")
    }
}

/// A note about locations the scan could not read.
#[must_use]
pub fn skipped_note(scan: &ScanResult, theme: &Theme) -> String {
    if scan.skipped_count == 0 {
        return String::new();
    }
    format!(
        "{}\n",
        theme.dim(&format!(
            "Skipped {} inaccessible location{}",
            format_count(scan.skipped_count as u64),
            if scan.skipped_count == 1 { "" } else { "s" }
        ))
    )
}

/// Detail of skipped locations, shown by `doctor` and `--verbose`.
#[must_use]
pub fn skipped_detail(scan: &ScanResult, theme: &Theme, known: &KnownPaths) -> String {
    if scan.skipped.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let _ = writeln!(out, "{}", theme.heading("Skipped locations"));
    for skipped in &scan.skipped {
        let _ = writeln!(
            out,
            "  {} {}",
            theme.dim(skipped.reason.describe()),
            known.display(&skipped.path)
        );
    }
    if scan.skipped_count > scan.skipped.len() {
        let _ = writeln!(
            out,
            "  {}",
            theme.dim(&format!(
                "… and {} more",
                scan.skipped_count - scan.skipped.len()
            ))
        );
    }
    out
}

/// `"file"` or `"files"`, `"directory"` or `"directories"`.
fn plural(count: u64, singular: &'static str) -> String {
    if count == 1 {
        singular.to_string()
    } else if let Some(stem) = singular.strip_suffix('y') {
        format!("{stem}ies")
    } else {
        format!("{singular}s")
    }
}

fn quote_path(path: &str) -> String {
    if path.contains(' ') {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

/// Findings rendered as plain lines, used by the JSON fallback and tests.
#[must_use]
pub fn finding_line(finding: &Finding) -> String {
    match finding.severity {
        Severity::Warn => format!("WARN  {}", finding.message),
        Severity::Info => format!("INFO  {}", finding.message),
    }
}

/// Categories worth naming in a short summary.
#[must_use]
pub fn top_categories(scan: &ScanResult, limit: usize) -> Vec<(Category, u64)> {
    scan.categories
        .ranked()
        .into_iter()
        .take(limit)
        .map(|(category, bytes, _)| (category, bytes))
        .collect()
}

/// Docker resources that hold persistent data, for warning text.
#[must_use]
pub fn persistent_docker_resources(status: &DockerStatus) -> Vec<DockerResource> {
    match status {
        DockerStatus::Available { usage } => usage
            .iter()
            .filter(|u| u.kind.holds_persistent_data() && !u.size.is_zero())
            .map(|u| u.kind)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::ColorMode;

    #[test]
    fn signed_deltas_carry_their_sign() {
        assert!(signed(1024).starts_with('+'));
        assert!(signed(-1024).starts_with('-'));
        assert_eq!(signed(0), "+0 B");
    }

    #[test]
    fn plurals_read_correctly() {
        assert_eq!(plural(1, "file"), "file");
        assert_eq!(plural(0, "file"), "files");
        assert_eq!(plural(2, "file"), "files");
        assert_eq!(plural(1, "directory"), "directory");
        assert_eq!(plural(3, "directory"), "directories");
    }

    #[test]
    fn durations_use_a_useful_unit() {
        use std::time::Duration;
        assert_eq!(format_duration(Duration::from_millis(42)), "42 ms");
        assert_eq!(format_duration(Duration::from_millis(1_500)), "1.5s");
        assert_eq!(format_duration(Duration::from_secs(95)), "1m 35s");
    }

    #[test]
    fn paths_with_spaces_are_quoted_in_suggested_commands() {
        assert_eq!(quote_path("/a/b"), "/a/b");
        assert_eq!(quote_path("/a b/c"), "\"/a b/c\"");
    }

    #[test]
    fn docker_unavailable_renders_without_panicking() {
        let theme = Theme::new(ColorMode::Never, true);
        let text = docker_status(&DockerStatus::NotInstalled, &theme);
        assert!(text.contains("not installed"));
    }

    #[test]
    fn docker_volume_pruning_is_flagged_as_risky() {
        use crate::docker::DockerUsage;
        let theme = Theme::new(ColorMode::Never, true);
        let status = DockerStatus::Available {
            usage: vec![DockerUsage {
                kind: DockerResource::Volumes,
                size: ByteSize(9_000_000_000),
                reclaimable: ByteSize(1_000_000_000),
                count: 7,
            }],
        };
        let text = docker_status(&status, &theme);
        assert!(text.contains("docker volume prune"));
        assert!(text.contains("no second copy"));
        assert_eq!(
            persistent_docker_resources(&status),
            vec![DockerResource::Volumes]
        );
    }
}

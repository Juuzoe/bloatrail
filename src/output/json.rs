//! Machine-readable output.
//!
//! The JSON schema is defined by the types in this module, not by the internal
//! engine types. That separation is deliberate: refactoring the scanner should
//! not silently change the contract that someone's script depends on, and every
//! field here is one a consumer can reasonably act on.
//!
//! Every document carries `schema_version`. It is bumped on any breaking change.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analysis::domain::{Category, CleanupSafety, Confidence, Detection};
use crate::analysis::reclaim;
use crate::cleanup::executor::ExecutionReport;
use crate::cleanup::planner::{CleanupPlan, TargetKind};
use crate::docker::DockerStatus;
use crate::doctor::{DoctorReport, Severity};
use crate::duplicates::DuplicateReport;
use crate::history::Diff;
use crate::scanner::tree::{DirTree, NodeId};
use crate::scanner::ScanResult;

/// Version of the JSON contract.
pub const SCHEMA_VERSION: u32 = 1;

/// Totals shared by several documents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Totals {
    /// Total bytes.
    pub bytes: u64,
    /// Total files.
    pub files: u64,
    /// Total directories.
    pub directories: u64,
}

/// One row of the storage breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRow {
    /// Stable category identifier.
    pub category: String,
    /// Display label.
    pub label: String,
    /// Bytes in this category.
    pub bytes: u64,
    /// Files in this category.
    pub files: u64,
}

/// A classification, flattened for consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionView {
    /// What it is.
    pub category: String,
    /// Which ecosystem, if any.
    pub technology: Option<String>,
    /// How sure Bloatrail is.
    pub confidence: Confidence,
    /// Whether it may be removed.
    pub cleanup: CleanupSafety,
    /// Short explanation.
    pub reason: String,
    /// Longer supporting statements.
    pub evidence: Vec<String>,
    /// Command that regenerates the contents.
    pub regenerated_by: Option<String>,
}

impl DetectionView {
    /// Flatten a [`Detection`] for serialisation.
    #[must_use]
    pub fn new(detection: &Detection) -> Self {
        DetectionView {
            category: detection.category.id().to_string(),
            technology: detection.technology.map(|t| t.label().to_string()),
            confidence: detection.confidence,
            cleanup: detection.cleanup,
            reason: detection.reason.to_string(),
            evidence: detection.evidence.iter().map(ToString::to_string).collect(),
            regenerated_by: detection.regenerated_by.as_ref().map(ToString::to_string),
        }
    }
}

/// A directory in the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryView {
    /// Absolute path.
    pub path: String,
    /// Subtree bytes.
    pub bytes: u64,
    /// Subtree file count.
    pub files: u64,
    /// Depth below the scan root.
    pub depth: u16,
    /// Bytes Bloatrail believes are recoverable.
    pub reclaimable: u64,
    /// `true` when children were not retained.
    pub truncated: bool,
    /// Classification, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionView>,
    /// Child directories, when the requested depth includes them.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<DirectoryView>,
}

/// A file in the "largest files" list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileView {
    /// Absolute path.
    pub path: String,
    /// Size in bytes.
    pub bytes: u64,
    /// Category assigned during the scan.
    pub category: String,
    /// Modification time, seconds since the Unix epoch.
    pub modified: Option<u64>,
}

/// A location the scan could not read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedView {
    /// The location.
    pub path: String,
    /// Why it was skipped.
    pub reason: String,
}

/// `bloatrail scan --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// When the scan started, seconds since the Unix epoch.
    pub started_at: u64,
    /// How long it took, in milliseconds.
    pub duration_ms: u64,
    /// Overall totals.
    pub totals: Totals,
    /// Storage breakdown.
    pub categories: Vec<CategoryRow>,
    /// Directory tree, to the requested depth.
    pub tree: DirectoryView,
    /// Largest files.
    pub largest_files: Vec<FileView>,
    /// Sample of skipped locations.
    pub skipped: Vec<SkippedView>,
    /// Total number of skipped locations.
    pub skipped_count: usize,
    /// `true` when the scan was interrupted; totals are a lower bound.
    #[serde(default)]
    pub cancelled: bool,
}

/// Build the `scan` document.
#[must_use]
pub fn scan_document(scan: &ScanResult, depth: usize, top_files: usize) -> ScanDocument {
    ScanDocument {
        schema_version: SCHEMA_VERSION,
        root: display(&scan.root),
        started_at: scan
            .started_at
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        duration_ms: scan.duration.as_millis() as u64,
        totals: Totals {
            bytes: scan.totals.bytes,
            files: scan.totals.files,
            directories: scan.totals.dirs,
        },
        categories: scan
            .categories
            .ranked()
            .into_iter()
            .map(|(category, bytes, files)| CategoryRow {
                category: category.id().to_string(),
                label: category.label().to_string(),
                bytes,
                files,
            })
            .collect(),
        tree: directory_view(&scan.tree, scan.tree.root(), depth),
        largest_files: scan
            .largest_files
            .iter()
            .take(top_files)
            .map(|entry| FileView {
                path: display(&entry.path),
                bytes: entry.size,
                category: entry.category.id().to_string(),
                modified: entry.modified,
            })
            .collect(),
        skipped: scan
            .skipped
            .iter()
            .map(|s| SkippedView {
                path: display(&s.path),
                reason: s.reason.describe().to_string(),
            })
            .collect(),
        skipped_count: scan.skipped_count,
        cancelled: scan.cancelled,
    }
}

fn directory_view(tree: &DirTree, id: NodeId, depth: usize) -> DirectoryView {
    let node = tree.node(id);
    let estimate = reclaim::estimate(node.detection.as_ref(), &node.total);

    DirectoryView {
        path: display(&tree.path_of(id)),
        bytes: node.total.bytes,
        files: node.total.files,
        depth: node.depth,
        reclaimable: estimate.bytes.as_u64(),
        truncated: node.truncated,
        detection: node.detection.as_ref().map(DetectionView::new),
        children: if depth == 0 {
            Vec::new()
        } else {
            node.children
                .iter()
                .map(|child| directory_view(tree, *child, depth - 1))
                .collect()
        },
    }
}

/// A cleanup target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetView {
    /// Absolute path.
    pub path: String,
    /// Bytes involved.
    pub bytes: u64,
    /// `directory`, `aged_files` or `external`.
    pub kind: String,
    /// Age threshold for `aged_files` targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_than_days: Option<u32>,
}

/// A cleanup group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupView {
    /// Selection number, when the group can be selected.
    pub index: Option<usize>,
    /// Group title.
    pub title: String,
    /// Cleanup classification.
    pub safety: CleanupSafety,
    /// Category.
    pub category: String,
    /// Ecosystem.
    pub technology: Option<String>,
    /// Total bytes.
    pub bytes: u64,
    /// Whether recovery needs an external tool.
    pub external: bool,
    /// Command that regenerates the contents.
    pub regenerated_by: Option<String>,
    /// Locations.
    pub targets: Vec<TargetView>,
}

/// `bloatrail clean --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// Whether this run modified anything.
    pub dry_run: bool,
    /// Proposed groups.
    pub groups: Vec<GroupView>,
    /// Storage reported but never offered.
    pub protected: Vec<ProtectedView>,
    /// Total recoverable bytes.
    pub recoverable: u64,
    /// Bytes classified as safe for unattended cleanup.
    pub safe: u64,
    /// What was removed, when a removal actually ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionView>,
}

/// Storage reported in the "do not auto delete" section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedView {
    /// What it is.
    pub label: String,
    /// How much of it there is.
    pub bytes: u64,
}

/// The outcome of an execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionView {
    /// Whether anything was actually modified.
    pub dry_run: bool,
    /// Bytes freed (or that would be freed).
    pub bytes_freed: u64,
    /// Paths removed.
    pub removed: Vec<RemovalView>,
    /// Paths not removed, with reasons.
    pub failures: Vec<FailureView>,
}

/// One removal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalView {
    /// What was removed.
    pub path: String,
    /// How many bytes it accounted for.
    pub bytes: u64,
    /// `trash`, `permanent` or `simulated`.
    pub method: String,
}

/// One failure or refusal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureView {
    /// What was not removed.
    pub path: String,
    /// Why not.
    pub reason: String,
    /// `true` when the safety layer declined.
    pub refused: bool,
}

/// Build the `clean` document.
#[must_use]
pub fn clean_document(
    plan: &CleanupPlan,
    dry_run: bool,
    execution: Option<&ExecutionReport>,
) -> CleanDocument {
    CleanDocument {
        schema_version: SCHEMA_VERSION,
        root: display(&plan.root),
        dry_run,
        groups: plan
            .groups
            .iter()
            .map(|group| GroupView {
                index: group.index,
                title: group.title.clone(),
                safety: group.safety,
                category: group.category.id().to_string(),
                technology: group.technology.map(|t| t.label().to_string()),
                bytes: group.bytes,
                external: group.external,
                regenerated_by: group.regenerated_by.clone(),
                targets: group
                    .targets
                    .iter()
                    .map(|target| TargetView {
                        path: display(&target.path),
                        bytes: target.bytes,
                        kind: match target.kind {
                            TargetKind::Directory => "directory",
                            TargetKind::AgedFiles { .. } => "aged_files",
                            TargetKind::External => "external",
                        }
                        .to_string(),
                        older_than_days: match target.kind {
                            TargetKind::AgedFiles { days } => Some(days),
                            _ => None,
                        },
                    })
                    .collect(),
            })
            .collect(),
        protected: plan
            .protected
            .iter()
            .map(|row| ProtectedView {
                label: row.label.clone(),
                bytes: row.bytes,
            })
            .collect(),
        recoverable: plan.recoverable().as_u64(),
        safe: plan.automatically_safe().as_u64(),
        execution: execution.map(|report| ExecutionView {
            dry_run: report.dry_run,
            bytes_freed: report.bytes_freed,
            removed: report
                .removed
                .iter()
                .map(|removal| RemovalView {
                    path: display(&removal.path),
                    bytes: removal.bytes,
                    method: match removal.method {
                        crate::cleanup::RemovalMethod::Trash => "trash",
                        crate::cleanup::RemovalMethod::Permanent => "permanent",
                        crate::cleanup::RemovalMethod::Simulated => "simulated",
                    }
                    .to_string(),
                })
                .collect(),
            failures: report
                .failures
                .iter()
                .map(|failure| FailureView {
                    path: display(&failure.path),
                    reason: failure.reason.clone(),
                    refused: failure.refused,
                })
                .collect(),
        }),
    }
}

/// `bloatrail explain --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The path that was explained.
    pub path: String,
    /// Its total size.
    pub bytes: u64,
    /// Files beneath it.
    pub files: u64,
    /// Classification, when one applies.
    pub detection: Option<DetectionView>,
    /// Bytes Bloatrail believes are recoverable.
    pub reclaimable: u64,
    /// Whether recovery needs an external tool.
    pub reclaim_is_external: bool,
}

/// Build the `explain` document.
#[must_use]
pub fn explain_document(
    path: &Path,
    detection: Option<&Detection>,
    scan: &ScanResult,
) -> ExplainDocument {
    let estimate = reclaim::estimate(detection, &scan.totals);
    ExplainDocument {
        schema_version: SCHEMA_VERSION,
        path: display(path),
        bytes: scan.totals.bytes,
        files: scan.totals.files,
        detection: detection.map(DetectionView::new),
        reclaimable: estimate.bytes.as_u64(),
        reclaim_is_external: estimate.external,
    }
}

/// `bloatrail largest --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargestDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// Ranked directories.
    pub directories: Vec<DirectoryRow>,
    /// Ranked files.
    pub files: Vec<FileView>,
}

/// One ranked directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryRow {
    /// Absolute path.
    pub path: String,
    /// Subtree bytes.
    pub bytes: u64,
    /// Classification, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionView>,
}

/// Build the `largest` document.
#[must_use]
pub fn largest_document(scan: &ScanResult, limit: usize) -> LargestDocument {
    LargestDocument {
        schema_version: SCHEMA_VERSION,
        root: display(&scan.root),
        directories: scan
            .largest_directories(limit)
            .into_iter()
            .map(|(id, bytes)| DirectoryRow {
                path: display(&scan.tree.path_of(id)),
                bytes,
                detection: scan
                    .tree
                    .node(id)
                    .detection
                    .as_ref()
                    .map(DetectionView::new),
            })
            .collect(),
        files: scan
            .largest_files
            .iter()
            .take(limit)
            .map(|entry| FileView {
                path: display(&entry.path),
                bytes: entry.size,
                category: entry.category.id().to_string(),
                modified: entry.modified,
            })
            .collect(),
    }
}

/// `bloatrail duplicates --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicatesDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// Groups of identical files.
    pub groups: Vec<DuplicateGroupView>,
    /// Bytes the listed groups can free: every removable copy counted after
    /// hardlink names are folded and copies pinned by unlisted names are set
    /// aside.
    pub reclaimable: u64,
    /// Files compared after the size filter.
    pub candidates: u64,
    /// Files read in full.
    pub hashed: u64,
    /// Paths that were extra hardlinks of another candidate and so count no
    /// storage of their own.
    #[serde(default)]
    pub hardlinks: u64,
}

/// One duplicate group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroupView {
    /// Size of each copy.
    pub size: u64,
    /// Bytes freed by deduplicating the group. Extra hardlink names do not
    /// count, and neither do copies pinned by names outside the search.
    /// Storage shared without hardlinks — APFS and btrfs clones, ReFS block
    /// sharing — is not detected and counts as distinct.
    pub reclaimable: u64,
    /// Every path in the group, hardlinks included.
    pub paths: Vec<String>,
    /// The same paths grouped by storage.
    #[serde(default)]
    pub copies: Vec<DuplicateCopyView>,
}

/// One piece of storage within a duplicate group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateCopyView {
    /// The names found for this storage; several means hardlinks.
    pub paths: Vec<String>,
    /// Whether the file has more names than the listed ones — outside the
    /// search, excluded, or unmatchable because the filesystem's file IDs
    /// cannot be trusted. Deleting the listed paths of such a copy frees
    /// nothing.
    pub linked_elsewhere: bool,
}

/// Build the `duplicates` document.
#[must_use]
pub fn duplicates_document(root: &Path, report: &DuplicateReport) -> DuplicatesDocument {
    DuplicatesDocument {
        schema_version: SCHEMA_VERSION,
        root: display(root),
        groups: report
            .groups
            .iter()
            .map(|group| DuplicateGroupView {
                size: group.size,
                reclaimable: group.reclaimable(),
                paths: group.paths().map(|p| display(p)).collect(),
                copies: group
                    .copies
                    .iter()
                    .map(|copy| DuplicateCopyView {
                        paths: copy.paths.iter().map(|p| display(p)).collect(),
                        linked_elsewhere: copy.linked_elsewhere(),
                    })
                    .collect(),
            })
            .collect(),
        reclaimable: report.reclaimable,
        candidates: report.candidates,
        hashed: report.hashed,
        hardlinks: report.hardlinks,
    }
}

/// `bloatrail doctor --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// Observations.
    pub findings: Vec<FindingView>,
    /// Total space the findings suggest could be recovered.
    pub recoverable: u64,
    /// Docker's own report, when it answered.
    pub docker: DockerView,
}

/// One observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingView {
    /// `warn` or `info`.
    pub severity: String,
    /// The observation.
    pub message: String,
    /// A suggested next step.
    pub hint: Option<String>,
    /// Space involved.
    pub bytes: u64,
}

/// Docker's disk usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerView {
    /// `available`, `not_installed` or `unavailable`.
    pub status: String,
    /// Total space Docker occupies.
    pub total: u64,
    /// Space Docker reports as reclaimable.
    pub reclaimable: u64,
    /// Per-resource detail.
    pub resources: Vec<DockerResourceView>,
}

/// One Docker resource kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerResourceView {
    /// Resource label.
    pub kind: String,
    /// Space used.
    pub bytes: u64,
    /// Space reclaimable.
    pub reclaimable: u64,
    /// The command that reclaims it.
    pub prune_command: String,
    /// Whether pruning it can destroy data.
    pub holds_persistent_data: bool,
}

/// Build the `doctor` document.
#[must_use]
pub fn doctor_document(
    root: &Path,
    report: &DoctorReport,
    docker: &DockerStatus,
) -> DoctorDocument {
    DoctorDocument {
        schema_version: SCHEMA_VERSION,
        root: display(root),
        findings: report
            .findings
            .iter()
            .map(|finding| FindingView {
                severity: match finding.severity {
                    Severity::Warn => "warn",
                    Severity::Info => "info",
                }
                .to_string(),
                message: finding.message.clone(),
                hint: finding.hint.clone(),
                bytes: finding.bytes.as_u64(),
            })
            .collect(),
        recoverable: report.recoverable.as_u64(),
        docker: docker_view(docker),
    }
}

fn docker_view(status: &DockerStatus) -> DockerView {
    DockerView {
        status: match status {
            DockerStatus::Available { .. } => "available",
            DockerStatus::NotInstalled => "not_installed",
            DockerStatus::NotRunning { .. } => "unavailable",
            DockerStatus::NotChecked => "not_checked",
        }
        .to_string(),
        total: status.total().as_u64(),
        reclaimable: status.reclaimable().as_u64(),
        resources: match status {
            DockerStatus::Available { usage } => usage
                .iter()
                .map(|row| DockerResourceView {
                    kind: row.kind.label().to_string(),
                    bytes: row.size.as_u64(),
                    reclaimable: row.reclaimable.as_u64(),
                    prune_command: row.kind.prune_command().to_string(),
                    holds_persistent_data: row.kind.holds_persistent_data(),
                })
                .collect(),
            _ => Vec::new(),
        },
    }
}

/// `bloatrail diff --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffDocument {
    /// Contract version.
    pub schema_version: u32,
    /// The scanned path.
    pub root: String,
    /// Timestamp of the earlier scan.
    pub from: u64,
    /// Timestamp of the current scan.
    pub to: u64,
    /// Category changes.
    pub categories: Vec<ChangeView>,
    /// Directory changes.
    pub directories: Vec<ChangeView>,
    /// Net byte change.
    pub net: i64,
}

/// One change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeView {
    /// What changed.
    pub label: String,
    /// Signed byte delta.
    pub delta: i64,
}

/// Build the `diff` document.
#[must_use]
pub fn diff_document(root: &Path, diff: &Diff) -> DiffDocument {
    let convert = |changes: &[crate::history::Change]| {
        changes
            .iter()
            .map(|change| ChangeView {
                label: change.label.clone(),
                delta: change.delta,
            })
            .collect()
    };
    DiffDocument {
        schema_version: SCHEMA_VERSION,
        root: display(root),
        from: diff.from,
        to: diff.to,
        categories: convert(&diff.categories),
        directories: convert(&diff.directories),
        net: diff.net,
    }
}

/// Serialise a document as pretty-printed JSON with a trailing newline.
///
/// # Errors
///
/// Propagates serialisation failures, which in practice only happen for
/// non-representable floats — none of which appear in these documents.
pub fn to_string<T: Serialize>(value: &T) -> crate::error::Result<String> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    Ok(text)
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Categories exposed in the schema, for documentation and tests.
#[must_use]
pub fn category_ids() -> Vec<&'static str> {
    Category::ALL.iter().map(|c| c.id()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::{CategoryTotals, Confidence, Technology};
    use crate::scanner::tree::{DirNode, Totals};
    use crate::scanner::ScanResult;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn sample_scan() -> ScanResult {
        let mut categories = CategoryTotals::new();
        categories.add_bulk(Category::Dependency, 6_000, 12);

        let nodes = vec![
            DirNode {
                name: "".into(),
                parent: None,
                children: vec![1],
                depth: 0,
                own: Totals::default(),
                total: Totals {
                    bytes: 6_000,
                    files: 12,
                    dirs: 2,
                    stale_bytes: 0,
                },
                detection: None,
                truncated: false,
            },
            DirNode {
                name: "node_modules".into(),
                parent: Some(0),
                children: vec![],
                depth: 1,
                own: Totals::default(),
                total: Totals {
                    bytes: 6_000,
                    files: 12,
                    dirs: 1,
                    stale_bytes: 0,
                },
                detection: Some(
                    Detection::new(
                        Category::Dependency,
                        Confidence::High,
                        CleanupSafety::Safe,
                        "npm dependencies",
                    )
                    .with_technology(Technology::Node)
                    .regenerated_by("npm install"),
                ),
                truncated: true,
            },
        ];

        let tree = DirTree::new(PathBuf::from("/scan"), nodes);
        let totals = tree.node(tree.root()).total;
        ScanResult {
            root: PathBuf::from("/scan"),
            tree,
            totals,
            categories,
            largest_files: Vec::new(),
            skipped: Vec::new(),
            skipped_count: 0,
            duration: Duration::from_millis(1_500),
            started_at: SystemTime::UNIX_EPOCH,
            cancelled: false,
        }
    }

    #[test]
    fn scan_documents_round_trip() {
        let document = scan_document(&sample_scan(), 2, 10);
        let text = to_string(&document).expect("serialise");
        let parsed: ScanDocument = serde_json::from_str(&text).expect("deserialise");

        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.totals.bytes, 6_000);
        assert_eq!(parsed.categories[0].category, "dependency");
        assert_eq!(parsed.tree.children.len(), 1);
        assert_eq!(parsed.tree.children[0].reclaimable, 6_000);
        assert!(parsed.tree.children[0].truncated);
    }

    #[test]
    fn depth_zero_omits_children() {
        let document = scan_document(&sample_scan(), 0, 10);
        assert!(document.tree.children.is_empty());
    }

    #[test]
    fn detections_expose_stable_identifiers() {
        let document = scan_document(&sample_scan(), 1, 10);
        let detection = document.tree.children[0]
            .detection
            .as_ref()
            .expect("detection");
        assert_eq!(detection.category, "dependency");
        assert_eq!(detection.technology.as_deref(), Some("Node.js"));
        assert_eq!(detection.cleanup, CleanupSafety::Safe);
        assert_eq!(detection.regenerated_by.as_deref(), Some("npm install"));
    }

    #[test]
    fn clean_documents_include_every_group_even_unselectable_ones() {
        let scan = sample_scan();
        let plan = CleanupPlan::from_scan(&scan);
        let document = clean_document(&plan, true, None);
        assert_eq!(document.schema_version, SCHEMA_VERSION);
        assert_eq!(document.groups.len(), plan.groups.len());
        assert!(document.execution.is_none());

        let text = to_string(&document).expect("serialise");
        let parsed: CleanDocument = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(parsed.recoverable, plan.recoverable().as_u64());
    }

    #[test]
    fn every_category_id_is_unique_and_snake_case() {
        let ids = category_ids();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "category ids must be unique");
        for id in ids {
            assert!(
                id.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "`{id}` is not snake_case"
            );
        }
    }

    #[test]
    fn output_ends_with_a_newline_for_shell_friendliness() {
        let document = scan_document(&sample_scan(), 1, 5);
        assert!(to_string(&document).unwrap().ends_with('\n'));
    }
}

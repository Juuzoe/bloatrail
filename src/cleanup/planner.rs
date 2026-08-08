//! Turning a scan into a reviewable cleanup plan.
//!
//! The planner never deletes anything and never decides anything on the user's
//! behalf. It groups the scanner's detections into named, explainable units,
//! attaches exact byte figures, and marks which of them a human still has to
//! look at. Selection and execution happen elsewhere, deliberately.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::analysis::domain::{
    Category, CleanupSafety, Confidence, Detection, Reclaim, Technology,
};
use crate::scanner::tree::{DirTree, NodeId};
use crate::scanner::ScanResult;
use crate::units::ByteSize;

/// What kind of removal a target implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// Remove the directory and everything in it.
    Directory,
    /// Remove only files under the directory older than `days`.
    AgedFiles {
        /// Age threshold in days.
        days: u32,
    },
    /// Reported for awareness; Bloatrail will not remove it itself.
    External,
}

/// One location within a cleanup group.
#[derive(Debug, Clone)]
pub struct CleanupTarget {
    /// Absolute path.
    pub path: PathBuf,
    /// Bytes this target accounts for.
    pub bytes: u64,
    /// Files this target accounts for.
    pub files: u64,
    /// What removing it means.
    pub kind: TargetKind,
    /// Confidence in the detection behind it.
    pub confidence: Confidence,
    /// The detection itself, re-checked before any deletion.
    pub detection: Detection,
}

/// A named set of targets sharing one explanation.
#[derive(Debug, Clone)]
pub struct CleanupGroup {
    /// 1-based selection number, or `None` when the group cannot be selected.
    pub index: Option<usize>,
    /// Short title, e.g. `"Rust build artifacts"`.
    pub title: String,
    /// Cleanup classification shared by every target.
    pub safety: CleanupSafety,
    /// Category shared by every target.
    pub category: Category,
    /// Ecosystem, when the group has one.
    pub technology: Option<Technology>,
    /// Supporting statements shown by `bloatrail explain`.
    pub evidence: Vec<String>,
    /// Command that regenerates the contents, if any.
    pub regenerated_by: Option<String>,
    /// Locations in this group.
    pub targets: Vec<CleanupTarget>,
    /// Total bytes across all targets.
    pub bytes: u64,
    /// `true` when recovery requires an external tool rather than a deletion.
    pub external: bool,
}

impl CleanupGroup {
    /// Whether `bloatrail clean` can act on this group.
    #[must_use]
    pub fn is_selectable(&self) -> bool {
        self.index.is_some()
    }

    /// Number of locations in the group.
    #[must_use]
    pub fn location_count(&self) -> usize {
        self.targets.len()
    }
}

/// Storage that Bloatrail deliberately refuses to offer for deletion.
#[derive(Debug, Clone)]
pub struct ProtectedSummary {
    /// What it is.
    pub label: String,
    /// How much of it there is.
    pub bytes: u64,
}

/// A complete, reviewable cleanup proposal.
#[derive(Debug, Clone)]
pub struct CleanupPlan {
    /// The scan root the plan was built from.
    pub root: PathBuf,
    /// Groups, ordered by safety then size.
    pub groups: Vec<CleanupGroup>,
    /// Categories reported but never offered.
    pub protected: Vec<ProtectedSummary>,
}

impl CleanupPlan {
    /// Build a plan from a completed scan.
    ///
    /// `stale_days` must be the threshold the scan used to accumulate
    /// `stale_bytes`; it is what age-limited targets will be executed against.
    #[must_use]
    pub fn from_scan_with(scan: &ScanResult, stale_days: u32) -> Self {
        let mut collected: BTreeMap<GroupKey, GroupAccumulator> = BTreeMap::new();
        collect_targets(&scan.tree, stale_days, &mut collected);

        let mut groups: Vec<CleanupGroup> = collected
            .into_values()
            .map(GroupAccumulator::finish)
            .collect();

        // Safest first, then largest — the order a person wants to read.
        groups.sort_by(|a, b| {
            a.safety
                .cmp(&b.safety)
                .then(b.bytes.cmp(&a.bytes))
                .then(a.title.cmp(&b.title))
        });

        let mut next_index = 1usize;
        for group in &mut groups {
            let selectable = !group.external
                && group.safety.is_deletable()
                && !group.targets.is_empty()
                && group.bytes > 0;
            if selectable {
                group.index = Some(next_index);
                next_index += 1;
            }
        }

        CleanupPlan {
            root: scan.root.clone(),
            groups,
            protected: protected_summary(scan),
        }
    }

    /// Build a plan using the scanner's default age threshold.
    #[must_use]
    pub fn from_scan(scan: &ScanResult) -> Self {
        Self::from_scan_with(scan, crate::scanner::DEFAULT_STALE_DAYS)
    }

    /// Total bytes across every group Bloatrail could remove.
    #[must_use]
    pub fn recoverable(&self) -> ByteSize {
        ByteSize(
            self.groups
                .iter()
                .filter(|g| g.safety.is_deletable())
                .map(|g| g.bytes)
                .sum(),
        )
    }

    /// Bytes in groups classified [`CleanupSafety::Safe`].
    #[must_use]
    pub fn automatically_safe(&self) -> ByteSize {
        ByteSize(
            self.groups
                .iter()
                .filter(|g| g.safety == CleanupSafety::Safe && g.is_selectable())
                .map(|g| g.bytes)
                .sum(),
        )
    }

    /// Groups matching a safety classification.
    pub fn by_safety(&self, safety: CleanupSafety) -> impl Iterator<Item = &CleanupGroup> {
        self.groups.iter().filter(move |g| g.safety == safety)
    }

    /// Look up a selectable group by its displayed number.
    #[must_use]
    pub fn group_by_index(&self, index: usize) -> Option<&CleanupGroup> {
        self.groups.iter().find(|g| g.index == Some(index))
    }

    /// Every group the user can select.
    pub fn selectable(&self) -> impl Iterator<Item = &CleanupGroup> {
        self.groups.iter().filter(|g| g.is_selectable())
    }

    /// Whether there is nothing to offer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.iter().all(|g| !g.is_selectable())
    }
}

/// Grouping key. Ordered so `BTreeMap` iteration is deterministic across runs,
/// which keeps `--json` output stable and tests reproducible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey {
    safety: CleanupSafety,
    category: Category,
    title: String,
}

struct GroupAccumulator {
    key: GroupKey,
    technology: Option<Technology>,
    evidence: Vec<String>,
    regenerated_by: Option<String>,
    targets: Vec<CleanupTarget>,
    bytes: u64,
    external: bool,
}

impl GroupAccumulator {
    fn finish(mut self) -> CleanupGroup {
        // Largest locations first inside a group.
        self.targets
            .sort_by_key(|target| std::cmp::Reverse(target.bytes));

        // An age-limited group's figure covers only the aged portion, so the
        // title has to say so. "Downloads folder — 8.7 GB" next to a 40 GB
        // folder would read as a promise to delete all of it.
        let title = match self.targets.first().map(|target| target.kind) {
            Some(TargetKind::AgedFiles { days }) => {
                format!("{} older than {days} days", self.key.title)
            }
            _ => self.key.title.clone(),
        };

        CleanupGroup {
            index: None,
            title,
            safety: self.key.safety,
            category: self.key.category,
            technology: self.technology,
            evidence: self.evidence,
            regenerated_by: self.regenerated_by,
            targets: self.targets,
            bytes: self.bytes,
            external: self.external,
        }
    }
}

/// Depth-first walk collecting targets, skipping anything beneath a location
/// that has already been claimed.
///
/// Without that suppression a `.next` inside an already-targeted project
/// directory would be counted twice, and the executor would try to delete a
/// path whose parent it had just removed.
fn collect_targets(
    tree: &DirTree,
    stale_days: u32,
    groups: &mut BTreeMap<GroupKey, GroupAccumulator>,
) {
    let mut stack: Vec<NodeId> = vec![tree.root()];

    while let Some(id) = stack.pop() {
        let node = tree.node(id);
        let mut claimed = false;

        if let Some(detection) = &node.detection {
            if let Some(target) = build_target(tree, id, detection, stale_days) {
                // Aged-file targets remove individual files, not the tree, so
                // detections below them stay visible and selectable.
                claimed = !matches!(target.kind, TargetKind::AgedFiles { .. });
                let key = GroupKey {
                    safety: detection.cleanup,
                    category: detection.category,
                    title: detection.reason.to_string(),
                };
                let entry = groups
                    .entry(key.clone())
                    .or_insert_with(|| GroupAccumulator {
                        key,
                        technology: detection.technology,
                        evidence: detection.evidence.iter().map(ToString::to_string).collect(),
                        regenerated_by: detection.regenerated_by.as_ref().map(ToString::to_string),
                        targets: Vec::new(),
                        bytes: 0,
                        external: detection.reclaim == Reclaim::External,
                    });
                entry.bytes = entry.bytes.saturating_add(target.bytes);
                entry.targets.push(target);
            }
        }

        if !claimed {
            stack.extend(node.children.iter().copied());
        }
    }
}

fn build_target(
    tree: &DirTree,
    id: NodeId,
    detection: &Detection,
    stale_days: u32,
) -> Option<CleanupTarget> {
    let node = tree.node(id);
    // Never propose removing the scan root itself unless the user pointed at it
    // directly; even then the safety guard has the final say.
    let path = tree.path_of(id);

    match detection.reclaim {
        Reclaim::None => None,
        Reclaim::All => {
            if !detection.cleanup.is_deletable() || node.total.bytes == 0 {
                return None;
            }
            Some(CleanupTarget {
                path,
                bytes: node.total.bytes,
                files: node.total.files,
                kind: TargetKind::Directory,
                confidence: detection.confidence,
                detection: detection.clone(),
            })
        }
        Reclaim::OlderThan { .. } => {
            if !detection.cleanup.is_deletable() || node.total.stale_bytes == 0 {
                return None;
            }
            Some(CleanupTarget {
                path,
                bytes: node.total.stale_bytes,
                files: 0,
                // The age threshold reported here has to be the one the byte
                // figure was actually computed with, which is the scan's
                // `stale_days` — not the detector's preferred value. Otherwise
                // the preview and the deletion disagree about what "old" means.
                kind: TargetKind::AgedFiles { days: stale_days },
                confidence: detection.confidence,
                detection: detection.clone(),
            })
        }
        Reclaim::External => {
            if node.total.bytes == 0 {
                return None;
            }
            Some(CleanupTarget {
                path,
                bytes: node.total.bytes,
                files: node.total.files,
                kind: TargetKind::External,
                confidence: detection.confidence,
                detection: detection.clone(),
            })
        }
    }
}

/// Categories reported in the "do not auto delete" section.
fn protected_summary(scan: &ScanResult) -> Vec<ProtectedSummary> {
    let interesting = [
        (Category::SourceCode, "Project source files"),
        (Category::GitData, "Git repositories"),
        (Category::Document, "Documents"),
        (Category::Video, "Videos"),
        (Category::Image, "Images"),
        (Category::VirtualMachine, "Virtual machine disks"),
    ];

    let mut rows: Vec<ProtectedSummary> = interesting
        .into_iter()
        .filter_map(|(category, label)| {
            let bytes = scan.categories.bytes(category);
            (bytes > 0).then(|| ProtectedSummary {
                label: label.to_string(),
                bytes,
            })
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.bytes));
    rows
}

/// Whether `path` lies inside `root` (or is `root`).
#[must_use]
pub fn is_within(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::Confidence;
    use crate::scanner::tree::{DirNode, Totals};

    fn detection(
        category: Category,
        safety: CleanupSafety,
        reason: &'static str,
        reclaim: Reclaim,
    ) -> Detection {
        Detection::new(category, Confidence::High, safety, reason).with_reclaim(reclaim)
    }

    fn node(
        name: &str,
        parent: Option<NodeId>,
        children: Vec<NodeId>,
        bytes: u64,
        stale: u64,
        detection: Option<Detection>,
    ) -> DirNode {
        DirNode {
            name: name.into(),
            parent,
            children,
            depth: parent.map_or(0, |_| 1),
            own: Totals::default(),
            total: Totals {
                bytes,
                files: 1,
                dirs: 1,
                stale_bytes: stale,
            },
            detection,
            truncated: false,
        }
    }

    fn tree_with(nodes: Vec<DirNode>) -> DirTree {
        DirTree::new(PathBuf::from("/scan"), nodes)
    }

    #[test]
    fn nested_targets_below_a_claimed_directory_are_suppressed() {
        // /scan
        //   node_modules       (claimed, 100)
        //     .cache           (would be claimed too, but must be suppressed)
        let tree = tree_with(vec![
            node("", None, vec![1], 100, 0, None),
            node(
                "node_modules",
                Some(0),
                vec![2],
                100,
                0,
                Some(detection(
                    Category::Dependency,
                    CleanupSafety::Safe,
                    "npm dependencies",
                    Reclaim::All,
                )),
            ),
            node(
                ".cache",
                Some(1),
                vec![],
                40,
                0,
                Some(detection(
                    Category::Cache,
                    CleanupSafety::Safe,
                    "cache",
                    Reclaim::All,
                )),
            ),
        ]);

        let mut groups = BTreeMap::new();
        collect_targets(&tree, 90, &mut groups);
        assert_eq!(groups.len(), 1, "the nested cache must not become a target");
        let group = groups.into_values().next().unwrap().finish();
        assert_eq!(group.bytes, 100);
    }

    #[test]
    fn aged_targets_use_only_stale_bytes_and_do_not_suppress_children() {
        let tree = tree_with(vec![
            node("", None, vec![1], 500, 0, None),
            node(
                "Downloads",
                Some(0),
                vec![2],
                500,
                200,
                Some(detection(
                    Category::Download,
                    CleanupSafety::Review,
                    "Downloads folder",
                    Reclaim::OlderThan { days: 90 },
                )),
            ),
            node(
                "project/target",
                Some(1),
                vec![],
                50,
                0,
                Some(detection(
                    Category::BuildArtifact,
                    CleanupSafety::Safe,
                    "Rust build artifacts",
                    Reclaim::All,
                )),
            ),
        ]);

        let mut groups = BTreeMap::new();
        collect_targets(&tree, 90, &mut groups);
        assert_eq!(
            groups.len(),
            2,
            "a build directory inside Downloads is still offered"
        );

        let downloads = groups
            .values()
            .find(|g| g.key.title == "Downloads folder")
            .expect("downloads group");
        assert_eq!(downloads.bytes, 200, "only the stale portion is offered");
    }

    #[test]
    fn age_limited_group_titles_state_the_threshold() {
        let tree = tree_with(vec![
            node("", None, vec![1], 500, 0, None),
            node(
                "Downloads",
                Some(0),
                vec![],
                500,
                200,
                Some(detection(
                    Category::Download,
                    CleanupSafety::Review,
                    "Downloads folder",
                    Reclaim::OlderThan { days: 90 },
                )),
            ),
        ]);

        let mut groups = BTreeMap::new();
        collect_targets(&tree, 90, &mut groups);
        let group = groups.into_values().next().unwrap().finish();
        assert_eq!(group.title, "Downloads folder older than 90 days");
    }

    #[test]
    fn never_delete_detections_never_become_targets() {
        let tree = tree_with(vec![
            node("", None, vec![1], 900, 0, None),
            node(
                ".git",
                Some(0),
                vec![],
                900,
                0,
                Some(detection(
                    Category::GitData,
                    CleanupSafety::NeverDelete,
                    "Git repository data",
                    Reclaim::None,
                )),
            ),
        ]);
        let mut groups = BTreeMap::new();
        collect_targets(&tree, 90, &mut groups);
        assert!(groups.is_empty());
    }

    #[test]
    fn external_groups_are_reported_but_not_selectable() {
        let tree = tree_with(vec![
            node("", None, vec![1], 1_000, 0, None),
            node(
                "docker",
                Some(0),
                vec![],
                1_000,
                0,
                Some(detection(
                    Category::ContainerData,
                    CleanupSafety::Review,
                    "Docker data",
                    Reclaim::External,
                )),
            ),
        ]);
        let mut groups = BTreeMap::new();
        collect_targets(&tree, 90, &mut groups);
        let group = groups.into_values().next().unwrap().finish();
        assert!(group.external);
        assert_eq!(group.targets[0].kind, TargetKind::External);
    }

    #[test]
    fn containment_check_rejects_siblings() {
        assert!(is_within(Path::new("/a"), Path::new("/a/b")));
        assert!(is_within(Path::new("/a"), Path::new("/a")));
        assert!(!is_within(Path::new("/a"), Path::new("/ab")));
        assert!(!is_within(Path::new("/a"), Path::new("/b")));
    }
}

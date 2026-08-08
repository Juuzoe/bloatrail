//! `bloatrail doctor` — a read-only health check.
//!
//! Doctor answers "is anything obviously wrong here?" without deleting,
//! modifying or even proposing anything. Each finding is derived from figures
//! the scan already produced, so running it costs one scan and nothing else.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::analysis::domain::{Category, CleanupSafety, Technology};
use crate::docker::DockerStatus;
use crate::platform::{DiskUsage, KnownPaths};
use crate::scanner::ScanResult;
use crate::units::{format_count, ByteSize};

/// How much attention a finding deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Worth acting on.
    Warn,
    /// Worth knowing.
    Info,
}

/// One observation.
#[derive(Debug, Clone)]
pub struct Finding {
    /// How much attention it deserves.
    pub severity: Severity,
    /// The observation itself.
    pub message: String,
    /// An optional suggested next step.
    pub hint: Option<String>,
    /// Space this finding relates to, if any.
    pub bytes: ByteSize,
}

impl Finding {
    fn warn(message: impl Into<String>, bytes: ByteSize) -> Self {
        Finding {
            severity: Severity::Warn,
            message: message.into(),
            hint: None,
            bytes,
        }
    }

    fn info(message: impl Into<String>, bytes: ByteSize) -> Self {
        Finding {
            severity: Severity::Info,
            message: message.into(),
            hint: None,
            bytes,
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// The complete health check.
#[derive(Debug, Clone, Default)]
pub struct DoctorReport {
    /// Observations, most important first.
    pub findings: Vec<Finding>,
    /// Total space the findings suggest could be recovered.
    pub recoverable: ByteSize,
}

/// Thresholds that decide when something becomes a warning.
///
/// Collected here so the policy is visible in one place rather than scattered
/// through the checks.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// Disk usage above which the volume is called full.
    pub disk_full_fraction: f64,
    /// Dependency bytes above which `node_modules` is worth mentioning.
    pub dependencies: u64,
    /// Build-artifact bytes above which they are worth mentioning.
    pub build_artifacts: u64,
    /// Package-cache bytes above which they are worth mentioning.
    pub package_caches: u64,
    /// Docker reclaimable bytes above which it becomes a warning.
    pub docker: u64,
    /// Size above which an individual file is called out.
    pub huge_file: u64,
    /// `.git` size above which a repository is called unusually large.
    pub large_repository: u64,
    /// Share of the scan above which a category is notable regardless of the
    /// absolute thresholds.
    ///
    /// Without this, `doctor` says "nothing notable" for every project-sized
    /// directory, which is precisely where developers run it.
    pub significant_fraction: f64,
    /// Floor for the relative rule, so a 40 MB scan does not produce warnings.
    pub significant_minimum: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        const GB: u64 = 1024 * 1024 * 1024;
        Thresholds {
            disk_full_fraction: 0.85,
            dependencies: 5 * GB,
            build_artifacts: 2 * GB,
            package_caches: 2 * GB,
            docker: GB,
            huge_file: 2 * GB,
            large_repository: GB,
            significant_fraction: 0.25,
            significant_minimum: 64 * 1024 * 1024,
        }
    }
}

impl Thresholds {
    /// Whether `bytes` is worth mentioning, given the size of the whole scan.
    #[must_use]
    pub fn is_notable(&self, bytes: u64, total: u64, absolute: u64) -> bool {
        if bytes >= absolute {
            return true;
        }
        if bytes < self.significant_minimum || total == 0 {
            return false;
        }
        (bytes as f64 / total as f64) >= self.significant_fraction
    }
}

/// Run the health check over a completed scan.
#[must_use]
pub fn diagnose(
    scan: &ScanResult,
    known: &KnownPaths,
    docker: &DockerStatus,
    disk: Option<DiskUsage>,
    thresholds: &Thresholds,
) -> DoctorReport {
    let mut findings = Vec::new();
    let mut recoverable: u64 = 0;

    if let Some(disk) = disk {
        let fraction = disk.used_fraction();
        if fraction >= thresholds.disk_full_fraction {
            findings.push(
                Finding::warn(
                    format!(
                        "The volume holding this path is {:.0}% full ({} free)",
                        fraction * 100.0,
                        ByteSize(disk.available)
                    ),
                    ByteSize::ZERO,
                )
                .with_hint("run `bloatrail clean --dry-run` to see what can be recovered"),
            );
        }
    }

    // ---- developer storage ------------------------------------------------
    let total = scan.totals.bytes;
    let dependencies = scan.categories.bytes(Category::Dependency);
    if thresholds.is_notable(dependencies, total, thresholds.dependencies) {
        recoverable = recoverable.saturating_add(dependencies);
        findings.push(
            Finding::warn(
                format!(
                    "{} contains {} of installed dependencies",
                    known.display(&scan.root),
                    ByteSize(dependencies)
                ),
                ByteSize(dependencies),
            )
            .with_hint("reinstalling them is a single command in each project"),
        );
    }

    let build = scan.categories.bytes(Category::BuildArtifact);
    if thresholds.is_notable(build, total, thresholds.build_artifacts) {
        recoverable = recoverable.saturating_add(build);
        findings.push(
            Finding::warn(
                format!("{} of build artifacts can be regenerated", ByteSize(build)),
                ByteSize(build),
            )
            .with_hint("see `bloatrail clean --dry-run`"),
        );
    }

    let caches = scan
        .categories
        .bytes(Category::PackageCache)
        .saturating_add(scan.categories.bytes(Category::Cache));
    if thresholds.is_notable(caches, total, thresholds.package_caches) {
        recoverable = recoverable.saturating_add(caches);
        findings.push(Finding::info(
            format!(
                "{} is held in caches and package registries",
                ByteSize(caches)
            ),
            ByteSize(caches),
        ));
    }

    // ---- per-technology breakdown ------------------------------------------
    for (technology, bytes) in technology_totals(scan) {
        if thresholds.is_notable(bytes, total, thresholds.package_caches) {
            findings.push(Finding::info(
                format!("{technology} storage accounts for {}", ByteSize(bytes)),
                ByteSize(bytes),
            ));
        }
    }

    // ---- repositories --------------------------------------------------------
    if let Some((path, bytes)) = largest_repository(scan) {
        if thresholds.is_notable(bytes, total, thresholds.large_repository) {
            findings.push(
                Finding::info(
                    format!(
                        "Largest repository: {} ({} of history)",
                        known.display(&path),
                        ByteSize(bytes)
                    ),
                    ByteSize::ZERO,
                )
                .with_hint("`git gc --aggressive --prune=now` can shrink it without data loss"),
            );
        }
    }

    // ---- individual files ------------------------------------------------------
    let huge: Vec<_> = scan
        .largest_files
        .iter()
        .filter(|entry| entry.size >= thresholds.huge_file)
        .collect();
    if !huge.is_empty() {
        let total: u64 = huge.iter().map(|entry| entry.size).sum();
        findings.push(
            Finding::warn(
                format!(
                    "{} file{} larger than {} ({} in total)",
                    huge.len(),
                    if huge.len() == 1 { "" } else { "s" },
                    ByteSize(thresholds.huge_file),
                    ByteSize(total)
                ),
                ByteSize::ZERO,
            )
            .with_hint("`bloatrail largest --files` lists them"),
        );
    }

    // ---- stale downloads --------------------------------------------------------
    if scan.totals.stale_bytes > 0 {
        let downloads = scan.categories.bytes(Category::Download);
        if downloads > 0 {
            findings.push(Finding::info(
                format!(
                    "{} of downloads have not been touched recently",
                    ByteSize(scan.totals.stale_bytes.min(downloads))
                ),
                ByteSize::ZERO,
            ));
        }
    }

    // ---- Docker ------------------------------------------------------------------
    match docker {
        DockerStatus::Available { .. } => {
            let reclaimable = docker.reclaimable();
            if reclaimable.as_u64() >= thresholds.docker {
                recoverable = recoverable.saturating_add(reclaimable.as_u64());
                findings.push(
                    Finding::warn(
                        format!("Docker reports {reclaimable} as reclaimable"),
                        reclaimable,
                    )
                    .with_hint("`docker system prune` reclaims it safely; volumes need care"),
                );
            } else if !docker.total().is_zero() {
                findings.push(Finding::info(
                    format!("Docker is using {}", docker.total()),
                    docker.total(),
                ));
            }
        }
        DockerStatus::NotInstalled | DockerStatus::NotChecked => {}
        DockerStatus::NotRunning { detail } => {
            findings.push(Finding::info(
                format!("Docker usage could not be checked: {detail}"),
                ByteSize::ZERO,
            ));
        }
    }

    // ---- empty directories -----------------------------------------------------------
    let empty_dirs = empty_directory_roots(scan);
    if empty_dirs >= 10 {
        findings.push(
            Finding::info(
                format!(
                    "{} directories contain no files at all",
                    format_count(empty_dirs)
                ),
                ByteSize::ZERO,
            )
            .with_hint(
                "they hold no space; usually left behind by moved projects or uninstalled tools",
            ),
        );
    }

    // ---- scan quality ---------------------------------------------------------------
    if scan.skipped_count > 0 {
        findings.push(Finding::info(
            format!(
                "{} location{} could not be read, so the totals are a lower bound",
                format_count(scan.skipped_count as u64),
                if scan.skipped_count == 1 { "" } else { "s" }
            ),
            ByteSize::ZERO,
        ));
    }

    // Warnings first, then by the space involved.
    findings.sort_by(|a, b| {
        a.severity
            .rank()
            .cmp(&b.severity.rank())
            .then(b.bytes.cmp(&a.bytes))
    });

    DoctorReport {
        findings,
        recoverable: ByteSize(recoverable),
    }
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::Warn => 0,
            Severity::Info => 1,
        }
    }
}

/// Bytes attributable to each detected technology.
fn technology_totals(scan: &ScanResult) -> Vec<(Technology, u64)> {
    let mut totals: BTreeMap<&'static str, (Technology, u64)> = BTreeMap::new();
    for (_, node) in scan.tree.iter() {
        let Some(detection) = &node.detection else {
            continue;
        };
        let Some(technology) = detection.technology else {
            continue;
        };
        if detection.cleanup == CleanupSafety::NeverDelete {
            continue;
        }
        let entry = totals.entry(technology.label()).or_insert((technology, 0));
        entry.1 = entry.1.saturating_add(node.total.bytes);
    }

    let mut rows: Vec<(Technology, u64)> = totals.into_values().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    rows.truncate(3);
    rows
}

/// Number of empty subtree *roots*: directories holding no files whose parent
/// does hold some.
///
/// Counting roots rather than every empty node keeps `a/b/c` (all empty) from
/// being reported as three findings when it is one.
fn empty_directory_roots(scan: &ScanResult) -> u64 {
    let root = scan.tree.root();
    scan.tree
        .iter()
        .filter(|(id, node)| {
            *id != root
                && node.total.files == 0
                && !node.truncated
                && node
                    .parent
                    .is_some_and(|parent| parent == root || scan.tree.node(parent).total.files > 0)
        })
        .count() as u64
}

/// The largest version-control directory in the scan.
fn largest_repository(scan: &ScanResult) -> Option<(PathBuf, u64)> {
    scan.tree
        .iter()
        .filter(|(_, node)| {
            node.detection
                .as_ref()
                .is_some_and(|d| d.category == Category::GitData)
        })
        .max_by_key(|(_, node)| node.total.bytes)
        .map(|(id, node)| (scan.tree.path_of(id), node.total.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::{CategoryTotals, Confidence, Detection};
    use crate::scanner::tree::{DirNode, DirTree, Totals};
    use crate::scanner::ScanResult;
    use std::time::{Duration, SystemTime};

    fn scan_with(categories: CategoryTotals, nodes: Vec<DirNode>) -> ScanResult {
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
            duration: Duration::from_secs(1),
            started_at: SystemTime::UNIX_EPOCH,
            cancelled: false,
        }
    }

    fn root_node(bytes: u64, children: Vec<u32>) -> DirNode {
        DirNode {
            name: "".into(),
            parent: None,
            children,
            depth: 0,
            own: Totals::default(),
            total: Totals {
                bytes,
                files: 1,
                dirs: 1,
                stale_bytes: 0,
            },
            detection: None,
            truncated: false,
        }
    }

    #[test]
    fn large_dependency_trees_produce_a_warning() {
        const GB: u64 = 1024 * 1024 * 1024;
        let mut categories = CategoryTotals::new();
        categories.add_bulk(Category::Dependency, 31 * GB, 100);

        let scan = scan_with(categories, vec![root_node(31 * GB, vec![])]);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );

        assert!(report
            .findings
            .iter()
            .any(|f| f.severity == Severity::Warn && f.message.contains("dependencies")));
        assert!(report.recoverable.as_u64() >= 31 * GB);
    }

    #[test]
    fn a_category_dominating_a_small_scan_is_still_notable() {
        const MB: u64 = 1024 * 1024;
        let mut categories = CategoryTotals::new();
        categories.add_bulk(Category::BuildArtifact, 400 * MB, 20);
        categories.add_bulk(Category::SourceCode, 10 * MB, 200);

        let scan = scan_with(categories, vec![root_node(410 * MB, vec![])]);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.message.contains("build artifacts")),
            "a category that is most of a project must be reported"
        );
    }

    #[test]
    fn a_small_share_of_a_small_scan_stays_quiet() {
        const MB: u64 = 1024 * 1024;
        let thresholds = Thresholds::default();
        // Below the absolute floor, so the relative rule must not fire.
        assert!(!thresholds.is_notable(10 * MB, 12 * MB, u64::MAX));
        // Above the floor and a large share: notable.
        assert!(thresholds.is_notable(400 * MB, 500 * MB, u64::MAX));
        // Above the floor but a small share: not notable.
        assert!(!thresholds.is_notable(100 * MB, 100_000 * MB, u64::MAX));
    }

    #[test]
    fn a_quiet_machine_produces_no_findings() {
        let scan = scan_with(CategoryTotals::new(), vec![root_node(1024, vec![])]);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );
        assert!(report.findings.is_empty());
        assert!(report.recoverable.is_zero());
    }

    #[test]
    fn a_full_disk_is_warned_about() {
        let scan = scan_with(CategoryTotals::new(), vec![root_node(1024, vec![])]);
        let disk = DiskUsage {
            total: 1_000,
            available: 50,
        };
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            Some(disk),
            &Thresholds::default(),
        );
        assert!(report.findings.iter().any(|f| f.message.contains("% full")));
    }

    #[test]
    fn the_largest_repository_is_reported_but_never_counted_as_recoverable() {
        const GB: u64 = 1024 * 1024 * 1024;
        let git = DirNode {
            name: ".git".into(),
            parent: Some(0),
            children: vec![],
            depth: 1,
            own: Totals::default(),
            total: Totals {
                bytes: 4 * GB,
                files: 10,
                dirs: 2,
                stale_bytes: 0,
            },
            detection: Some(Detection::new(
                Category::GitData,
                Confidence::Certain,
                CleanupSafety::NeverDelete,
                "Git repository data",
            )),
            truncated: false,
        };
        let scan = scan_with(CategoryTotals::new(), vec![root_node(4 * GB, vec![1]), git]);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );

        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("Largest repository")));
        assert!(
            report.recoverable.is_zero(),
            "git data must never be counted as recoverable"
        );
    }

    #[test]
    fn empty_directory_chains_count_once() {
        // root(has files) -> a(empty) -> b(empty) -> c(empty): one finding-unit.
        let nodes = vec![
            DirNode {
                name: "".into(),
                parent: None,
                children: vec![1],
                depth: 0,
                own: Totals::default(),
                total: Totals {
                    bytes: 100,
                    files: 3,
                    dirs: 4,
                    stale_bytes: 0,
                },
                detection: None,
                truncated: false,
            },
            DirNode {
                name: "a".into(),
                parent: Some(0),
                children: vec![2],
                depth: 1,
                own: Totals::default(),
                total: Totals {
                    bytes: 0,
                    files: 0,
                    dirs: 3,
                    stale_bytes: 0,
                },
                detection: None,
                truncated: false,
            },
            DirNode {
                name: "b".into(),
                parent: Some(1),
                children: vec![],
                depth: 2,
                own: Totals::default(),
                total: Totals {
                    bytes: 0,
                    files: 0,
                    dirs: 2,
                    stale_bytes: 0,
                },
                detection: None,
                truncated: false,
            },
        ];
        let scan = scan_with(CategoryTotals::new(), nodes);
        assert_eq!(empty_directory_roots(&scan), 1, "a chain counts once");
    }

    #[test]
    fn many_empty_directories_produce_an_info_finding() {
        let mut nodes = vec![root_node(1_000, (1..=12).collect())];
        for index in 1..=12u32 {
            nodes.push(DirNode {
                name: format!("empty-{index}").into(),
                parent: Some(0),
                children: vec![],
                depth: 1,
                own: Totals::default(),
                total: Totals {
                    bytes: 0,
                    files: 0,
                    dirs: 1,
                    stale_bytes: 0,
                },
                detection: None,
                truncated: false,
            });
        }
        let scan = scan_with(CategoryTotals::new(), nodes);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );
        assert!(report
            .findings
            .iter()
            .any(|f| f.message.contains("contain no files")));
    }

    #[test]
    fn warnings_sort_before_information() {
        const GB: u64 = 1024 * 1024 * 1024;
        let mut categories = CategoryTotals::new();
        categories.add_bulk(Category::Dependency, 10 * GB, 1);
        categories.add_bulk(Category::Cache, 3 * GB, 1);

        let scan = scan_with(categories, vec![root_node(13 * GB, vec![])]);
        let report = diagnose(
            &scan,
            &KnownPaths::empty(),
            &DockerStatus::NotInstalled,
            None,
            &Thresholds::default(),
        );
        assert_eq!(report.findings[0].severity, Severity::Warn);
    }
}

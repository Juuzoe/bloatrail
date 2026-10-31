//! The filesystem scanning engine.
//!
//! [`scan`] is the single entry point. It owns the Rayon thread pool, the
//! progress reporter and the classifier, and returns a [`ScanResult`] that every
//! command in the CLI is built on.

pub mod progress;
pub mod tree;
mod walker;

pub use walker::ALWAYS_TRAVERSED;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::analysis::domain::CategoryTotals;
use crate::analysis::Classifier;
use crate::error::{Error, Result};
use crate::pattern::ExcludeSet;
use crate::platform::KnownPaths;
use crate::scanner::progress::ProgressReporter;
use crate::scanner::tree::{DirTree, FileEntry, Totals};

/// Default number of large files retained during a scan.
pub const DEFAULT_TOP_FILES: usize = 200;

/// Default age threshold, in days, above which a file counts as stale.
pub const DEFAULT_STALE_DAYS: u32 = 90;

/// Hard limit on directory nesting.
///
/// The walk is recursive, so unbounded depth means an unbounded stack. Real
/// filesystems do not come close to this — the deepest thing most machines
/// contain is a legacy nested `node_modules` tree at a few dozen levels — but a
/// symlink cycle, a fuzzer or a deliberately hostile archive can, and a stack
/// overflow aborts the process rather than raising an error. Anything deeper is
/// reported as skipped.
pub const MAX_TRAVERSAL_DEPTH: u16 = 400;

/// Stack size for scanner worker threads.
///
/// Comfortably more than [`MAX_TRAVERSAL_DEPTH`] frames of the walker plus
/// Rayon's own join frames, which is what makes the depth limit the binding
/// constraint rather than the stack.
const WORKER_STACK_SIZE: usize = 16 * 1024 * 1024;

/// A shared flag that stops a scan early.
///
/// Cloning the token clones the handle, not the flag: every clone observes the
/// same cancellation. The walker checks it once per directory, so a cancelled
/// scan stops within milliseconds and still returns everything measured so
/// far, with [`ScanResult::cancelled`] set.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the scan to stop. Idempotent.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Everything a scan needs to know.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Directory to scan. Must be absolute by the time the scan starts.
    pub root: PathBuf,
    /// Maximum depth of *retained* tree nodes. Traversal always goes to the
    /// bottom, because a directory's size depends on everything beneath it.
    pub max_depth: Option<usize>,
    /// Exclusion patterns.
    pub excludes: ExcludeSet,
    /// Whether to traverse dot-directories that are not on the always-traverse
    /// list.
    pub include_hidden: bool,
    /// Whether to descend into symbolic links and reparse points.
    pub follow_symlinks: bool,
    /// Whether to stay on the filesystem the scan root lives on.
    pub same_filesystem: bool,
    /// Worker threads. `None` lets Rayon choose based on available parallelism.
    pub threads: Option<usize>,
    /// How many large files to remember.
    pub top_files: usize,
    /// Age in days above which a file counts towards `stale_bytes`.
    pub stale_days: u32,
    /// Whether to draw live progress on stderr.
    pub show_progress: bool,
    /// Cooperative cancellation. Cancel it from another thread (a Ctrl+C
    /// handler, a GUI button) and the scan returns partial results.
    pub cancel: CancelToken,
}

impl ScanOptions {
    /// Options for scanning `root` with sensible defaults.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ScanOptions {
            root: root.into(),
            max_depth: None,
            excludes: ExcludeSet::default(),
            include_hidden: false,
            follow_symlinks: false,
            same_filesystem: false,
            threads: None,
            top_files: DEFAULT_TOP_FILES,
            stale_days: DEFAULT_STALE_DAYS,
            show_progress: false,
            cancel: CancelToken::new(),
        }
    }
}

/// Why a location could not be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The process lacks permission to read it.
    PermissionDenied,
    /// It disappeared between being listed and being read.
    NotFound,
    /// It lives on another filesystem and `--same-filesystem` was set.
    OtherFilesystem,
    /// Following it would revisit a directory already seen.
    SymlinkLoop,
    /// Already counted through another path (only possible when following
    /// symlinks).
    AlreadyVisited,
    /// The directory nesting exceeded [`MAX_TRAVERSAL_DEPTH`].
    TooDeep,
    /// Any other I/O failure.
    IoError,
}

impl SkipReason {
    fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => SkipReason::PermissionDenied,
            std::io::ErrorKind::NotFound => SkipReason::NotFound,
            _ => SkipReason::IoError,
        }
    }

    /// Human-readable description.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            SkipReason::PermissionDenied => "permission denied",
            SkipReason::NotFound => "no longer exists",
            SkipReason::OtherFilesystem => "on another filesystem",
            SkipReason::SymlinkLoop => "symlink loop",
            SkipReason::AlreadyVisited => "already counted via another path",
            SkipReason::TooDeep => "nested too deeply",
            SkipReason::IoError => "could not be read",
        }
    }
}

/// A location the scan could not read.
#[derive(Debug, Clone)]
pub struct SkippedPath {
    /// The location.
    pub path: PathBuf,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// The result of a completed scan.
#[derive(Debug)]
pub struct ScanResult {
    /// The directory the scan started from.
    pub root: PathBuf,
    /// The retained directory tree.
    pub tree: DirTree,
    /// Totals for the whole scan.
    pub totals: Totals,
    /// Bytes and file counts per category.
    pub categories: CategoryTotals,
    /// Largest files seen, largest first.
    pub largest_files: Vec<FileEntry>,
    /// A sample of skipped locations (capped for reporting).
    pub skipped: Vec<SkippedPath>,
    /// Total number of skipped locations, including those not retained.
    pub skipped_count: usize,
    /// Wall-clock duration of the scan.
    pub duration: Duration,
    /// When the scan started.
    pub started_at: SystemTime,
    /// `true` when the scan was stopped early. Totals are a lower bound.
    pub cancelled: bool,
    /// Fingerprint of what this scan counted; see [`coverage_stamp`].
    pub coverage: String,
}

impl ScanResult {
    /// Throughput in bytes per second.
    #[must_use]
    pub fn throughput(&self) -> f64 {
        let seconds = self.duration.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.totals.bytes as f64 / seconds
    }

    /// Directories ranked by subtree size, largest first, excluding the root.
    #[must_use]
    pub fn largest_directories(&self, limit: usize) -> Vec<(tree::NodeId, u64)> {
        let mut rows: Vec<(tree::NodeId, u64)> = self
            .tree
            .iter()
            .filter(|(id, _)| *id != self.tree.root())
            .map(|(id, node)| (id, node.total.bytes))
            .collect();
        rows.sort_unstable_by_key(|row| std::cmp::Reverse(row.1));
        rows.truncate(limit);
        rows
    }
}

/// Scan a directory tree.
///
/// # Errors
///
/// Fails only when the root itself is unusable — missing, not a directory, or
/// unreadable. Everything encountered *during* the walk is recorded in
/// [`ScanResult::skipped`] instead of aborting the scan.
pub fn scan(
    options: &ScanOptions,
    classifier: &Classifier,
    known: &KnownPaths,
) -> Result<ScanResult> {
    let mut reporter = ProgressReporter::start(options.show_progress);
    let result = scan_with_progress(options, classifier, known, reporter.counters());
    reporter.finish();
    result
}

/// Scan a directory tree, reporting progress into caller-owned counters.
///
/// This is the entry point for embedders that render progress themselves — the
/// GUI polls the counters from its own frame loop. [`scan`] wraps it with the
/// terminal progress reporter.
///
/// # Errors
///
/// Same contract as [`scan`].
pub fn scan_with_progress(
    options: &ScanOptions,
    classifier: &Classifier,
    known: &KnownPaths,
    counters: Arc<progress::Counters>,
) -> Result<ScanResult> {
    let root = canonical_root(&options.root)?;
    let options = ScanOptions {
        root,
        ..options.clone()
    };

    let started_at = SystemTime::now();
    let clock = Instant::now();

    // Always build a dedicated pool rather than borrowing Rayon's global one:
    // the walk is recursive, so it needs a stack size chosen for it.
    let mut builder = rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("bloatrail-{index}"))
        .stack_size(WORKER_STACK_SIZE);
    if let Some(threads) = options.threads.filter(|threads| *threads > 0) {
        builder = builder.num_threads(threads);
    }
    let pool = builder
        .build()
        .map_err(|error| Error::ThreadPool(error.to_string()))?;

    let walk = walker::Walk::new(&options, classifier, known, counters);
    let result = pool.install(|| walk.run());

    Ok(ScanResult {
        cancelled: options.cancel.is_cancelled(),
        coverage: coverage_stamp(&options, known),
        root: options.root,
        tree: result.tree,
        totals: result.totals,
        categories: result.categories,
        largest_files: result.largest_files,
        skipped: result.skipped,
        skipped_count: result.skipped_count,
        duration: clock.elapsed(),
        started_at,
    })
}

/// A short, stable fingerprint of what a scan with these options counts.
///
/// History compares scans recorded weeks apart, by whatever version of
/// Bloatrail was installed at the time and under whatever settings were in
/// force. When those differ, so do the bytes a scan sees: a dot-directory
/// added to [`ALWAYS_TRAVERSED`] is suddenly counted, a new well-known
/// location moves gigabytes from one category to another, `--include-hidden`
/// adds every hidden tree. Compared naively, each of those reads as growth.
/// Every snapshot records this stamp so that `growth` and `diff` can tell a
/// change in coverage from a change on disk.
///
/// The stamp hashes the inputs that decide which bytes are counted and where
/// they are attributed: the hidden-directory policy (the always-traversed
/// list, or the fact that every hidden directory is traversed), symlink and
/// filesystem-boundary handling, the exclusion patterns as written, and the
/// well-known location rules ([`KnownPaths::rules`]). It hashes no resolved
/// path, so it is the same on every run and on every machine of one platform
/// with the same settings. Scan root, thread count, progress and the
/// staleness threshold are left out: none changes what is counted.
#[must_use]
pub fn coverage_stamp(options: &ScanOptions, known: &KnownPaths) -> String {
    coverage_digest(ALWAYS_TRAVERSED, options, known)
}

/// [`coverage_stamp`] over an explicit always-traversed list, so tests can
/// show that changing the list changes the stamp.
fn coverage_digest(traversed: &[&str], options: &ScanOptions, known: &KnownPaths) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut line = |text: &str| {
        hasher.update(text.as_bytes());
        hasher.update(b"\n");
    };

    // Versions the scheme itself: hashing differently must not collide with
    // stamps written the old way.
    line("bloatrail coverage 1");

    if options.include_hidden {
        // The list stops mattering when every hidden directory is walked.
        line("hidden all");
    } else {
        let mut names = traversed.to_vec();
        names.sort_unstable();
        for name in names {
            line(&format!("hidden traverse {name}"));
        }
    }
    line(&format!("follow-symlinks {}", options.follow_symlinks));
    line(&format!("same-filesystem {}", options.same_filesystem));

    let mut excludes: Vec<&str> = options.excludes.iter().collect();
    excludes.sort_unstable();
    excludes.dedup();
    for pattern in excludes {
        line(&format!("exclude {pattern}"));
    }

    for rule in known.rules() {
        line(&format!("known {rule}"));
    }

    hasher.finalize().to_hex()[..16].to_string()
}

/// Resolve and validate a scan root.
///
/// # Errors
///
/// Returns [`Error::NotFound`] or [`Error::NotADirectory`] when the path cannot
/// serve as a scan root.
pub fn canonical_root(path: &Path) -> Result<PathBuf> {
    let metadata = std::fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => Error::NotFound(path.to_path_buf()),
        std::io::ErrorKind::PermissionDenied => Error::PermissionDenied(path.to_path_buf()),
        _ => Error::Io {
            path: path.to_path_buf(),
            source: error,
        },
    })?;

    if !metadata.is_dir() {
        return Err(Error::NotADirectory(path.to_path_buf()));
    }

    // Canonicalisation gives every later stage an absolute, symlink-free path to
    // reason about, which the cleanup safety checks depend on.
    match std::fs::canonicalize(path) {
        Ok(canonical) => Ok(strip_verbatim(canonical)),
        Err(_) => std::path::absolute(path).map_err(|error| Error::Io {
            path: path.to_path_buf(),
            source: error,
        }),
    }
}

/// Remove Windows' `\\?\` verbatim prefix.
///
/// `canonicalize` always produces one, and it leaks into every path Bloatrail
/// prints. Stripping it keeps output readable; the paths remain valid because
/// they are still absolute.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    if !cfg!(windows) {
        return path;
    }
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest.to_string()),
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_options_have_usable_defaults() {
        let options = ScanOptions::new("/tmp");
        assert!(options.max_depth.is_none());
        assert!(!options.follow_symlinks);
        assert!(!options.same_filesystem);
        assert_eq!(options.top_files, DEFAULT_TOP_FILES);
        assert_eq!(options.stale_days, DEFAULT_STALE_DAYS);
    }

    #[test]
    fn missing_roots_are_reported_clearly() {
        let error = canonical_root(Path::new("/definitely/not/here/bloatrail")).unwrap_err();
        assert!(matches!(error, Error::NotFound(_)));
    }

    #[test]
    fn files_are_rejected_as_scan_roots() {
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"hello").expect("write");
        let error = canonical_root(&file).unwrap_err();
        assert!(matches!(error, Error::NotADirectory(_)));
    }

    #[cfg(windows)]
    #[test]
    fn verbatim_prefixes_are_stripped() {
        assert_eq!(
            strip_verbatim(PathBuf::from(r"\\?\C:\Users\dev")),
            PathBuf::from(r"C:\Users\dev")
        );
        assert_eq!(
            strip_verbatim(PathBuf::from(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\server\share")
        );
    }

    #[test]
    fn a_pre_cancelled_scan_returns_immediately_and_says_so() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::create_dir_all(dir.path().join("a/b")).expect("dirs");
        std::fs::write(dir.path().join("a/b/file.bin"), vec![0u8; 512]).expect("file");

        let options = ScanOptions::new(dir.path());
        options.cancel.cancel();

        let classifier = crate::analysis::Classifier::with_default_detectors();
        let known = crate::platform::KnownPaths::empty();
        let result = scan(&options, &classifier, &known).expect("scan");

        assert!(result.cancelled, "the flag must be reported");
        assert_eq!(result.totals.files, 0, "nothing below the root was read");
        assert!(result.tree.node(result.tree.root()).truncated);
    }

    #[test]
    fn cancel_tokens_share_state_across_clones() {
        let token = CancelToken::new();
        let clone = token.clone();
        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn the_coverage_stamp_ignores_what_does_not_change_the_count() {
        let known = KnownPaths::empty();
        let base = ScanOptions::new("/a");
        let stamp = coverage_stamp(&base, &known);
        assert_eq!(stamp.len(), 16);
        assert!(stamp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(coverage_stamp(&base, &known), stamp, "deterministic");

        let mut elsewhere = ScanOptions::new("/somewhere/else");
        elsewhere.threads = Some(3);
        elsewhere.stale_days = 7;
        elsewhere.top_files = 5;
        elsewhere.max_depth = Some(2);
        elsewhere.show_progress = true;
        assert_eq!(coverage_stamp(&elsewhere, &known), stamp);

        let mut one_way = base.clone();
        one_way.excludes = ExcludeSet::new(["*.iso", "~/VMs"]);
        let mut other_way = base.clone();
        other_way.excludes = ExcludeSet::new(["~/VMs", "*.iso", "*.iso"]);
        assert_eq!(
            coverage_stamp(&one_way, &known),
            coverage_stamp(&other_way, &known),
            "the order patterns were given in does not change what they exclude"
        );
    }

    #[test]
    fn the_coverage_stamp_changes_with_everything_that_changes_the_count() {
        let known = KnownPaths::empty();
        let base = ScanOptions::new("/a");
        let stamp = coverage_stamp(&base, &known);

        let mut hidden = base.clone();
        hidden.include_hidden = true;
        let mut follow = base.clone();
        follow.follow_symlinks = true;
        let mut one_volume = base.clone();
        one_volume.same_filesystem = true;
        let mut excluded = base.clone();
        excluded.excludes = ExcludeSet::new(["*.iso"]);

        let mut stamps = vec![stamp.clone()];
        for options in [&hidden, &follow, &one_volume, &excluded] {
            stamps.push(coverage_stamp(options, &known));
        }
        // The registry of well-known locations decides categories and which
        // subtrees collapse, so a different one is different coverage.
        stamps.push(coverage_stamp(&base, &KnownPaths::discover()));

        let mut distinct = stamps.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), stamps.len(), "{stamps:?}");
    }

    #[test]
    fn the_coverage_stamp_follows_the_always_traversed_list() {
        let known = KnownPaths::empty();
        let options = ScanOptions::new("/a");
        let current = coverage_digest(ALWAYS_TRAVERSED, &options, &known);
        assert_eq!(current, coverage_stamp(&options, &known));

        // One name more or one name fewer is a different set of bytes.
        let shorter = &ALWAYS_TRAVERSED[1..];
        assert_ne!(coverage_digest(shorter, &options, &known), current);
        let mut longer = ALWAYS_TRAVERSED.to_vec();
        longer.push(".example-store");
        assert_ne!(coverage_digest(&longer, &options, &known), current);

        // The list's source order is presentation; reordering it is not a
        // change in coverage.
        let mut reversed = ALWAYS_TRAVERSED.to_vec();
        reversed.reverse();
        assert_eq!(coverage_digest(&reversed, &options, &known), current);

        // With every hidden directory walked, the list no longer decides
        // anything, and changing it must not restart anyone's history.
        let mut hidden = options.clone();
        hidden.include_hidden = true;
        assert_eq!(
            coverage_digest(shorter, &hidden, &known),
            coverage_digest(ALWAYS_TRAVERSED, &hidden, &known)
        );
    }

    #[test]
    fn the_default_coverage_stamp_is_pinned() {
        // The same value on every platform, which is the point: no machine
        // detail goes in. When the always-traversed list changes, this value
        // changes too, and every user's next `growth` starts a new window at
        // the first scan recorded under it. Update it deliberately.
        let stamp = coverage_stamp(&ScanOptions::new("/a"), &KnownPaths::empty());
        assert_eq!(stamp, "fdac67f6d581f571");
    }

    #[test]
    fn skip_reasons_describe_themselves() {
        assert_eq!(SkipReason::PermissionDenied.describe(), "permission denied");
        assert_eq!(SkipReason::SymlinkLoop.describe(), "symlink loop");
    }
}

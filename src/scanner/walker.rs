//! The parallel filesystem walker.
//!
//! # Design
//!
//! The walk is a parallel depth-first traversal: each directory reads its own
//! entries, then hands its subdirectories to Rayon. Rayon's work-stealing
//! scheduler turns that into balanced parallelism without any explicit queue,
//! and because the recursion *returns* aggregated values, directory totals are
//! computed on the way back up with no second pass and no shared mutable tree.
//!
//! Three decisions keep memory bounded on very large scans:
//!
//! * Subtree category totals are **returned and merged**, never stored per node.
//! * "Largest files" is a single shared bounded heap guarded by an atomic
//!   threshold, so the common case — a file that will not make the list — costs
//!   one relaxed load and no allocation.
//! * Directories classified as opaque (`node_modules`, `target`, `.git`) are
//!   **collapsed**: their sizes are counted exactly, but their children are not
//!   retained and not classified. On a developer machine that is the difference
//!   between a hundred thousand retained nodes and a million.

use std::fs::{self, Metadata};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rayon::prelude::*;

use crate::analysis::categorize::categorize_file;
use crate::analysis::context::{DirContext, Markers};
use crate::analysis::domain::{Category, CategoryTotals, Detection};
use crate::analysis::Classifier;
use crate::platform::{self, KnownPaths};
use crate::scanner::progress::Counters;
use crate::scanner::tree::{DirNode, DirTree, FileEntry, NodeId, TopFiles, Totals};
use crate::scanner::{ScanOptions, SkipReason, SkippedPath};

/// Maximum number of skipped locations retained for reporting.
const MAX_REPORTED_SKIPS: usize = 64;

/// How an enclosing detection constrains a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inherited {
    /// Nothing above claims this subtree.
    None,
    /// Bytes belong to `Category`, but directories here are still classified.
    ///
    /// Used by locations like `~/Downloads`, which own their contents for
    /// reporting purposes while remaining worth exploring.
    Claimed(Category),
    /// Inside a collapsed subtree: no classification, no node retention.
    Collapsed(Category),
}

impl Inherited {
    fn category(self) -> Option<Category> {
        match self {
            Inherited::None => None,
            Inherited::Claimed(category) | Inherited::Collapsed(category) => Some(category),
        }
    }

    fn is_collapsed(self) -> bool {
        matches!(self, Inherited::Collapsed(_))
    }
}

/// Shared, read-mostly state for one walk.
pub(crate) struct Walk<'a> {
    options: &'a ScanOptions,
    classifier: &'a Classifier,
    known: &'a KnownPaths,
    counters: Arc<Counters>,
    skipped: Mutex<Vec<SkippedPath>>,
    skipped_count: AtomicUsize,
    top: TopShared,
    root_volume: Option<u64>,
    stale_before: Option<u64>,
    /// Hard-linked files already counted, keyed by `(device, inode)`.
    ///
    /// Only consulted for files whose link count exceeds one, so this stays
    /// empty on the overwhelming majority of machines.
    #[cfg(unix)]
    hardlinks: Mutex<std::collections::HashSet<(u64, u64)>>,
    /// Canonical paths already visited; only used when following symlinks.
    visited: Mutex<std::collections::HashSet<std::path::PathBuf>>,
}

/// A bounded top-N collection shared by every worker.
struct TopShared {
    threshold: AtomicU64,
    inner: Mutex<TopFiles>,
}

impl TopShared {
    fn new(capacity: usize) -> Self {
        TopShared {
            threshold: AtomicU64::new(0),
            inner: Mutex::new(TopFiles::new(capacity)),
        }
    }

    /// Offer a file. `build` runs only when the entry will be kept, so the
    /// `PathBuf` allocation never happens for the files that are rejected.
    #[inline]
    fn offer(&self, size: u64, build: impl FnOnce() -> FileEntry) {
        if size <= self.threshold.load(Ordering::Relaxed) {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard.push(build());
        self.threshold.store(guard.threshold(), Ordering::Relaxed);
    }
}

/// Aggregated result of walking one directory.
struct WalkOutput {
    dir: RawDir,
    categories: CategoryTotals,
}

/// A directory before it is flattened into the arena.
struct RawDir {
    name: Box<str>,
    own: Totals,
    total: Totals,
    detection: Option<Detection>,
    children: Vec<RawDir>,
    truncated: bool,
}

/// What one `read_dir` pass learned about a directory.
struct Listing {
    markers: Markers,
    subdirs: Vec<Box<str>>,
    files: Vec<FileRecord>,
}

struct FileRecord {
    name: Box<str>,
    size: u64,
    modified: Option<u64>,
    #[cfg(unix)]
    identity: Option<(u64, u64)>,
}

impl<'a> Walk<'a> {
    /// Prepare a walk.
    pub(crate) fn new(
        options: &'a ScanOptions,
        classifier: &'a Classifier,
        known: &'a KnownPaths,
        counters: Arc<Counters>,
    ) -> Self {
        let root_volume = fs::symlink_metadata(&options.root)
            .ok()
            .and_then(|meta| platform::volume_id(&options.root, &meta));

        let stale_before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|now| now.as_secs())
            .and_then(|now| now.checked_sub(u64::from(options.stale_days) * 86_400));

        Walk {
            options,
            classifier,
            known,
            counters,
            skipped: Mutex::new(Vec::new()),
            skipped_count: AtomicUsize::new(0),
            top: TopShared::new(options.top_files.max(1)),
            root_volume,
            stale_before,
            #[cfg(unix)]
            hardlinks: Mutex::new(std::collections::HashSet::new()),
            visited: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Run the walk and flatten the result into a tree.
    pub(crate) fn run(self) -> WalkResult {
        // Seed the root so a link pointing back at it is recognised as a cycle
        // on the first hop rather than the second.
        if self.options.follow_symlinks {
            self.mark_visited(&self.options.root);
        }

        // The root's own classification depends on what its *parent* contains,
        // so read the parent directory once. This is what lets
        // `bloatrail explain ./target` see the `Cargo.toml` next to it.
        let parent_markers = self
            .options
            .root
            .parent()
            .map(read_markers)
            .unwrap_or_default();

        let name: Box<str> = self
            .options
            .root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .into();

        let output = self.walk_dir(
            &self.options.root,
            name,
            0,
            parent_markers,
            Markers::empty(),
            Inherited::None,
        );

        let mut nodes = Vec::with_capacity(count_nodes(&output.dir));
        flatten(output.dir, None, 0, &mut nodes);
        sort_children(&mut nodes);

        let tree = DirTree::new(self.options.root.clone(), nodes);
        let totals = tree.node(tree.root()).total;
        let skipped_count = self.skipped_count.load(Ordering::Relaxed);

        WalkResult {
            tree,
            totals,
            categories: output.categories,
            largest_files: unwrap_lock(self.top.inner).into_sorted(),
            skipped: unwrap_lock(self.skipped),
            skipped_count,
        }
    }

    fn record_skip(&self, path: &Path, reason: SkipReason) {
        self.counters.skipped();
        let index = self.skipped_count.fetch_add(1, Ordering::Relaxed);
        if index < MAX_REPORTED_SKIPS {
            if let Ok(mut guard) = self.skipped.lock() {
                guard.push(SkippedPath {
                    path: path.to_path_buf(),
                    reason,
                });
            }
        }
    }

    /// Read a directory, gathering markers, subdirectories and file records in a
    /// single pass over the entries.
    fn list(&self, path: &Path) -> Option<Listing> {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                self.record_skip(path, SkipReason::from_io(&error));
                return None;
            }
        };

        let mut listing = Listing {
            markers: Markers::empty(),
            subdirs: Vec::new(),
            files: Vec::new(),
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.record_skip(path, SkipReason::from_io(&error));
                    continue;
                }
            };

            let raw_name = entry.file_name();
            match raw_name.to_str() {
                Some(name) => self.consume_entry(path, &entry, name, &mut listing),
                None => {
                    // Non-UTF-8 names are rare; a lossy copy keeps their bytes
                    // counted rather than silently under-reporting the total.
                    let lossy = raw_name.to_string_lossy().into_owned();
                    self.consume_entry(path, &entry, &lossy, &mut listing);
                }
            }
        }

        Some(listing)
    }

    fn consume_entry(
        &self,
        parent: &Path,
        entry: &fs::DirEntry,
        name: &str,
        listing: &mut Listing,
    ) {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                self.record_skip(&entry.path(), SkipReason::from_io(&error));
                return;
            }
        };
        let is_dir_entry = file_type.is_dir();

        // Markers are evidence, not content: record them even for entries the
        // hidden-directory filter is about to drop.
        listing.markers.observe(name, is_dir_entry);

        // `--include-hidden` governs *directories*. Hidden files are always
        // counted: dropping them would silently under-report the disk usage
        // this tool exists to measure, and a dot-file can be arbitrarily large.
        if is_dir_entry
            && !self.options.include_hidden
            && is_hidden(name)
            && !is_always_traversed(name)
        {
            return;
        }

        // `DirEntry::metadata` does not traverse symlinks, so a broken link is
        // an ordinary small entry rather than an error.
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                self.record_skip(&entry.path(), SkipReason::from_io(&error));
                return;
            }
        };

        let is_link = file_type.is_symlink() || platform::is_reparse_point(&meta);

        if is_link && !self.options.follow_symlinks {
            // Count the link itself, never its target. That is what stops a
            // symlink farm from inflating the totals.
            if !is_dir_entry && !self.excluded_file(parent, name) {
                listing.files.push(FileRecord {
                    name: name.into(),
                    size: meta.len(),
                    modified: modified_secs(&meta),
                    #[cfg(unix)]
                    identity: None,
                });
            }
            return;
        }

        if is_dir_entry || is_link {
            self.consider_subdir(parent, name, is_link, &meta, listing);
            return;
        }

        if !file_type.is_file() {
            // FIFOs, sockets and device nodes occupy no meaningful space.
            return;
        }

        if self.excluded_file(parent, name) {
            return;
        }

        listing.files.push(FileRecord {
            name: name.into(),
            size: meta.len(),
            modified: modified_secs(&meta),
            #[cfg(unix)]
            identity: hardlink_identity(&meta),
        });
    }

    fn consider_subdir(
        &self,
        parent: &Path,
        name: &str,
        is_link: bool,
        meta: &Metadata,
        listing: &mut Listing,
    ) {
        let path = parent.join(name);

        // Exclusions are checked before the link is resolved, so an excluded
        // name is skipped whether it is a real directory or a link to one.
        if self.options.excludes.excludes(&path, name) {
            return;
        }

        if is_link {
            // Only reached with --follow-symlinks. Resolve what it points at.
            match fs::metadata(&path) {
                Ok(target) if target.is_dir() => {}
                Ok(target) => {
                    listing.files.push(FileRecord {
                        name: name.into(),
                        size: target.len(),
                        modified: modified_secs(&target),
                        #[cfg(unix)]
                        identity: None,
                    });
                    return;
                }
                Err(error) => {
                    self.record_skip(&path, SkipReason::from_io(&error));
                    return;
                }
            }
        }

        if self.options.same_filesystem {
            if is_link {
                // A followed link can land on a different filesystem entirely.
                self.record_skip(&path, SkipReason::OtherFilesystem);
                return;
            }
            if let (Some(root), Some(current)) =
                (self.root_volume, platform::volume_id(&path, meta))
            {
                if root != current {
                    self.record_skip(&path, SkipReason::OtherFilesystem);
                    return;
                }
            }
        }

        // When following links, *every* directory is registered, not just the
        // linked ones. Recording only link targets would let a subtree that is
        // reachable both directly and through a link be counted twice.
        if self.options.follow_symlinks && !self.mark_visited(&path) {
            self.record_skip(
                &path,
                if is_link {
                    SkipReason::SymlinkLoop
                } else {
                    SkipReason::AlreadyVisited
                },
            );
            return;
        }

        listing.subdirs.push(name.into());
    }

    /// Exclusion test for a file, avoiding the path join when no anchored
    /// pattern is configured.
    #[inline]
    fn excluded_file(&self, parent: &Path, name: &str) -> bool {
        let excludes = &self.options.excludes;
        if excludes.is_empty() {
            return false;
        }
        excludes.excludes_name(name)
            || (excludes.has_path_patterns() && { excludes.excludes(&parent.join(name), name) })
    }

    /// Register a canonical path as visited. `false` means it was already seen,
    /// which is how symlink loops are broken.
    fn mark_visited(&self, path: &Path) -> bool {
        let Ok(canonical) = fs::canonicalize(path) else {
            return false;
        };
        match self.visited.lock() {
            Ok(mut guard) => guard.insert(canonical),
            Err(_) => false,
        }
    }

    /// Whether this file was already counted through another hard link.
    #[cfg(unix)]
    fn already_counted(&self, identity: Option<(u64, u64)>) -> bool {
        let Some(identity) = identity else {
            return false;
        };
        match self.hardlinks.lock() {
            Ok(mut guard) => !guard.insert(identity),
            Err(_) => false,
        }
    }

    /// Windows exposes a file's link count only through an open handle, so
    /// detecting hard links would cost one `CreateFile` per file. Hard links are
    /// rare enough there that the trade is not worth making; this limitation is
    /// documented rather than silently approximated.
    #[cfg(not(unix))]
    #[inline]
    fn already_counted(&self, _identity: Option<(u64, u64)>) -> bool {
        false
    }

    fn walk_dir(
        &self,
        path: &Path,
        name: Box<str>,
        depth: u16,
        parent_markers: Markers,
        grandparent_markers: Markers,
        inherited: Inherited,
    ) -> WalkOutput {
        self.counters.dir();
        if depth <= 3 {
            self.counters.set_current(&self.known.display(path));
        }

        // A cancelled scan stops descending but keeps everything already
        // measured; the caller learns about it through `ScanResult::cancelled`.
        if self.options.cancel.is_cancelled() {
            return WalkOutput {
                dir: RawDir {
                    name,
                    own: Totals::default(),
                    total: Totals {
                        dirs: 1,
                        ..Totals::default()
                    },
                    detection: None,
                    children: Vec::new(),
                    truncated: true,
                },
                categories: CategoryTotals::new(),
            };
        }

        // The walk is recursive, so depth has to be bounded or a pathological
        // tree takes the whole process down with a stack overflow.
        if depth >= crate::scanner::MAX_TRAVERSAL_DEPTH {
            self.record_skip(path, SkipReason::TooDeep);
            return WalkOutput {
                dir: RawDir {
                    name,
                    own: Totals::default(),
                    total: Totals {
                        dirs: 1,
                        ..Totals::default()
                    },
                    detection: None,
                    children: Vec::new(),
                    truncated: true,
                },
                categories: CategoryTotals::new(),
            };
        }

        let Some(listing) = self.list(path) else {
            return WalkOutput {
                dir: RawDir {
                    name,
                    own: Totals::default(),
                    total: Totals {
                        dirs: 1,
                        ..Totals::default()
                    },
                    detection: None,
                    children: Vec::new(),
                    // Unreadable, like TooDeep and cancelled: the zero counts
                    // mean "unknown", and downstream consumers (doctor's
                    // empty-directory finding included) must not read them as
                    // "verified empty".
                    truncated: true,
                },
                categories: CategoryTotals::new(),
            };
        };
        let Listing {
            markers,
            subdirs,
            files,
        } = listing;

        // ---- classification -------------------------------------------------
        let detection = if inherited.is_collapsed() {
            None
        } else {
            self.classify(
                path,
                &name,
                depth,
                markers,
                parent_markers,
                grandparent_markers,
                subdirs.len(),
                files.len(),
            )
        };

        // The scan root is never collapsed: `bloatrail tree ./node_modules`
        // should still show what is inside it.
        let collapse_here = depth > 0 && detection.as_ref().is_some_and(|d| d.collapse);
        let child_inherited = match (&inherited, &detection) {
            (Inherited::Collapsed(category), _) => Inherited::Collapsed(*category),
            (_, Some(detection)) if collapse_here => Inherited::Collapsed(detection.category),
            (_, Some(detection)) if detection.claims_contents => {
                Inherited::Claimed(detection.category)
            }
            (Inherited::Claimed(category), _) => Inherited::Claimed(*category),
            _ => Inherited::None,
        };
        let file_category = child_inherited.category();

        // ---- files ------------------------------------------------------------
        let mut own = Totals::default();
        let mut categories = CategoryTotals::new();

        for file in &files {
            if self.already_counted(file_identity(file)) {
                continue;
            }
            let stale = self.is_stale(file.modified);
            own.add_file(file.size, stale);
            self.counters.file(file.size);

            let category = file_category.unwrap_or_else(|| categorize_file(&file.name));
            categories.add_file(category, file.size);

            self.top.offer(file.size, || FileEntry {
                path: path.join(&*file.name),
                size: file.size,
                category,
                modified: file.modified,
            });
        }

        // ---- subdirectories ----------------------------------------------------
        let retain_children = !collapse_here
            && self
                .options
                .max_depth
                .is_none_or(|max| usize::from(depth) < max);

        let outputs: Vec<WalkOutput> = if subdirs.is_empty() {
            Vec::new()
        } else {
            subdirs
                .into_par_iter()
                .map(|child_name| {
                    let child_path = path.join(&*child_name);
                    self.walk_dir(
                        &child_path,
                        child_name,
                        depth.saturating_add(1),
                        markers,
                        parent_markers,
                        child_inherited,
                    )
                })
                .collect()
        };

        let mut total = own;
        total.dirs = total.dirs.saturating_add(1);
        let mut children = Vec::with_capacity(if retain_children { outputs.len() } else { 0 });
        let mut truncated = collapse_here;

        for output in outputs {
            total.merge(&output.dir.total);
            categories.merge(&output.categories);
            if retain_children {
                children.push(output.dir);
            } else {
                truncated = true;
            }
        }

        WalkOutput {
            dir: RawDir {
                name,
                own,
                total,
                detection,
                children,
                truncated,
            },
            categories,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn classify(
        &self,
        path: &Path,
        name: &str,
        depth: u16,
        markers: Markers,
        parent_markers: Markers,
        grandparent_markers: Markers,
        subdir_count: usize,
        file_count: usize,
    ) -> Option<Detection> {
        // Most directory names are already lowercase; only allocate when they
        // are not.
        let lower_storage;
        let name_lower = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_storage = name.to_lowercase();
            lower_storage.as_str()
        } else {
            name
        };

        let ctx = DirContext {
            path,
            name,
            name_lower,
            parent_name: path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str()),
            markers,
            parent_markers,
            grandparent_markers,
            depth,
            subdir_count: subdir_count as u32,
            file_count: file_count as u32,
            env: self.known,
        };
        self.classifier.classify(&ctx)
    }

    fn is_stale(&self, modified: Option<u64>) -> bool {
        match (modified, self.stale_before) {
            (Some(modified), Some(threshold)) => modified < threshold,
            _ => false,
        }
    }
}

/// Everything a completed walk produced.
pub(crate) struct WalkResult {
    pub(crate) tree: DirTree,
    pub(crate) totals: Totals,
    pub(crate) categories: CategoryTotals,
    pub(crate) largest_files: Vec<FileEntry>,
    pub(crate) skipped: Vec<SkippedPath>,
    pub(crate) skipped_count: usize,
}

fn unwrap_lock<T>(mutex: Mutex<T>) -> T {
    mutex
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(unix)]
fn file_identity(file: &FileRecord) -> Option<(u64, u64)> {
    file.identity
}

#[cfg(not(unix))]
fn file_identity(_file: &FileRecord) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn hardlink_identity(meta: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if meta.nlink() > 1 {
        Some((meta.dev(), meta.ino()))
    } else {
        None
    }
}

fn modified_secs(meta: &Metadata) -> Option<u64> {
    meta.modified()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Hidden-file test. The leading-dot convention is what developers rely on and
/// it is the one that matters for `.git`, `.venv` and friends.
fn is_hidden(name: &str) -> bool {
    name.starts_with('.') && name != "." && name != ".."
}

/// Dot-directories carrying so much meaning that they are always traversed,
/// even without `--include-hidden`.
///
/// Skipping these by default would make Bloatrail miss the single largest
/// category of developer bloat, which would defeat the point of the tool.
fn is_always_traversed(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".jj"
            | ".next"
            | ".nuxt"
            | ".turbo"
            | ".parcel-cache"
            | ".svelte-kit"
            | ".angular"
            | ".astro"
            | ".docusaurus"
            | ".expo"
            | ".vite"
            | ".output"
            | ".gradle"
            | ".kotlin"
            | ".venv"
            | ".virtualenv"
            | ".tox"
            | ".nox"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".hypothesis"
            | ".ipynb_checkpoints"
            | ".eggs"
            | ".vs"
            | ".idea"
            | ".vscode"
            | ".fleet"
            | ".zed"
            | ".history"
            | ".cargo"
            | ".rustup"
            | ".npm"
            | ".yarn"
            | ".pnpm-store"
            | ".bun"
            | ".deno"
            | ".m2"
            | ".nuget"
            | ".gem"
            | ".bundle"
            | ".conda"
            | ".cache"
            | ".ccache"
            | ".docker"
            | ".terraform"
            | ".stack-work"
            | ".dart_tool"
            | ".build"
            | ".packages"
            | ".local"
            | ".config"
            | ".android"
            | ".ollama"
            | ".node-gyp"
            | ".electron"
            | ".pyenv"
            | ".nvm"
            | ".sdkman"
            | ".rollup.cache"
            | ".eslintcache"
            | ".wrangler"
            | ".zig-cache"
    )
}

fn read_markers(path: &Path) -> Markers {
    let mut markers = Markers::empty();
    let Ok(entries) = fs::read_dir(path) else {
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

fn count_nodes(dir: &RawDir) -> usize {
    1 + dir.children.iter().map(count_nodes).sum::<usize>()
}

/// Flatten the recursive walk result into the arena, parents before children.
fn flatten(dir: RawDir, parent: Option<NodeId>, depth: u16, nodes: &mut Vec<DirNode>) -> NodeId {
    let id = nodes.len() as NodeId;
    nodes.push(DirNode {
        name: dir.name,
        parent,
        children: Vec::new(),
        depth,
        own: dir.own,
        total: dir.total,
        detection: dir.detection,
        truncated: dir.truncated,
    });

    let mut children = Vec::with_capacity(dir.children.len());
    for child in dir.children {
        children.push(flatten(child, Some(id), depth.saturating_add(1), nodes));
    }
    nodes[id as usize].children = children;
    id
}

/// Order every node's children largest-first, once, so no renderer has to.
fn sort_children(nodes: &mut [DirNode]) {
    // Sizes are read from *other* nodes while sorting, so they are snapshotted
    // first rather than borrowed.
    let sizes: Vec<u64> = nodes.iter().map(|node| node.total.bytes).collect();
    for node in nodes.iter_mut() {
        node.children
            .sort_unstable_by(|a, b| sizes[*b as usize].cmp(&sizes[*a as usize]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_detection_follows_the_dot_convention() {
        assert!(is_hidden(".git"));
        assert!(!is_hidden("src"));
        assert!(!is_hidden("."));
        assert!(!is_hidden(".."));
    }

    #[test]
    fn important_dot_directories_are_always_traversed() {
        for name in [".git", ".next", ".venv", ".cargo", ".gradle"] {
            assert!(
                is_always_traversed(name),
                "{name} must be traversed without --include-hidden"
            );
        }
        assert!(!is_always_traversed(".secret-stuff"));
    }

    #[test]
    fn inherited_collapse_propagates_but_claims_do_not_suppress_classification() {
        assert!(Inherited::Collapsed(Category::Dependency).is_collapsed());
        assert!(!Inherited::Claimed(Category::Download).is_collapsed());
        assert_eq!(
            Inherited::Claimed(Category::Download).category(),
            Some(Category::Download)
        );
        assert_eq!(Inherited::None.category(), None);
    }
}

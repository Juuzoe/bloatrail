//! The directory tree produced by a scan.
//!
//! Nodes live in a flat arena addressed by [`NodeId`]. Each node stores only
//! its own name, so a path is reconstructed by walking parent links on demand.
//! For a scan with hundreds of thousands of directories this is the difference
//! between tens of megabytes and hundreds: storing a `PathBuf` per node would
//! repeat every ancestor's bytes at every level.

use std::path::{Path, PathBuf};

use crate::analysis::domain::Detection;

/// Index of a node within a [`DirTree`].
pub type NodeId = u32;

/// The root node of every tree.
pub const ROOT: NodeId = 0;

/// Aggregate counters for a directory or subtree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Total bytes.
    pub bytes: u64,
    /// Number of regular files.
    pub files: u64,
    /// Number of directories.
    pub dirs: u64,
    /// Bytes held by files older than the scan's age threshold.
    pub stale_bytes: u64,
}

impl Totals {
    /// Fold `other` into `self`.
    #[inline]
    pub fn merge(&mut self, other: &Totals) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.files = self.files.saturating_add(other.files);
        self.dirs = self.dirs.saturating_add(other.dirs);
        self.stale_bytes = self.stale_bytes.saturating_add(other.stale_bytes);
    }

    /// Record one file.
    #[inline]
    pub fn add_file(&mut self, bytes: u64, stale: bool) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.files = self.files.saturating_add(1);
        if stale {
            self.stale_bytes = self.stale_bytes.saturating_add(bytes);
        }
    }
}

/// One directory in the scanned tree.
#[derive(Debug)]
pub struct DirNode {
    /// Final path component. Empty for the root.
    pub name: Box<str>,
    /// Parent node, or `None` for the root.
    pub parent: Option<NodeId>,
    /// Children, sorted by subtree size, largest first.
    pub children: Vec<NodeId>,
    /// Depth below the scan root.
    pub depth: u16,
    /// Counters for files directly inside this directory.
    pub own: Totals,
    /// Counters for the whole subtree.
    pub total: Totals,
    /// Classification, if any rule matched.
    pub detection: Option<Detection>,
    /// `true` when children were intentionally not retained.
    ///
    /// Sizes are still exact; only the per-child breakdown is unavailable.
    pub truncated: bool,
}

impl DirNode {
    /// Whether this node has retained children.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

/// A scanned directory tree.
#[derive(Debug)]
pub struct DirTree {
    root_path: PathBuf,
    nodes: Vec<DirNode>,
}

impl DirTree {
    /// Build a tree from an arena. The first node must be the root.
    #[must_use]
    pub fn new(root_path: PathBuf, nodes: Vec<DirNode>) -> Self {
        debug_assert!(!nodes.is_empty(), "a tree always has a root node");
        DirTree { root_path, nodes }
    }

    /// The path the scan started from.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// The root node id.
    #[must_use]
    pub fn root(&self) -> NodeId {
        ROOT
    }

    /// Look up a node.
    ///
    /// # Panics
    /// Panics if `id` was not produced by this tree.
    #[must_use]
    pub fn node(&self, id: NodeId) -> &DirNode {
        &self.nodes[id as usize]
    }

    /// Number of retained nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the tree holds only its root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    /// Every node with its id, in arena order (parents before children).
    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &DirNode)> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (index as NodeId, node))
    }

    /// Reconstruct the absolute path of a node.
    #[must_use]
    pub fn path_of(&self, id: NodeId) -> PathBuf {
        let mut parts: Vec<&str> = Vec::new();
        let mut current = id;
        while let Some(parent) = self.nodes[current as usize].parent {
            parts.push(&self.nodes[current as usize].name);
            current = parent;
        }
        let mut path = self.root_path.clone();
        for part in parts.iter().rev() {
            path.push(part);
        }
        path
    }

    /// Find a node by absolute path, if it was retained.
    #[must_use]
    pub fn find(&self, path: &Path) -> Option<NodeId> {
        let relative = path.strip_prefix(&self.root_path).ok()?;
        let mut current = ROOT;
        for component in relative.components() {
            let needle = component.as_os_str().to_str()?;
            let next = self.nodes[current as usize]
                .children
                .iter()
                .copied()
                .find(|child| &*self.nodes[*child as usize].name == needle)?;
            current = next;
        }
        Some(current)
    }
}

/// A bounded "largest files" collection.
///
/// Implemented as a min-heap capped at `capacity`, so inserting a file that is
/// smaller than the current smallest kept entry is a single comparison.
#[derive(Debug)]
pub struct TopFiles {
    capacity: usize,
    heap: std::collections::BinaryHeap<std::cmp::Reverse<FileEntry>>,
}

/// A file worth remembering after the scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Absolute path.
    pub path: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// Category assigned during the scan.
    pub category: crate::analysis::domain::Category,
    /// Modification time as seconds since the Unix epoch, when available.
    pub modified: Option<u64>,
}

impl Ord for FileEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.size
            .cmp(&other.size)
            .then_with(|| other.path.cmp(&self.path))
    }
}

impl PartialOrd for FileEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl TopFiles {
    /// Create a collection that keeps at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        TopFiles {
            capacity: capacity.max(1),
            heap: std::collections::BinaryHeap::with_capacity(capacity.max(1) + 1),
        }
    }

    /// Size of the smallest retained entry once the collection is full.
    ///
    /// Callers use this as a cheap rejection threshold before building a
    /// `PathBuf`.
    #[must_use]
    pub fn threshold(&self) -> u64 {
        if self.heap.len() < self.capacity {
            0
        } else {
            self.heap.peek().map_or(0, |entry| entry.0.size)
        }
    }

    /// Offer an entry; it is kept only if it belongs in the top `capacity`.
    pub fn push(&mut self, entry: FileEntry) {
        if self.heap.len() < self.capacity {
            self.heap.push(std::cmp::Reverse(entry));
            return;
        }
        if let Some(smallest) = self.heap.peek() {
            if entry.size <= smallest.0.size {
                return;
            }
        }
        self.heap.pop();
        self.heap.push(std::cmp::Reverse(entry));
    }

    /// Consume the collection, returning entries largest first.
    #[must_use]
    pub fn into_sorted(self) -> Vec<FileEntry> {
        let mut entries: Vec<FileEntry> = self.heap.into_iter().map(|r| r.0).collect();
        entries.sort_by(|a, b| b.cmp(a));
        entries
    }

    /// Number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether nothing has been retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::domain::Category;

    fn entry(path: &str, size: u64) -> FileEntry {
        FileEntry {
            path: PathBuf::from(path),
            size,
            category: Category::Unknown,
            modified: None,
        }
    }

    #[test]
    fn totals_merge_additively() {
        let mut a = Totals::default();
        a.add_file(100, true);
        let mut b = Totals::default();
        b.add_file(50, false);
        a.merge(&b);
        assert_eq!(a.bytes, 150);
        assert_eq!(a.files, 2);
        assert_eq!(a.stale_bytes, 100);
    }

    #[test]
    fn top_files_keeps_only_the_largest() {
        let mut top = TopFiles::new(3);
        for (name, size) in [("a", 10), ("b", 50), ("c", 30), ("d", 5), ("e", 40)] {
            top.push(entry(name, size));
        }
        let sorted = top.into_sorted();
        let sizes: Vec<u64> = sorted.iter().map(|e| e.size).collect();
        assert_eq!(sizes, vec![50, 40, 30]);
    }

    #[test]
    fn threshold_is_zero_until_full_then_tracks_the_minimum() {
        let mut top = TopFiles::new(2);
        assert_eq!(top.threshold(), 0);
        top.push(entry("a", 10));
        assert_eq!(top.threshold(), 0);
        top.push(entry("b", 20));
        assert_eq!(top.threshold(), 10);
        top.push(entry("c", 30));
        assert_eq!(top.threshold(), 20);
    }

    #[test]
    fn tree_paths_are_reconstructed_from_parent_links() {
        let nodes = vec![
            DirNode {
                name: "".into(),
                parent: None,
                children: vec![1],
                depth: 0,
                own: Totals::default(),
                total: Totals::default(),
                detection: None,
                truncated: false,
            },
            DirNode {
                name: "project".into(),
                parent: Some(0),
                children: vec![2],
                depth: 1,
                own: Totals::default(),
                total: Totals::default(),
                detection: None,
                truncated: false,
            },
            DirNode {
                name: "target".into(),
                parent: Some(1),
                children: vec![],
                depth: 2,
                own: Totals::default(),
                total: Totals::default(),
                detection: None,
                truncated: false,
            },
        ];
        let root = PathBuf::from("/home/dev");
        let tree = DirTree::new(root.clone(), nodes);

        assert_eq!(tree.path_of(0), root);
        assert_eq!(tree.path_of(2), root.join("project").join("target"));
        assert_eq!(tree.find(&root.join("project").join("target")), Some(2));
        assert_eq!(tree.find(&root.join("nope")), None);
        assert_eq!(tree.len(), 3);
    }
}

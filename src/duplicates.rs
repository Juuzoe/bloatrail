//! Duplicate file detection.
//!
//! Hashing every file on a disk would take longer than the rest of Bloatrail
//! combined, so the search is staged and each stage only sees what the previous
//! one could not rule out:
//!
//! 1. **Group by size.** Two files of different sizes cannot be identical, and
//!    size comes free from the directory walk.
//! 2. **Discard unique sizes.** On a typical machine this removes the large
//!    majority of files without reading a single byte of content.
//! 3. **Fold hardlinks.** Paths that share a storage identity are one file
//!    under several names, so they collapse into a single copy: proven
//!    identical without reading anything, and worth nothing to delete. pnpm
//!    and Cargo both lean on hardlinks, so developer trees are full of them.
//! 4. **Partial hash.** For the surviving copies, hash the first and last
//!    16 KiB. Near-duplicates that differ anywhere in their head or tail — the
//!    common case for same-size-but-different media files — drop out here.
//! 5. **Full hash.** Only groups that still collide are read end to end.
//!
//! The final comparison uses BLAKE3 over the whole file, so a reported duplicate
//! is a genuine byte-for-byte match rather than a heuristic guess.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rayon::prelude::*;

use crate::error::{Error, Result};
use crate::pattern::ExcludeSet;
use crate::scanner::progress::Counters;

/// Bytes read from each end of a file during the partial-hash stage.
const PARTIAL_WINDOW: usize = 16 * 1024;

/// Buffer size used when hashing a file in full.
const READ_BUFFER: usize = 128 * 1024;

/// Number of independent shards in the size index.
///
/// Sharding turns one heavily contended mutex into 64 lightly contended ones,
/// which matters because every file in the scan touches this structure.
const SHARDS: usize = 64;

/// Settings for a duplicate search.
#[derive(Debug, Clone)]
pub struct DuplicateOptions {
    /// Where to search.
    pub root: PathBuf,
    /// Ignore files smaller than this. Small duplicates are numerous and rarely
    /// worth acting on.
    pub min_size: u64,
    /// Exclusion patterns.
    pub excludes: ExcludeSet,
    /// Whether to consider dot-files.
    pub include_hidden: bool,
    /// Maximum number of groups to return.
    pub limit: usize,
}

impl DuplicateOptions {
    /// Defaults: 1 MB minimum, 20 groups.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DuplicateOptions {
            root: root.into(),
            min_size: 1024 * 1024,
            excludes: ExcludeSet::default(),
            include_hidden: false,
            limit: 20,
        }
    }
}

/// One piece of on-disk storage, named by every path that reaches it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DuplicateCopy {
    /// The names found for this storage, sorted. More than one means hardlinks.
    pub paths: Vec<PathBuf>,
    /// How many names the file has on disk in total. When this exceeds
    /// `paths.len()`, names exist beyond the listed ones — outside the scanned
    /// root, excluded, hidden, or unmatchable because the filesystem's file
    /// IDs cannot be trusted — and deleting the listed ones cannot free the
    /// storage. `1` when the file is not hardlinked or its link count could
    /// not be determined.
    pub links: u64,
    /// The storage identity the names shared when the search matched them up,
    /// when the filesystem provided one.
    pub id: Option<(u64, u64)>,
}

impl DuplicateCopy {
    /// Whether names outside the search keep this storage alive no matter what
    /// happens to the listed paths.
    #[must_use]
    pub fn linked_elsewhere(&self) -> bool {
        self.links > self.paths.len() as u64
    }
}

/// A set of files with identical content.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Size of each file in the group.
    pub size: u64,
    /// Distinct on-disk copies, sorted for stable output. Deleting one name of
    /// a hardlinked file frees nothing, so only whole copies can be freed —
    /// and only the ones with no names outside the search.
    pub copies: Vec<DuplicateCopy>,
}

impl DuplicateGroup {
    /// Bytes that deduplicating this group can actually free.
    ///
    /// A copy pinned by names outside the search cannot be freed from here,
    /// but it does keep the content alive: when one exists, every free copy
    /// can go; when none does, one free copy has to stay.
    #[must_use]
    pub fn reclaimable(&self) -> u64 {
        let free = self
            .copies
            .iter()
            .filter(|copy| !copy.linked_elsewhere())
            .count() as u64;
        let pinned = self.copies.len() as u64 - free;
        let removable = if pinned > 0 {
            free
        } else {
            free.saturating_sub(1)
        };
        self.size.saturating_mul(removable)
    }

    /// Every path in the group, hardlinks included.
    pub fn paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.copies.iter().flat_map(|copy| &copy.paths)
    }
}

/// The outcome of a duplicate search.
#[derive(Debug, Clone, Default)]
pub struct DuplicateReport {
    /// Groups, largest reclaimable first.
    pub groups: Vec<DuplicateGroup>,
    /// Files considered after the size filter.
    pub candidates: u64,
    /// Files whose contents were read.
    pub hashed: u64,
    /// Candidate paths that turned out to be extra names for storage another
    /// candidate already covers. Folding them out is what keeps the reclaim
    /// figures honest on trees that use hardlinks.
    pub hardlinks: u64,
    /// Total bytes the groups can free: every removable copy counted after
    /// hardlink names are folded and copies pinned by unlisted names are set
    /// aside.
    pub reclaimable: u64,
}

/// Search for duplicate files.
///
/// # Errors
///
/// Fails only if the root cannot be used. Unreadable files encountered during
/// the search are skipped.
pub fn find(options: &DuplicateOptions, counters: Arc<Counters>) -> Result<DuplicateReport> {
    let root = crate::scanner::canonical_root(&options.root)?;

    let index = SizeIndex::new();
    collect(&root, options, &index, &counters);

    let candidates: Vec<(u64, Vec<PathBuf>)> = index.into_candidates();
    let candidate_count: u64 = candidates.iter().map(|(_, paths)| paths.len() as u64).sum();
    let hashed = AtomicU64::new(0);
    let folded = AtomicU64::new(0);

    let mut groups: Vec<DuplicateGroup> = candidates
        .into_par_iter()
        .flat_map_iter(|(size, paths)| {
            let confirmed = confirm_group(size, paths, &hashed, &folded);
            confirmed.into_iter()
        })
        .collect();

    groups.sort_by(|a, b| {
        b.reclaimable()
            .cmp(&a.reclaimable())
            .then(a.copies.cmp(&b.copies))
    });
    let reclaimable = groups
        .iter()
        .map(DuplicateGroup::reclaimable)
        .fold(0u64, u64::saturating_add);
    groups.truncate(options.limit);

    Ok(DuplicateReport {
        groups,
        candidates: candidate_count,
        hashed: hashed.load(Ordering::Relaxed),
        hardlinks: folded.load(Ordering::Relaxed),
        reclaimable,
    })
}

/// A sharded map from file size to the paths of that size.
struct SizeIndex {
    shards: Vec<Mutex<HashMap<u64, Vec<PathBuf>>>>,
}

impl SizeIndex {
    fn new() -> Self {
        SizeIndex {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    fn insert(&self, size: u64, path: PathBuf) {
        // Sizes cluster around round numbers, so mix the low bits before
        // choosing a shard.
        let shard = ((size.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as usize) % SHARDS;
        if let Ok(mut guard) = self.shards[shard].lock() {
            guard.entry(size).or_default().push(path);
        }
    }

    /// Collapse to the size groups that contain more than one file.
    fn into_candidates(self) -> Vec<(u64, Vec<PathBuf>)> {
        let mut out = Vec::new();
        for shard in self.shards {
            let map = shard.into_inner().unwrap_or_else(|e| e.into_inner());
            for (size, paths) in map {
                if paths.len() > 1 {
                    out.push((size, paths));
                }
            }
        }
        out
    }
}

fn collect(dir: &Path, options: &DuplicateOptions, index: &SizeIndex, counters: &Arc<Counters>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        counters.skipped();
        return;
    };

    let mut subdirs = Vec::new();
    counters.dir();

    for entry in entries.flatten() {
        let raw_name = entry.file_name();
        let name = raw_name.to_string_lossy();

        if !options.include_hidden && name.starts_with('.') {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }

        let path = entry.path();
        if options.excludes.excludes(&path, &name) {
            continue;
        }

        if file_type.is_dir() {
            subdirs.push(path);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let Ok(meta) = entry.metadata() else { continue };
        let size = meta.len();
        counters.file(size);
        if size < options.min_size {
            continue;
        }
        index.insert(size, path);
    }

    subdirs
        .into_par_iter()
        .for_each(|subdir| collect(&subdir, options, index, counters));
}

/// Confirm which files in a same-size group are genuinely identical.
fn confirm_group(
    size: u64,
    paths: Vec<PathBuf>,
    hashed: &AtomicU64,
    folded: &AtomicU64,
) -> Vec<DuplicateGroup> {
    // Stage 3: fold hardlinks. From here on the unit of work is a copy — one
    // piece of storage with every name that reaches it — and only one of its
    // names needs reading, because the others are the same bytes.
    let copies = fold_hardlinks(paths, folded);

    // Stage 4: cheap partial hash.
    let mut by_partial: HashMap<[u8; 32], Vec<DuplicateCopy>> = HashMap::new();
    for mut copy in copies {
        match hash_copy(&mut copy, |path| partial_hash(path, size).ok()) {
            Some(hash) => by_partial.entry(hash).or_default().push(copy),
            // A copy none of whose names can be read is simply not a duplicate.
            None => continue,
        }
    }

    let mut groups = Vec::new();
    for (_, candidates) in by_partial {
        if candidates.len() < 2 {
            continue;
        }

        // A file smaller than both windows was already hashed in full.
        if size <= (PARTIAL_WINDOW as u64) * 2 {
            groups.push(finish_group(size, candidates));
            continue;
        }

        // Stage 5: full hash.
        let mut by_full: HashMap<[u8; 32], Vec<DuplicateCopy>> = HashMap::new();
        for mut copy in candidates {
            match hash_copy(&mut copy, |path| full_hash(path).ok()) {
                Some(hash) => {
                    hashed.fetch_add(1, Ordering::Relaxed);
                    by_full.entry(hash).or_default().push(copy);
                }
                None => continue,
            }
        }
        for (_, identical) in by_full {
            if identical.len() >= 2 {
                groups.push(finish_group(size, identical));
            }
        }
    }
    groups
}

/// Hash a copy through its first name that is readable and still points at
/// the storage the fold recorded.
///
/// Every name of a copy is the same storage, so one read is normally enough —
/// but between the fold and this read a name can be unlinked while its
/// siblings live on, or another file can be renamed over it. A name that
/// fails either check is pruned, so a reported copy never lists a path the
/// search did not read or match. Files mutated during the scan can at worst
/// go unreported; they are never misreported as duplicates of bytes that were
/// not read.
fn hash_copy(
    copy: &mut DuplicateCopy,
    read: impl Fn(&Path) -> Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    while let Some(first) = copy.paths.first().cloned() {
        if copy.paths.len() > 1 && !names_folded_storage(copy, &first) {
            copy.paths.remove(0);
            continue;
        }
        match read(&first) {
            Some(hash) => return Some(hash),
            None => {
                copy.paths.remove(0);
            }
        }
    }
    None
}

/// Whether a name still points at the storage identity recorded at fold time.
///
/// Unverifiable states answer `true`: the read that follows is the authority,
/// and a name is only pruned on positive evidence that it moved.
fn names_folded_storage(copy: &DuplicateCopy, path: &Path) -> bool {
    let (Some(folded), Some(current)) = (copy.id, crate::platform::file_identity(path)) else {
        return true;
    };
    match current.id {
        Some(now) => now == folded,
        None => true,
    }
}

/// Collapse paths that name the same storage into single copies.
///
/// The identity check costs a syscall per path, so it runs here — after the
/// size stages have discarded most files — rather than during the walk. It
/// also runs before any hashing, so a folded name is never read. A hardlinked
/// file whose names cannot be matched up (the filesystem's file IDs are
/// untrustworthy) keeps its link count and reads as pinned: underclaiming
/// beats counting phantom space. Paths whose identity is entirely unknown
/// stay as copies of their own, which is exactly the pre-fold behaviour.
fn fold_hardlinks(paths: Vec<PathBuf>, folded: &AtomicU64) -> Vec<DuplicateCopy> {
    let mut by_id: HashMap<(u64, u64), usize> = HashMap::new();
    let mut copies: Vec<DuplicateCopy> = Vec::with_capacity(paths.len());

    for path in paths {
        let identity = crate::platform::file_identity(&path);
        let single = DuplicateCopy {
            paths: vec![path],
            links: 1,
            id: identity.and_then(|i| i.id),
        };
        match identity {
            Some(identity) if identity.links > 1 => match identity.id {
                Some(id) => match by_id.get(&id) {
                    Some(&index) => {
                        copies[index].paths.extend(single.paths);
                        folded.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        by_id.insert(id, copies.len());
                        copies.push(DuplicateCopy {
                            links: identity.links,
                            ..single
                        });
                    }
                },
                None => copies.push(DuplicateCopy {
                    links: identity.links,
                    ..single
                }),
            },
            _ => copies.push(single),
        }
    }

    for copy in &mut copies {
        copy.paths.sort();
    }
    copies
}

fn finish_group(size: u64, mut copies: Vec<DuplicateCopy>) -> DuplicateGroup {
    copies.sort();
    DuplicateGroup { size, copies }
}

/// Hash enough of a file to rule out most non-duplicates cheaply.
///
/// For files up to `PARTIAL_WINDOW * 2` the "partial" hash covers the entire
/// file, which is what makes the short-circuit in [`confirm_group`] sound: a
/// head-only hash would declare two 24 KiB files identical whenever their first
/// 16 KiB matched.
fn partial_hash(path: &Path, size: u64) -> Result<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| Error::io(path, error))?;
    let mut hasher = blake3::Hasher::new();
    // Mixing the length in keeps two files with identical windows but different
    // lengths from colliding, which matters for sparse and padded files.
    hasher.update(&size.to_le_bytes());

    if size <= (PARTIAL_WINDOW as u64) * 2 {
        // Small enough to read in full; do that instead of sampling.
        let mut buffer = vec![0u8; PARTIAL_WINDOW * 2];
        let filled = read_up_to(&mut file, &mut buffer).map_err(|error| Error::io(path, error))?;
        hasher.update(&buffer[..filled]);
        return Ok(*hasher.finalize().as_bytes());
    }

    let mut buffer = vec![0u8; PARTIAL_WINDOW];
    read_exact_or_less(&mut file, &mut buffer).map_err(|error| Error::io(path, error))?;
    hasher.update(&buffer);

    file.seek(SeekFrom::End(-(PARTIAL_WINDOW as i64)))
        .map_err(|error| Error::io(path, error))?;
    read_exact_or_less(&mut file, &mut buffer).map_err(|error| Error::io(path, error))?;
    hasher.update(&buffer);

    Ok(*hasher.finalize().as_bytes())
}

/// Hash a whole file.
fn full_hash(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| Error::io(path, error))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; READ_BUFFER];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::io(path, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Fill `buffer` as far as the file allows, zeroing the remainder.
fn read_exact_or_less(file: &mut File, buffer: &mut [u8]) -> std::io::Result<()> {
    let filled = read_up_to(file, buffer)?;
    buffer[filled..].fill(0);
    Ok(())
}

/// Read until `buffer` is full or the file ends; returns how much was read.
fn read_up_to(file: &mut File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn identical_files_are_grouped_and_different_ones_are_not() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        let payload = vec![7u8; 4096];
        let mut other = vec![7u8; 4096];
        other[2048] = 9;

        write(&root.join("a/one.bin"), &payload);
        write(&root.join("b/copy.bin"), &payload);
        write(&root.join("c/different.bin"), &other);
        write(&root.join("d/small.bin"), b"tiny");

        let options = DuplicateOptions {
            min_size: 1024,
            limit: 10,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();

        assert_eq!(
            report.groups.len(),
            1,
            "only one true duplicate pair exists"
        );
        let group = &report.groups[0];
        assert_eq!(group.copies.len(), 2);
        assert_eq!(group.size, 4096);
        assert_eq!(group.reclaimable(), 4096);
    }

    #[test]
    fn files_below_the_size_threshold_are_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a.bin"), b"same");
        write(&root.join("b.bin"), b"same");

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(report.groups.is_empty());
        assert_eq!(report.candidates, 0);
    }

    #[test]
    fn same_size_different_content_is_not_a_duplicate() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        // Large enough that the full-hash stage is exercised.
        let mut a = vec![0u8; 64 * 1024];
        let mut b = vec![0u8; 64 * 1024];
        a[32 * 1024] = 1;
        b[32 * 1024] = 2;
        write(&root.join("a.bin"), &a);
        write(&root.join("b.bin"), &b);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(
            report.groups.is_empty(),
            "files differing only in the middle must not be reported as duplicates"
        );
        assert_eq!(report.hashed, 2, "both files needed a full hash");
    }

    #[test]
    fn three_copies_report_two_reclaimable_units() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let payload = vec![3u8; 8192];
        for name in ["x.bin", "y.bin", "z.bin"] {
            write(&root.join(name), &payload);
        }

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].copies.len(), 3);
        assert_eq!(report.reclaimable, 8192 * 2);
    }

    #[test]
    fn medium_files_differing_only_in_their_tail_are_not_duplicates() {
        // 24 KiB: larger than one partial window, smaller than two. The
        // short-circuit that accepts the partial hash as definitive is only
        // sound because the partial hash covers the whole file at this size.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut a = vec![5u8; 24 * 1024];
        let mut b = vec![5u8; 24 * 1024];
        a[23 * 1024] = 1;
        b[23 * 1024] = 2;
        write(&root.join("a.bin"), &a);
        write(&root.join("b.bin"), &b);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(
            report.groups.is_empty(),
            "files differing in their last kilobyte must not be reported as identical"
        );
    }

    #[test]
    fn medium_files_that_really_match_are_still_found() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let payload = vec![9u8; 24 * 1024];
        write(&root.join("a.bin"), &payload);
        write(&root.join("b.bin"), &payload);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert_eq!(report.groups.len(), 1);
        assert_eq!(report.groups[0].copies.len(), 2);
    }

    /// Hardlink two paths; skip the test if the filesystem refuses (some CI
    /// sandboxes and network mounts do), because that proves nothing either way.
    /// A missing source is a broken test, not a filesystem limit, and fails.
    fn try_hard_link(original: &Path, link: &Path) -> bool {
        match std::fs::hard_link(original, link) {
            Ok(()) => true,
            Err(error) => {
                assert!(
                    original.exists(),
                    "hard_link failed because the source does not exist — \
                     that is a test bug, not a filesystem limit: {error}"
                );
                false
            }
        }
    }

    #[test]
    fn hardlinks_alone_are_not_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("original.bin"), &vec![4u8; 8192]);
        if !try_hard_link(&root.join("original.bin"), &root.join("alias.bin")) {
            return;
        }

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(
            report.groups.is_empty(),
            "two names for one piece of storage reclaim nothing"
        );
        assert_eq!(report.hardlinks, 1, "the fold must be reported");
        assert_eq!(report.reclaimable, 0);
    }

    #[test]
    fn a_real_copy_beside_hardlinks_counts_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        // Big enough to force the full-hash stage.
        let payload = vec![6u8; 64 * 1024];
        write(&root.join("original.bin"), &payload);
        write(&root.join("copy.bin"), &payload);
        if !try_hard_link(&root.join("original.bin"), &root.join("alias.bin")) {
            return;
        }

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();

        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(
            group.copies.len(),
            2,
            "three paths, but only two pieces of storage"
        );
        assert_eq!(
            group.reclaimable(),
            64 * 1024,
            "deleting the copy frees one file's worth, deleting a hardlink frees nothing"
        );
        assert_eq!(group.paths().count(), 3, "every path is still listed");
        assert_eq!(report.hardlinks, 1);
        assert_eq!(
            report.hashed, 2,
            "the folded link must not be read a second time"
        );

        // The hardlinked pair sits together in one copy, and both of its names
        // are inside the search, so nothing pins it.
        let linked = group
            .copies
            .iter()
            .find(|copy| copy.paths.len() == 2)
            .expect("one copy should carry both hardlinked names");
        assert!(linked.paths.iter().any(|p| p.ends_with("original.bin")));
        assert!(linked.paths.iter().any(|p| p.ends_with("alias.bin")));
        assert!(!linked.linked_elsewhere());
    }

    #[test]
    fn copies_pinned_from_outside_the_search_do_not_count_as_reclaimable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let payload = vec![8u8; 8192];
        // The second name of `pinned.bin` lives outside the scanned root, so
        // no deletion inside the scan can ever free that storage.
        write(&root.join("outside.bin"), &payload);
        std::fs::create_dir_all(root.join("scan")).unwrap();
        if !try_hard_link(&root.join("outside.bin"), &root.join("scan/pinned.bin")) {
            return;
        }
        write(&root.join("scan/free.bin"), &payload);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root.join("scan"))
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();

        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(group.copies.len(), 2);
        let pinned = group
            .copies
            .iter()
            .find(|c| c.paths[0].ends_with("pinned.bin"))
            .unwrap();
        assert!(pinned.linked_elsewhere(), "one of its two names is unseen");
        assert_eq!(
            group.reclaimable(),
            8192,
            "the pinned copy keeps the content alive, so the free copy can go"
        );

        // With every copy pinned, nothing at all is reclaimable.
        write(&root.join("outside2.bin"), &payload);
        if !try_hard_link(&root.join("outside2.bin"), &root.join("scan/free.bin.2")) {
            return;
        }
        std::fs::remove_file(root.join("scan/free.bin")).unwrap();
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert_eq!(report.groups.len(), 1, "still byte-identical duplicates");
        assert_eq!(
            report.groups[0].reclaimable(),
            0,
            "both copies are pinned from outside; deleting the listed names frees nothing"
        );
        assert_eq!(report.reclaimable, 0);
    }

    #[test]
    fn every_extra_name_is_counted_when_several_files_are_multiply_linked() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        // Same size everywhere so all of it lands in one candidate group.
        let mut first = vec![1u8; 8192];
        let mut second = vec![2u8; 8192];
        first[0] = 11;
        second[0] = 22;
        write(&root.join("first.bin"), &first);
        write(&root.join("second.bin"), &second);
        if !try_hard_link(&root.join("first.bin"), &root.join("first-b.bin")) {
            return;
        }
        if !try_hard_link(&root.join("first.bin"), &root.join("first-c.bin")) {
            return;
        }
        if !try_hard_link(&root.join("second.bin"), &root.join("second-b.bin")) {
            return;
        }
        // And one genuine copy of `first`, so a group forms.
        write(&root.join("first-copy.bin"), &first);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();

        assert_eq!(
            report.hardlinks, 3,
            "two extra names on `first` plus one on `second`, counted per path"
        );
        assert_eq!(report.groups.len(), 1);
        let group = &report.groups[0];
        assert_eq!(group.copies.len(), 2);
        assert_eq!(group.paths().count(), 4, "three names plus the real copy");
        assert_eq!(group.reclaimable(), 8192);
        let triple = group
            .copies
            .iter()
            .find(|c| c.paths.len() == 3)
            .expect("the triply linked file is one copy");
        assert!(!triple.linked_elsewhere(), "all three names were found");
    }

    #[test]
    fn hashing_falls_back_to_a_surviving_name_when_the_first_is_gone() {
        // A name can be unlinked between the fold and the read; the copy's
        // other names still exist and must keep it in the running.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let payload = vec![3u8; 64 * 1024];
        write(&root.join("real.bin"), &payload);

        let mut copy = DuplicateCopy {
            paths: vec![root.join("already-deleted.bin"), root.join("real.bin")],
            links: 2,
            id: None,
        };
        let partial = hash_copy(&mut copy, |p| partial_hash(p, 64 * 1024).ok());
        assert!(partial.is_some(), "the surviving name must be read instead");
        assert_eq!(
            partial,
            partial_hash(&root.join("real.bin"), 64 * 1024).ok()
        );
        assert_eq!(
            copy.paths,
            vec![root.join("real.bin")],
            "the vanished name must be pruned, not reported"
        );

        let full = hash_copy(&mut copy, |p| full_hash(p).ok());
        assert_eq!(full, full_hash(&root.join("real.bin")).ok());

        let mut all_gone = DuplicateCopy {
            paths: vec![root.join("gone-a.bin"), root.join("gone-b.bin")],
            links: 2,
            id: None,
        };
        assert_eq!(hash_copy(&mut all_gone, |p| full_hash(p).ok()), None);
        assert!(all_gone.paths.is_empty());
    }

    #[test]
    fn a_name_that_stopped_pointing_at_the_folded_storage_is_pruned() {
        // Between the fold and the read, another file can be renamed over one
        // of a copy's names. The impostor's bytes must not be attributed to
        // the copy's unread sibling names.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        write(&root.join("a-impostor.bin"), &vec![1u8; 8192]);
        write(&root.join("b-real.bin"), &vec![2u8; 8192]);

        let Some(real_identity) = crate::platform::file_identity(&root.join("b-real.bin")) else {
            return;
        };
        let Some(real_id) = real_identity.id else {
            // No usable file IDs on this filesystem; verification cannot run.
            return;
        };

        let mut copy = DuplicateCopy {
            paths: vec![root.join("a-impostor.bin"), root.join("b-real.bin")],
            links: 2,
            id: Some(real_id),
        };
        let hash = hash_copy(&mut copy, |p| full_hash(p).ok());
        assert_eq!(
            hash,
            full_hash(&root.join("b-real.bin")).ok(),
            "the name whose identity no longer matches must be skipped"
        );
        assert_eq!(copy.paths, vec![root.join("b-real.bin")]);
    }

    #[test]
    fn hardlinks_are_folded_even_when_nothing_matches_in_content() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut a = vec![0u8; 8192];
        let mut b = vec![0u8; 8192];
        a[100] = 1;
        b[100] = 2;
        write(&root.join("a.bin"), &a);
        write(&root.join("b.bin"), &b);
        if !try_hard_link(&root.join("a.bin"), &root.join("a-link.bin")) {
            return;
        }

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(report.groups.is_empty(), "contents differ");
        assert_eq!(report.hardlinks, 1, "the fold happened before hashing");
    }

    #[test]
    fn partial_hash_distinguishes_head_differences_without_a_full_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let mut a = vec![0u8; 128 * 1024];
        let mut b = vec![0u8; 128 * 1024];
        a[0] = 1;
        b[0] = 2;
        write(&root.join("a.bin"), &a);
        write(&root.join("b.bin"), &b);

        let options = DuplicateOptions {
            min_size: 1024,
            ..DuplicateOptions::new(root)
        };
        let report = find(&options, Arc::new(Counters::default())).unwrap();
        assert!(report.groups.is_empty());
        assert_eq!(report.hashed, 0, "the partial hash should have been enough");
    }
}

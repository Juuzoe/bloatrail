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
//! 3. **Partial hash.** For the survivors, hash the first and last 16 KiB.
//!    Near-duplicates that differ anywhere in their head or tail — the common
//!    case for same-size-but-different media files — drop out here.
//! 4. **Full hash.** Only groups that still collide are read end to end.
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

/// A set of files with identical content.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Size of each file in the group.
    pub size: u64,
    /// Paths, sorted for stable output.
    pub paths: Vec<PathBuf>,
}

impl DuplicateGroup {
    /// Bytes that would be freed by keeping exactly one copy.
    #[must_use]
    pub fn reclaimable(&self) -> u64 {
        self.size
            .saturating_mul(self.paths.len().saturating_sub(1) as u64)
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
    /// Total bytes that keeping one copy of each group would free.
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

    let mut groups: Vec<DuplicateGroup> = candidates
        .into_par_iter()
        .flat_map_iter(|(size, paths)| {
            let confirmed = confirm_group(size, paths, &hashed);
            confirmed.into_iter()
        })
        .collect();

    groups.sort_by(|a, b| {
        b.reclaimable()
            .cmp(&a.reclaimable())
            .then(a.paths.cmp(&b.paths))
    });
    let reclaimable = groups.iter().map(DuplicateGroup::reclaimable).sum();
    groups.truncate(options.limit);

    Ok(DuplicateReport {
        groups,
        candidates: candidate_count,
        hashed: hashed.load(Ordering::Relaxed),
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
fn confirm_group(size: u64, paths: Vec<PathBuf>, hashed: &AtomicU64) -> Vec<DuplicateGroup> {
    // Stage 3: cheap partial hash.
    let mut by_partial: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
    for path in paths {
        match partial_hash(&path, size) {
            Ok(hash) => by_partial.entry(hash).or_default().push(path),
            // A file that vanished or cannot be read is simply not a duplicate.
            Err(_) => continue,
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

        // Stage 4: full hash.
        let mut by_full: HashMap<[u8; 32], Vec<PathBuf>> = HashMap::new();
        for path in candidates {
            match full_hash(&path) {
                Ok(hash) => {
                    hashed.fetch_add(1, Ordering::Relaxed);
                    by_full.entry(hash).or_default().push(path);
                }
                Err(_) => continue,
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

fn finish_group(size: u64, mut paths: Vec<PathBuf>) -> DuplicateGroup {
    paths.sort();
    DuplicateGroup { size, paths }
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
        assert_eq!(group.paths.len(), 2);
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
        assert_eq!(report.groups[0].paths.len(), 3);
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
        assert_eq!(report.groups[0].paths.len(), 2);
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

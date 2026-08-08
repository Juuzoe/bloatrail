//! Scan history and `bloatrail diff`.
//!
//! A snapshot is a small summary — totals, per-category figures and the largest
//! directories — not a full tree. That keeps the store tiny (a few kilobytes per
//! scan) while still answering the question people actually ask: *what grew?*

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::domain::Category;
use crate::error::{Error, Result};
use crate::scanner::ScanResult;

/// Schema version, so old snapshots can be recognised and skipped.
pub const SNAPSHOT_VERSION: u32 = 1;

/// How many snapshots to keep per scanned root.
const KEEP_SNAPSHOTS: usize = 20;

/// A recorded scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Schema version.
    pub version: u32,
    /// The directory that was scanned.
    pub root: PathBuf,
    /// When the scan started, in seconds since the Unix epoch.
    pub timestamp: u64,
    /// Total bytes.
    pub bytes: u64,
    /// Total files.
    pub files: u64,
    /// Total directories.
    pub dirs: u64,
    /// Bytes per category, keyed by the stable category id.
    pub categories: BTreeMap<String, u64>,
    /// The largest directories at scan time, as `(relative path, bytes)`.
    pub largest: Vec<(String, u64)>,
}

impl Snapshot {
    /// Summarise a completed scan.
    #[must_use]
    pub fn from_scan(scan: &ScanResult, largest: usize) -> Self {
        let categories = Category::ALL
            .iter()
            .filter_map(|category| {
                let bytes = scan.categories.bytes(*category);
                (bytes > 0).then(|| (category.id().to_string(), bytes))
            })
            .collect();

        let largest = scan
            .largest_directories(largest)
            .into_iter()
            .map(|(id, bytes)| {
                let path = scan.tree.path_of(id);
                let label = path
                    .strip_prefix(&scan.root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                (label, bytes)
            })
            .collect();

        Snapshot {
            version: SNAPSHOT_VERSION,
            root: scan.root.clone(),
            timestamp: scan
                .started_at
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            bytes: scan.totals.bytes,
            files: scan.totals.files,
            dirs: scan.totals.dirs,
            categories,
            largest,
        }
    }
}

/// One line of a `bloatrail diff` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// What changed.
    pub label: String,
    /// Signed byte delta.
    pub delta: i64,
}

/// The comparison of two snapshots.
#[derive(Debug, Clone)]
pub struct Diff {
    /// The older snapshot's timestamp.
    pub from: u64,
    /// The newer snapshot's timestamp.
    pub to: u64,
    /// Category-level changes, largest magnitude first.
    pub categories: Vec<Change>,
    /// Directory-level changes, largest magnitude first.
    pub directories: Vec<Change>,
    /// Total byte delta.
    pub net: i64,
}

/// Compare two snapshots.
#[must_use]
pub fn diff(previous: &Snapshot, current: &Snapshot) -> Diff {
    Diff {
        from: previous.timestamp,
        to: current.timestamp,
        categories: rank(compare_maps(
            &previous.categories,
            &current.categories,
            label_for,
        )),
        directories: rank(compare_pairs(&previous.largest, &current.largest)),
        net: current.bytes as i64 - previous.bytes as i64,
    }
}

fn label_for(id: &str) -> String {
    Category::ALL
        .iter()
        .find(|c| c.id() == id)
        .map_or_else(|| id.to_string(), |c| c.label().to_string())
}

fn compare_maps(
    previous: &BTreeMap<String, u64>,
    current: &BTreeMap<String, u64>,
    label: fn(&str) -> String,
) -> Vec<Change> {
    let mut keys: Vec<&String> = previous.keys().chain(current.keys()).collect();
    keys.sort_unstable();
    keys.dedup();

    keys.into_iter()
        .filter_map(|key| {
            let before = previous.get(key).copied().unwrap_or(0) as i64;
            let after = current.get(key).copied().unwrap_or(0) as i64;
            let delta = after - before;
            (delta != 0).then(|| Change {
                label: label(key),
                delta,
            })
        })
        .collect()
}

fn compare_pairs(previous: &[(String, u64)], current: &[(String, u64)]) -> Vec<Change> {
    let before: BTreeMap<String, u64> = previous.iter().cloned().collect();
    let after: BTreeMap<String, u64> = current.iter().cloned().collect();
    compare_maps(&before, &after, |key| key.to_string())
}

fn rank(mut changes: Vec<Change>) -> Vec<Change> {
    changes.sort_by(|a, b| {
        b.delta
            .abs()
            .cmp(&a.delta.abs())
            .then(a.label.cmp(&b.label))
    });
    changes
}

/// Directory holding snapshots for `root`.
#[must_use]
pub fn store_dir(root: &Path) -> Option<PathBuf> {
    Some(
        crate::config::data_dir()?
            .join("history")
            .join(root_key(root)),
    )
}

/// A filesystem-safe, stable key for a scanned path.
fn root_key(root: &Path) -> String {
    let normalised = crate::platform::normalise_key(root);
    let digest = blake3::hash(normalised.as_bytes());
    // 16 hex characters is ample: this only has to avoid collisions between the
    // handful of directories one person scans.
    digest.to_hex()[..16].to_string()
}

/// Persist a snapshot, pruning older ones.
///
/// # Errors
///
/// Returns [`Error::Io`] if the history directory cannot be written.
pub fn save(snapshot: &Snapshot) -> Result<PathBuf> {
    let dir = store_dir(&snapshot.root)
        .ok_or_else(|| Error::io(&snapshot.root, std::io::Error::other("no data directory")))?;
    std::fs::create_dir_all(&dir).map_err(|error| Error::io(&dir, error))?;

    let path = dir.join(format!("{:020}.json", snapshot.timestamp));
    let text = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(&path, text).map_err(|error| Error::io(&path, error))?;

    prune(&dir);
    Ok(path)
}

fn prune(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    if files.len() <= KEEP_SNAPSHOTS {
        return;
    }
    // Names are zero-padded timestamps, so lexical order is chronological.
    files.sort();
    for stale in &files[..files.len() - KEEP_SNAPSHOTS] {
        let _ = std::fs::remove_file(stale);
    }
}

/// Load stored snapshots for `root`, oldest first.
///
/// # Errors
///
/// Never fails for a missing store; returns an empty list instead.
pub fn load_all(root: &Path) -> Result<Vec<Snapshot>> {
    let Some(dir) = store_dir(root) else {
        return Ok(Vec::new());
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };

    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();

    let mut snapshots = Vec::with_capacity(paths.len());
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match serde_json::from_str::<Snapshot>(&text) {
            // Snapshots from a future or unknown schema are ignored rather than
            // fatal: an upgrade should never break `diff`.
            Ok(snapshot) if snapshot.version == SNAPSHOT_VERSION => snapshots.push(snapshot),
            _ => continue,
        }
    }
    Ok(snapshots)
}

/// The most recent snapshot recorded before the current one.
///
/// # Errors
///
/// Returns [`Error::NoHistory`] when fewer than two snapshots exist.
pub fn previous(root: &Path) -> Result<Snapshot> {
    let mut snapshots = load_all(root)?;
    if snapshots.len() < 2 {
        return Err(Error::NoHistory(root.to_path_buf()));
    }
    snapshots.pop();
    snapshots
        .pop()
        .ok_or_else(|| Error::NoHistory(root.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(
        timestamp: u64,
        bytes: u64,
        categories: &[(&str, u64)],
        largest: &[(&str, u64)],
    ) -> Snapshot {
        Snapshot {
            version: SNAPSHOT_VERSION,
            root: PathBuf::from("/scan"),
            timestamp,
            bytes,
            files: 1,
            dirs: 1,
            categories: categories
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
            largest: largest
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect(),
        }
    }

    #[test]
    fn diff_reports_growth_and_shrinkage() {
        let before = snapshot(
            1_000,
            100,
            &[("container_data", 10), ("video", 40)],
            &[("Docker", 10)],
        );
        let after = snapshot(
            2_000,
            130,
            &[("container_data", 50), ("video", 20)],
            &[("Docker", 50)],
        );

        let diff = diff(&before, &after);
        assert_eq!(diff.net, 30);
        assert_eq!(diff.categories[0].label, "Containers");
        assert_eq!(diff.categories[0].delta, 40);
        assert_eq!(diff.categories[1].label, "Videos");
        assert_eq!(diff.categories[1].delta, -20);
    }

    #[test]
    fn categories_present_in_only_one_snapshot_still_appear() {
        let before = snapshot(1, 10, &[("video", 10)], &[]);
        let after = snapshot(2, 20, &[("dependency", 20)], &[]);
        let diff = diff(&before, &after);

        let labels: Vec<&str> = diff.categories.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.contains(&"Videos"));
        assert!(labels.contains(&"Developer dependencies"));
    }

    #[test]
    fn unchanged_categories_are_omitted() {
        let before = snapshot(1, 10, &[("video", 10)], &[]);
        let after = snapshot(2, 10, &[("video", 10)], &[]);
        assert!(diff(&before, &after).categories.is_empty());
        assert_eq!(diff(&before, &after).net, 0);
    }

    #[test]
    fn changes_are_ranked_by_magnitude() {
        let before = snapshot(1, 0, &[("video", 100), ("cache", 100)], &[]);
        let after = snapshot(2, 0, &[("video", 90), ("cache", 300)], &[]);
        let diff = diff(&before, &after);
        assert_eq!(diff.categories[0].label, "Caches");
        assert_eq!(diff.categories[0].delta, 200);
    }

    #[test]
    fn root_keys_are_stable_and_distinct() {
        let a = root_key(Path::new("/home/dev/project"));
        let b = root_key(Path::new("/home/dev/project"));
        let c = root_key(Path::new("/home/dev/other"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn snapshots_round_trip_through_json() {
        let original = snapshot(42, 4_096, &[("cache", 4_096)], &[("x", 4_096)]);
        let text = serde_json::to_string(&original).unwrap();
        let parsed: Snapshot = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.timestamp, 42);
        assert_eq!(parsed.bytes, 4_096);
        assert_eq!(parsed.categories.get("cache"), Some(&4_096));
    }
}

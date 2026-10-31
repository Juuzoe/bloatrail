//! Scan history, `bloatrail diff` and `bloatrail growth`.
//!
//! A snapshot is a small summary — totals, per-category figures and the largest
//! directories — not a full tree. That keeps the store tiny (a few kilobytes per
//! scan) while still answering the question people actually ask: *what grew?*
//!
//! [`diff`] compares the two most recent snapshots. [`growth`] reads the whole
//! recorded series: what changed across it, how fast the volume underneath is
//! filling, and — when the record is long enough to say so honestly — roughly
//! when it runs out. Both are pure functions over [`Snapshot`] values, so the
//! terminal report and the JSON document cannot disagree about the arithmetic.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::domain::Category;
use crate::error::{Error, Result};
use crate::scanner::ScanResult;

/// Schema version, so old snapshots can be recognised and skipped.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Hard ceiling on snapshots kept per scanned root.
///
/// Reached only by a machine scanning the same directory constantly; the
/// age-thinning in [`retain`] normally keeps the count far below this.
const MAX_SNAPSHOTS: usize = 200;

/// Snapshots newer than this are all kept, whatever their density.
const KEEP_ALL_WITHIN: u64 = 7 * 86_400;

/// Between [`KEEP_ALL_WITHIN`] and this, one snapshot per day is kept.
const KEEP_DAILY_WITHIN: u64 = 30 * 86_400;

/// Beyond [`KEEP_DAILY_WITHIN`], one snapshot per week is kept, up to here.
const KEEP_WEEKLY_WITHIN: u64 = 400 * 86_400;

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
    // The three fields below arrived after 0.3.0. They are additive and
    // optional rather than a version bump: a bump would make every snapshot a
    // user already recorded unreadable, which is a poor trade for three
    // numbers. Old snapshots load with `None`; old binaries ignore the extra
    // keys because the deserialiser does not deny unknown fields.
    /// Capacity of the volume holding the root, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total: Option<u64>,
    /// Bytes free on that volume at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_available: Option<u64>,
    /// Bytes Bloatrail judged recoverable at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<u64>,
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
            disk_total: None,
            disk_available: None,
            reclaimable: None,
        }
    }

    /// The snapshot recorded for a completed scan.
    ///
    /// Every frontend that records history builds its snapshot here — the
    /// CLI's `scan`, `diff` and `growth`, and the desktop app — so a snapshot
    /// cannot depend on which of them wrote it: the same top-directory count,
    /// the same volume figures, and the same recoverable estimate `clean`
    /// would report. `stale_days` must be the threshold the scan ran with,
    /// because it decides which age-limited sweeps count as recoverable.
    ///
    /// This only builds the snapshot; [`save`] writes it.
    #[must_use]
    pub fn capture(scan: &ScanResult, stale_days: u32) -> Self {
        let reclaimable = crate::cleanup::CleanupPlan::from_scan_with(scan, stale_days)
            .recoverable()
            .0;
        Snapshot::from_scan(scan, LARGEST_TRACKED)
            .with_environment(crate::platform::disk_usage(&scan.root), reclaimable)
    }

    /// Attach the figures that describe the machine around the scan: the
    /// volume's capacity and free space, and what Bloatrail judged recoverable.
    ///
    /// These are what let a later `bloatrail growth` show the volume's
    /// trajectory rather than only the tree's.
    #[must_use]
    pub fn with_environment(
        mut self,
        disk: Option<crate::platform::DiskUsage>,
        reclaimable: u64,
    ) -> Self {
        if let Some(disk) = disk {
            self.disk_total = Some(disk.total);
            self.disk_available = Some(disk.available);
        }
        self.reclaimable = Some(reclaimable);
        self
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
        directories: directory_changes(&previous.largest, &current.largest),
        net: current.bytes as i64 - previous.bytes as i64,
    }
}

/// Directory-level changes between two "largest directories" lists.
fn directory_changes(previous: &[(String, u64)], current: &[(String, u64)]) -> Vec<Change> {
    let mut changes = compare_pairs(previous, current);
    collapse_explained_ancestors(&mut changes);
    rank(changes)
}

/// Drop ancestor rows whose change is already told by their descendants.
///
/// The largest-directories list is flat, so when `backend-api/target` grows,
/// `backend-api` grows by the same amount and both make the list. The second
/// row is a duplicate pointer, not information. An ancestor survives only if
/// its delta is *not* explained by the listed rows beneath it — meaning
/// something else inside it moved, which is exactly when the row says
/// something the descendants cannot.
fn collapse_explained_ancestors(changes: &mut Vec<Change>) {
    let paths: Vec<&Path> = changes
        .iter()
        .map(|change| Path::new(&change.label))
        .collect();

    let mut residual: Vec<i64> = changes.iter().map(|change| change.delta).collect();
    let mut has_descendant = vec![false; changes.len()];

    for child in 0..changes.len() {
        // The nearest listed ancestor absorbs this row's delta, so a chain of
        // ancestors is not charged for the same bytes more than once.
        let parent = (0..changes.len())
            .filter(|&index| {
                index != child
                    && paths[child].starts_with(paths[index])
                    && paths[child] != paths[index]
            })
            .max_by_key(|&index| paths[index].components().count());
        if let Some(parent) = parent {
            residual[parent] -= changes[child].delta;
            has_descendant[parent] = true;
        }
    }

    // "Explained" tolerates the incidental churn that rides along with any
    // real change — a lockfile, a log line — up to 1% of the ancestor's own
    // delta. Anything larger is a genuine second story and the row stays.
    let mut index = 0;
    changes.retain(|change| {
        let keep = !has_descendant[index] || residual[index].abs() * 100 > change.delta.abs();
        index += 1;
        keep
    });
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

/// How many directories a snapshot records.
///
/// The list is a top-N, not the whole tree, which is what keeps a snapshot a
/// few kilobytes, and why directory comparison has to account for a directory
/// crossing the edge of the list rather than reading absence as zero.
pub const LARGEST_TRACKED: usize = 25;

/// The largest size a directory could have had without appearing in `list`.
///
/// Zero when the list was not full: nothing was cut, so absence really does
/// mean the directory was not there. When the list *is* full, absence only
/// means "smaller than the smallest row", and that row is the bound.
fn absence_bound(list: &[(String, u64)]) -> u64 {
    if list.len() < LARGEST_TRACKED {
        return 0;
    }
    list.iter().map(|(_, bytes)| *bytes).min().unwrap_or(0)
}

fn compare_pairs(previous: &[(String, u64)], current: &[(String, u64)]) -> Vec<Change> {
    let before: BTreeMap<String, u64> = previous.iter().cloned().collect();
    let after: BTreeMap<String, u64> = current.iter().cloned().collect();

    // A directory that crosses the edge of the top-N list is the awkward case.
    // Treating its absence as zero turns "grew from 900 MB to 1.0 GB" into
    // "+1.0 GB, created", and turns a directory merely pushed off the list by
    // busier neighbours into a deletion that never happened. Substituting the
    // list's floor instead yields the smallest change the data can prove, so
    // the figure is always an understatement rather than an invention.
    let before_bound = absence_bound(previous);
    let after_bound = absence_bound(current);

    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort_unstable();
    keys.dedup();

    keys.into_iter()
        .filter_map(|key| {
            let was = before.get(key).copied().unwrap_or(before_bound) as i64;
            let now = after.get(key).copied().unwrap_or(after_bound) as i64;
            let delta = now - was;
            (delta != 0).then(|| Change {
                label: key.to_string(),
                delta,
            })
        })
        .collect()
}

/// How many rows of a change list a report lists before counting the rest.
pub const REPORTED_CHANGES: usize = 10;

/// The rows of a ranked change list worth a line of their own, at most
/// `limit` of them.
///
/// The floor is a thousandth of the biggest mover: a +79 B lockfile under a
/// +75 MB build tree is real but not reportable at this altitude, while a
/// small tree whose biggest change is a few kilobytes still shows everything.
/// Every frontend filters through here so they list the same rows, and each
/// says how many it left out rather than hiding them silently.
#[must_use]
pub fn reportable(changes: &[Change], limit: usize) -> Vec<&Change> {
    let floor = changes
        .iter()
        .map(|change| change.delta.abs())
        .max()
        .unwrap_or(0)
        / 1_000;
    changes
        .iter()
        .filter(|change| change.delta.abs() > floor)
        .take(limit)
        .collect()
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

/// The shortest recorded span, in seconds, from which a "full around" date is
/// projected.
///
/// Two scans an hour apart can measure a rate, but extrapolating a build
/// afternoon out to a calendar date is exactly the kind of confident nonsense
/// Bloatrail exists to avoid. Two days is the floor at which a daily average
/// has seen at least one overnight lull and one working day.
pub const MIN_PROJECTION_SPAN: u64 = 48 * 60 * 60;

/// Beyond this many days, a projected exhaustion date is reported as "more
/// than a year away" rather than as a date: the trend will not survive that
/// long, and a specific day would be theatre.
pub const MAX_PROJECTION_DAYS: f64 = 365.0;

/// One recorded scan, reduced to the figures the growth report plots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowthPoint {
    /// When the scan ran, in seconds since the Unix epoch.
    pub timestamp: u64,
    /// Total bytes under the scanned root.
    pub bytes: u64,
    /// Free bytes on the volume, when the snapshot recorded them.
    pub disk_available: Option<u64>,
    /// Bytes judged recoverable, when the snapshot recorded them.
    pub reclaimable: Option<u64>,
}

/// The volume's trajectory across the recorded window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VolumeTrend {
    /// Free bytes at the first usable point.
    pub first_available: u64,
    /// Free bytes at the last usable point.
    pub last_available: u64,
    /// Timestamp of the first usable point.
    pub first_timestamp: u64,
    /// Timestamp of the last usable point.
    pub last_timestamp: u64,
    /// Change in free bytes per day, averaged over the window. Negative means
    /// the volume is filling.
    pub rate_per_day: i64,
    /// Projected moment the volume runs out.
    ///
    /// Present only when free space is falling, the window spans at least
    /// [`MIN_PROJECTION_SPAN`], and the date lands within
    /// [`MAX_PROJECTION_DAYS`]. [`VolumeTrend::projection`] says which.
    pub full_at: Option<u64>,
    /// Why `full_at` is present or absent.
    pub projection: Projection,
}

/// What the volume trend was able to say about the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Projection {
    /// Free space is falling and the window is long enough: `full_at` is set.
    FullAround,
    /// Free space is falling, but the exhaustion date is more than
    /// [`MAX_PROJECTION_DAYS`] away.
    MoreThanAYear,
    /// Free space is falling, but the recorded window is shorter than
    /// [`MIN_PROJECTION_SPAN`] — too short to extrapolate from.
    WindowTooShort,
    /// Free space did not fall over the window.
    NotShrinking,
}

/// Everything `bloatrail growth` reports, computed from the recorded series.
#[derive(Debug, Clone)]
pub struct Growth {
    /// The recorded scans, oldest first.
    pub points: Vec<GrowthPoint>,
    /// Seconds between the first and last point.
    pub span: u64,
    /// Category-level changes from the first point to the last, largest
    /// magnitude first.
    pub categories: Vec<Change>,
    /// Directory-level changes from the first point to the last, largest
    /// magnitude first.
    pub directories: Vec<Change>,
    /// Net change in the scanned tree's bytes.
    pub net: i64,
    /// The volume's trajectory, when enough snapshots recorded free space.
    pub volume: Option<VolumeTrend>,
    /// Bytes judged recoverable at the most recent scan.
    pub reclaimable_now: Option<u64>,
}

/// Analyse a recorded series of snapshots, oldest first.
///
/// Returns `None` only for an empty series. A single snapshot yields a report
/// with one point and no changes — the starting line, which the renderers
/// present as such rather than as an error, because it is how every first run
/// arrives here. Attribution compares the first snapshot against the last —
/// the question is "what happened across this window", not a chain of
/// pairwise diffs.
#[must_use]
pub fn growth(snapshots: &[Snapshot]) -> Option<Growth> {
    let (first, last) = match snapshots {
        [] => return None,
        [only] => (only, only),
        [first, .., last] => (first, last),
    };

    let points: Vec<GrowthPoint> = snapshots
        .iter()
        .map(|snapshot| GrowthPoint {
            timestamp: snapshot.timestamp,
            bytes: snapshot.bytes,
            disk_available: snapshot.disk_available,
            reclaimable: snapshot.reclaimable,
        })
        .collect();

    Some(Growth {
        span: last.timestamp.saturating_sub(first.timestamp),
        categories: rank(compare_maps(&first.categories, &last.categories, label_for)),
        directories: directory_changes(&first.largest, &last.largest),
        net: last.bytes as i64 - first.bytes as i64,
        volume: volume_trend(snapshots),
        reclaimable_now: last.reclaimable,
        points,
    })
}

/// The volume trajectory, from the snapshots that recorded free space.
///
/// Only points whose recorded capacity matches the most recent one are used: a
/// capacity that changed mid-window means the disk was replaced or resized,
/// and a rate straddling that event would measure the hardware change, not the
/// usage.
/// Change in free bytes per second, as a least-squares fit over every point.
///
/// Not `(last - first) / span`. Bloatrail's own `clean` command frees space,
/// so on any machine where the tool is actually used, the window very often
/// ends with *more* free space than it started with. Differencing the
/// endpoints reads that as "not shrinking" and withholds the projection
/// entirely — the tool's most-engaged users would be the ones it goes quiet
/// for, which is precisely backwards.
///
/// A fit through all the points keeps the underlying downward drift visible
/// through a one-off reclaim, and reduces to the endpoint difference when only
/// two points exist. `x` is measured from `origin` rather than the epoch, so a
/// 1.7-billion-second timestamp cannot eat the precision of the slope.
fn fill_rate(points: &[(u64, u64)], origin: u64) -> f64 {
    let n = points.len() as f64;
    if n < 2.0 {
        return 0.0;
    }

    let xs: Vec<f64> = points
        .iter()
        .map(|(t, _)| (t.saturating_sub(origin)) as f64)
        .collect();
    let ys: Vec<f64> = points.iter().map(|(_, free)| *free as f64).collect();

    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;

    let mut covariance = 0.0;
    let mut variance = 0.0;
    for (x, y) in xs.iter().zip(&ys) {
        covariance += (x - mean_x) * (y - mean_y);
        variance += (x - mean_x) * (x - mean_x);
    }

    if variance == 0.0 {
        return 0.0;
    }
    covariance / variance
}

fn volume_trend(snapshots: &[Snapshot]) -> Option<VolumeTrend> {
    let current_total = snapshots.iter().rev().find_map(|s| s.disk_total)?;

    let usable: Vec<(u64, u64)> = snapshots
        .iter()
        .filter(|s| s.disk_total == Some(current_total))
        .filter_map(|s| Some((s.timestamp, s.disk_available?)))
        .collect();

    let (&(first_timestamp, first_available), &(last_timestamp, last_available)) =
        (usable.first()?, usable.last()?);
    let span = last_timestamp.saturating_sub(first_timestamp);
    if span == 0 {
        return None;
    }

    let per_second = fill_rate(&usable, first_timestamp);
    let rate_per_day = (per_second * 86_400.0).round() as i64;

    let (projection, full_at) = if per_second >= 0.0 {
        (Projection::NotShrinking, None)
    } else if span < MIN_PROJECTION_SPAN {
        (Projection::WindowTooShort, None)
    } else {
        let days_left = last_available as f64 / (-per_second * 86_400.0);
        if days_left > MAX_PROJECTION_DAYS {
            (Projection::MoreThanAYear, None)
        } else {
            // Rounded, not truncated: the projection is a day on a calendar,
            // and a float's last bit should not be able to move it.
            let full_at = last_timestamp + (days_left * 86_400.0).round() as u64;
            (Projection::FullAround, Some(full_at))
        }
    };

    Some(VolumeTrend {
        first_available,
        last_available,
        first_timestamp,
        last_timestamp,
        rate_per_day,
        full_at,
        projection,
    })
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

    // Two scans inside the same second must not overwrite each other — the
    // filename is the identity. The nudge is to the name alone: the snapshot
    // keeps its true timestamp, and lexical order still matches write order.
    let mut name = snapshot.timestamp;
    let mut path = dir.join(format!("{name:020}.json"));
    while path.exists() {
        name += 1;
        path = dir.join(format!("{name:020}.json"));
    }
    let text = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(&path, text).map_err(|error| Error::io(&path, error))?;

    prune(&dir);
    Ok(path)
}

/// Which snapshots to keep, given their timestamps (ascending) and "now".
///
/// A flat "keep the newest N" is the wrong shape for this data. `scan`, `diff`
/// and `growth` all record, so a person exploring the tool for an afternoon
/// can emit twenty snapshots in an hour — and under a flat cap those evict the
/// weeks of history that make a trend meaningful. The feature would eat its
/// own input on first contact.
///
/// So resolution is traded for reach: everything in the last week, one a day
/// for the last month, one a week for the year beyond that. The newest and
/// oldest are always kept — they are the endpoints of the reported window.
///
/// Pure and total, so it is tested without touching a filesystem.
#[must_use]
pub fn retain(now: u64, timestamps: &[u64]) -> Vec<bool> {
    let mut keep = vec![false; timestamps.len()];
    if timestamps.is_empty() {
        return keep;
    }

    // Walk newest first, keeping one per bucket as the buckets widen.
    let mut last_kept: Option<u64> = None;
    for (index, &stamp) in timestamps.iter().enumerate().rev() {
        let age = now.saturating_sub(stamp);
        let spacing = if age <= KEEP_ALL_WITHIN {
            0
        } else if age <= KEEP_DAILY_WITHIN {
            86_400
        } else if age <= KEEP_WEEKLY_WITHIN {
            7 * 86_400
        } else {
            // Older than the longest window the report will ever draw.
            continue;
        };

        let far_enough = last_kept.is_none_or(|kept| kept.saturating_sub(stamp) >= spacing);
        if far_enough {
            keep[index] = true;
            last_kept = Some(stamp);
        }
    }

    // The endpoints define the window every report quotes, so neither is ever
    // thinned away — including an oldest snapshot past the weekly horizon,
    // which is the only record that the window is as long as it is.
    keep[timestamps.len() - 1] = true;
    if let Some(first) = keep.first_mut() {
        *first = true;
    }

    // Ceiling, applied oldest-first so the densest recent detail survives.
    let mut kept = keep.iter().filter(|k| **k).count();
    for (index, flag) in keep.iter_mut().enumerate() {
        if kept <= MAX_SNAPSHOTS {
            break;
        }
        if *flag && index != timestamps.len() - 1 {
            *flag = false;
            kept -= 1;
        }
    }

    keep
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
    if files.len() <= 1 {
        return;
    }
    // Names are zero-padded timestamps, so lexical order is chronological.
    files.sort();

    // The name is the timestamp, so thinning needs no file reads. A name that
    // does not parse is left alone rather than guessed at.
    let stamps: Vec<u64> = files
        .iter()
        .map(|path| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        })
        .collect();
    if stamps.contains(&0) {
        return;
    }

    let now = stamps.last().copied().unwrap_or(0);
    for (path, keep) in files.iter().zip(retain(now, &stamps)) {
        if !keep {
            let _ = std::fs::remove_file(path);
        }
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
            disk_total: None,
            disk_available: None,
            reclaimable: None,
        }
    }

    fn volume_snapshot(timestamp: u64, total: u64, available: u64) -> Snapshot {
        Snapshot {
            disk_total: Some(total),
            disk_available: Some(available),
            reclaimable: Some(0),
            ..snapshot(timestamp, 100, &[], &[])
        }
    }

    const DAY: u64 = 86_400;
    const GB: u64 = 1 << 30;

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

    fn changes(rows: &[(&str, i64)]) -> Vec<Change> {
        rows.iter()
            .map(|(label, delta)| Change {
                label: (*label).to_string(),
                delta: *delta,
            })
            .collect()
    }

    fn labels(changes: &[Change]) -> Vec<&str> {
        changes.iter().map(|c| c.label.as_str()).collect()
    }

    #[test]
    fn an_ancestor_explained_by_its_descendant_is_dropped() {
        let mut rows = changes(&[("api", 55), ("api/target", 55)]);
        collapse_explained_ancestors(&mut rows);
        assert_eq!(labels(&rows), vec!["api/target"]);
    }

    #[test]
    fn an_ancestor_with_its_own_story_survives() {
        // 55 of the 65 came from `target`; the other 10 grew elsewhere in
        // `api`, which is exactly what the ancestor row is there to say.
        let mut rows = changes(&[("api", 65), ("api/target", 55)]);
        collapse_explained_ancestors(&mut rows);
        assert_eq!(labels(&rows), vec!["api", "api/target"]);
    }

    #[test]
    fn a_chain_of_explained_ancestors_collapses_to_the_deepest() {
        let mut rows = changes(&[("a", 55), ("a/b", 55), ("a/b/c", 55)]);
        collapse_explained_ancestors(&mut rows);
        assert_eq!(labels(&rows), vec!["a/b/c"]);
    }

    #[test]
    fn a_shrinking_child_does_not_explain_a_growing_parent() {
        // The child lost 50 while the parent still gained 10, so 60 grew
        // somewhere else inside the parent. Both rows carry real signal.
        let mut rows = changes(&[("api", 10), ("api/logs", -50)]);
        collapse_explained_ancestors(&mut rows);
        assert_eq!(labels(&rows), vec!["api", "api/logs"]);
    }

    #[test]
    fn name_prefixes_are_not_path_ancestry() {
        let mut rows = changes(&[("app", 30), ("app2/dist", 30)]);
        collapse_explained_ancestors(&mut rows);
        assert_eq!(labels(&rows), vec!["app", "app2/dist"]);
    }

    #[test]
    fn diff_directories_collapse_explained_ancestors_too() {
        let before = snapshot(1, 0, &[], &[("api", 100), ("api/target", 90)]);
        let after = snapshot(2, 0, &[], &[("api", 160), ("api/target", 150)]);
        let diff = diff(&before, &after);
        assert_eq!(labels(&diff.directories), vec!["api/target"]);
    }

    fn largest(rows: &[(&str, u64)]) -> Vec<(String, u64)> {
        rows.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn a_directory_entering_a_full_list_is_not_reported_as_created() {
        // 25 rows means the list was truncated, so "absent" cannot be read as
        // "zero bytes". `newcomer` was at most 1000 before — the floor — so the
        // provable growth is 200, not the 1200 that endpoint-differencing
        // against zero would have claimed.
        let mut before = largest(&[("newcomer", 0)]);
        before.clear();
        for i in 0..LARGEST_TRACKED {
            before.push((format!("dir{i}"), 1000 + i as u64));
        }
        let mut after = before.clone();
        after.pop();
        after.push(("newcomer".to_string(), 1200));

        let changes = compare_pairs(&before, &after);
        let newcomer = changes.iter().find(|c| c.label == "newcomer").expect("row");
        assert_eq!(
            newcomer.delta, 200,
            "growth must be bounded by the list floor"
        );
    }

    #[test]
    fn a_short_list_still_reports_a_genuine_creation_in_full() {
        // Only three rows: nothing was cut, so absence really does mean zero
        // and the full size is the honest delta.
        let before = largest(&[("a", 10), ("b", 20)]);
        let after = largest(&[("a", 10), ("b", 20), ("c", 500)]);
        let changes = compare_pairs(&before, &after);
        let c = changes.iter().find(|c| c.label == "c").expect("row");
        assert_eq!(c.delta, 500);
    }

    #[test]
    fn a_cleanup_inside_the_window_does_not_silence_the_projection() {
        // Twelve days of steady filling, then a big reclaim on day 13. Free
        // space ends higher than it started, so comparing the endpoints would
        // report "not shrinking" and refuse to project — going quiet for the
        // very people who use `clean`.
        let mut series: Vec<Snapshot> = (0..13)
            .map(|day| volume_snapshot(day * DAY, 100 * GB, (40 - day) * GB))
            .collect();
        series.push(volume_snapshot(13 * DAY, 100 * GB, 45 * GB));

        let trend = growth(&series).unwrap().volume.expect("trend");
        assert!(
            trend.rate_per_day < 0,
            "the underlying downward drift must survive one reclaim, got {}",
            trend.rate_per_day
        );
        assert_eq!(trend.projection, Projection::FullAround);
    }

    #[test]
    fn thinning_keeps_recent_detail_and_still_reaches_back() {
        let now = 400 * DAY;
        // Six scans in one afternoon, plus a weekly series going back a year.
        let mut stamps: Vec<u64> = (0..52).map(|w| (400 - 7 * (52 - w)) * DAY).collect();
        stamps.extend((0..6).map(|i| now - i * 600));
        stamps.sort_unstable();

        let keep = retain(now, &stamps);
        let kept: Vec<u64> = stamps
            .iter()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(s, _)| *s)
            .collect();

        assert_eq!(
            kept.first(),
            stamps.first(),
            "the oldest point anchors the window"
        );
        assert_eq!(
            kept.last(),
            stamps.last(),
            "the newest point is always kept"
        );
        // Nothing inside the keep-everything window is thinned, whether it is
        // one of today's six scans or a weekly point that happens to land in
        // the last seven days.
        let recent = |s: &u64| now - *s <= KEEP_ALL_WITHIN;
        assert_eq!(
            kept.iter().filter(|s| recent(s)).count(),
            stamps.iter().filter(|s| recent(s)).count(),
            "this week's detail survives in full"
        );
        assert!(kept.len() <= MAX_SNAPSHOTS);
    }

    #[test]
    fn thinning_an_afternoon_of_scans_never_discards_the_past() {
        // The regression that motivated age-thinning: a flat cap of 20 meant
        // 25 scans in one hour evicted every older point.
        let now = 90 * DAY;
        let old: Vec<u64> = (0..10).map(|w| (90 - 7 * (10 - w)) * DAY).collect();
        let mut stamps = old.clone();
        stamps.extend((0..25).map(|i| now - i * 120));
        stamps.sort_unstable();

        let keep = retain(now, &stamps);
        let kept: Vec<u64> = stamps
            .iter()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(s, _)| *s)
            .collect();

        assert!(
            kept.contains(&old[0]),
            "the oldest snapshot must survive a burst of new ones"
        );
        assert!(
            kept.len() > 10,
            "the older series is not collapsed to nothing"
        );
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

    #[test]
    fn snapshots_recorded_before_the_environment_fields_still_load() {
        // A 0.3.0 snapshot, verbatim: no disk figures, no reclaimable.
        let text = r#"{"version":1,"root":"/scan","timestamp":9,"bytes":10,
                       "files":1,"dirs":1,"categories":{},"largest":[]}"#;
        let parsed: Snapshot = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.disk_total, None);
        assert_eq!(parsed.disk_available, None);
        assert_eq!(parsed.reclaimable, None);
    }

    #[test]
    fn a_single_snapshot_is_a_starting_line_with_nothing_to_compare() {
        assert!(growth(&[]).is_none());

        let only = growth(&[snapshot(1, 10, &[("cache", 10)], &[])]).expect("one point");
        assert_eq!(only.points.len(), 1);
        assert_eq!(only.span, 0);
        assert_eq!(only.net, 0);
        assert!(only.categories.is_empty(), "nothing changed against itself");
        assert!(only.volume.is_none());
    }

    #[test]
    fn growth_attributes_across_the_whole_window_not_the_last_pair() {
        let series = [
            snapshot(1, 100, &[("cache", 100)], &[("a", 100)]),
            snapshot(2, 900, &[("cache", 900)], &[("a", 900)]),
            snapshot(3, 400, &[("cache", 400)], &[("a", 400)]),
        ];
        let growth = growth(&series).expect("three points");
        assert_eq!(growth.net, 300, "first vs last, not the pairwise spike");
        assert_eq!(growth.categories[0].delta, 300);
        assert_eq!(growth.directories[0].label, "a");
        assert_eq!(growth.points.len(), 3);
        assert_eq!(growth.span, 2);
    }

    #[test]
    fn a_steadily_filling_volume_earns_a_projected_date() {
        // Losing 1 GB/day over four recorded days, 10 GB free at the last
        // point: full ten days after it.
        let series: Vec<Snapshot> = (0..5)
            .map(|day| volume_snapshot(day * DAY, 100 * GB, (14 - day) * GB))
            .collect();
        let trend = growth(&series).unwrap().volume.expect("trend");

        assert_eq!(trend.rate_per_day, -(GB as i64));
        assert_eq!(trend.projection, Projection::FullAround);
        let full_at = trend.full_at.expect("a date");
        assert_eq!(full_at, 4 * DAY + 10 * DAY);
    }

    #[test]
    fn a_short_window_measures_a_rate_but_names_no_date() {
        let series = [
            volume_snapshot(0, 100 * GB, 10 * GB),
            volume_snapshot(3_600, 100 * GB, 9 * GB),
        ];
        let trend = growth(&series).unwrap().volume.expect("trend");
        assert!(trend.rate_per_day < 0);
        assert_eq!(trend.projection, Projection::WindowTooShort);
        assert_eq!(trend.full_at, None);
    }

    #[test]
    fn a_recovering_volume_projects_nothing() {
        let series = [
            volume_snapshot(0, 100 * GB, 10 * GB),
            volume_snapshot(3 * DAY, 100 * GB, 20 * GB),
        ];
        let trend = growth(&series).unwrap().volume.expect("trend");
        assert!(trend.rate_per_day > 0);
        assert_eq!(trend.projection, Projection::NotShrinking);
        assert_eq!(trend.full_at, None);
    }

    #[test]
    fn a_distant_exhaustion_is_not_given_a_date() {
        // Losing 1 MB/day with 10 GB free: over 27 years away.
        let series = [
            volume_snapshot(0, 100 * GB, 10 * GB),
            volume_snapshot(10 * DAY, 100 * GB, 10 * GB - 10 * (1 << 20)),
        ];
        let trend = growth(&series).unwrap().volume.expect("trend");
        assert_eq!(trend.projection, Projection::MoreThanAYear);
        assert_eq!(trend.full_at, None);
    }

    #[test]
    fn a_replaced_disk_does_not_pollute_the_rate() {
        // Three points on a 100 GB disk losing ground, preceded by one from
        // the 50 GB disk it replaced. Straddling the swap would measure the
        // hardware change; the old point must be ignored.
        let series = [
            volume_snapshot(0, 50 * GB, 40 * GB),
            volume_snapshot(10 * DAY, 100 * GB, 30 * GB),
            volume_snapshot(12 * DAY, 100 * GB, 28 * GB),
            volume_snapshot(14 * DAY, 100 * GB, 26 * GB),
        ];
        let trend = growth(&series).unwrap().volume.expect("trend");
        assert_eq!(trend.first_timestamp, 10 * DAY);
        assert_eq!(trend.rate_per_day, -(GB as i64));
    }

    #[test]
    fn snapshots_without_disk_figures_yield_no_volume_trend() {
        let series = [snapshot(1, 10, &[], &[]), snapshot(2, 20, &[], &[])];
        let growth = growth(&series).expect("two points");
        assert!(growth.volume.is_none());
        assert_eq!(growth.net, 10);
    }

    #[test]
    fn with_environment_records_what_it_was_given() {
        let bare = snapshot(1, 10, &[], &[]).with_environment(None, 7);
        assert_eq!(bare.disk_total, None);
        assert_eq!(bare.reclaimable, Some(7));

        let disk = crate::platform::DiskUsage {
            total: 100,
            available: 40,
        };
        let full = snapshot(1, 10, &[], &[]).with_environment(Some(disk), 7);
        assert_eq!(full.disk_total, Some(100));
        assert_eq!(full.disk_available, Some(40));
    }

    /// Scan a real temporary tree: a Rust project with build output, plus
    /// more sibling directories than a snapshot tracks.
    fn scanned_tree() -> (tempfile::TempDir, ScanResult) {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("api/src")).unwrap();
        std::fs::create_dir_all(root.join("api/target/debug")).unwrap();
        std::fs::write(root.join("api/Cargo.toml"), b"[package]\nname = \"p\"\n").unwrap();
        std::fs::write(root.join("api/Cargo.lock"), b"# lock\n").unwrap();
        std::fs::write(root.join("api/src/main.rs"), [b'x'; 256]).unwrap();
        std::fs::write(root.join("api/target/debug/app"), vec![b'x'; 64 * 1024]).unwrap();
        for i in 0..LARGEST_TRACKED + 5 {
            let folder = root.join(format!("notes-{i:02}"));
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("a.txt"), vec![b'x'; 100 + i]).unwrap();
        }

        let options = crate::scanner::ScanOptions::new(root);
        let scan = crate::scanner::scan(
            &options,
            &crate::analysis::Classifier::with_default_detectors(),
            &crate::platform::KnownPaths::empty(),
        )
        .expect("scan");
        (dir, scan)
    }

    #[test]
    fn capture_records_the_scan_and_the_machine_around_it() {
        let (_dir, scan) = scanned_tree();
        let stale_days = crate::scanner::DEFAULT_STALE_DAYS;
        let captured = Snapshot::capture(&scan, stale_days);

        assert_eq!(captured.root, scan.root);
        assert_eq!(captured.bytes, scan.totals.bytes);
        assert_eq!(captured.files, scan.totals.files);
        assert_eq!(captured.dirs, scan.totals.dirs);

        // The top-N list is exactly what comparison assumes it is: a full
        // list is a truncated one, which is how absence gets its bound.
        assert_eq!(captured.largest.len(), LARGEST_TRACKED);
        assert_eq!(
            captured.largest,
            Snapshot::from_scan(&scan, LARGEST_TRACKED).largest
        );

        // The recoverable figure is the one `clean` would report for this
        // scan, and the build output makes it more than nothing.
        let plan = crate::cleanup::CleanupPlan::from_scan_with(&scan, stale_days);
        assert_eq!(captured.reclaimable, Some(plan.recoverable().0));
        assert!(captured.reclaimable.unwrap_or(0) >= 64 * 1024);

        // Volume figures are recorded wherever the platform can report them.
        let disk = crate::platform::disk_usage(&scan.root);
        assert_eq!(captured.disk_total.is_some(), disk.is_some());
        assert_eq!(captured.disk_available.is_some(), disk.is_some());
    }

    #[test]
    fn reportable_rows_skip_noise_and_respect_the_limit() {
        let mut rows = changes(&[("target", 75 << 20), ("Cargo.lock", 79)]);
        assert_eq!(labels_of(&reportable(&rows, 10)), vec!["target"]);

        rows = changes(&[("a", 900), ("b", -800), ("c", 700), ("d", 600)]);
        assert_eq!(labels_of(&reportable(&rows, 2)), vec!["a", "b"]);

        assert!(reportable(&[], 10).is_empty());
    }

    fn labels_of<'a>(rows: &[&'a Change]) -> Vec<&'a str> {
        rows.iter().map(|change| change.label.as_str()).collect()
    }
}

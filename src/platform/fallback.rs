//! Neutral implementations for targets that are neither Windows nor Unix.
//!
//! Bloatrail's core is portable; only these three primitives need native
//! support. Where it is unavailable the features that depend on it (disk
//! capacity in `doctor`, `--same-filesystem`) degrade to "unknown" instead of
//! failing the build.

use std::fs::Metadata;
use std::path::Path;

use super::DiskUsage;

/// Disk capacity is unavailable on this target.
#[must_use]
pub fn disk_usage(_path: &Path) -> Option<DiskUsage> {
    None
}

/// Fall back to the portable symlink check.
#[must_use]
pub fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Filesystem identity is unavailable, so `--same-filesystem` cannot restrict
/// traversal on this target.
#[must_use]
pub fn volume_id(_path: &Path, _meta: &Metadata) -> Option<u64> {
    None
}

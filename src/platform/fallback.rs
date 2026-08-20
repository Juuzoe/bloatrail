//! Neutral implementations for targets that are neither Windows nor Unix.
//!
//! Bloatrail's core is portable; only these four primitives need native
//! support. Where it is unavailable the features that depend on it degrade
//! rather than failing the build: disk capacity in `doctor` reads "unknown",
//! `--same-filesystem` cannot restrict traversal, and `duplicates` treats
//! every name as its own copy the way it did before hardlink folding.

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

/// File identity is unavailable, so hardlinks cannot be recognised and every
/// path is treated as its own copy.
#[must_use]
pub fn file_identity(_path: &Path) -> Option<super::FileIdentity> {
    None
}

//! Unix-specific filesystem facts (Linux, macOS and friends).

use std::ffi::CString;
use std::fs::Metadata;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use super::DiskUsage;

/// Capacity and free space of the filesystem containing `path`.
#[must_use]
pub fn disk_usage(path: &Path) -> Option<DiskUsage> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };

    // SAFETY: `c_path` is a valid NUL-terminated C string and `stat` is a live,
    // correctly sized, zero-initialised `statvfs`.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        return None;
    }

    // `f_frsize` is the fragment size; some platforms report 0, in which case
    // `f_bsize` is the right multiplier.
    let block = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    let total = (stat.f_blocks as u64).saturating_mul(block);
    if total == 0 {
        return None;
    }
    Some(DiskUsage {
        total,
        available: (stat.f_bavail as u64).saturating_mul(block),
    })
}

/// On Unix the analogue of a reparse point is a symbolic link.
#[must_use]
pub fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// The device number identifying the filesystem an entry lives on.
#[must_use]
pub fn volume_id(_path: &Path, meta: &Metadata) -> Option<u64> {
    Some(meta.dev() as u64)
}

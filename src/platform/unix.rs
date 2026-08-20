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
///
/// `MetadataExt::dev` returns `u64` on every Unix target, so no cast is needed.
#[must_use]
pub fn volume_id(_path: &Path, meta: &Metadata) -> Option<u64> {
    Some(meta.dev())
}

/// The identity facts one `stat` reveals about a file.
///
/// Two paths with the same `id` are hardlinks of one inode: the same bytes on
/// disk, reachable under two names. Inode 0 cannot be trusted to distinguish
/// files, so it degrades the identity to `None` while the link count — which
/// is meaningful regardless — survives.
#[must_use]
pub fn file_identity(path: &Path) -> Option<super::FileIdentity> {
    let meta = std::fs::metadata(path).ok()?;
    Some(super::FileIdentity {
        id: (meta.ino() != 0).then(|| (meta.dev(), meta.ino())),
        links: meta.nlink().max(1),
    })
}

//! Windows-specific filesystem facts.
//!
//! Bloatrail deliberately avoids a heavyweight Win32 binding: the four
//! primitives it needs (free space, reparse-point detection, a volume identity
//! and a file identity) are two FFI calls plus two attribute checks.

use std::fs::Metadata;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use super::DiskUsage;

/// `FILE_ATTRIBUTE_REPARSE_POINT` from `winnt.h`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// `BY_HANDLE_FILE_INFORMATION` from `fileapi.h`. The three `FILETIME` fields
/// are kept as `u32` pairs because nothing here reads them.
#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(
        directory_name: *const u16,
        free_bytes_available_to_caller: *mut u64,
        total_number_of_bytes: *mut u64,
        total_number_of_free_bytes: *mut u64,
    ) -> i32;

    fn GetFileInformationByHandle(
        file: std::os::windows::io::RawHandle,
        file_information: *mut ByHandleFileInformation,
    ) -> i32;
}

/// Capacity and free space of the volume containing `path`.
///
/// Returns `None` when the path cannot be queried (removed drive, permission
/// error, unusual filesystem) — callers treat that as "unknown", never as zero.
#[must_use]
pub fn disk_usage(path: &Path) -> Option<DiskUsage> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut available: u64 = 0;
    let mut total: u64 = 0;
    let mut free: u64 = 0;

    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call,
    // and the three out-pointers reference live, correctly sized locals.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut free) };

    if ok == 0 || total == 0 {
        return None;
    }
    Some(DiskUsage { total, available })
}

/// Whether an entry is a reparse point (symlink, junction or mount point).
///
/// Junctions are how Windows grafts one volume into another's namespace, so
/// this is the check that makes `--same-filesystem` meaningful here.
#[must_use]
pub fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// An identifier for the volume a path lives on.
///
/// Windows exposes the true volume serial number only through an open file
/// handle, which would cost one `CreateFile` per directory. Bloatrail instead
/// uses the path prefix (drive letter or UNC share) and refuses to traverse
/// reparse points when `--same-filesystem` is set — together those give the
/// same practical guarantee without the syscall.
#[must_use]
pub fn volume_id(path: &Path, _meta: &Metadata) -> Option<u64> {
    use std::hash::{Hash, Hasher};
    use std::path::{Component, Prefix};

    let prefix = path.components().next().and_then(|c| match c {
        Component::Prefix(p) => Some(p),
        _ => None,
    })?;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            letter.to_ascii_uppercase().hash(&mut hasher);
        }
        other => {
            // UNC and device paths: hash the whole prefix.
            format!("{other:?}").hash(&mut hasher);
        }
    }
    Some(hasher.finish())
}

/// The identity facts one handle query reveals about a file.
///
/// Two paths with the same `id` are hardlinks of one NTFS file record: the
/// same bytes on disk under two names. A file ID of all zeros, or the all-ones
/// marker ReFS reports for IDs that do not fit in 64 bits, cannot be trusted
/// to distinguish files, so it degrades the identity to `None` while the link
/// count — which is meaningful regardless — survives. Costs an open handle, so
/// callers should reserve it for files already suspected of colliding.
#[must_use]
pub fn file_identity(path: &Path) -> Option<super::FileIdentity> {
    let file = std::fs::File::open(path).ok()?;
    // SAFETY: zero is a valid bit pattern for a struct of plain integers.
    let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };

    // SAFETY: the handle is open for the duration of the call and `info` is a
    // live, correctly laid out `BY_HANDLE_FILE_INFORMATION`.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return None;
    }

    let index = (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
    Some(super::FileIdentity {
        id: (index != 0 && index != u64::MAX)
            .then_some((u64::from(info.volume_serial_number), index)),
        links: u64::from(info.number_of_links).max(1),
    })
}

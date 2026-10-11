//! Win32 calls that std does not expose. Every `unsafe` block passes a live handle owned by a
//! `File` borrowed for the duration of the call, plus pointers to correctly sized local buffers.

#![allow(unsafe_code)]

use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::ops::Range;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALLOCATION_INFO, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_ID_INFO, FileAllocationInfo,
    FileDispositionInfo, FileDispositionInfoEx, FileIdInfo, GetDiskFreeSpaceExW, GetDiskFreeSpaceW,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
    GetVolumePathNameW, MOVEFILE_WRITE_THROUGH, MoveFileExW, ReOpenFile,
    SetFileInformationByHandle,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{
    FILE_ALLOCATED_RANGE_BUFFER, FILE_ZERO_DATA_INFORMATION, FSCTL_QUERY_ALLOCATED_RANGES,
    FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};

/// `FILE_FLAG_BACKUP_SEMANTICS`: required to open a directory handle.
pub(crate) const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open the link itself rather than its target.
pub(crate) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
pub(crate) const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
/// Access rights for `OpenOptions::access_mode` and [`reopen`].
pub(crate) const GENERIC_READ: u32 = 0x8000_0000;
pub(crate) const DELETE: u32 = 0x0001_0000;
pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
/// `FILE_SHARE_*` flags for `OpenOptions::share_mode`.
pub(crate) const FILE_SHARE_READ: u32 = 1;
pub(crate) const FILE_SHARE_WRITE: u32 = 2;
/// `FILE_SUPPORTS_SPARSE_FILES` volume flag.
const FILE_SUPPORTS_SPARSE_FILES: u32 = 0x0040;
/// Cloud Files placeholder attributes (OneDrive and other sync providers).
pub(crate) const CLOUD_ATTRIBUTES: u32 = 0x0004_0000 // RECALL_ON_OPEN
    | 0x0008_0000 // PINNED
    | 0x0010_0000 // UNPINNED
    | 0x0040_0000; // RECALL_ON_DATA_ACCESS

fn handle(f: &File) -> HANDLE {
    f.as_raw_handle() as HANDLE
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn u32_len<T>() -> u32 {
    u32::try_from(size_of::<T>()).expect("struct size fits in u32")
}

/// Mark a file sparse so zeroed ranges can be deallocated.
pub(crate) fn set_sparse(f: &File) -> io::Result<()> {
    let mut returned = 0u32;
    // SAFETY: valid handle; a null input buffer means "set sparse" for FSCTL_SET_SPARSE; no
    // output buffer; `returned` outlives the call; no OVERLAPPED (synchronous handle).
    let ok = unsafe {
        DeviceIoControl(
            handle(f),
            FSCTL_SET_SPARSE,
            null(),
            0,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    check(ok)
}

/// Zero `[start, end)`; on a sparse file whole allocation units in the range are freed.
pub(crate) fn zero_range(f: &File, start: u64, end: u64) -> io::Result<()> {
    let info = FILE_ZERO_DATA_INFORMATION {
        FileOffset: i64::try_from(start).map_err(|_| io::ErrorKind::InvalidInput)?,
        BeyondFinalZero: i64::try_from(end).map_err(|_| io::ErrorKind::InvalidInput)?,
    };
    let mut returned = 0u32;
    // SAFETY: valid handle; input pointer and size describe `info`, which outlives the call.
    let ok = unsafe {
        DeviceIoControl(
            handle(f),
            FSCTL_SET_ZERO_DATA,
            (&raw const info).cast::<c_void>(),
            u32_len::<FILE_ZERO_DATA_INFORMATION>(),
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    };
    check(ok)
}

/// Allocated ranges of a file of length `len`.
pub(crate) fn allocated_ranges(f: &File, len: u64) -> io::Result<Vec<Range<u64>>> {
    let mut out = Vec::new();
    let mut from = 0u64;
    let mut buf: Vec<FILE_ALLOCATED_RANGE_BUFFER> = Vec::with_capacity(64);
    loop {
        if from >= len {
            return Ok(out);
        }
        let query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: i64::try_from(from).map_err(|_| io::ErrorKind::InvalidInput)?,
            Length: i64::try_from(len - from).map_err(|_| io::ErrorKind::InvalidInput)?,
        };
        let cap = u32::try_from(buf.capacity() * size_of::<FILE_ALLOCATED_RANGE_BUFFER>())
            .expect("buffer size fits in u32");
        let mut returned = 0u32;
        // SAFETY: valid handle; input describes `query`; output pointer/size describe the
        // spare capacity of `buf`, which the call fills with whole FILE_ALLOCATED_RANGE_BUFFERs.
        let ok = unsafe {
            DeviceIoControl(
                handle(f),
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&raw const query).cast::<c_void>(),
                u32_len::<FILE_ALLOCATED_RANGE_BUFFER>(),
                buf.as_mut_ptr().cast::<c_void>(),
                cap,
                &mut returned,
                null_mut(),
            )
        };
        // SAFETY: reading the thread's last-error value has no preconditions.
        let more = ok == 0 && unsafe { GetLastError() } == ERROR_MORE_DATA;
        if ok == 0 && !more {
            return Err(io::Error::last_os_error());
        }
        let n = returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        // SAFETY: the call initialised exactly `n` elements.
        unsafe { buf.set_len(n) };
        for r in &buf {
            let s = u64::try_from(r.FileOffset).unwrap_or(0);
            let l = u64::try_from(r.Length).unwrap_or(0);
            out.push(s..s + l);
        }
        if !more || n == 0 {
            return Ok(out);
        }
        from = out.last().map_or(len, |r| r.end);
        buf.clear();
    }
}

/// Set the file's allocation size. After shrinking the end of file, this releases the clusters
/// beyond it immediately; with only the end-of-file change, NTFS keeps them allocated until the
/// last handle closes (measured: `tests/os.rs::shrinking_frees_space_while_open`).
pub(crate) fn set_allocation(f: &File, len: u64) -> io::Result<()> {
    let info = FILE_ALLOCATION_INFO {
        AllocationSize: i64::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?,
    };
    // SAFETY: valid handle; input pointer/size describe `info`, which outlives the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle(f),
            FileAllocationInfo,
            (&raw const info).cast::<c_void>(),
            u32_len::<FILE_ALLOCATION_INFO>(),
        )
    };
    check(ok)
}

/// Volume serial and 128-bit file id.
pub(crate) fn file_id(f: &File) -> io::Result<(u64, u128)> {
    // SAFETY: FILE_ID_INFO is plain data; all-zero is a valid value.
    let mut info: FILE_ID_INFO = unsafe { zeroed() };
    // SAFETY: valid handle; output pointer/size describe `info`.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle(f),
            FileIdInfo,
            (&raw mut info).cast::<c_void>(),
            u32_len::<FILE_ID_INFO>(),
        )
    };
    check(ok)?;
    Ok((
        info.VolumeSerialNumber,
        u128::from_le_bytes(info.FileId.Identifier),
    ))
}

pub(crate) struct VolumeFacts {
    pub fs_name: String,
    pub serial: u32,
    pub supports_sparse: bool,
}

/// Filesystem name, serial and capability flags of the volume holding an open file or directory.
pub(crate) fn volume_facts(f: &File) -> io::Result<VolumeFacts> {
    let mut fs_name = [0u16; 64];
    let mut serial = 0u32;
    let mut max_component = 0u32;
    let mut flags = 0u32;
    // SAFETY: valid handle; the name buffer is not requested (null, 0); every output pointer
    // refers to a live local of the documented type; the fs-name buffer length is in u16s.
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            handle(f),
            null_mut(),
            0,
            &mut serial,
            &mut max_component,
            &mut flags,
            fs_name.as_mut_ptr(),
            u32::try_from(fs_name.len()).expect("small"),
        )
    };
    check(ok)?;
    let n = fs_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name.len());
    Ok(VolumeFacts {
        fs_name: String::from_utf16_lossy(&fs_name[..n]),
        serial,
        supports_sparse: flags & FILE_SUPPORTS_SPARSE_FILES != 0,
    })
}

/// Root of the volume containing `path` (e.g. `C:\`).
pub(crate) fn volume_root(path: &Path) -> io::Result<PathBuf> {
    let p = wide(path.as_os_str());
    let mut out = vec![0u16; 1024];
    // SAFETY: `p` is NUL-terminated; output pointer/length (in u16s) describe `out`.
    let ok = unsafe {
        GetVolumePathNameW(
            p.as_ptr(),
            out.as_mut_ptr(),
            u32::try_from(out.len()).expect("small"),
        )
    };
    check(ok)?;
    let n = out.iter().position(|&c| c == 0).unwrap_or(out.len());
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&out[..n])))
}

/// (free bytes available to the caller, total bytes) for the volume holding `dir`.
pub(crate) fn disk_space(dir: &Path) -> io::Result<(u64, u64)> {
    let p = wide(dir.as_os_str());
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    // SAFETY: `p` is NUL-terminated; outputs are live locals.
    let ok = unsafe { GetDiskFreeSpaceExW(p.as_ptr(), &mut avail, &mut total, &mut free) };
    check(ok)?;
    Ok((avail, total))
}

/// Cluster size of the volume whose root is `root`.
pub(crate) fn cluster_size(root: &Path) -> io::Result<u32> {
    let p = wide(root.as_os_str());
    let (mut spc, mut bps, mut free, mut total) = (0u32, 0u32, 0u32, 0u32);
    // SAFETY: `p` is NUL-terminated; outputs are live locals.
    let ok = unsafe { GetDiskFreeSpaceW(p.as_ptr(), &mut spc, &mut bps, &mut free, &mut total) };
    check(ok)?;
    Ok(spc.saturating_mul(bps))
}

/// Rename that fails if `to` exists (no MOVEFILE_REPLACE_EXISTING), written through to disk.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (wide(from.as_os_str()), wide(to.as_os_str()));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let ok = unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    check(ok)
}

/// A new handle on the very file `f` refers to, with other access and sharing (`ReOpenFile`: a
/// relative open of the file itself, not of its path).
pub(crate) fn reopen(f: &File, access: u32, share: u32, flags: u32) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle;
    // SAFETY: valid handle; the call takes no pointers.
    let h = unsafe { ReOpenFile(handle(f), access, share, flags) };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` is a fresh, valid handle that nothing else owns.
    Ok(unsafe { File::from_raw_handle(h) })
}

/// Delete the file or empty directory an open handle refers to, by the handle rather than by a
/// path that could have been redirected since. The handle needs `DELETE` access. POSIX semantics
/// remove the name at once; older Windows (and filesystems without them) fall back to the
/// classic delete-on-close.
pub(crate) fn delete_by_handle(f: &File) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: valid handle; input pointer/size describe `info`, which outlives the call.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle(f),
            FileDispositionInfoEx,
            (&raw const info).cast::<c_void>(),
            u32_len::<FILE_DISPOSITION_INFO_EX>(),
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
    // SAFETY: as above, for `info`.
    let ok = unsafe {
        SetFileInformationByHandle(
            handle(f),
            FileDispositionInfo,
            (&raw const info).cast::<c_void>(),
            u32_len::<FILE_DISPOSITION_INFO>(),
        )
    };
    check(ok)
}

/// Where a handle really is, after every junction and link: its volume serial number and its
/// path within that volume (`\\dir\\file`, case as stored on disk). Leaving out the drive name
/// (`VOLUME_NAME_NONE`) avoids a slow mount-manager query; the serial tells volumes apart.
pub(crate) fn final_path(f: &File) -> io::Result<(u64, PathBuf)> {
    const VOLUME_NAME_NONE: u32 = 0x4;
    let volume = file_id(f)?.0;
    let mut buf = vec![0u16; 512];
    loop {
        let cap = u32::try_from(buf.len()).expect("small buffer");
        // SAFETY: valid handle; the output pointer and `cap` describe `buf`, which outlives the
        // call; the API writes at most `cap` UTF-16 units.
        let n = unsafe {
            GetFinalPathNameByHandleW(handle(f), buf.as_mut_ptr(), cap, VOLUME_NAME_NONE)
        } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            return Ok((volume, PathBuf::from(std::ffi::OsString::from_wide(&buf))));
        }
        buf.resize(n + 1, 0);
    }
}

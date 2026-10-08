//! The real filesystem.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::{
    Dealloc, FileHandle, FileId, FsBackend, FsError, FsKind, Meta, NodeKind, OpenMode, Result,
    Share, SnapshotHint, VolumeInfo,
};

/// The operating system's filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsFs;

impl OsFs {
    pub fn new() -> Self {
        OsFs
    }
}

#[cfg(windows)]
const FILE_SHARE_READ: u32 = 1;

#[derive(Debug)]
struct OsFile {
    file: File,
    path: PathBuf,
    #[cfg(windows)]
    sparse: std::sync::atomic::AtomicBool,
    /// Lazily opened unbuffered handle for `read_back`.
    #[cfg(windows)]
    uncached: std::sync::Mutex<Option<File>>,
}

fn err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> FsError + 'a {
    move |e| FsError::from_io(op, path, e)
}

/// Nearest existing ancestor of `path` (itself if it exists).
fn existing_ancestor(path: &Path) -> Result<PathBuf> {
    let abs = std::path::absolute(path).map_err(err("resolving", path))?;
    let mut p = abs.as_path();
    loop {
        if fs::symlink_metadata(p).is_ok() {
            return Ok(p.to_path_buf());
        }
        p = p.parent().ok_or_else(|| FsError::NotFound {
            path: path.to_path_buf(),
        })?;
    }
}

impl FsBackend for OsFs {
    fn open(&self, path: &Path, mode: OpenMode, share: Share) -> Result<Box<dyn FileHandle>> {
        let mut oo = OpenOptions::new();
        oo.read(true);
        match mode {
            OpenMode::Read => {}
            OpenMode::ReadWrite => {
                oo.write(true);
            }
            OpenMode::CreateNew => {
                oo.write(true).create_new(true);
            }
            OpenMode::CreateOrTruncate => {
                oo.write(true).create(true).truncate(true);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            oo.custom_flags(crate::win::FILE_FLAG_OPEN_REPARSE_POINT);
            if share == Share::Exclusive {
                oo.share_mode(FILE_SHARE_READ);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = share;
            // Without openat2 (phase 5) this check is racy; it still stops the common case.
            if let Ok(md) = fs::symlink_metadata(path) {
                if md.file_type().is_symlink() {
                    return Err(FsError::Link {
                        path: path.to_path_buf(),
                    });
                }
            }
        }
        let file = match oo.open(path) {
            Ok(f) => f,
            // Opening a directory junction as a file fails with a generic access error; report
            // what is actually there.
            Err(e) => {
                if let Ok(Some(Meta {
                    kind: NodeKind::Link,
                    ..
                })) = self.metadata(path)
                {
                    return Err(FsError::Link {
                        path: path.to_path_buf(),
                    });
                }
                return Err(FsError::from_io("opening", path, e));
            }
        };
        let md = file.metadata().map_err(err("reading metadata of", path))?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if md.file_attributes() & crate::win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(FsError::Link {
                    path: path.to_path_buf(),
                });
            }
        }
        if !md.is_file() {
            return Err(FsError::Io {
                op: "opening",
                path: path.to_path_buf(),
                source: io::Error::other("not a regular file"),
            });
        }
        Ok(Box::new(OsFile {
            file,
            path: path.to_path_buf(),
            #[cfg(windows)]
            sparse: std::sync::atomic::AtomicBool::new(false),
            #[cfg(windows)]
            uncached: std::sync::Mutex::new(None),
        }))
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        fs::create_dir(path).map_err(err("creating directory", path))
    }

    fn flush_dir(&self, dir: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // NTFS journals directory changes; flushing a directory handle forces the log and
            // the directory's metadata to disk.
            let d = OpenOptions::new()
                .write(true)
                .custom_flags(crate::win::FILE_FLAG_BACKUP_SEMANTICS)
                .open(dir)
                .map_err(err("opening directory", dir))?;
            d.sync_all().map_err(err("flushing directory", dir))
        }
        #[cfg(not(windows))]
        {
            let d = File::open(dir).map_err(err("opening directory", dir))?;
            d.sync_all().map_err(err("flushing directory", dir))
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            crate::win::rename_noreplace(from, to).map_err(err("renaming", from))
        }
        #[cfg(not(windows))]
        {
            // renameat2(RENAME_NOREPLACE) arrives with the Linux backend (phase 5).
            if fs::symlink_metadata(to).is_ok() {
                return Err(FsError::AlreadyExists {
                    path: to.to_path_buf(),
                });
            }
            fs::rename(from, to).map_err(err("renaming", from))
        }
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        fs::remove_file(path).map_err(err("removing", path))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        fs::remove_dir(path).map_err(err("removing directory", path))
    }

    fn metadata(&self, path: &Path) -> Result<Option<Meta>> {
        match fs::symlink_metadata(path) {
            Ok(md) => {
                let ft = md.file_type();
                #[cfg(windows)]
                let is_link = {
                    use std::os::windows::fs::MetadataExt;
                    ft.is_symlink()
                        || md.file_attributes() & crate::win::FILE_ATTRIBUTE_REPARSE_POINT != 0
                };
                #[cfg(not(windows))]
                let is_link = ft.is_symlink();
                let kind = if is_link {
                    NodeKind::Link
                } else if ft.is_dir() {
                    NodeKind::Dir
                } else if ft.is_file() {
                    NodeKind::File
                } else {
                    NodeKind::Other
                };
                Ok(Some(Meta {
                    kind,
                    len: md.len(),
                }))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(FsError::from_io("reading metadata of", path, e)),
        }
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(path).map_err(err("listing", path))? {
            let entry = entry.map_err(err("listing", path))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn set_mode(&self, path: &Path, mode: u32) -> Result<()> {
        if self.metadata(path)?.map(|m| m.kind) == Some(NodeKind::Link) {
            return Err(FsError::Link {
                path: path.to_path_buf(),
            });
        }
        #[cfg(unix)]
        let perms = {
            use std::os::unix::fs::PermissionsExt;
            fs::Permissions::from_mode(mode & 0o777)
        };
        #[cfg(not(unix))]
        let perms = {
            let mut p = fs::metadata(path)
                .map_err(err("reading metadata of", path))?
                .permissions();
            p.set_readonly(mode & 0o222 == 0);
            p
        };
        fs::set_permissions(path, perms).map_err(err("setting permissions of", path))
    }

    fn probe_volume(&self, path: &Path) -> Result<VolumeInfo> {
        let at = existing_ancestor(path)?;
        let sync = crate::sync::detect_sync(&at);
        #[cfg(windows)]
        {
            probe_windows(&at, sync)
        }
        #[cfg(not(windows))]
        {
            Ok(VolumeInfo {
                fs: FsKind::Unknown,
                fs_name: "unknown".into(),
                root: None,
                volume_id: unix_dev(&at),
                cluster_size: 4096,
                free_bytes: None,
                total_bytes: None,
                supports_sparse: false,
                sparse_granularity: 0,
                max_file_size: u64::MAX,
                sync,
                snapshots: SnapshotHint::Unknown(
                    "filesystem probing on this platform arrives with the Linux backend".into(),
                ),
            })
        }
    }
}

#[cfg(windows)]
fn probe_windows(at: &Path, sync: crate::SyncHint) -> Result<VolumeInfo> {
    use std::os::windows::fs::OpenOptionsExt;
    let root = crate::win::volume_root(at).map_err(err("finding volume of", at))?;
    let h = OpenOptions::new()
        .read(true)
        .custom_flags(crate::win::FILE_FLAG_BACKUP_SEMANTICS)
        .open(&root)
        .map_err(err("opening volume root", &root))?;
    let facts = crate::win::volume_facts(&h).map_err(err("querying volume", &root))?;
    let fs_kind = FsKind::from_name(&facts.fs_name);
    let cluster = crate::win::cluster_size(&root).unwrap_or(4096);
    let space_at = if at.is_dir() {
        at.to_path_buf()
    } else {
        at.parent().unwrap_or(at).to_path_buf()
    };
    let (free, total) = crate::win::disk_space(&space_at)
        .map(|(a, t)| (Some(a), Some(t)))
        .unwrap_or((None, None));
    let sparse_granularity = match fs_kind {
        // NTFS frees sparse ranges in compression-unit sized pieces (16 clusters). Measured by
        // tests/os_windows.rs::sparse_granularity_matches_probe.
        FsKind::Ntfs if facts.supports_sparse => cluster.saturating_mul(16),
        _ if facts.supports_sparse => cluster,
        _ => 0,
    };
    Ok(VolumeInfo {
        fs: fs_kind,
        fs_name: facts.fs_name,
        root: Some(root),
        volume_id: Some(u64::from(facts.serial)),
        cluster_size: cluster,
        free_bytes: free,
        total_bytes: total,
        supports_sparse: facts.supports_sparse,
        sparse_granularity,
        max_file_size: if fs_kind == FsKind::Fat32 {
            (4u64 << 30) - 1
        } else {
            u64::MAX
        },
        sync,
        snapshots: SnapshotHint::Unknown(
            "Volume Shadow Copies cannot be listed without administrator rights; System Restore \
             points may keep truncated data allocated"
                .into(),
        ),
    })
}

#[cfg(unix)]
fn unix_dev(p: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| m.dev())
}

#[cfg(not(any(unix, windows)))]
fn unix_dev(_p: &Path) -> Option<u64> {
    None
}

impl OsFile {
    fn e<'a>(&'a self, op: &'static str) -> impl FnOnce(io::Error) -> FsError + 'a {
        err(op, &self.path)
    }
}

impl FileHandle for OsFile {
    fn path(&self) -> &Path {
        &self.path
    }

    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> Result<()> {
        while !buf.is_empty() {
            match read_at(&self.file, buf, off) {
                Ok(0) => {
                    return Err(FsError::from_io(
                        "reading",
                        &self.path,
                        io::ErrorKind::UnexpectedEof.into(),
                    ));
                }
                Ok(n) => {
                    buf = &mut buf[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(FsError::from_io("reading", &self.path, e)),
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn read_back(&self, buf: &mut [u8], off: u64) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        const ALIGN: u64 = 4096; // covers 512-byte and 4 KiB sectors
        const ALIGN_BYTES: usize = 4096;
        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        let mut guard = self
            .uncached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let f = OpenOptions::new()
                .read(true)
                .share_mode(7) // read | write | delete: coexist with our own writer handle
                .custom_flags(FILE_FLAG_NO_BUFFERING | crate::win::FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&self.path)
                .map_err(self.e("opening for verification"))?;
            *guard = Some(f);
        }
        let f = guard.as_ref().expect("set above");
        // Unbuffered reads need sector-aligned offsets, lengths and memory.
        let start = off / ALIGN * ALIGN;
        let end = (off + buf.len() as u64).div_ceil(ALIGN) * ALIGN;
        let span = usize::try_from(end - start)
            .map_err(|_| self.e("verifying")(io::ErrorKind::InvalidInput.into()))?;
        let mut raw = vec![0u8; span + ALIGN_BYTES];
        let a = raw.as_ptr().align_offset(ALIGN_BYTES);
        let aligned = &mut raw[a..a + span];
        let mut got = 0usize;
        while got < span {
            match read_at(f, &mut aligned[got..], start + got as u64) {
                // Unbuffered reads are only ever short at end of file; continuing from an
                // unaligned offset would fail with ERROR_INVALID_PARAMETER.
                Ok(n) if n < span - got => {
                    got += n;
                    break;
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(FsError::from_io("verifying", &self.path, e)),
            }
        }
        let rel = usize::try_from(off - start).expect("< ALIGN");
        if got < rel + buf.len() {
            return Err(FsError::from_io(
                "verifying",
                &self.path,
                io::ErrorKind::UnexpectedEof.into(),
            ));
        }
        buf.copy_from_slice(&aligned[rel..rel + buf.len()]);
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> Result<()> {
        while !buf.is_empty() {
            match write_at(&self.file, buf, off) {
                Ok(0) => {
                    return Err(FsError::from_io(
                        "writing",
                        &self.path,
                        io::ErrorKind::WriteZero.into(),
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(FsError::from_io("writing", &self.path, e)),
            }
        }
        Ok(())
    }

    fn size(&self) -> Result<u64> {
        Ok(self
            .file
            .metadata()
            .map_err(self.e("reading size of"))?
            .len())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        #[cfg(windows)]
        let shrinking = len < self.size()?;
        self.file.set_len(len).map_err(self.e("resizing"))?;
        #[cfg(windows)]
        if shrinking {
            crate::win::set_allocation(&self.file, len).map_err(self.e("releasing space of"))?;
        }
        Ok(())
    }

    fn preallocate(&self, len: u64) -> Result<()> {
        // NTFS allocates clusters for the new length of a non-sparse file, so running out of
        // space shows up here. (fallocate on Linux arrives in phase 5.)
        if len > self.size()? {
            self.set_len(len)?;
        }
        Ok(())
    }

    fn flush_data(&self) -> Result<()> {
        self.file.sync_data().map_err(self.e("flushing"))
    }

    fn deallocate(&self, start: u64, end: u64) -> Result<Dealloc> {
        if start >= end {
            return Ok(Dealloc::Freed {
                freed: start..start,
            });
        }
        #[cfg(windows)]
        {
            use std::sync::atomic::Ordering;
            if !self.sparse.load(Ordering::Relaxed) {
                match crate::win::set_sparse(&self.file) {
                    Ok(()) => self.sparse.store(true, Ordering::Relaxed),
                    // ERROR_INVALID_FUNCTION: the filesystem (FAT, exFAT) has no sparse files.
                    Err(e) if e.raw_os_error() == Some(1) => return Ok(Dealloc::Unsupported),
                    Err(e) => return Err(FsError::from_io("marking sparse", &self.path, e)),
                }
            }
            crate::win::zero_range(&self.file, start, end).map_err(self.e("deallocating"))?;
            // Report what is actually unallocated now within the request.
            let len = self.size()?;
            let allocated = crate::win::allocated_ranges(&self.file, len)
                .map_err(self.e("querying allocation of"))?;
            Ok(Dealloc::Freed {
                freed: largest_hole(&allocated, start, end.min(len)),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Dealloc::Unsupported)
        }
    }

    fn allocated_ranges(&self) -> Result<Vec<Range<u64>>> {
        let len = self.size()?;
        #[cfg(windows)]
        {
            crate::win::allocated_ranges(&self.file, len).map_err(self.e("querying allocation of"))
        }
        #[cfg(not(windows))]
        {
            Ok(if len == 0 {
                vec![]
            } else {
                vec![Range { start: 0, end: len }]
            })
        }
    }

    fn file_id(&self) -> Result<FileId> {
        #[cfg(windows)]
        {
            let (volume, file) =
                crate::win::file_id(&self.file).map_err(self.e("reading file id of"))?;
            Ok(FileId { volume, file })
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let md = self.file.metadata().map_err(self.e("reading file id of"))?;
            Ok(FileId {
                volume: md.dev(),
                file: u128::from(md.ino()),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(FsError::Unsupported {
                op: "file id",
                path: self.path.clone(),
            })
        }
    }

    fn set_modified(&self, t: SystemTime) -> Result<()> {
        self.file
            .set_modified(t)
            .map_err(self.e("setting mtime of"))
    }
}

/// The largest unallocated sub-range of `[start, end)` given the allocated ranges.
#[cfg_attr(not(windows), allow(dead_code))]
fn largest_hole(allocated: &[Range<u64>], start: u64, end: u64) -> Range<u64> {
    let mut best = start..start;
    let mut cursor = start;
    for r in allocated.iter().filter(|r| r.end > start && r.start < end) {
        if r.start > cursor && r.start - cursor > best.end - best.start {
            best = cursor..r.start.min(end);
        }
        cursor = cursor.max(r.end);
    }
    if end > cursor && end - cursor > best.end - best.start {
        best = cursor..end;
    }
    best
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(f, buf, off)
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(f, buf, off)
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(f, buf, off)
}

#[cfg(windows)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(f, buf, off)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::single_range_in_vec_init)] // a list holding one allocated range is intended
    fn largest_hole_cases() {
        assert_eq!(largest_hole(&[], 10, 20), 10..20);
        assert_eq!(largest_hole(&[0..100], 10, 20), 10..10);
        assert_eq!(largest_hole(&[0..12, 18..30], 10, 20), 12..18);
        assert_eq!(largest_hole(&[0..12, 14..15, 30..40], 10, 20), 15..20);
    }
}

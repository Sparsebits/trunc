//! Filesystem backend abstraction.
//!
//! The consume engine performs every filesystem operation through [`FsBackend`] and
//! [`FileHandle`], so the same code runs against:
//!
//! - [`OsFs`]: the real filesystem. On Windows it adds NTFS sparse-file deallocation, `FILE_ID_INFO`
//!   identities, volume probing and no-replace renames. On Linux: hole punching, `fallocate`
//!   reservations, `openat2` confinement, `renameat2` no-replace renames, `O_DIRECT` read-back,
//!   advisory locks and mount lookup. Other platforms get the std-only subset.
//! - `trunc_testkit::FaultFs`: an in-memory filesystem that injects crashes, torn writes, lost
//!   unflushed data, space exhaustion and mapped-file truncation failures.
//!
//! This is the only crate allowed to contain `unsafe` code, confined to the `win` module.

use std::fmt::Debug;
use std::io;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

mod error;
#[cfg(target_os = "linux")]
mod linux;
mod os;
mod sync;
#[cfg(windows)]
mod win;

pub use error::{FsError, Result};
pub use os::OsFs;
pub use sync::detect_sync;

/// Stable identity of an open file: volume plus file number. Two handles with equal ids refer to
/// the same file even through different paths (hard links, renames).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub volume: u64,
    pub file: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    /// Symlink, junction or any other reparse point. Never followed.
    Link,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub kind: NodeKind,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Existing file, read only.
    Read,
    /// Existing file, read and write.
    ReadWrite,
    /// New file; fails if anything exists at the path.
    CreateNew,
    /// Create or truncate a regular file.
    CreateOrTruncate,
}

impl OpenMode {
    pub fn writes(self) -> bool {
        !matches!(self, OpenMode::Read)
    }

    pub fn creates(self) -> bool {
        matches!(self, OpenMode::CreateNew | OpenMode::CreateOrTruncate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Share {
    /// Other processes may read, write and delete concurrently.
    Shared,
    /// Other handles may read but not write or delete while this one exists. Readers are allowed
    /// so antivirus scanners, indexers and our own uncached verification handle can coexist;
    /// nothing can change the file under us. Enforced on Windows. On Linux it is an advisory
    /// `flock` (exclusive for writers, shared for readers): it stops a second trunc, not
    /// arbitrary programs.
    Exclusive,
}

/// Outcome of [`FileHandle::deallocate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dealloc {
    /// The requested range now reads as zeros and `freed` (aligned inward to the filesystem's
    /// deallocation unit, possibly empty) no longer occupies disk space.
    Freed { freed: Range<u64> },
    /// The filesystem cannot deallocate ranges; nothing was changed.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Ntfs,
    ReFs,
    Fat32,
    ExFat,
    Ext4,
    Xfs,
    Btrfs,
    Zfs,
    Apfs,
    /// In-memory test filesystem.
    Memory,
    Unknown,
}

impl FsKind {
    /// Whether metadata changes (sizes, directory entries) are journaled, so a crash leaves the
    /// filesystem consistent. Destructive mode requires this unless explicitly overridden.
    pub fn journaled(self) -> bool {
        matches!(
            self,
            FsKind::Ntfs
                | FsKind::ReFs
                | FsKind::Ext4
                | FsKind::Xfs
                | FsKind::Btrfs
                | FsKind::Zfs
                | FsKind::Apfs
                | FsKind::Memory
        )
    }

    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_uppercase().as_str() {
            "NTFS" => FsKind::Ntfs,
            "REFS" => FsKind::ReFs,
            "FAT32" | "FAT" | "VFAT" => FsKind::Fat32,
            "EXFAT" => FsKind::ExFat,
            "EXT4" => FsKind::Ext4,
            "XFS" => FsKind::Xfs,
            "BTRFS" => FsKind::Btrfs,
            "ZFS" => FsKind::Zfs,
            "APFS" => FsKind::Apfs,
            _ => FsKind::Unknown,
        }
    }
}

/// A cloud-sync client that appears to manage a path. Destructive mode refuses to run there:
/// every truncation could be uploaded, replacing the cloud copy of the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncHint {
    None,
    OneDrive,
    Dropbox,
    GoogleDrive,
    ICloud,
    /// Cloud Files placeholder attributes are present but the provider is not known.
    CloudFiles,
}

/// Whether filesystem snapshots may keep truncated blocks allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotHint {
    None,
    /// Snapshots exist or are likely (with the mechanism named).
    Present(String),
    /// Could not be determined (with the reason).
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub fs: FsKind,
    /// Filesystem name as reported by the OS.
    pub fs_name: String,
    /// Volume root (e.g. `C:\`), if known.
    pub root: Option<PathBuf>,
    /// Volume serial / device number, for same-volume checks.
    pub volume_id: Option<u64>,
    pub cluster_size: u32,
    /// Bytes available to the current user.
    pub free_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub supports_sparse: bool,
    /// Unit in which deallocated ranges are actually freed (0 if unsupported).
    pub sparse_granularity: u32,
    pub max_file_size: u64,
    pub sync: SyncHint,
    pub snapshots: SnapshotHint,
}

impl VolumeInfo {
    pub fn journaled(&self) -> bool {
        self.fs.journaled()
    }
}

/// An open file.
pub trait FileHandle: Send + Sync + Debug {
    /// Path the file was opened at (diagnostics only; the file may have been renamed since).
    fn path(&self) -> &Path;
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> Result<()>;
    /// Read what is on the storage device, bypassing the OS cache where the platform allows
    /// (Windows: `FILE_FLAG_NO_BUFFERING`). Used to verify written data before releasing the
    /// source. The drive's own cache may still answer. The default reads normally.
    fn read_back(&self, buf: &mut [u8], off: u64) -> Result<()> {
        self.read_exact_at(buf, off)
    }
    fn write_all_at(&self, buf: &[u8], off: u64) -> Result<()>;
    fn size(&self) -> Result<u64>;
    /// Truncate or extend. Shrinking a file that another process has memory-mapped fails with
    /// [`FsError::Mapped`], which callers should retry.
    fn set_len(&self, len: u64) -> Result<()>;
    /// Reserve space for `len` bytes so that running out of space surfaces now rather than
    /// mid-write. Never shrinks.
    fn preallocate(&self, len: u64) -> Result<()>;
    /// Make written data (and the file's size) durable: `FlushFileBuffers` / `fdatasync`.
    fn flush_data(&self) -> Result<()>;
    /// Zero `[start, end)` and free whatever whole allocation units it covers.
    fn deallocate(&self, start: u64, end: u64) -> Result<Dealloc>;
    /// Ranges that occupy disk space (the whole file when the filesystem has no sparse support).
    fn allocated_ranges(&self) -> Result<Vec<Range<u64>>>;
    fn file_id(&self) -> Result<FileId>;
    fn set_modified(&self, t: SystemTime) -> Result<()>;
    /// Last modification time, where the backend records one.
    fn modified(&self) -> Result<Option<SystemTime>> {
        Ok(None)
    }
}

/// Filesystem operations the engine needs. Paths are never followed through links: opening or
/// creating at a path that is a symlink or junction fails with [`FsError::Link`].
pub trait FsBackend: Send + Sync + Debug {
    fn open(&self, path: &Path, mode: OpenMode, share: Share) -> Result<Box<dyn FileHandle>>;
    /// Like [`open`](Self::open), for a `path` inside the directory `root`: no component between
    /// `root` and the file may be a link, and `..` may not climb out. Linux enforces this
    /// atomically (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`); the default checks
    /// each existing component first, which a concurrent local attacker could race.
    fn open_beneath(
        &self,
        root: &Path,
        path: &Path,
        mode: OpenMode,
        share: Share,
    ) -> Result<Box<dyn FileHandle>> {
        check_beneath(self, root, path)?;
        self.open(path, mode, share)
    }
    /// Create one directory; fails if anything already exists at the path.
    fn create_dir(&self, path: &Path) -> Result<()>;
    /// [`create_dir`](Self::create_dir) with the confinement of
    /// [`open_beneath`](Self::open_beneath).
    fn create_dir_beneath(&self, root: &Path, path: &Path) -> Result<()> {
        check_beneath(self, root, path)?;
        self.create_dir(path)
    }
    /// Make directory entries created, renamed or removed in `dir` durable.
    fn flush_dir(&self, dir: &Path) -> Result<()>;
    /// Whether callers may issue calls from several threads at once to hide latency (the OS
    /// backend). The fault-injecting test backend says no, so its operations keep a fixed
    /// order and crash points stay reproducible.
    fn parallel_io(&self) -> bool {
        false
    }
    /// Make the data of every file in `files`, then the entries of every directory in `dirs`,
    /// durable. The OS backend flushes in parallel, which lets the drive and the filesystem
    /// journal combine the work; the result is the same as flushing one by one.
    fn flush_all(&self, files: &[&dyn FileHandle], dirs: &[PathBuf]) -> Result<()> {
        for f in files {
            f.flush_data()?;
        }
        for d in dirs {
            self.flush_dir(d)?;
        }
        Ok(())
    }
    /// Rename without replacing: fails with [`FsError::AlreadyExists`] if `to` exists.
    fn rename(&self, from: &Path, to: &Path) -> Result<()>;
    fn remove_file(&self, path: &Path) -> Result<()>;
    /// Remove an empty directory.
    fn remove_dir(&self, path: &Path) -> Result<()>;
    /// Metadata without following links; `None` if nothing exists at the path.
    fn metadata(&self, path: &Path) -> Result<Option<Meta>>;
    /// Names of the entries in a directory, sorted.
    fn read_dir(&self, path: &Path) -> Result<Vec<String>>;
    /// Describe the volume holding `path` (or its nearest existing ancestor).
    fn probe_volume(&self, path: &Path) -> Result<VolumeInfo>;
    /// Apply Unix permission bits (lower 9 only; Windows honours just the write bits, as the
    /// read-only attribute). Never follows links.
    fn set_mode(&self, path: &Path, mode: u32) -> Result<()>;
}

/// `path` relative to `root`, refusing paths outside it and `..` components.
pub fn relative_beneath<'a>(root: &Path, path: &'a Path) -> Result<&'a Path> {
    let outside = || FsError::Io {
        op: "resolving",
        path: path.to_path_buf(),
        source: io::Error::other(format!("not inside {}", root.display())),
    };
    let rel = path.strip_prefix(root).map_err(|_| outside())?;
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(outside());
    }
    Ok(rel)
}

/// Check that every existing directory between `root` and `path` (exclusive) is a real directory.
/// Missing components are left for the following open or create to report.
pub fn check_beneath<F: FsBackend + ?Sized>(fs: &F, root: &Path, path: &Path) -> Result<()> {
    let rel = relative_beneath(root, path)?;
    let mut at = root.to_path_buf();
    let mut parts = rel.components().peekable();
    while let Some(c) = parts.next() {
        if parts.peek().is_none() {
            break; // the final component is the open's or create's own business
        }
        at.push(c);
        match fs.metadata(&at)? {
            Some(Meta {
                kind: NodeKind::Dir,
                ..
            }) => {}
            Some(Meta {
                kind: NodeKind::Link,
                ..
            }) => return Err(FsError::Link { path: at }),
            Some(_) => {
                return Err(FsError::Io {
                    op: "resolving",
                    path: at,
                    source: io::Error::other("not a directory"),
                });
            }
            None => return Ok(()),
        }
    }
    Ok(())
}

/// Close (drop) `items` on several threads and wait. Closing a file can take a fraction of a
/// millisecond on Windows (antivirus and indexers look at it), so closing thousands one after
/// another adds up; nothing about durability depends on the order.
pub fn close_all<T: Send>(items: Vec<T>) {
    let _prof = trunc_prof::span("fs.close");
    if items.len() <= 8 {
        drop(items);
        return;
    }
    let threads = items.len().div_ceil(64).min(16);
    let per = items.len().div_ceil(threads);
    let mut items = items;
    std::thread::scope(|s| {
        while !items.is_empty() {
            let chunk: Vec<T> = items.split_off(items.len().saturating_sub(per));
            s.spawn(move || drop(chunk));
        }
    });
}

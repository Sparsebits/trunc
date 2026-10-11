//! The real filesystem.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
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

    /// [`FsBackend::open`] for callers that want a plain [`File`]: a link as the final component
    /// is refused with [`FsError::Link`], and anything but a regular file is refused.
    pub fn open_file(&self, path: &Path, mode: OpenMode, share: Share) -> Result<File> {
        let _prof = trunc_prof::span("fs.open");
        let file = self.open_unchecked(path, mode, share)?;
        // With `Share::Exclusive` on Linux the caller owns the lock with the file. Closing the
        // file alone may not release it while a child process is being started (see
        // [`OsFile`]'s `Drop`); no caller asks for that here.
        check_opened(&file, path, mode, share)?;
        Ok(file)
    }

    fn open_unchecked(&self, path: &Path, mode: OpenMode, share: Share) -> Result<File> {
        match open_options(mode, share).open(path) {
            Ok(f) => Ok(f),
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
                Err(FsError::from_io("opening", path, e))
            }
        }
    }
}

#[derive(Debug)]
struct OsFile {
    file: File,
    path: PathBuf,
    #[cfg(windows)]
    sparse: std::sync::atomic::AtomicBool,
    /// Lazily opened cache-bypassing handle for `read_back`.
    #[cfg(any(windows, target_os = "linux"))]
    uncached: std::sync::Mutex<Uncached>,
    /// Holds the `flock` standing in for `Share::Exclusive`, released explicitly when dropped.
    #[cfg(target_os = "linux")]
    locked: bool,
}

/// Unlock before closing. The lock belongs to the open file description, and closing this
/// descriptor releases it only if it is the last reference. A process being started on another
/// thread holds a copy of every descriptor from fork until exec (`O_CLOEXEC` takes effect only
/// at exec), and keeps the lock for that long: the next exclusive open of the file, by this
/// process, would fail as busy. `LOCK_UN` releases it whatever else refers to the description.
#[cfg(target_os = "linux")]
impl Drop for OsFile {
    fn drop(&mut self) {
        if self.locked {
            crate::linux::unlock(&self.file);
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
#[derive(Debug)]
enum Uncached {
    Untried,
    Open(File),
    /// The filesystem cannot bypass the cache (Linux tmpfs and some FUSE filesystems).
    Unavailable,
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

fn open_options(mode: OpenMode, share: Share) -> OpenOptions {
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
            // On Unix the file is truncated in `check_opened`, after the advisory lock is taken,
            // so an open refused as busy leaves another process's file alone.
            oo.write(true).create(true).truncate(cfg!(not(unix)));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        oo.custom_flags(crate::win::FILE_FLAG_OPEN_REPARSE_POINT);
        if share == Share::Exclusive {
            oo.share_mode(crate::win::FILE_SHARE_READ);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = share;
        // A symlink as the final component fails with ELOOP, which maps to `FsError::Link`.
        #[allow(clippy::cast_possible_wrap)]
        oo.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    oo
}

/// Checks shared by every way of opening: refuse links and non-regular files, and take the
/// advisory lock that stands in for Windows share modes on Linux.
fn finish_open(
    file: File,
    path: &Path,
    mode: OpenMode,
    share: Share,
) -> Result<Box<dyn FileHandle>> {
    let locked = check_opened(&file, path, mode, share)?;
    #[cfg(not(target_os = "linux"))]
    let _ = locked;
    Ok(Box::new(OsFile {
        file,
        path: path.to_path_buf(),
        #[cfg(windows)]
        sparse: std::sync::atomic::AtomicBool::new(false),
        #[cfg(any(windows, target_os = "linux"))]
        uncached: std::sync::Mutex::new(Uncached::Untried),
        #[cfg(target_os = "linux")]
        locked,
    }))
}

/// Returns whether the open took the advisory lock (Linux, `Share::Exclusive`).
fn check_opened(file: &File, path: &Path, mode: OpenMode, share: Share) -> Result<bool> {
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
    #[cfg(target_os = "linux")]
    if share == Share::Exclusive
        && !crate::linux::lock(file, mode.writes()).map_err(err("locking", path))?
    {
        return Err(FsError::Busy {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    if mode == OpenMode::CreateOrTruncate {
        file.set_len(0).map_err(err("truncating", path))?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (mode, share);
    Ok(cfg!(target_os = "linux") && share == Share::Exclusive)
}

/// Errors from the confined Linux calls: EXDEV means the path tried to leave the root.
#[cfg(target_os = "linux")]
fn beneath_err(op: &'static str, path: &Path, e: io::Error) -> FsError {
    if e.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error()) {
        FsError::Link {
            path: path.to_path_buf(),
        }
    } else {
        FsError::from_io(op, path, e)
    }
}

/// Run `f(0..n)` on up to 16 threads; the first error wins. Flushes wait on the device, so
/// running them side by side lets it (and the filesystem journal) serve them together.
fn in_parallel(n: usize, f: &(dyn Fn(usize) -> Result<()> + Sync)) -> Result<()> {
    if n <= 2 {
        return (0..n).try_for_each(f);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failed: std::sync::Mutex<Option<FsError>> = std::sync::Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..n.min(16) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    if let Err(e) = f(i) {
                        let mut slot = failed
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        slot.get_or_insert(e);
                        next.store(n, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                }
            });
        }
    });
    match failed
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// A failed hard link. The errors that mean "this filesystem gives files one name" (FAT, exFAT,
/// some network filesystems) or "this file has all the names it may have" become
/// [`FsError::Unsupported`], so the caller can copy instead.
fn link_err(path: &Path, e: io::Error) -> FsError {
    // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, ERROR_TOO_MANY_LINKS.
    #[cfg(windows)]
    let no_link = matches!(e.raw_os_error(), Some(1 | 50 | 1142));
    #[cfg(unix)]
    let no_link = e.raw_os_error().is_some_and(|n| {
        [
            rustix::io::Errno::PERM,
            rustix::io::Errno::OPNOTSUPP,
            rustix::io::Errno::MLINK,
        ]
        .iter()
        .any(|x| x.raw_os_error() == n)
    });
    #[cfg(not(any(windows, unix)))]
    let no_link = false;
    if no_link {
        FsError::Unsupported {
            op: "hard link",
            path: path.to_path_buf(),
        }
    } else {
        FsError::from_io("linking", path, e)
    }
}

/// A confinement root opened once by `hold_root`. Confined calls under it resolve against this
/// handle (Linux) or check against the location captured from it (Windows), never against
/// whatever the root's path names later.
#[cfg(any(windows, target_os = "linux"))]
#[derive(Debug)]
struct Pinned {
    #[cfg(target_os = "linux")]
    dir: std::os::fd::OwnedFd,
    /// Opened without `FILE_SHARE_DELETE`: while it exists the directory cannot be renamed or
    /// deleted, so its path keeps naming it.
    #[cfg(windows)]
    _dir: File,
    /// Volume serial and in-volume path of the directory.
    #[cfg(windows)]
    real: (u64, PathBuf),
}

#[cfg(any(windows, target_os = "linux"))]
type PinMap = std::collections::HashMap<PathBuf, std::sync::Arc<Pinned>>;
/// Held roots by path. The map owns the handles; a [`Hold`] only removes its own entry.
#[cfg(any(windows, target_os = "linux"))]
static PINNED: std::sync::Mutex<Option<PinMap>> = std::sync::Mutex::new(None);

#[cfg(any(windows, target_os = "linux"))]
fn pins() -> std::sync::MutexGuard<'static, Option<PinMap>> {
    PINNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The pin on `root`, if it is held.
#[cfg(any(windows, target_os = "linux"))]
fn pinned(root: &Path) -> Option<std::sync::Arc<Pinned>> {
    pins().as_ref()?.get(root).cloned()
}

/// The held root that `path` lies beneath, if any.
#[cfg(any(windows, target_os = "linux"))]
fn pinned_above(path: &Path) -> Option<(PathBuf, std::sync::Arc<Pinned>)> {
    let guard = pins();
    let map = guard.as_ref()?;
    path.ancestors()
        .skip(1)
        .find_map(|a| map.get_key_value(a))
        .map(|(k, v)| (k.clone(), v.clone()))
}

/// Returned by `hold_root`: releases the pin when dropped (unless `remove_dir` already did).
#[cfg(any(windows, target_os = "linux"))]
#[derive(Debug)]
struct Hold {
    root: PathBuf,
    pin: std::sync::Weak<Pinned>,
}

#[cfg(any(windows, target_os = "linux"))]
impl Drop for Hold {
    fn drop(&mut self) {
        let mut guard = pins();
        if let Some(map) = guard.as_mut() {
            if map
                .get(&self.root)
                .is_some_and(|p| std::ptr::eq(std::sync::Arc::as_ptr(p), self.pin.as_ptr()))
            {
                map.remove(&self.root);
            }
        }
    }
}

/// Real locations of roots used without `hold_root`, resolved at first use, so each check costs
/// one query on the opened handle.
#[cfg(windows)]
type RootMap = std::collections::HashMap<PathBuf, (u64, PathBuf)>;
#[cfg(windows)]
static ROOTS: std::sync::Mutex<Option<RootMap>> = std::sync::Mutex::new(None);

/// Whether `opened` (at `path`) is really somewhere outside `root`: a junction on the way led
/// elsewhere. One query on the handle instead of checking every component before the open, and
/// it checks the very handle that will be written through. A held root is compared with the
/// location captured when it was pinned.
#[cfg(windows)]
fn outside_root(opened: &File, root: &Path, path: &Path) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    let real = crate::win::final_path(opened).map_err(err("resolving", path))?;
    let root_real = match pinned(root) {
        Some(p) => p.real.clone(),
        None => {
            let mut roots = ROOTS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let map = roots.get_or_insert_with(RootMap::new);
            match map.get(root) {
                Some(r) => r.clone(),
                None => {
                    let d = OpenOptions::new()
                        .read(true)
                        .custom_flags(crate::win::FILE_FLAG_BACKUP_SEMANTICS)
                        .open(root)
                        .map_err(err("opening directory", root))?;
                    let r = crate::win::final_path(&d).map_err(err("resolving", root))?;
                    map.insert(root.to_path_buf(), r.clone());
                    r
                }
            }
        }
    };
    let inside = real.0 == root_real.0 && real.1 != root_real.1 && real.1.starts_with(&root_real.1);
    Ok(!inside)
}

/// Take back something just created through a junction, through its own handle: deleting by
/// path could be redirected to something else by then.
#[cfg(windows)]
fn take_back(opened: File) {
    use crate::win::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES};
    const SHARE_ALL: u32 = 7;
    // The handle may deny sharing deletion (Share::Exclusive): keep the file by an attributes-only
    // handle, which takes no part in sharing checks, close the original, then reopen the file
    // itself for deletion.
    let Ok(attrs) = crate::win::reopen(
        &opened,
        FILE_READ_ATTRIBUTES,
        SHARE_ALL,
        FILE_FLAG_OPEN_REPARSE_POINT,
    ) else {
        return;
    };
    drop(opened);
    if let Ok(d) = crate::win::reopen(&attrs, DELETE, SHARE_ALL, FILE_FLAG_OPEN_REPARSE_POINT) {
        let _ = crate::win::delete_by_handle(&d);
    }
}

/// Open the directory `dir` itself (not a link there) and pin it.
#[cfg(any(windows, target_os = "linux"))]
fn pin_dir(dir: &Path) -> Result<Pinned> {
    let refuse_link = |e: io::Error| {
        if fs::symlink_metadata(dir).is_ok_and(|md| md.file_type().is_symlink()) {
            FsError::Link {
                path: dir.to_path_buf(),
            }
        } else {
            FsError::from_io("opening directory", dir, e)
        }
    };
    #[cfg(target_os = "linux")]
    {
        let fd = crate::linux::open_dir_nofollow(dir).map_err(refuse_link)?;
        Ok(Pinned { dir: fd })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // Read access, not just attributes: a handle without data access takes no part in
        // sharing checks, and would not stop the rename.
        let d = OpenOptions::new()
            .read(true)
            .share_mode(crate::win::FILE_SHARE_READ | crate::win::FILE_SHARE_WRITE)
            .custom_flags(
                crate::win::FILE_FLAG_BACKUP_SEMANTICS | crate::win::FILE_FLAG_OPEN_REPARSE_POINT,
            )
            .open(dir)
            .map_err(refuse_link)?;
        let md = d.metadata().map_err(err("reading metadata of", dir))?;
        if md.file_attributes() & crate::win::FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(FsError::Link {
                path: dir.to_path_buf(),
            });
        }
        if !md.is_dir() {
            return Err(FsError::Io {
                op: "opening directory",
                path: dir.to_path_buf(),
                source: io::Error::other("not a directory"),
            });
        }
        let real = crate::win::final_path(&d).map_err(err("resolving", dir))?;
        Ok(Pinned { _dir: d, real })
    }
}

impl FsBackend for OsFs {
    fn open(&self, path: &Path, mode: OpenMode, share: Share) -> Result<Box<dyn FileHandle>> {
        let _prof = trunc_prof::span("fs.open");
        let file = self.open_unchecked(path, mode, share)?;
        finish_open(file, path, mode, share)
    }

    #[cfg(windows)]
    fn open_beneath(
        &self,
        root: &Path,
        path: &Path,
        mode: OpenMode,
        share: Share,
    ) -> Result<Box<dyn FileHandle>> {
        let _prof = trunc_prof::span("fs.open");
        crate::relative_beneath(root, path)?;
        let file = match open_options(mode, share).open(path) {
            Ok(f) => f,
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
        if outside_root(&file, root, path)? {
            if mode == OpenMode::CreateNew {
                // Created through a junction: it is ours and new, so take it back.
                take_back(file);
            }
            return Err(FsError::Link {
                path: path.to_path_buf(),
            });
        }
        finish_open(file, path, mode, share)
    }

    #[cfg(target_os = "linux")]
    fn open_beneath(
        &self,
        root: &Path,
        path: &Path,
        mode: OpenMode,
        share: Share,
    ) -> Result<Box<dyn FileHandle>> {
        let _prof = trunc_prof::span("fs.open");
        use rustix::fs::OFlags;
        let rel = crate::relative_beneath(root, path)?;
        let flags = match mode {
            OpenMode::Read => OFlags::RDONLY,
            OpenMode::ReadWrite => OFlags::RDWR,
            OpenMode::CreateNew => OFlags::RDWR | OFlags::CREATE | OFlags::EXCL,
            // Truncated in `check_opened`, once the lock is held.
            OpenMode::CreateOrTruncate => OFlags::RDWR | OFlags::CREATE,
        };
        let opened = match pinned(root) {
            Some(pin) => crate::linux::open_beneath(pin.dir.as_fd(), rel, flags),
            None => crate::linux::open_root(root)
                .and_then(|dir| crate::linux::open_beneath(dir.as_fd(), rel, flags)),
        };
        match opened {
            Ok(Some(file)) => finish_open(file, path, mode, share),
            Ok(None) => {
                crate::check_beneath(self, root, path)?;
                self.open(path, mode, share)
            }
            Err(e) => Err(beneath_err("opening", path, e)),
        }
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn hold_root(&self, dir: &Path, create: bool) -> Result<crate::RootHold> {
        if create {
            self.create_dir(dir)?;
        }
        // Opened right after the mkdir, refusing a link or junction put in its place; from here
        // on confined calls go through this handle, not the path.
        let pin = std::sync::Arc::new(pin_dir(dir)?);
        let hold = Hold {
            root: dir.to_path_buf(),
            pin: std::sync::Arc::downgrade(&pin),
        };
        pins()
            .get_or_insert_with(PinMap::new)
            .insert(dir.to_path_buf(), pin);
        Ok(Box::new(hold))
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.create_dir");
        fs::create_dir(path).map_err(err("creating directory", path))
    }

    #[cfg(windows)]
    fn create_dir_beneath(&self, root: &Path, path: &Path) -> Result<()> {
        use std::os::windows::fs::OpenOptionsExt;
        let _prof = trunc_prof::span("fs.create_dir");
        crate::relative_beneath(root, path)?;
        fs::create_dir(path).map_err(err("creating directory", path))?;
        let mut oo = OpenOptions::new();
        oo.custom_flags(
            crate::win::FILE_FLAG_BACKUP_SEMANTICS | crate::win::FILE_FLAG_OPEN_REPARSE_POINT,
        );
        // With DELETE access, so a directory made through a junction can be taken back by this
        // handle. (Directories cannot be reopened by handle the way `take_back` does for files.)
        let all = crate::win::GENERIC_READ | crate::win::DELETE;
        let d = match oo.clone().access_mode(all).open(path) {
            Ok(d) => d,
            // A directory we may create but not delete (unusual ACLs): check without.
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => oo
                .read(true)
                .open(path)
                .map_err(err("opening directory", path))?,
            Err(e) => return Err(FsError::from_io("opening directory", path, e)),
        };
        if outside_root(&d, root, path)? {
            // Created through a junction: take it back by the handle that was checked, never
            // by its path, which a swapped junction could send somewhere else.
            let _ = crate::win::delete_by_handle(&d);
            return Err(FsError::Link {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn create_dir_beneath(&self, root: &Path, path: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.create_dir");
        let rel = crate::relative_beneath(root, path)?;
        let made = match pinned(root) {
            Some(pin) => crate::linux::mkdir_beneath(pin.dir.as_fd(), rel),
            None => crate::linux::open_root(root)
                .and_then(|dir| crate::linux::mkdir_beneath(dir.as_fd(), rel)),
        };
        match made {
            Ok(true) => Ok(()),
            Ok(false) => {
                crate::check_beneath(self, root, path)?;
                self.create_dir(path)
            }
            Err(e) => Err(beneath_err("creating directory", path, e)),
        }
    }

    fn flush_dir(&self, dir: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.flush_dir");
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

    fn parallel_io(&self) -> bool {
        true
    }

    fn flush_all(&self, files: &[&dyn FileHandle], dirs: &[PathBuf]) -> Result<()> {
        let _prof = trunc_prof::span("fs.flush_all");
        in_parallel(files.len(), &|i| files[i].flush_data())?;
        in_parallel(dirs.len(), &|i| self.flush_dir(&dirs[i]))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.rename");
        #[cfg(windows)]
        {
            crate::win::rename_noreplace(from, to).map_err(err("renaming", from))
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "linux")]
            {
                // Out of a held root: name the entry relative to the pinned directory, so a link
                // put in the root's place cannot change what is moved.
                let pin = from.parent().and_then(pinned);
                if let (Some(pin), Some(name)) = (pin, from.file_name()) {
                    if crate::linux::rename_noreplace_from(pin.dir.as_fd(), Path::new(name), to)
                        .map_err(err("renaming", from))?
                    {
                        return Ok(());
                    }
                } else if crate::linux::rename_noreplace(from, to).map_err(err("renaming", from))? {
                    return Ok(());
                }
            }
            // Without renameat2 support, checking and renaming are two steps.
            if fs::symlink_metadata(to).is_ok() {
                return Err(FsError::AlreadyExists {
                    path: to.to_path_buf(),
                });
            }
            fs::rename(from, to).map_err(err("renaming", from))
        }
    }

    fn hard_link(&self, src: &Path, dst: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.hard_link");
        fs::hard_link(src, dst).map_err(|e| link_err(dst, e))
    }

    #[cfg(target_os = "linux")]
    fn hard_link_beneath(&self, root: &Path, src: &Path, dst: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.hard_link");
        let (s, d) = (
            crate::relative_beneath(root, src)?,
            crate::relative_beneath(root, dst)?,
        );
        // Under a held root both parents resolve against the pinned descriptor, so a link put
        // in the root's place cannot redirect either name.
        let linked = match pinned(root) {
            Some(pin) => crate::linux::link_beneath(pin.dir.as_fd(), s, d),
            None => crate::linux::open_root(root)
                .and_then(|dir| crate::linux::link_beneath(dir.as_fd(), s, d)),
        };
        match linked {
            Ok(true) => Ok(()),
            Ok(false) => {
                crate::check_beneath(self, root, src)?;
                crate::check_beneath(self, root, dst)?;
                self.hard_link(src, dst)?;
                // linkat does not follow a symlink at `src`: it would link the symlink itself.
                match self.metadata(dst)? {
                    Some(Meta {
                        kind: NodeKind::File,
                        ..
                    }) => Ok(()),
                    _ => {
                        let _ = fs::remove_file(dst);
                        Err(FsError::Link {
                            path: src.to_path_buf(),
                        })
                    }
                }
            }
            Err(e)
                if e.raw_os_error() == Some(rustix::io::Errno::XDEV.raw_os_error())
                    || e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) =>
            {
                Err(FsError::Link {
                    path: dst.to_path_buf(),
                })
            }
            Err(e) => Err(link_err(dst, e)),
        }
    }

    #[cfg(windows)]
    fn hard_link_beneath(&self, root: &Path, src: &Path, dst: &Path) -> Result<()> {
        use crate::win::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES};
        use std::os::windows::fs::OpenOptionsExt;
        const SHARE_ALL: u32 = 7;
        let _prof = trunc_prof::span("fs.hard_link");
        // The source through a confined open (its location checked against the root, pinned or
        // not), so the new name can be compared with the very file meant.
        let sid = self
            .open_beneath(root, src, OpenMode::Read, Share::Shared)?
            .file_id()?;
        crate::check_beneath(self, root, dst)?;
        fs::hard_link(src, dst).map_err(|e| link_err(dst, e))?;
        // CreateHardLinkW follows junctions in both paths. Open the new name itself, with DELETE
        // access, and check where it really is and what it is: a stray is taken back through
        // this handle, never by a path that a swapped junction could send elsewhere.
        let d = OpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .share_mode(SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dst)
            .map_err(err("opening", dst))?;
        let id = crate::win::file_id(&d).map_err(err("reading file id of", dst))?;
        let same = id == (sid.volume, sid.file);
        let outside = outside_root(&d, root, dst)?;
        // Outside the root only a name for the source itself is surely the one just made (a
        // different file there may be someone else's); inside it, any stray name is ours.
        if outside && same || !outside && !same {
            let _ = crate::win::delete_by_handle(&d);
        }
        if outside || !same {
            return Err(FsError::Link {
                path: dst.to_path_buf(),
            });
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.remove");
        fs::remove_file(path).map_err(err("removing", path))
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        let _prof = trunc_prof::span("fs.remove");
        // A held root's handle would stop its own removal on Windows.
        #[cfg(any(windows, target_os = "linux"))]
        if let Some(map) = pins().as_mut() {
            map.remove(path);
        }
        fs::remove_dir(path).map_err(err("removing directory", path))
    }

    fn metadata(&self, path: &Path) -> Result<Option<Meta>> {
        let _prof = trunc_prof::span("fs.metadata");
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
        let _prof = trunc_prof::span("fs.read_dir");
        let mut names = Vec::new();
        for entry in fs::read_dir(path).map_err(err("listing", path))? {
            let entry = entry.map_err(err("listing", path))?;
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    fn set_mode(&self, path: &Path, mode: u32) -> Result<()> {
        let _prof = trunc_prof::span("fs.set_mode");
        // Windows keeps only a read-only flag. Files trunc writes are writable already, so a
        // mode with any write bit changes nothing and needs no calls.
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            if mode & 0o222 != 0 {
                return Ok(());
            }
            // Change the attribute through a handle on the node itself, never a link's target.
            let f = OpenOptions::new()
                .access_mode(crate::win::FILE_READ_ATTRIBUTES | crate::win::FILE_WRITE_ATTRIBUTES)
                .custom_flags(
                    crate::win::FILE_FLAG_OPEN_REPARSE_POINT
                        | crate::win::FILE_FLAG_BACKUP_SEMANTICS,
                )
                .open(path)
                .map_err(err("opening", path))?;
            let md = f.metadata().map_err(err("reading metadata of", path))?;
            let link = md.file_attributes() & crate::win::FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let outside = match pinned_above(path) {
                Some((root, _)) => outside_root(&f, &root, path)?,
                None => false,
            };
            if link || outside {
                return Err(FsError::Link {
                    path: path.to_path_buf(),
                });
            }
            let mut p = md.permissions();
            p.set_readonly(true);
            f.set_permissions(p)
                .map_err(err("setting permissions of", path))
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::OFlags;
            // Under a held root, every component is confined; otherwise only the final one is
            // never followed, as for `open`.
            let pin = pinned_above(path);
            let open = |flags: OFlags| -> Result<std::os::fd::OwnedFd> {
                let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC;
                if let Some((root, pin)) = &pin {
                    let rel = crate::relative_beneath(root, path)?;
                    match crate::linux::openat_beneath(pin.dir.as_fd(), rel, flags) {
                        Ok(Some(fd)) => return Ok(fd),
                        Ok(None) => crate::check_beneath(self, root, path)?,
                        Err(e) => return Err(beneath_err("opening", path, e)),
                    }
                }
                rustix::fs::open(path, flags, rustix::fs::Mode::empty())
                    .map_err(|e| err("opening", path)(e.into()))
            };
            let fd = open(OFlags::PATH)?;
            if !crate::linux::chmod_path_fd(&fd, mode)
                .map_err(err("setting permissions of", path))?
            {
                // No /proc: a readable descriptor can be fchmod-ed, once it is known to be the
                // same file.
                let rd = open(OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY)?;
                crate::linux::fchmod_same(&fd, &rd, mode)
                    .map_err(err("setting permissions of", path))?;
            }
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
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
    }

    fn probe_volume(&self, path: &Path) -> Result<VolumeInfo> {
        let _prof = trunc_prof::span("fs.probe_volume");
        let at = existing_ancestor(path)?;
        let sync = crate::sync::detect_sync(&at);
        #[cfg(windows)]
        {
            probe_windows(&at, sync)
        }
        #[cfg(unix)]
        {
            probe_unix(&at, sync)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(VolumeInfo {
                fs: FsKind::Unknown,
                fs_name: "unknown".into(),
                root: None,
                volume_id: None,
                cluster_size: 4096,
                free_bytes: None,
                total_bytes: None,
                supports_sparse: false,
                sparse_granularity: 0,
                max_file_size: u64::MAX,
                sync,
                snapshots: SnapshotHint::Unknown("filesystem probing is not supported here".into()),
            })
        }
    }
}

/// Filesystem kind from a Linux `statfs` magic number.
#[cfg(target_os = "linux")]
fn linux_fs_kind(magic: u32) -> (FsKind, &'static str) {
    match magic {
        0xEF53 => (FsKind::Ext4, "ext4"),
        0x5846_5342 => (FsKind::Xfs, "xfs"),
        0x9123_683E => (FsKind::Btrfs, "btrfs"),
        0x2FC1_2FC1 => (FsKind::Zfs, "zfs"),
        0x2011_BAB0 => (FsKind::ExFat, "exfat"),
        0x4D44 => (FsKind::Fat32, "vfat"),
        0x7366_746E => (FsKind::Ntfs, "ntfs3"),
        0x0102_1994 => (FsKind::Unknown, "tmpfs"),
        0x794C_7630 => (FsKind::Unknown, "overlayfs"),
        _ => (FsKind::Unknown, "unknown"),
    }
}

#[cfg(unix)]
fn probe_unix(at: &Path, sync: crate::SyncHint) -> Result<VolumeInfo> {
    let vfs = rustix::fs::statvfs(at).map_err(|e| err("querying volume of", at)(e.into()))?;
    let unit = if vfs.f_frsize > 0 {
        vfs.f_frsize
    } else {
        vfs.f_bsize
    };
    #[cfg(target_os = "linux")]
    let mount = crate::linux::mount_of(at);
    #[cfg(target_os = "linux")]
    let (fs, name) = {
        let st = rustix::fs::statfs(at).map_err(|e| err("querying volume of", at)(e.into()))?;
        // The magic is a 32-bit value stored in a signed or wider field depending on the ABI.
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        let magic = st.f_type as u32;
        match (linux_fs_kind(magic), &mount) {
            // Not a magic we know (9p, fuseblk, nfs...): name it after the mount table.
            ((FsKind::Unknown, "unknown"), Some(m)) => {
                (FsKind::from_name(&m.fstype), m.fstype.clone())
            }
            ((kind, name), _) => (kind, name.to_owned()),
        }
    };
    #[cfg(not(target_os = "linux"))]
    let (fs, name) = (FsKind::Unknown, String::from("unknown"));
    let snapshots = match fs {
        FsKind::Btrfs | FsKind::Zfs => SnapshotHint::Unknown(format!(
            "{name} snapshots can keep truncated data allocated; not checked"
        )),
        #[cfg(target_os = "linux")]
        _ if mount.as_ref().is_some_and(|m| {
            m.source.starts_with("/dev/mapper/") || m.source.starts_with("/dev/dm-")
        }) =>
        {
            SnapshotHint::Unknown(
                "device-mapper volume (LVM?): thin snapshots would keep truncated data \
                 allocated; not checked"
                    .into(),
            )
        }
        _ => SnapshotHint::None,
    };
    // Filesystems known to punch holes with fallocate, freeing whole blocks.
    let supports_sparse = cfg!(target_os = "linux")
        && matches!(fs, FsKind::Ext4 | FsKind::Xfs | FsKind::Btrfs | FsKind::Zfs);
    Ok(VolumeInfo {
        fs,
        fs_name: name,
        #[cfg(target_os = "linux")]
        root: mount.map(|m| m.point),
        #[cfg(not(target_os = "linux"))]
        root: None,
        volume_id: unix_dev(at),
        cluster_size: u32::try_from(unit).unwrap_or(4096).max(512),
        free_bytes: Some(vfs.f_bavail.saturating_mul(unit)),
        total_bytes: Some(vfs.f_blocks.saturating_mul(unit)),
        supports_sparse,
        sparse_granularity: if supports_sparse {
            u32::try_from(vfs.f_bsize).unwrap_or(4096).max(512)
        } else {
            0
        },
        max_file_size: if fs == FsKind::Fat32 {
            (4u64 << 30) - 1
        } else {
            u64::MAX
        },
        sync,
        snapshots,
    })
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
        let _prof = trunc_prof::span("fs.read").bytes(buf.len() as u64);
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

    #[cfg(any(windows, target_os = "linux"))]
    fn read_back(&self, buf: &mut [u8], off: u64) -> Result<()> {
        let _prof = trunc_prof::span("fs.read_back").bytes(buf.len() as u64);
        let mut guard = self
            .uncached
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*guard, Uncached::Untried) {
            *guard = match open_uncached(&self.path) {
                Ok(f) => Uncached::Open(f),
                Err(e) if direct_unsupported(&e) => Uncached::Unavailable,
                Err(e) => return Err(self.e("opening for verification")(e)),
            };
        }
        let direct = match &*guard {
            Uncached::Open(f) => Some(read_aligned(f, buf, off)),
            _ => None,
        };
        match direct {
            Some(Ok(())) => return Ok(()),
            Some(Err(e)) if direct_unsupported(&e) => *guard = Uncached::Unavailable,
            Some(Err(e)) => return Err(FsError::from_io("verifying", &self.path, e)),
            None => {}
        }
        drop(guard);
        // No cache bypass on this filesystem: drop the cached pages (clean, since the data was
        // flushed), so the read below has to go to the device.
        #[cfg(target_os = "linux")]
        crate::linux::drop_cache(&self.file, off, buf.len() as u64).map_err(self.e("verifying"))?;
        self.read_exact_at(buf, off)
    }

    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> Result<()> {
        let _prof = trunc_prof::span("fs.write").bytes(buf.len() as u64);
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
        let _prof = trunc_prof::span("fs.set_len");
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
        let _prof = trunc_prof::span("fs.preallocate");
        let size = self.size()?;
        if len <= size {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        if crate::linux::reserve(&self.file, size, len).map_err(self.e("reserving space for"))? {
            return Ok(());
        }
        // NTFS allocates clusters for the new length of a non-sparse file, so running out of
        // space shows up here. Elsewhere this at least fixes the size.
        self.set_len(len)
    }

    fn flush_data(&self) -> Result<()> {
        let _prof = trunc_prof::span("fs.flush");
        self.file.sync_data().map_err(self.e("flushing"))
    }

    fn deallocate(&self, start: u64, end: u64) -> Result<Dealloc> {
        let _prof = trunc_prof::span("fs.deallocate").bytes(end.saturating_sub(start));
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
        #[cfg(target_os = "linux")]
        {
            if !crate::linux::punch_hole(&self.file, start, end).map_err(self.e("deallocating"))? {
                return Ok(Dealloc::Unsupported);
            }
            let len = self.size()?;
            let allocated = crate::linux::allocated_ranges(&self.file, len)
                .map_err(self.e("querying allocation of"))?;
            Ok(Dealloc::Freed {
                freed: largest_hole(&allocated, start, end.min(len)),
            })
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Ok(Dealloc::Unsupported)
        }
    }

    fn allocated_ranges(&self) -> Result<Vec<Range<u64>>> {
        let _prof = trunc_prof::span("fs.allocated_ranges");
        let len = self.size()?;
        #[cfg(windows)]
        {
            crate::win::allocated_ranges(&self.file, len).map_err(self.e("querying allocation of"))
        }
        #[cfg(target_os = "linux")]
        {
            crate::linux::allocated_ranges(&self.file, len)
                .map_err(self.e("querying allocation of"))
        }
        #[cfg(not(any(windows, target_os = "linux")))]
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
        let _prof = trunc_prof::span("fs.set_modified");
        self.file
            .set_modified(t)
            .map_err(self.e("setting mtime of"))
    }

    fn modified(&self) -> Result<Option<SystemTime>> {
        let m = self
            .file
            .metadata()
            .map_err(self.e("reading metadata of"))?;
        Ok(m.modified().ok())
    }
}

/// The largest unallocated sub-range of `[start, end)` given the allocated ranges.
#[cfg_attr(not(any(windows, target_os = "linux")), allow(dead_code))]
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

/// Open a second handle on `path` that reads from the device, not the OS cache.
#[cfg(windows)]
fn open_uncached(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(7) // read | write | delete: coexist with our own writer handle
        .custom_flags(FILE_FLAG_NO_BUFFERING | crate::win::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(target_os = "linux")]
fn open_uncached(path: &Path) -> io::Result<File> {
    use rustix::fs::OFlags;
    use std::os::unix::fs::OpenOptionsExt;
    #[allow(clippy::cast_possible_wrap)]
    let flags = (OFlags::DIRECT | OFlags::NOFOLLOW).bits() as i32;
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}

/// EINVAL from an `O_DIRECT` open or read: the filesystem cannot bypass the cache.
#[cfg(any(windows, target_os = "linux"))]
fn direct_unsupported(e: &io::Error) -> bool {
    cfg!(target_os = "linux") && e.raw_os_error() == Some(22)
}

/// Read `buf.len()` bytes at `off` through a handle that needs sector-aligned offsets, lengths
/// and memory (Windows `FILE_FLAG_NO_BUFFERING`, Linux `O_DIRECT`).
#[cfg(any(windows, target_os = "linux"))]
fn read_aligned(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    const ALIGN: u64 = 4096; // covers 512-byte and 4 KiB sectors
    const ALIGN_BYTES: usize = 4096;
    let start = off / ALIGN * ALIGN;
    let end = (off + buf.len() as u64).div_ceil(ALIGN) * ALIGN;
    let span =
        usize::try_from(end - start).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut raw = vec![0u8; span + ALIGN_BYTES];
    let a = raw.as_ptr().align_offset(ALIGN_BYTES);
    let aligned = &mut raw[a..a + span];
    let mut got = 0usize;
    while got < span {
        match read_at(f, &mut aligned[got..], start + got as u64) {
            // Unbuffered reads are only ever short at end of file; continuing from an
            // unaligned offset would fail with an invalid-parameter error.
            Ok(n) if n < span - got => {
                got += n;
                break;
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let rel = usize::try_from(off - start).expect("< ALIGN");
    if got < rel + buf.len() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    buf.copy_from_slice(&aligned[rel..rel + buf.len()]);
    Ok(())
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

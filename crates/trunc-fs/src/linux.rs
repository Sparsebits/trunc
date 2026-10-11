//! Linux specifics, all through rustix (no `unsafe`): hole punching, space reservation,
//! confined opens and hard links, no-replace renames, page-cache control, advisory locks and mount
//! lookup.
//!
//! Each helper reports a missing kernel or filesystem feature as `Ok(None)` / `Ok(false)` so the
//! caller can fall back, and every other failure as an `io::Error`.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::ops::Range;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{
    Advice, AtFlags, CWD, FallocateFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags,
    ResolveFlags, SeekFrom,
};
use rustix::io::Errno;

/// Errors meaning "this kernel, sandbox or filesystem lacks the feature", not "it failed".
/// Container seccomp profiles answer unknown syscalls with ENOSYS or, in older ones, EPERM.
fn missing(e: Errno) -> bool {
    e == Errno::NOSYS || e == Errno::OPNOTSUPP || e == Errno::PERM
}

/// `fallocate(PUNCH_HOLE | KEEP_SIZE)`: zero `[start, end)` and free the blocks it covers.
/// `Ok(false)` if the filesystem cannot punch holes (FAT, exFAT, some FUSE filesystems).
pub(crate) fn punch_hole(f: &File, start: u64, end: u64) -> io::Result<bool> {
    let flags = FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE;
    match rustix::fs::fallocate(f, flags, start, end - start) {
        Ok(()) => Ok(true),
        Err(e) if missing(e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `fallocate(0)`: allocate blocks for `[from, to)`, extending the file, so running out of space
/// shows up now rather than in the middle of a write. `Ok(false)` if unsupported.
pub(crate) fn reserve(f: &File, from: u64, to: u64) -> io::Result<bool> {
    match rustix::fs::fallocate(f, FallocateFlags::empty(), from, to - from) {
        Ok(()) => Ok(true),
        Err(e) if missing(e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Ranges of the first `len` bytes that hold data, from `SEEK_DATA` / `SEEK_HOLE`.
pub(crate) fn allocated_ranges(f: &File, len: u64) -> io::Result<Vec<Range<u64>>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < len {
        let data = match rustix::fs::seek(f, SeekFrom::Data(pos)) {
            Ok(d) => d,
            Err(Errno::NXIO) => break, // no data at or after `pos`
            // Kernels before 3.1 lack SEEK_DATA; every byte then counts as allocated.
            #[allow(clippy::single_range_in_vec_init)] // one allocated range is intended
            Err(Errno::INVAL) if pos == 0 => return Ok(vec![0..len]),
            Err(e) => return Err(e.into()),
        };
        if data >= len {
            break;
        }
        let hole = rustix::fs::seek(f, SeekFrom::Hole(data))?.min(len);
        out.push(data..hole);
        pos = hole;
    }
    Ok(out)
}

fn confined() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

/// Open the root of confined calls by path. The root itself may be reached through links: it is
/// the user's choice of destination. Used only for roots not pinned with `hold_root`.
pub(crate) fn open_root(root: &Path) -> io::Result<OwnedFd> {
    Ok(rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// Open the directory `dir` to pin it as a root: the path up to it may go through links (the
/// user's choice of destination), `dir` itself may not.
pub(crate) fn open_dir_nofollow(dir: &Path) -> io::Result<OwnedFd> {
    let fd = rustix::fs::open(
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    // O_PATH | O_NOFOLLOW can open a symlink itself; make sure this is the directory.
    if FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) != FileType::Directory {
        return Err(Errno::NOTDIR.into());
    }
    Ok(fd)
}

/// `openat2(dir, rel, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`, refusing a link as the final
/// component too. `Ok(None)` if openat2 is missing (kernels before 5.6, restrictive sandboxes).
pub(crate) fn openat_beneath(
    dir: BorrowedFd<'_>,
    rel: &Path,
    flags: OFlags,
) -> io::Result<Option<OwnedFd>> {
    // openat2, unlike open, rejects a mode unless the call can create the file.
    let mode = if flags.contains(OFlags::CREATE) {
        Mode::from_raw_mode(0o666)
    } else {
        Mode::empty()
    };
    let flags = flags | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    match rustix::fs::openat2(dir, rel, flags, mode, confined()) {
        Ok(fd) => Ok(Some(fd)),
        Err(e) if missing(e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// [`openat_beneath`] for a file to read or write.
pub(crate) fn open_beneath(
    dir: BorrowedFd<'_>,
    rel: &Path,
    flags: OFlags,
) -> io::Result<Option<File>> {
    Ok(openat_beneath(dir, rel, flags)?.map(File::from))
}

/// The parent directory of `rel`, opened beneath `dir` as in [`open_beneath`] (a duplicate of
/// `dir` when `rel` is a single component), and the last component. `Ok(None)` if openat2 is
/// missing.
fn parent_beneath<'a>(
    dir: BorrowedFd<'_>,
    rel: &'a Path,
) -> io::Result<Option<(OwnedFd, &'a OsStr)>> {
    let name = rel
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = rel.parent().filter(|p| !p.as_os_str().is_empty());
    let parent_fd = match parent {
        None => dir.try_clone_to_owned()?,
        Some(p) => {
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
            match rustix::fs::openat2(dir, p, flags, Mode::empty(), confined()) {
                Ok(fd) => fd,
                Err(e) if missing(e) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
    };
    Ok(Some((parent_fd, name)))
}

/// `mkdirat` in the parent of `rel`, the parent resolved as in [`open_beneath`].
pub(crate) fn mkdir_beneath(dir: BorrowedFd<'_>, rel: &Path) -> io::Result<bool> {
    let Some((parent, name)) = parent_beneath(dir, rel)? else {
        return Ok(false);
    };
    rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o777))?;
    Ok(true)
}

/// `linkat` between the parents of `src` and `dst`, both resolved beneath `dir` as in
/// [`open_beneath`] (`dir` being the pinned root when it is held). `linkat` without
/// `AT_SYMLINK_FOLLOW` links a symlink itself, never its target: when the new name turns out
/// not to be a regular file it is unlinked again, relative to the same parent descriptor, and
/// the call fails with ELOOP. `Ok(false)` if openat2 is missing.
pub(crate) fn link_beneath(dir: BorrowedFd<'_>, src: &Path, dst: &Path) -> io::Result<bool> {
    let Some((sp, sname)) = parent_beneath(dir, src)? else {
        return Ok(false);
    };
    let Some((dp, dname)) = parent_beneath(dir, dst)? else {
        return Ok(false);
    };
    rustix::fs::linkat(&sp, sname, &dp, dname, AtFlags::empty())?;
    let st = rustix::fs::statat(&dp, dname, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        let _ = rustix::fs::unlinkat(&dp, dname, AtFlags::empty());
        return Err(Errno::LOOP.into());
    }
    Ok(true)
}

/// Change the mode of what an `O_PATH` descriptor refers to, through its `/proc/self/fd` link
/// (`fchmod` refuses `O_PATH` descriptors). A symlink is refused with ELOOP: going through the
/// link would change its target. `Ok(false)` if `/proc` is not mounted.
pub(crate) fn chmod_path_fd(fd: &OwnedFd, mode: u32) -> io::Result<bool> {
    if FileType::from_raw_mode(rustix::fs::fstat(fd)?.st_mode) == FileType::Symlink {
        return Err(Errno::LOOP.into());
    }
    let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
    match rustix::fs::chmod(link.as_str(), Mode::from_raw_mode(mode & 0o777)) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) if std::fs::symlink_metadata("/proc/self/fd").is_err() => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `fchmod` on `f`, a second, readable descriptor for what `path_fd` refers to, after checking
/// that both really are the same file (the fallback without `/proc`).
pub(crate) fn fchmod_same(path_fd: &OwnedFd, f: &OwnedFd, mode: u32) -> io::Result<()> {
    let (a, b) = (rustix::fs::fstat(path_fd)?, rustix::fs::fstat(f)?);
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino) {
        return Err(io::Error::other("replaced while setting its mode"));
    }
    Ok(rustix::fs::fchmod(f, Mode::from_raw_mode(mode & 0o777))?)
}

/// `renameat2(from_dir, from_name, CWD, to, RENAME_NOREPLACE)`: move an entry out of a pinned
/// directory without resolving the directory's path again. `Ok(false)` if the kernel or
/// filesystem lacks the flag.
pub(crate) fn rename_noreplace_from(
    from_dir: BorrowedFd<'_>,
    from_name: &Path,
    to: &Path,
) -> io::Result<bool> {
    match rustix::fs::renameat_with(from_dir, from_name, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(true),
        Err(e) if missing(e) || e == Errno::INVAL => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// `renameat2(RENAME_NOREPLACE)`. `Ok(false)` if the kernel or filesystem lacks the flag.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<bool> {
    match rustix::fs::renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(true),
        Err(e) if missing(e) || e == Errno::INVAL => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Take a non-blocking `flock`. `Ok(false)` if another open file holds a conflicting lock;
/// `Ok(true)` also when the filesystem has no locking (advisory protection only).
pub(crate) fn lock(f: &File, exclusive: bool) -> io::Result<bool> {
    let op = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    match rustix::fs::flock(f, op) {
        Ok(()) => Ok(true),
        Err(Errno::WOULDBLOCK) => Ok(false),
        Err(e) if missing(e) || e == Errno::NOLCK => Ok(true),
        Err(e) => Err(e.into()),
    }
}

/// Release a lock taken with `lock`. Failure leaves nothing to do: the lock ends with the
/// open file description anyway.
pub(crate) fn unlock(f: &File) {
    let _ = rustix::fs::flock(f, FlockOperation::Unlock);
}

/// Ask the kernel to drop cached pages of `[off, off + len)` so the next read comes from the
/// device. Only clean (already flushed) pages are dropped.
pub(crate) fn drop_cache(f: &File, off: u64, len: u64) -> io::Result<()> {
    rustix::fs::fadvise(f, off, NonZeroU64::new(len), Advice::DontNeed)?;
    Ok(())
}

/// The mount holding a path, from `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mount {
    pub point: PathBuf,
    pub fstype: String,
    pub source: String,
}

pub(crate) fn mount_of(path: &Path) -> Option<Mount> {
    let canon = std::fs::canonicalize(path).ok()?;
    let table = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    find_mount(&table, &canon)
}

/// The longest mount point containing `path`; for stacked mounts the last one listed wins.
fn find_mount(table: &str, path: &Path) -> Option<Mount> {
    let mut best: Option<Mount> = None;
    for line in table.lines() {
        // id parent major:minor root mount-point options [optional...] - fstype source super
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let Some(point) = left.split(' ').nth(4) else {
            continue;
        };
        let point = PathBuf::from(unescape(point));
        let mut r = right.split(' ');
        let fstype = r.next().unwrap_or("").to_owned();
        let source = unescape(r.next().unwrap_or(""));
        if path.starts_with(&point)
            && best
                .as_ref()
                .is_none_or(|b| point.components().count() >= b.point.components().count())
        {
            best = Some(Mount {
                point,
                fstype,
                source,
            });
        }
    }
    best
}

/// Undo mountinfo's octal escapes (`\040` for space, `\011` tab, `\012` newline, `\134` `\`).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
22 1 8:3 / / rw,relatime shared:1 - ext4 /dev/sdc rw
40 22 0:35 / /mnt/d rw,noatime - 9p drvfs rw,aname=drvfs;path=D:\\
41 22 253:0 / /srv/my\\040data rw - xfs /dev/mapper/vg-data rw
42 41 0:50 / /srv/my\\040data/tmp rw - tmpfs tmpfs rw
";

    #[test]
    fn finds_the_deepest_mount() {
        let m = find_mount(TABLE, Path::new("/home/u/x")).unwrap();
        assert_eq!((m.point, m.fstype.as_str()), (PathBuf::from("/"), "ext4"));
        let m = find_mount(TABLE, Path::new("/mnt/d/trunc")).unwrap();
        assert_eq!(m.fstype, "9p");
        let m = find_mount(TABLE, Path::new("/srv/my data/a")).unwrap();
        assert_eq!(
            (m.fstype.as_str(), m.source.as_str()),
            ("xfs", "/dev/mapper/vg-data")
        );
        let m = find_mount(TABLE, Path::new("/srv/my data/tmp/a")).unwrap();
        assert_eq!(m.fstype, "tmpfs");
        // Component-wise prefix: /mnt/dd is not under /mnt/d.
        assert_eq!(
            find_mount(TABLE, Path::new("/mnt/dd")).unwrap().fstype,
            "ext4"
        );
    }

    #[test]
    fn unescapes_octal() {
        assert_eq!(unescape(r"a\040b\134c"), r"a b\c");
        assert_eq!(unescape(r"trailing\04"), r"trailing\04");
    }
}

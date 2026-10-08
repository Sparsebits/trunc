//! Linux specifics, all through rustix (no `unsafe`): hole punching, space reservation,
//! confined opens, no-replace renames, page-cache control, advisory locks and mount lookup.
//!
//! Each helper reports a missing kernel or filesystem feature as `Ok(None)` / `Ok(false)` so the
//! caller can fall back, and every other failure as an `io::Error`.

use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::ops::Range;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{
    Advice, CWD, FallocateFlags, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags, SeekFrom,
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

fn open_root(root: &Path) -> io::Result<OwnedFd> {
    // The root itself may be reached through links: it is the user's choice of destination.
    Ok(rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?)
}

/// `openat2(root, rel, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. `Ok(None)` if openat2 is missing
/// (kernels before 5.6, restrictive sandboxes).
pub(crate) fn open_beneath(root: &Path, rel: &Path, flags: OFlags) -> io::Result<Option<File>> {
    let dir = open_root(root)?;
    // openat2, unlike open, rejects a mode unless the call can create the file.
    let mode = if flags.contains(OFlags::CREATE) {
        Mode::from_raw_mode(0o666)
    } else {
        Mode::empty()
    };
    let flags = flags | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    match rustix::fs::openat2(&dir, rel, flags, mode, confined()) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(e) if missing(e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `mkdirat` in the parent of `rel`, the parent resolved as in [`open_beneath`].
pub(crate) fn mkdir_beneath(root: &Path, rel: &Path) -> io::Result<bool> {
    let dir = open_root(root)?;
    let name = rel
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent = rel.parent().filter(|p| !p.as_os_str().is_empty());
    let parent_fd = match parent {
        None => dir,
        Some(p) => {
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
            match rustix::fs::openat2(&dir, p, flags, Mode::empty(), confined()) {
                Ok(fd) => fd,
                Err(e) if missing(e) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
    };
    rustix::fs::mkdirat(&parent_fd, name, Mode::from_raw_mode(0o777))?;
    Ok(true)
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

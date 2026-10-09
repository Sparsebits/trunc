//! Split archives: parts named `name.001`, `name.002`, … (or `name.aa`, `name.ab`, …) that
//! are slices of one file. They are read through [`Parts`], which looks like one file.
//!
//! Reading works for every format. Consuming works for compressed tarballs and files, which
//! are consumed from the front: once a checkpoint passes the end of a part, the part is
//! deleted, which frees its space even on filesystems that cannot punch holes.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use trunc_fs::{Dealloc, FileHandle, FileId, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_legacy::split::{Numbering, PartName};

use crate::error::{Error, Result};
use crate::stage::{ignore_not_found, parent_of};

/// Sets with more parts than this are refused (a sanity bound, not a format limit).
const MAX_PARTS: u64 = 100_000;

fn is_file(fs: &dyn FsBackend, p: &Path) -> Result<bool> {
    Ok(fs.metadata(p)?.is_some_and(|m| m.kind == NodeKind::File))
}

/// The name parser for `path` and the set's first part, if `path` names a part of a set whose
/// first two parts exist.
fn set_of(fs: &dyn FsBackend, path: &Path) -> Result<Option<(PartName, PathBuf)>> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(None);
    };
    let Some(mut p) = PartName::parse(name) else {
        return Ok(None);
    };
    let dir = parent_of(path);
    if let Numbering::Digits { .. } = p.numbering {
        let z = p.from_zero();
        if is_file(fs, &dir.join(z.name_of(0).expect("index 0")))? {
            p = z;
        }
    }
    let first = dir.join(p.name_of(0).expect("index 0"));
    let second = p.name_of(1).map(|n| dir.join(n));
    if !is_file(fs, &first)? || !second.map_or(Ok(false), |s| is_file(fs, &s))? {
        return Ok(None);
    }
    Ok(Some((p, first)))
}

/// The parts of the split archive `path` names, in order, or `None` if it is not one. Naming a
/// later part is an error: the set must be named by its first part.
pub fn split_parts(fs: &dyn FsBackend, path: &Path) -> Result<Option<Vec<PathBuf>>> {
    let Some((p, first)) = set_of(fs, path)? else {
        return Ok(None);
    };
    if p.index != 0 {
        return Err(Error::Input(format!(
            "{} is part {} of a split archive; pass the first part, {}",
            path.display(),
            p.index.wrapping_add(1),
            first.display()
        )));
    }
    let dir = parent_of(path);
    let mut parts = Vec::new();
    for i in 0..=MAX_PARTS {
        let Some(n) = p.name_of(i) else { break };
        let part = dir.join(n);
        if !is_file(fs, &part)? {
            break;
        }
        if i == MAX_PARTS {
            return Err(Error::Input(format!(
                "{} has more than {MAX_PARTS} parts",
                path.display()
            )));
        }
        parts.push(part);
    }
    Ok(Some(parts))
}

/// The name the parts of a split archive stand for (`big.tar.gz` for `big.tar.gz.001`), if
/// `path` is the first part of one.
pub fn joined_path(fs: &dyn FsBackend, path: &Path) -> Result<Option<PathBuf>> {
    Ok(set_of(fs, path)?
        .filter(|(p, _)| p.index == 0)
        .map(|(p, _)| parent_of(path).join(p.joined())))
}

/// Open `path` for reading: the parts of a split archive as one file, or the file itself.
pub fn open_read(fs: &dyn FsBackend, path: &Path) -> Result<Box<dyn FileHandle>> {
    match split_parts(fs, path)? {
        Some(parts) => Ok(Box::new(Parts::open(
            fs,
            &parts,
            OpenMode::Read,
            Share::Shared,
        )?)),
        None => Ok(fs.open(path, OpenMode::Read, Share::Shared)?),
    }
}

/// Sizes of the parts of the split archive `path`, or empty if it is a single file.
pub fn part_sizes(fs: &dyn FsBackend, path: &Path) -> Result<Vec<u64>> {
    let Some(parts) = split_parts(fs, path)? else {
        return Ok(Vec::new());
    };
    parts
        .iter()
        .map(|p| Ok(fs.metadata(p)?.map_or(0, |m| m.len)))
        .collect()
}

/// What a journal records about one part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartRecord {
    pub name: String,
    pub size: u64,
    pub id: FileId,
}

#[derive(Debug)]
struct Slot {
    path: PathBuf,
    offset: u64,
    size: u64,
    id: FileId,
    /// `None` once the part has been deleted.
    h: Mutex<Option<Box<dyn FileHandle>>>,
}

/// The parts of a split archive, read as one file. Parts may be deleted from the front while
/// it is in use; reading a deleted part fails.
#[derive(Debug)]
pub struct Parts {
    path: PathBuf,
    slots: Vec<Slot>,
    len: u64,
}

fn lock(s: &Slot) -> std::sync::MutexGuard<'_, Option<Box<dyn FileHandle>>> {
    s.h.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Parts {
    fn open(fs: &dyn FsBackend, paths: &[PathBuf], mode: OpenMode, share: Share) -> Result<Self> {
        let mut slots = Vec::with_capacity(paths.len());
        let mut offset = 0u64;
        for p in paths {
            let h = fs.open(p, mode, share)?;
            let size = h.size()?;
            slots.push(Slot {
                path: p.clone(),
                offset,
                size,
                id: h.file_id()?,
                h: Mutex::new(Some(h)),
            });
            offset += size;
        }
        Ok(Self {
            path: paths[0].clone(),
            slots,
            len: offset,
        })
    }

    /// Open every part of a set for consuming (read-write, exclusive).
    pub(crate) fn open_for_consume(fs: &dyn FsBackend, paths: &[PathBuf]) -> Result<Self> {
        Self::open(fs, paths, OpenMode::ReadWrite, Share::Exclusive)
    }

    /// Reopen a set being consumed. Parts entirely before `freed_below` may be gone (they were
    /// deleted); every other part must be there, unchanged. With `ended`, every part may be gone.
    pub(crate) fn reopen(
        fs: &dyn FsBackend,
        first: &Path,
        recs: &[PartRecord],
        freed_below: u64,
        ended: bool,
    ) -> Result<Self> {
        let dir = parent_of(first);
        let mut slots = Vec::with_capacity(recs.len());
        let mut offset = 0u64;
        for r in recs {
            let path = dir.join(&r.name);
            let h = match fs.open(&path, OpenMode::ReadWrite, Share::Exclusive) {
                Ok(h) => {
                    if h.file_id()? != r.id || h.size()? != r.size {
                        return Err(Error::Refused(format!(
                            "{} is not the part this journal recorded (it was replaced?)",
                            path.display()
                        )));
                    }
                    Some(h)
                }
                Err(FsError::NotFound { .. }) if ended || offset + r.size <= freed_below => None,
                Err(FsError::NotFound { .. }) => {
                    return Err(Error::Refused(format!(
                        "{} is missing, but its data has not been extracted yet",
                        path.display()
                    )));
                }
                Err(e) => return Err(e.into()),
            };
            slots.push(Slot {
                path,
                offset,
                size: r.size,
                id: r.id,
                h: Mutex::new(h),
            });
            offset += r.size;
        }
        Ok(Self {
            path: first.to_path_buf(),
            slots,
            len: offset,
        })
    }

    pub(crate) fn records(&self) -> Vec<PartRecord> {
        self.slots
            .iter()
            .map(|s| PartRecord {
                name: s
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                size: s.size,
                id: s.id,
            })
            .collect()
    }

    pub(crate) fn sizes(&self) -> Vec<u64> {
        self.slots.iter().map(|s| s.size).collect()
    }

    pub(crate) fn all_present(&self) -> bool {
        self.slots.iter().all(|s| lock(s).is_some())
    }

    /// File ids of the parts still present.
    pub(crate) fn ids(&self) -> Vec<FileId> {
        self.slots
            .iter()
            .filter(|s| lock(s).is_some())
            .map(|s| s.id)
            .collect()
    }

    /// Release `[from, below)`: delete every part that ends at or before `below`, and
    /// deallocate (where the filesystem can) the start of the part that contains it.
    pub(crate) fn free(&self, fs: &dyn FsBackend, from: u64, below: u64, gran: u64) -> Result<()> {
        let mut removed = false;
        for s in &self.slots {
            let end = s.offset + s.size;
            if end <= below {
                if let Some(h) = lock(s).take() {
                    drop(h);
                    ignore_not_found(fs.remove_file(&s.path))?;
                    removed = true;
                }
            } else if s.offset < below {
                if let Some(h) = lock(s).as_ref() {
                    let start = from.max(s.offset) - s.offset;
                    match h.deallocate(start / gran * gran, below - s.offset)? {
                        Dealloc::Freed { .. } | Dealloc::Unsupported => {}
                    }
                }
            }
        }
        if removed {
            fs.flush_dir(&parent_of(&self.path))?;
        }
        Ok(())
    }

    /// Delete every part still present.
    pub(crate) fn remove_all(&self, fs: &dyn FsBackend) -> Result<()> {
        for s in &self.slots {
            drop(lock(s).take());
            ignore_not_found(fs.remove_file(&s.path))?;
        }
        fs.flush_dir(&parent_of(&self.path))?;
        Ok(())
    }
}

fn read_only(p: &Path, op: &'static str) -> FsError {
    FsError::Unsupported {
        op,
        path: p.to_path_buf(),
    }
}

impl FileHandle for Parts {
    fn path(&self) -> &Path {
        &self.path
    }

    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> trunc_fs::Result<()> {
        if off + buf.len() as u64 > self.len {
            return Err(FsError::Io {
                op: "reading",
                path: self.path.clone(),
                source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            });
        }
        let mut i = self.slots.partition_point(|s| s.offset + s.size <= off);
        while !buf.is_empty() {
            let s = &self.slots[i];
            let within = off - s.offset;
            let n = usize::try_from((s.size - within).min(buf.len() as u64)).expect("<= buf");
            let g = lock(s);
            let h = g.as_ref().ok_or_else(|| FsError::NotFound {
                path: s.path.clone(),
            })?;
            h.read_exact_at(&mut buf[..n], within)?;
            drop(g);
            buf = &mut buf[n..];
            off += n as u64;
            i += 1;
        }
        Ok(())
    }

    fn write_all_at(&self, _buf: &[u8], _off: u64) -> trunc_fs::Result<()> {
        Err(read_only(&self.path, "writing to a split archive"))
    }

    fn size(&self) -> trunc_fs::Result<u64> {
        Ok(self.len)
    }

    fn set_len(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(read_only(&self.path, "resizing a split archive"))
    }

    fn preallocate(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(read_only(&self.path, "preallocating a split archive"))
    }

    fn flush_data(&self) -> trunc_fs::Result<()> {
        Ok(())
    }

    fn deallocate(&self, _start: u64, _end: u64) -> trunc_fs::Result<Dealloc> {
        Ok(Dealloc::Unsupported)
    }

    fn allocated_ranges(&self) -> trunc_fs::Result<Vec<Range<u64>>> {
        Ok(std::iter::once(0..self.len).collect())
    }

    fn file_id(&self) -> trunc_fs::Result<FileId> {
        Ok(self.slots[0].id)
    }

    fn set_modified(&self, _t: SystemTime) -> trunc_fs::Result<()> {
        Err(read_only(&self.path, "setting the time of a split archive"))
    }

    fn modified(&self) -> trunc_fs::Result<Option<SystemTime>> {
        match lock(&self.slots[0]).as_ref() {
            Some(h) => h.modified(),
            None => Ok(None),
        }
    }
}

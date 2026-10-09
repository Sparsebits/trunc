//! Staging-directory mechanics shared by native and legacy consumption: building the directory
//! structure, renaming finished items into place, and small durable-filesystem helpers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use trunc_fs::{FileHandle, FsBackend, FsError, NodeKind, OpenMode, Share};

use crate::consume::{ConsumeSummary, RetryPolicy};
use crate::error::{Error, PauseReason, Result};
use crate::walk::system_time;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ItemKind {
    File,
    Dir,
    Symlink,
}

/// One archive entry, format-neutral.
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub path: String,
    pub kind: ItemKind,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
}

/// Parent directory; `.` for a bare file name, the path itself for a root.
pub(crate) fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => p.to_path_buf(),
    }
}

pub(crate) fn join_rel(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    p
}

/// Where staged outputs may be written, and what they must never turn out to be.
pub(crate) struct StageGuard<'a> {
    /// The staging directory. Outputs are opened beneath it without following links.
    pub root: &'a Path,
    /// Whether a file id is the archive or its journal, as they exist now: an output that is one
    /// of these (e.g. a hard link planted in the staging directory) is refused. It is asked at
    /// each open, because a deleted part of a split archive frees its id for reuse (Linux hands
    /// inode numbers out again at once).
    pub protected: &'a dyn Fn(&trunc_fs::FileId) -> bool,
}

impl std::fmt::Debug for StageGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageGuard")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// Open (or create) a staging output. Returns the handle and whether the file was created.
pub(crate) fn open_staged_output(
    fs: &dyn FsBackend,
    guard: &StageGuard<'_>,
    p: &Path,
) -> Result<(Box<dyn FileHandle>, bool)> {
    let open = |mode| fs.open_beneath(guard.root, p, mode, Share::Exclusive);
    // Usually the file is new: try that first, and look closer only if something is there.
    let (h, created) = match open(OpenMode::CreateNew) {
        Ok(h) => (h, true),
        Err(FsError::AlreadyExists { .. }) => match fs.metadata(p)?.map(|m| m.kind) {
            Some(NodeKind::File) => {
                check_exact_name(fs, p)?;
                (open(OpenMode::ReadWrite)?, false)
            }
            _ => return Err(Error::Refused(format!("{} is not a file", p.display()))),
        },
        Err(e) => return Err(e.into()),
    };
    if (guard.protected)(&h.file_id()?) {
        return Err(Error::Refused(format!(
            "{} is the archive (or its journal) under another name; refusing to write to it",
            p.display()
        )));
    }
    Ok((h, created))
}

/// A read-back that came up short: the device holds less than was written.
pub(crate) fn is_short_read(e: &FsError) -> bool {
    matches!(e, FsError::Io { source, .. } if source.kind() == std::io::ErrorKind::UnexpectedEof)
}

pub(crate) fn ignore_not_found(r: std::result::Result<(), FsError>) -> Result<()> {
    match r {
        Ok(()) | Err(FsError::NotFound { .. }) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Create `dir` and any missing ancestors, flushing each new entry's parent.
pub(crate) fn ensure_dir(fs: &dyn FsBackend, dir: &Path) -> Result<()> {
    match fs.metadata(dir)? {
        Some(m) if m.kind == NodeKind::Dir => return Ok(()),
        Some(_) => {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                dir.display()
            )));
        }
        None => {}
    }
    let parent = parent_of(dir);
    if parent != dir {
        ensure_dir(fs, &parent)?;
    }
    fs.create_dir(dir)?;
    fs.flush_dir(&parent)?;
    Ok(())
}

/// Shrink the archive, retrying while another process has it memory-mapped.
pub(crate) fn truncate_with_retry(h: &dyn FileHandle, len: u64, retry: RetryPolicy) -> Result<()> {
    let mut delay = retry.initial_delay;
    for attempt in 0..=retry.attempts {
        match h.set_len(len) {
            Ok(()) => return Ok(()),
            Err(FsError::Mapped { .. }) if attempt < retry.attempts => {
                std::thread::sleep(delay);
                delay = delay.saturating_mul(2);
            }
            Err(FsError::Mapped { .. }) => return Err(Error::Paused(PauseReason::Mapped)),
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("loop returns on its last attempt")
}

/// Top-level names the extraction creates. A top-level symlink entry is never created, so it is
/// left out (otherwise "everything was moved into place" could never become true).
pub(crate) fn top_level_names(items: &[Item]) -> Vec<String> {
    let set: BTreeSet<String> = items
        .iter()
        .filter(|e| !(e.kind == ItemKind::Symlink && !e.path.contains('/')))
        .map(|e| e.path.split('/').next().unwrap_or(&e.path).to_owned())
        .collect();
    set.into_iter().collect()
}

/// Refuse a path that exists but under another name: an 8.3 short name (`LONGFI~1.TXT`), a
/// case variant, or a Unicode case-folding variant of an entry already extracted. Writing
/// through it would silently merge two entries into one file.
pub(crate) fn check_exact_name(fs: &dyn FsBackend, p: &Path) -> Result<()> {
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        return Ok(());
    };
    let name = name.to_string_lossy();
    if fs.read_dir(parent)?.iter().any(|n| *n == name) {
        return Ok(());
    }
    Err(Error::Refused(format!(
        "{} resolves to a different existing entry (names that differ only in case, or an 8.3 \
         short name); refusing to merge them",
        p.display()
    )))
}

/// Flush every directory under `stage`, then `stage` and `dest`. Run when resuming: an
/// interrupted run may have created entries it never flushed, and a resumed run only flushes
/// the entries it creates itself. File contents need no sweep: everything past the last point
/// where source bytes were released is rewritten and flushed again.
pub(crate) fn flush_staging_tree(fs: &dyn FsBackend, stage: &Path, dest: &Path) -> Result<()> {
    fn walk(fs: &dyn FsBackend, dir: &Path, all: &mut Vec<PathBuf>) -> Result<()> {
        for name in fs.read_dir(dir)? {
            let p = dir.join(&name);
            if fs.metadata(&p)?.map(|m| m.kind) == Some(NodeKind::Dir) {
                walk(fs, &p, all)?;
            }
        }
        all.push(dir.to_path_buf());
        Ok(())
    }
    let mut dirs = Vec::new();
    walk(fs, stage, &mut dirs)?;
    dirs.push(dest.to_path_buf());
    fs.flush_all(&[], &dirs)?;
    Ok(())
}

/// A top-level entry named like one of the archive's sidecar files (resume note, journal,
/// receipt) when extracting next to the archive. The sidecar is created after the conflict
/// check and removed at the end, so such an entry would be refused or deleted.
pub(crate) fn sidecar_conflict(archive: &Path, dest: &Path, tops: &[String]) -> Option<String> {
    let same_dir = archive
        .parent()
        .is_some_and(|p| p == dest || std::path::absolute(p).ok().as_deref() == Some(dest));
    if !same_dir {
        return None;
    }
    let base = archive.file_name()?.to_string_lossy().to_lowercase();
    let sidecars = [".trncr", ".trncj", ".trncj.tmp", ".receipt"].map(|s| format!("{base}{s}"));
    tops.iter()
        .find(|t| sidecars.contains(&t.to_lowercase()))
        .cloned()
}

/// Every directory the items need, including implicit parents, parents first.
fn all_dirs(items: &[Item]) -> Vec<String> {
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for e in items {
        if e.kind == ItemKind::Dir {
            dirs.insert(e.path.clone());
        }
        let mut p = trunc_core::path::parent(&e.path);
        while let Some(parent) = p {
            if !dirs.insert(parent.to_owned()) {
                break;
            }
            p = trunc_core::path::parent(parent);
        }
    }
    dirs.into_iter().collect()
}

pub(crate) fn all_exist(fs: &dyn FsBackend, dest: &Path, names: &[String]) -> Result<bool> {
    for name in names {
        if fs.metadata(&dest.join(name))?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn first_existing(
    fs: &dyn FsBackend,
    dest: &Path,
    names: &[String],
) -> Result<Option<PathBuf>> {
    for name in names {
        let p = dest.join(name);
        if fs.metadata(&p)?.is_some() {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

/// True if the entry's top-level item was already moved into the destination by an earlier run.
fn already_moved(fs: &dyn FsBackend, dest: &Path, stage: &Path, rel: &str) -> Result<bool> {
    let top = rel.split('/').next().unwrap_or(rel);
    Ok(fs.metadata(&stage.join(top))?.is_none() && fs.metadata(&dest.join(top))?.is_some())
}

/// Create directories and empty files in the staging area (idempotent).
pub(crate) fn build_structure(
    fs: &dyn FsBackend,
    items: &[Item],
    dest: &Path,
    stage: &Path,
    summary: &mut ConsumeSummary,
) -> Result<()> {
    let mut to_flush: BTreeSet<PathBuf> = BTreeSet::new();
    // Whether a top-level name was already moved into place, asked once per name.
    let mut moved: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    let mut already_moved = |rel: &str| -> Result<bool> {
        let top = rel.split('/').next().unwrap_or(rel);
        if let Some(&m) = moved.get(top) {
            return Ok(m);
        }
        let m = already_moved(fs, dest, stage, top)?;
        moved.insert(top.to_owned(), m);
        Ok(m)
    };
    for d in all_dirs(items) {
        if already_moved(&d)? {
            continue;
        }
        let p = join_rel(stage, &d);
        // Usually new: create first, and look closer only if something is there.
        match fs.create_dir_beneath(stage, &p) {
            Ok(()) => {
                to_flush.insert(parent_of(&p));
            }
            Err(FsError::AlreadyExists { .. }) => match fs.metadata(&p)?.map(|m| m.kind) {
                Some(NodeKind::Dir) => check_exact_name(fs, &p)?,
                _ => {
                    return Err(Error::Refused(format!(
                        "{} is not a directory",
                        p.display()
                    )));
                }
            },
            Err(e) => return Err(e.into()),
        }
        summary.dirs += 1;
    }
    let mut empty: Vec<Box<dyn trunc_fs::FileHandle>> = Vec::new();
    for e in items {
        match e.kind {
            ItemKind::Symlink => summary.symlinks_skipped += 1,
            ItemKind::File => summary.files += 1,
            ItemKind::Dir => {}
        }
        if e.kind != ItemKind::File || e.size > 0 || already_moved(&e.path)? {
            continue;
        }
        let p = join_rel(stage, &e.path);
        match fs.open_beneath(stage, &p, OpenMode::CreateNew, Share::Exclusive) {
            Ok(h) => {
                h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                empty.push(h);
                to_flush.insert(parent_of(&p));
            }
            Err(FsError::AlreadyExists { .. }) => match fs.metadata(&p)?.map(|m| m.kind) {
                Some(NodeKind::File) => check_exact_name(fs, &p)?,
                _ => return Err(Error::Refused(format!("{} is not a file", p.display()))),
            },
            Err(e) => return Err(e.into()),
        }
    }
    let files: Vec<&dyn trunc_fs::FileHandle> = empty.iter().map(AsRef::as_ref).collect();
    let dirs: Vec<PathBuf> = to_flush.into_iter().collect();
    fs.flush_all(&files, &dirs)?;
    Ok(())
}

/// Apply file modes, rename every top-level item from the staging directory into `dest`
/// (skipping ones already moved), and remove the empty staging directory. Idempotent.
pub(crate) fn rename_into_place(
    fs: &dyn FsBackend,
    items: &[Item],
    dest: &Path,
    stage: &Path,
) -> Result<()> {
    for e in items.iter().filter(|e| e.kind == ItemKind::File) {
        if let Some(mode) = e.mode {
            ignore_not_found(fs.set_mode(&join_rel(stage, &e.path), mode))?;
        }
    }
    let tops = top_level_names(items);
    for name in &tops {
        let from = stage.join(name);
        if fs.metadata(&from)?.is_none() {
            continue; // already moved by an earlier run
        }
        match fs.rename(&from, &dest.join(name)) {
            Ok(()) => {}
            Err(FsError::AlreadyExists { path }) => {
                return Err(Error::Refused(format!(
                    "{} appeared during extraction; move it away and resume",
                    path.display()
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
    if let Some(missing) = tops
        .iter()
        .find(|n| fs.metadata(&dest.join(n)).ok().flatten().is_none())
    {
        return Err(Error::Integrity(format!(
            "{} is missing from {} after moving files into place",
            missing,
            dest.display()
        )));
    }
    fs.flush_dir(stage)?;
    fs.flush_dir(dest)?;
    fs.remove_dir(stage)?;
    fs.flush_dir(dest)?;
    Ok(())
}

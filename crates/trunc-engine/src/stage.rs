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

/// Open (or create) a staging output, refusing anything that is really one of `protected`
/// (the archive or its journal, e.g. via a hard link planted in the staging directory).
/// Returns the handle and whether the file was created.
pub(crate) fn open_staged_output(
    fs: &dyn FsBackend,
    p: &Path,
    protected: &[trunc_fs::FileId],
) -> Result<(Box<dyn FileHandle>, bool)> {
    let (h, created) = match fs.metadata(p)?.map(|m| m.kind) {
        None => (fs.open(p, OpenMode::CreateNew, Share::Exclusive)?, true),
        Some(NodeKind::File) => (fs.open(p, OpenMode::ReadWrite, Share::Exclusive)?, false),
        Some(_) => return Err(Error::Refused(format!("{} is not a file", p.display()))),
    };
    if protected.contains(&h.file_id()?) {
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

pub(crate) fn top_level_names(items: &[Item]) -> Vec<String> {
    let set: BTreeSet<String> = items
        .iter()
        .map(|e| e.path.split('/').next().unwrap_or(&e.path).to_owned())
        .collect();
    set.into_iter().collect()
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
    for d in all_dirs(items) {
        if already_moved(fs, dest, stage, &d)? {
            continue;
        }
        let p = join_rel(stage, &d);
        match fs.metadata(&p)?.map(|m| m.kind) {
            None => {
                fs.create_dir(&p)?;
                to_flush.insert(parent_of(&p));
            }
            Some(NodeKind::Dir) => {}
            Some(_) => {
                return Err(Error::Refused(format!(
                    "{} is not a directory",
                    p.display()
                )));
            }
        }
        summary.dirs += 1;
    }
    for e in items {
        match e.kind {
            ItemKind::Symlink => summary.symlinks_skipped += 1,
            ItemKind::File => summary.files += 1,
            ItemKind::Dir => {}
        }
        if e.kind != ItemKind::File || e.size > 0 || already_moved(fs, dest, stage, &e.path)? {
            continue;
        }
        let p = join_rel(stage, &e.path);
        match fs.metadata(&p)?.map(|m| m.kind) {
            None => {
                let h = fs.open(&p, OpenMode::CreateNew, Share::Exclusive)?;
                h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                h.flush_data()?;
                to_flush.insert(parent_of(&p));
            }
            Some(NodeKind::File) => {}
            Some(_) => return Err(Error::Refused(format!("{} is not a file", p.display()))),
        }
    }
    for d in &to_flush {
        fs.flush_dir(d)?;
    }
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
    for name in top_level_names(items) {
        let from = stage.join(&name);
        if fs.metadata(&from)?.is_none() {
            continue; // already moved by an earlier run
        }
        match fs.rename(&from, &dest.join(&name)) {
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
    fs.flush_dir(stage)?;
    fs.flush_dir(dest)?;
    fs.remove_dir(stage)?;
    fs.flush_dir(dest)?;
    Ok(())
}

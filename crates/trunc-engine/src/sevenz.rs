//! 7z archives: inspection, verification and extraction.
//!
//! The whole header is parsed and validated (names, sizes, coder chains, dictionary limits)
//! before anything is written. Extraction then decodes every folder into a staging directory
//! inside the destination, checking each file's CRC (and the folder's, when recorded), and only
//! once everything decoded and matched are the files moved into place. A damaged or refused
//! archive leaves the destination as it was, apart from the staging directory being removed.
//!
//! Folders are independent, so they decode on several threads where the backend allows it.
//!
//! Destructive extraction (`--consume`) is not offered for 7z yet: see ADR-0017 for why and for
//! the design it would take.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use trunc_core::space::SpaceParams;
use trunc_fs::{FileHandle, FileId, FsBackend, NodeKind, OpenMode, Share};
use trunc_hash::Blake3Hasher;
use trunc_legacy::sevenz::{self, Entry, Kind, Layout, SevenZError};

use crate::consume::{ConsumeSummary, stage_dir};
use crate::error::{Error, Result};
use crate::source;
use crate::stage::{StageGuard, check_exact_name, ensure_dir, join_rel, open_staged_output};
use crate::walk::system_time;

fn sz_err(archive: &Path, e: SevenZError) -> Error {
    match e {
        SevenZError::Fs(f) => f.into(),
        SevenZError::Crc(m) => Error::Integrity(format!("{}: {m}", archive.display())),
        other => Error::Input(format!("{}: {other}", archive.display())),
    }
}

/// True if `path` (or the first part of a split archive) starts with the 7z signature.
pub fn is_7z(fs: &dyn FsBackend, path: &Path) -> bool {
    let Ok(h) = source::open_read(fs, path) else {
        return false;
    };
    let mut head = [0u8; 6];
    h.read_exact_at(&mut head, 0).is_ok() && sevenz::sniff(&head)
}

/// Parse a 7z archive for inspection or planning.
pub fn open_layout(fs: &dyn FsBackend, archive: &Path, max_window: u64) -> Result<Layout> {
    let h = source::open_read(fs, archive)?;
    sevenz::parse(h.as_ref(), max_window).map_err(|e| sz_err(archive, e))
}

/// Space needed to extract a 7z archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenZSpace {
    pub archive_len: u64,
    pub content: u64,
    /// Free space a non-destructive extraction needs.
    pub extract_extra: u64,
}

pub fn sevenz_space(layout: &Layout, params: &SpaceParams) -> SevenZSpace {
    let cl = params.cluster_size.max(1);
    let mut slack = 0u64;
    let mut content = 0u64;
    for e in &layout.entries {
        slack = slack.saturating_add(params.per_entry_overhead);
        if e.kind == Kind::File {
            content = content.saturating_add(e.size);
            slack = slack.saturating_add(e.size.div_ceil(cl) * cl - e.size);
        }
    }
    let margin = params.margin_fixed + content / 1_000_000 * params.margin_ppm;
    SevenZSpace {
        archive_len: layout.file_len,
        content,
        extract_extra: content.saturating_add(slack).saturating_add(margin),
    }
}

/// Run `f` for every folder, on several threads when `parallel`.
fn each_folder(
    layout: &Layout,
    parallel: bool,
    f: &(dyn Fn(usize) -> Result<()> + Sync),
) -> Result<()> {
    if parallel && layout.folders.len() > 1 {
        use rayon::prelude::*;
        (0..layout.folders.len()).into_par_iter().try_for_each(f)
    } else {
        (0..layout.folders.len()).try_for_each(f)
    }
}

/// Check every CRC without writing anything. Returns (entries, bytes) checked.
pub fn verify_7z(
    fs: &dyn FsBackend,
    archive: &Path,
    max_window: u64,
    threads: usize,
) -> Result<(usize, u64)> {
    let _prof = trunc_prof::span("7z.verify");
    let h = source::open_read(fs, archive)?;
    let layout = sevenz::parse(h.as_ref(), max_window).map_err(|e| sz_err(archive, e))?;
    each_folder(&layout, threads != 1, &|i| {
        sevenz::decode_folder(
            h.as_ref(),
            &layout,
            i,
            &mut |_| Ok(()),
            &mut |_, _| Ok(()),
            &mut |_| Ok(()),
        )
        .map_err(|e| sz_err(archive, e))
    })?;
    Ok((layout.entries.len(), layout.content_bytes()))
}

/// Every directory the entries need, including implicit parents, parents first.
fn all_dirs(entries: &[Entry]) -> Vec<String> {
    let mut dirs = BTreeSet::new();
    for e in entries.iter().filter(|e| e.kind != Kind::Symlink) {
        if e.kind == Kind::Dir {
            dirs.insert(e.name.clone());
        }
        let mut p = trunc_core::path::parent(&e.name);
        while let Some(d) = p {
            if !dirs.insert(d.to_owned()) {
                break;
            }
            p = trunc_core::path::parent(d);
        }
    }
    dirs.into_iter().collect()
}

/// Refuse up front anything that would clash with what is already in `dest`.
fn check_dest(fs: &dyn FsBackend, dest: &Path, layout: &Layout, overwrite: bool) -> Result<()> {
    for d in all_dirs(&layout.entries) {
        let p = join_rel(dest, &d);
        if fs.metadata(&p)?.is_some_and(|m| m.kind != NodeKind::Dir) {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                p.display()
            )));
        }
    }
    for e in layout.entries.iter().filter(|e| e.kind == Kind::File) {
        let p = join_rel(dest, &e.name);
        match fs.metadata(&p)?.map(|m| m.kind) {
            None => {}
            Some(NodeKind::File) if overwrite => {}
            Some(_) => return Err(Error::Refused(format!("{} already exists", p.display()))),
        }
    }
    Ok(())
}

/// Remove `p` and everything beneath it, never following links (a link is removed itself).
fn remove_tree(fs: &dyn FsBackend, p: &Path) -> Result<()> {
    match fs.metadata(p)?.map(|m| m.kind) {
        None => Ok(()),
        Some(NodeKind::Dir) => {
            for n in fs.read_dir(p)? {
                remove_tree(fs, &p.join(n))?;
            }
            Ok(fs.remove_dir(p)?)
        }
        Some(_) => match fs.remove_file(p) {
            Ok(()) => Ok(()),
            // A directory junction is removed like a directory.
            Err(_) => Ok(fs.remove_dir(p)?),
        },
    }
}

/// A staging directory name that depends only on the archive, so an interrupted run's
/// leftovers are found (and replaced) by the next one.
fn stage_id(h: &dyn FileHandle, layout: &Layout) -> Result<[u8; 16]> {
    let mut sig = [0u8; 32];
    h.read_exact_at(&mut sig, 0)?;
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"trunc 7z extract");
    hasher.update(&layout.file_len.to_le_bytes());
    hasher.update(&sig);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Ok(id)
}

/// File ids of the archive (every part of a split archive): outputs must never be one of them.
fn protected_ids(fs: &dyn FsBackend, archive: &Path) -> Result<HashSet<FileId>> {
    let paths = source::split_parts(fs, archive)?.unwrap_or_else(|| vec![archive.to_path_buf()]);
    let mut ids = HashSet::new();
    for p in paths {
        ids.insert(fs.open(&p, OpenMode::Read, Share::Shared)?.file_id()?);
    }
    Ok(ids)
}

/// Decode every folder into the staging directory. Returns the content bytes written.
fn stage_all(
    fs: &dyn FsBackend,
    h: &dyn FileHandle,
    archive: &Path,
    layout: &Layout,
    stage: &Path,
    guard: &StageGuard<'_>,
) -> Result<u64> {
    for d in all_dirs(&layout.entries) {
        let p = join_rel(stage, &d);
        match fs.create_dir_beneath(stage, &p) {
            Ok(()) => {}
            Err(trunc_fs::FsError::AlreadyExists { .. }) => check_exact_name(fs, &p)?,
            Err(e) => return Err(e.into()),
        }
    }
    let finish = |out: &dyn FileHandle, e: &Entry| -> Result<()> {
        out.set_len(e.size)?;
        out.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
        Ok(())
    };
    for e in &layout.entries {
        if e.kind == Kind::File && e.folder.is_none() {
            let (out, _) = open_staged_output(fs, guard, &join_rel(stage, &e.name))?;
            finish(out.as_ref(), e)?;
        }
    }
    let written = Mutex::new(0u64);
    each_folder(layout, fs.parallel_io(), &|i| {
        // An engine error met inside the decoder's callbacks, handed back after it stops.
        let held: Mutex<Option<Error>> = Mutex::new(None);
        let hold = |e: Error| {
            *held.lock().expect("not poisoned") = Some(e);
            SevenZError::Stopped
        };
        let out: RefCell<Option<(Box<dyn FileHandle>, u64)>> = RefCell::new(None);
        let bytes = Cell::new(0u64);
        let r = sevenz::decode_folder(
            h,
            layout,
            i,
            &mut |ei| {
                let e = &layout.entries[ei];
                if e.kind == Kind::File {
                    let (f, _) =
                        open_staged_output(fs, guard, &join_rel(stage, &e.name)).map_err(hold)?;
                    f.preallocate(e.size)?;
                    *out.borrow_mut() = Some((f, 0));
                }
                Ok(())
            },
            &mut |_, b| {
                if let Some((f, off)) = &mut *out.borrow_mut() {
                    f.write_all_at(b, *off)?;
                    *off += b.len() as u64;
                    bytes.set(bytes.get() + b.len() as u64);
                }
                Ok(())
            },
            &mut |ei| {
                if let Some((f, _)) = out.borrow_mut().take() {
                    finish(f.as_ref(), &layout.entries[ei]).map_err(hold)?;
                }
                Ok(())
            },
        );
        match r {
            Ok(()) => {
                *written.lock().expect("not poisoned") += bytes.get();
                Ok(())
            }
            Err(SevenZError::Stopped) => Err(held
                .into_inner()
                .expect("not poisoned")
                .unwrap_or_else(|| Error::Input("7z decoding stopped".into()))),
            Err(e) => Err(sz_err(archive, e)),
        }
    })?;
    Ok(written.into_inner().expect("not poisoned"))
}

/// Move staged items into `dest`: directories are created (or reused), files renamed one by
/// one, replacing existing files only with `overwrite`.
fn move_into_place(
    fs: &dyn FsBackend,
    layout: &Layout,
    stage: &Path,
    dest: &Path,
    overwrite: bool,
) -> Result<()> {
    for d in all_dirs(&layout.entries) {
        let p = join_rel(dest, &d);
        trunc_fs::check_beneath(fs, dest, &p)?;
        match fs.metadata(&p)?.map(|m| m.kind) {
            None => fs.create_dir(&p)?,
            Some(NodeKind::Dir) => {}
            Some(_) => {
                return Err(Error::Refused(format!(
                    "{} exists and is not a directory",
                    p.display()
                )));
            }
        }
    }
    for e in layout.entries.iter().filter(|e| e.kind == Kind::File) {
        let to = join_rel(dest, &e.name);
        trunc_fs::check_beneath(fs, dest, &to)?;
        match fs.metadata(&to)?.map(|m| m.kind) {
            None => {}
            Some(NodeKind::File) if overwrite => fs.remove_file(&to)?,
            Some(_) => {
                return Err(Error::Refused(format!(
                    "{} appeared during extraction",
                    to.display()
                )));
            }
        }
        fs.rename(&join_rel(stage, &e.name), &to)?;
        if let Some(m) = e.mode {
            fs.set_mode(&to, m)?;
        }
    }
    Ok(())
}

/// Non-destructive extraction of a 7z archive into `dest`. Symlink entries are skipped.
pub fn extract_7z(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    max_window: u64,
) -> Result<ConsumeSummary> {
    let _prof = trunc_prof::span("7z.extract");
    let h = source::open_read(fs, archive)?;
    let layout = sevenz::parse(h.as_ref(), max_window).map_err(|e| sz_err(archive, e))?;
    ensure_dir(fs, dest)?;
    check_dest(fs, dest, &layout, overwrite)?;
    let stage: PathBuf = stage_dir(dest, &stage_id(h.as_ref(), &layout)?);
    let stage_name = stage
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if layout
        .entries
        .iter()
        .any(|e| e.name.split('/').next().unwrap_or("").to_lowercase() == stage_name)
    {
        return Err(Error::Refused(format!(
            "the archive has an entry named like trunc's staging directory ({stage_name})"
        )));
    }
    let ids = protected_ids(fs, archive)?;
    let protected = |id: &FileId| ids.contains(id);
    let guard = StageGuard {
        root: &stage,
        protected: &protected,
    };
    remove_tree(fs, &stage)?;
    fs.create_dir(&stage)?;
    let run = || -> Result<u64> {
        let written = stage_all(fs, h.as_ref(), archive, &layout, &stage, &guard)?;
        move_into_place(fs, &layout, &stage, dest, overwrite)?;
        Ok(written)
    };
    let result = run();
    // Whatever happened, the staging directory goes (after success it holds only directories).
    let cleaned = remove_tree(fs, &stage);
    let written = result?;
    cleaned?;
    let mut summary = ConsumeSummary {
        bytes_written: written,
        ..ConsumeSummary::default()
    };
    summary.dirs = all_dirs(&layout.entries).len();
    for e in &layout.entries {
        match e.kind {
            Kind::File => summary.files += 1,
            Kind::Symlink => summary.symlinks_skipped += 1,
            Kind::Dir => {}
        }
    }
    Ok(summary)
}

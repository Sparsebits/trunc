//! Destructive extraction: extract while truncating the archive.
//!
//! Outputs are written into a staging directory inside the destination,
//! `<dest>/.trunc-stage-<archive id>/`, and renamed into place once every block has been
//! consumed (ADR-0003). For each batch of blocks, in this order (`docs/spec/invariants.md`):
//!
//! 1. read and verify each block (footer, payload hash), decode, verify the decoded hash;
//! 2. preallocate and write the outputs;
//! 3. flush the data of every output written, then every directory that gained an entry;
//! 4. truncate the archive past the batch, retrying while another process has it mapped;
//! 5. flush the archive, so a crash cannot resurrect blocks whose outputs already exist.
//!
//! Recovery needs no journal. The archive's length says which blocks are consumed; whatever is
//! still in the staging directory has not been renamed yet; a small resume note next to the
//! archive (`<archive>.trncr`) records the destination so a resume can find it. Every step is
//! idempotent, and an interrupted batch is simply redone (its blocks are still in the archive).

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rayon::prelude::*;
use trunc_core::space::{self, SpaceParams};
use trunc_core::{EntryKind, Manifest};
use trunc_fs::{FileHandle, FsBackend, FsError, NodeKind, OpenMode, Share};

use crate::archive::Archive;
use crate::error::{Error, PauseReason, Result};
use crate::extract::TrustPolicy;
use crate::io::len_usize;
use crate::preflight::{self, Finding};
use crate::walk::system_time;

/// How hard to retry truncating an archive that another process has memory-mapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub attempts: u32,
    /// Delay before the first retry; doubles each time.
    pub initial_delay: Duration,
}

impl Default for RetryPolicy {
    /// About 25 seconds in total.
    fn default() -> Self {
        Self {
            attempts: 9,
            initial_delay: Duration::from_millis(100),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsumeOptions {
    pub trust: TrustPolicy,
    /// Decode threads; 0 = all cores.
    pub threads: usize,
    /// Batch size and space-model allowances.
    pub space: SpaceParams,
    /// Proceed on filesystems without metadata journaling (FAT32, exFAT).
    pub allow_unjournaled: bool,
    /// Proceed even though the archive is in a cloud-synced folder.
    pub allow_sync: bool,
    /// Start even if preflight says the destination is too small.
    pub skip_space_check: bool,
    /// Keep the archive's remaining header + manifest as `<archive>.receipt`.
    pub keep_receipt: bool,
    pub retry: RetryPolicy,
}

impl Default for ConsumeOptions {
    fn default() -> Self {
        Self {
            trust: TrustPolicy::default(),
            threads: 0,
            space: SpaceParams::default(),
            allow_unjournaled: false,
            allow_sync: false,
            skip_space_check: false,
            keep_receipt: true,
            retry: RetryPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Started {
        resumed: bool,
        blocks_done: usize,
        blocks_total: usize,
    },
    Batch {
        blocks_done: usize,
        blocks_total: usize,
        bytes_written: u64,
        archive_len: u64,
    },
    Renaming,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsumeSummary {
    /// This run continued an earlier, interrupted one.
    pub resumed: bool,
    pub files: usize,
    pub dirs: usize,
    pub bytes_written: u64,
    pub batches: usize,
    pub symlinks_skipped: usize,
    pub receipt: Option<PathBuf>,
    /// Non-blocking preflight findings (warnings and notes).
    pub findings: Vec<Finding>,
}

/// The staging directory used for `archive_id` under `dest`.
pub fn stage_dir(dest: &Path, archive_id: &[u8; 16]) -> PathBuf {
    dest.join(format!(".trunc-stage-{}", hex::encode(archive_id)))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Where the resume note for `archive` lives.
pub fn resume_note_path(archive: &Path) -> PathBuf {
    sibling(archive, ".trncr")
}

/// Where the receipt for `archive` is written.
pub fn receipt_path(archive: &Path) -> PathBuf {
    sibling(archive, ".receipt")
}

/// Contents of a resume note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeNote {
    pub archive_id: [u8; 16],
    pub dest: PathBuf,
}

const NOTE_MAGIC: &str = "trunc-resume-v1";

/// Read the resume note next to `archive`, if there is a valid one.
pub fn read_resume_note(fs: &dyn FsBackend, archive: &Path) -> Option<ResumeNote> {
    let p = resume_note_path(archive);
    let h = fs.open(&p, OpenMode::Read, Share::Shared).ok()?;
    let len = h.size().ok()?;
    if len > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; len_usize(len)];
    h.read_exact_at(&mut buf, 0).ok()?;
    let text = String::from_utf8(buf).ok()?;
    let mut lines = text.lines();
    if lines.next()? != NOTE_MAGIC {
        return None;
    }
    let id = hex::decode(lines.next()?.strip_prefix("id=")?)
        .ok()?
        .try_into()
        .ok()?;
    let dest = PathBuf::from(lines.next()?.strip_prefix("dest=")?);
    Some(ResumeNote {
        archive_id: id,
        dest,
    })
}

/// Parent directory; `.` for a bare file name, the path itself for a root.
fn parent_of(p: &Path) -> PathBuf {
    match p.parent() {
        Some(parent) if parent.as_os_str().is_empty() => PathBuf::from("."),
        Some(parent) => parent.to_path_buf(),
        None => p.to_path_buf(),
    }
}

fn join_rel(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    p
}

fn top_level_names(m: &Manifest) -> Vec<String> {
    let set: BTreeSet<String> = m
        .entries
        .iter()
        .map(|e| e.path.split('/').next().unwrap_or(&e.path).to_owned())
        .collect();
    set.into_iter().collect()
}

fn ignore_not_found(r: std::result::Result<(), FsError>) -> Result<()> {
    match r {
        Ok(()) | Err(FsError::NotFound { .. }) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Create `dir` and any missing ancestors, flushing each new entry's parent.
fn ensure_dir(fs: &dyn FsBackend, dir: &Path) -> Result<()> {
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

fn write_note(fs: &dyn FsBackend, archive: &Path, note: &ResumeNote) -> Result<()> {
    let p = resume_note_path(archive);
    let text = format!(
        "{NOTE_MAGIC}\nid={}\ndest={}\n",
        hex::encode(note.archive_id),
        note.dest.display()
    );
    let h = fs.open(&p, OpenMode::CreateOrTruncate, Share::Shared)?;
    h.write_all_at(text.as_bytes(), 0)?;
    h.flush_data()?;
    drop(h);
    fs.flush_dir(&parent_of(archive))?;
    Ok(())
}

fn truncate_with_retry(h: &dyn FileHandle, len: u64, retry: RetryPolicy) -> Result<()> {
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

/// Consume `archive_path` into `dest`: extract everything while truncating the archive.
///
/// Safe to call again after any crash or pause with the same arguments; it resumes.
pub fn consume(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    opts: &ConsumeOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<ConsumeSummary> {
    let absolute = |p: &Path| std::path::absolute(p).map_err(|e| Error::Input(e.to_string()));
    let dest = absolute(dest)?;
    let archive_path = &absolute(archive_path)?;
    let note = read_resume_note(fs, archive_path);

    let mut archive =
        match Archive::open_with(fs, archive_path, OpenMode::ReadWrite, Share::Exclusive) {
            Ok(a) => a,
            // Crashed after the archive became a receipt but before the note was removed.
            Err(Error::Fs(FsError::NotFound { .. }))
                if note.as_ref().is_some_and(|n| n.dest == dest) =>
            {
                ignore_not_found(fs.remove_file(&resume_note_path(archive_path)))?;
                fs.flush_dir(&parent_of(archive_path))?;
                return Ok(ConsumeSummary {
                    resumed: true,
                    ..ConsumeSummary::default()
                });
            }
            // Already finished: the receipt shows a fully consumed archive whose contents are
            // in place. Running again is a no-op rather than an error.
            Err(e @ Error::Fs(FsError::NotFound { .. })) => {
                return match completed_receipt(fs, archive_path, &dest)? {
                    Some(r) => Ok(ConsumeSummary {
                        resumed: true,
                        receipt: Some(r),
                        ..ConsumeSummary::default()
                    }),
                    None => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
    opts.trust.check(&archive)?;
    let m = archive.manifest().clone();
    let n = m.blocks.len();
    let fbo = archive.header().first_block_off();
    let stage = stage_dir(&dest, &m.archive_id);
    let tops = top_level_names(&m);

    // Preflight: refuse unsafe situations before touching anything.
    let pre = preflight::assess(fs, &archive, &dest, opts.space)?;
    for f in pre.blockers() {
        match f {
            Finding::NotJournaled(_) if opts.allow_unjournaled => {}
            Finding::ArchiveSynced(_) if opts.allow_sync => {}
            _ => return Err(Error::Refused(f.to_string())),
        }
    }
    let findings: Vec<Finding> = pre
        .findings
        .iter()
        .filter(|f| f.severity() != preflight::Severity::Blocker)
        .cloned()
        .collect();

    let stage_kind = fs.metadata(&stage)?.map(|m| m.kind);
    let note_matches = note
        .as_ref()
        .is_some_and(|n| n.archive_id == m.archive_id && n.dest == dest);
    let mut summary = ConsumeSummary {
        findings,
        ..ConsumeSummary::default()
    };
    match stage_kind {
        Some(NodeKind::Dir) => summary.resumed = true,
        Some(_) => {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                stage.display()
            )));
        }
        None if archive.consumed() == n && note_matches && all_exist(fs, &dest, &tops)? => {
            // Everything was renamed into place; only the archive cleanup remains.
            summary.resumed = true;
            progress(Progress::Renaming);
            summary.receipt = finish(fs, archive, archive_path, opts)?;
            return Ok(summary);
        }
        None if archive.consumed() == 0 => {
            if !opts.skip_space_check && pre.consume_fits == Some(false) {
                return Err(Error::Refused(format!(
                    "not enough free space at {}: consuming needs about {} bytes, {} are free",
                    dest.display(),
                    pre.consume_needs,
                    pre.destination.free_bytes.unwrap_or(0)
                )));
            }
            if let Some(conflict) = first_existing(fs, &dest, &tops)? {
                return Err(Error::Refused(format!(
                    "{} already exists; move it away or choose another destination",
                    conflict.display()
                )));
            }
            write_note(
                fs,
                archive_path,
                &ResumeNote {
                    archive_id: m.archive_id,
                    dest: dest.clone(),
                },
            )?;
            ensure_dir(fs, &dest)?;
            fs.create_dir(&stage)?;
            fs.flush_dir(&dest)?;
        }
        None => {
            let hint = note
                .filter(|n| n.archive_id == m.archive_id)
                .map(|n| format!(" (it was being extracted into {})", n.dest.display()))
                .unwrap_or_default();
            return Err(Error::Refused(format!(
                "{} of {n} blocks of this archive were already consumed, but {} has no staging \
                 directory for it{hint}; resume with the original destination",
                archive.consumed(),
                dest.display()
            )));
        }
    }
    progress(Progress::Started {
        resumed: summary.resumed,
        blocks_done: archive.consumed(),
        blocks_total: n,
    });

    build_structure(fs, &m, &dest, &stage, &mut summary)?;
    consume_blocks(
        fs,
        &mut archive,
        &m,
        fbo,
        &stage,
        opts,
        progress,
        &mut summary,
    )?;

    // Rename phase: every block is consumed and every output is durable.
    progress(Progress::Renaming);
    for e in m
        .entries
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::File))
    {
        ignore_not_found(fs.set_mode(&join_rel(&stage, &e.path), e.mode))?;
    }
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
    fs.flush_dir(&stage)?;
    fs.flush_dir(&dest)?;
    fs.remove_dir(&stage)?;
    fs.flush_dir(&dest)?;
    summary.receipt = finish(fs, archive, archive_path, opts)?;
    Ok(summary)
}

/// If `archive_path` was fully consumed into `dest` and turned into a receipt, return the
/// receipt's path.
fn completed_receipt(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
) -> Result<Option<PathBuf>> {
    let r = receipt_path(archive_path);
    let Ok(receipt) = Archive::open_with(fs, &r, OpenMode::Read, Share::Shared) else {
        return Ok(None);
    };
    let m = receipt.manifest();
    let done = receipt.consumed() == m.blocks.len()
        && fs.metadata(&stage_dir(dest, &m.archive_id))?.is_none()
        && all_exist(fs, dest, &top_level_names(m))?;
    Ok(done.then_some(r))
}

fn all_exist(fs: &dyn FsBackend, dest: &Path, names: &[String]) -> Result<bool> {
    for name in names {
        if fs.metadata(&dest.join(name))?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn first_existing(fs: &dyn FsBackend, dest: &Path, names: &[String]) -> Result<Option<PathBuf>> {
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
fn build_structure(
    fs: &dyn FsBackend,
    m: &Manifest,
    dest: &Path,
    stage: &Path,
    summary: &mut ConsumeSummary,
) -> Result<()> {
    let mut to_flush: BTreeSet<PathBuf> = BTreeSet::new();
    for d in m.all_dirs() {
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
    for e in &m.entries {
        match &e.kind {
            EntryKind::Symlink { .. } => summary.symlinks_skipped += 1,
            EntryKind::File => summary.files += 1,
            EntryKind::Dir => {}
        }
        if !matches!(e.kind, EntryKind::File)
            || e.size > 0
            || already_moved(fs, dest, stage, &e.path)?
        {
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

#[allow(clippy::too_many_arguments)]
fn consume_blocks(
    fs: &dyn FsBackend,
    archive: &mut Archive,
    m: &Manifest,
    fbo: u64,
    stage: &Path,
    opts: &ConsumeOptions,
    progress: &mut dyn FnMut(Progress),
    summary: &mut ConsumeSummary,
) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads)
        .build()
        .map_err(|e| Error::Input(format!("cannot start worker threads: {e}")))?;
    let n = m.blocks.len();
    let groups = space::batches(m, archive.consumed(), opts.space.batch_max_u);
    let mut open: HashMap<usize, Box<dyn FileHandle>> = HashMap::new();
    let mut hashers: HashMap<usize, trunc_hash::Blake3Hasher> = HashMap::new();

    let pause_on_full = |e: FsError, consumed: usize| -> Error {
        match e {
            FsError::NoSpace { .. } => {
                let b = space::bound(m, fbo, consumed, &opts.space);
                Error::Paused(PauseReason::NoSpace {
                    needed: b.consume_extra,
                })
            }
            other => other.into(),
        }
    };

    for g in groups {
        let archive_ref: &Archive = archive;
        let decoded: Vec<Result<Vec<u8>>> = pool.install(|| {
            g.clone()
                .into_par_iter()
                .map(|i| archive_ref.decode_block(i))
                .collect()
        });

        let mut touched: BTreeSet<usize> = BTreeSet::new();
        let mut completed: Vec<usize> = Vec::new();
        let mut new_parents: BTreeSet<PathBuf> = BTreeSet::new();
        for (i, buf) in g.clone().zip(decoded) {
            let buf = buf?;
            let b = &m.blocks[i];
            for r in archive_ref.stream().runs(b.stream_off, b.u_len) {
                let e = &m.entries[r.entry];
                if let std::collections::hash_map::Entry::Vacant(slot) = open.entry(r.entry) {
                    let p = join_rel(stage, &e.path);
                    let h = match fs.metadata(&p)?.map(|m| m.kind) {
                        None => {
                            new_parents.insert(parent_of(&p));
                            fs.open(&p, OpenMode::CreateNew, Share::Exclusive)?
                        }
                        Some(NodeKind::File) => {
                            fs.open(&p, OpenMode::ReadWrite, Share::Exclusive)?
                        }
                        Some(_) => {
                            return Err(Error::Refused(format!("{} is not a file", p.display())));
                        }
                    };
                    slot.insert(h);
                }
                let h = &open[&r.entry];
                let s = len_usize(r.buf_off);
                let data = &buf[s..s + len_usize(r.len)];
                let end = r.entry_off + r.len;
                h.preallocate(end).map_err(|e| pause_on_full(e, g.start))?;
                h.write_all_at(data, r.entry_off)
                    .map_err(|e| pause_on_full(e, g.start))?;
                if r.entry_off == 0 {
                    hashers.insert(r.entry, trunc_hash::Blake3Hasher::new());
                }
                if let Some(hs) = hashers.get_mut(&r.entry) {
                    hs.update(data);
                }
                touched.insert(r.entry);
                summary.bytes_written += r.len;
                if end == e.size {
                    completed.push(r.entry);
                }
            }
        }

        for &entry in &completed {
            let e = &m.entries[entry];
            let h = &open[&entry];
            if let Some(hs) = hashers.remove(&entry) {
                if *hs.finalize().as_bytes() != e.blake3 {
                    return Err(Error::Integrity(format!(
                        "content hash mismatch for {:?}",
                        e.path
                    )));
                }
            }
            if h.size()? != e.size {
                h.set_len(e.size)?;
            }
            h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
        }
        // Durability before release: data, then directory entries.
        for entry in &touched {
            open[entry].flush_data()?;
        }
        for d in &new_parents {
            fs.flush_dir(d)?;
        }
        for entry in &completed {
            open.remove(entry);
        }
        // Release the batch's blocks and make the release itself durable.
        let new_len = m.len_after_consuming(fbo, g.end);
        truncate_with_retry(archive.handle(), new_len, opts.retry)?;
        archive.handle().flush_data()?;
        archive.note_consumed(g.end);
        summary.batches += 1;
        progress(Progress::Batch {
            blocks_done: g.end,
            blocks_total: n,
            bytes_written: summary.bytes_written,
            archive_len: new_len,
        });
    }
    debug_assert!(open.is_empty(), "every output received all its bytes");
    Ok(())
}

/// Turn the fully consumed archive into a receipt (or delete it) and remove the resume note.
fn finish(
    fs: &dyn FsBackend,
    archive: Archive,
    archive_path: &Path,
    opts: &ConsumeOptions,
) -> Result<Option<PathBuf>> {
    drop(archive); // close the exclusive handle before renaming or deleting the file
    let dir = parent_of(archive_path);
    let mut receipt = None;
    if opts.keep_receipt {
        let r = receipt_path(archive_path);
        match fs.rename(archive_path, &r) {
            Ok(()) => receipt = Some(r),
            Err(FsError::AlreadyExists { .. }) => fs.remove_file(archive_path)?,
            Err(e) => return Err(e.into()),
        }
    } else {
        fs.remove_file(archive_path)?;
    }
    fs.flush_dir(&dir)?;
    ignore_not_found(fs.remove_file(&resume_note_path(archive_path)))?;
    fs.flush_dir(&dir)?;
    Ok(receipt)
}

//! Destructive extraction of ZIP archives.
//!
//! ZIP stores entries front to back with the central directory at the end, so the archive is
//! consumed from the end: entries are processed in descending order of where their bytes end,
//! and after each one the file is truncated to the end of the furthest entry still needed. That
//! rule also keeps overlapping entries correct, since it never cuts bytes another entry needs.
//!
//! Before anything is destroyed, the parsed layout (which outlives the central directory),
//! the archive's identity and the destination are written to a journal next to the archive
//! (`<archive>.trncj`). As with `.trnc`, the archive's length then says which entries are done.
//!
//! **Punch mode** frees space inside a large entry as it decompresses: after each checkpoint
//! (output flushed, inflate state saved in the journal) the compressed bytes already consumed
//! are deallocated. The entry's CRC is verified in a read-only pass first, because once bytes
//! are punched a corrupt entry could no longer be retried.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use trunc_core::space::SpaceParams;
use trunc_fs::{Dealloc, FileHandle, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_journal::Journal;
use trunc_legacy::inflate::{Checkpoint, InflateError, Inflater, WINDOW};
use trunc_legacy::zip::{self, Entry, Kind, Layout, Method};

use crate::consume::{ConsumeOptions, ConsumeSummary, Progress, stage_dir};
use crate::error::{Error, PauseReason, Result};
use crate::preflight::{self, Finding, Severity};
use crate::stage::{
    Item, ItemKind, StageGuard, all_exist, build_structure, ensure_dir, first_existing,
    ignore_not_found, join_rel, open_staged_output, parent_of, rename_into_place, top_level_names,
    truncate_with_retry,
};
use crate::walk::system_time;

/// When to free space inside entries as they decompress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPolicy {
    /// Punch entries whose compressed size is at least `punch_min`, if the filesystem can
    /// deallocate ranges and no entries overlap.
    Auto,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipOptions {
    /// Process archives whose entries overlap (zip-bomb style). Off by default.
    pub allow_overlap: bool,
    pub punch: PunchPolicy,
    /// Smallest compressed entry size for which punch mode is used.
    pub punch_min: u64,
    /// Output bytes between punch-mode checkpoints.
    pub checkpoint_every: u64,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self {
            allow_overlap: false,
            punch: PunchPolicy::Auto,
            punch_min: 256 << 20,
            checkpoint_every: 64 << 20,
        }
    }
}

/// Where the journal for `archive` lives.
pub fn journal_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".trncj");
    PathBuf::from(s)
}

/// Room in a journal slot for an inflate checkpoint (window + fixed fields) plus our header.
const SLOT_CAP: u32 = 32 * 1024 + 64;
const _: () = assert!(WINDOW == 32 * 1024, "SLOT_CAP assumes a 32 KiB window");
/// Output that may accumulate past a checkpoint before the next block boundary allows another.
const BLOCK_SLACK: u64 = 4 << 20;
const PREAMBLE_MAGIC: &[u8; 5] = b"TZJP1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Preamble {
    archive_id: [u8; 16],
    original_len: u64,
    file_id: trunc_fs::FileId,
    dest: PathBuf,
    layout: Layout,
}

impl Preamble {
    fn encode(&self) -> Vec<u8> {
        let mut b = PREAMBLE_MAGIC.to_vec();
        b.extend_from_slice(&self.archive_id);
        b.extend_from_slice(&self.original_len.to_le_bytes());
        b.extend_from_slice(&self.file_id.volume.to_le_bytes());
        b.extend_from_slice(&self.file_id.file.to_le_bytes());
        let d = self.dest.to_string_lossy();
        b.extend_from_slice(&u32::try_from(d.len()).expect("path length").to_le_bytes());
        b.extend_from_slice(d.as_bytes());
        b.extend_from_slice(&self.layout.to_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.get(..5)? != PREAMBLE_MAGIC {
            return None;
        }
        let archive_id = b.get(5..21)?.try_into().ok()?;
        let original_len = u64::from_le_bytes(b.get(21..29)?.try_into().ok()?);
        let volume = u64::from_le_bytes(b.get(29..37)?.try_into().ok()?);
        let file = u128::from_le_bytes(b.get(37..53)?.try_into().ok()?);
        let dl = u32::from_le_bytes(b.get(53..57)?.try_into().ok()?) as usize;
        let dest = PathBuf::from(std::str::from_utf8(b.get(57..57 + dl)?).ok()?);
        let layout = Layout::from_bytes(b.get(57 + dl..)?)?;
        Some(Self {
            archive_id,
            original_len,
            file_id: trunc_fs::FileId { volume, file },
            dest,
            layout,
        })
    }
}

/// Punch-mode progress for one entry, stored in a journal slot.
#[derive(Debug, Clone)]
struct EntryCkpt {
    entry: u32,
    inflate: Checkpoint,
}

impl EntryCkpt {
    fn encode(&self) -> Vec<u8> {
        let mut b = self.entry.to_le_bytes().to_vec();
        b.extend_from_slice(&self.inflate.to_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        Some(Self {
            entry: u32::from_le_bytes(b.get(..4)?.try_into().ok()?),
            inflate: Checkpoint::from_bytes(b.get(4..)?)?,
        })
    }
}

fn items_of(layout: &Layout) -> Vec<Item> {
    layout
        .entries
        .iter()
        .map(|e| Item {
            path: e.name.clone(),
            kind: match e.kind {
                Kind::File => ItemKind::File,
                Kind::Dir => ItemKind::Dir,
                Kind::Symlink => ItemKind::Symlink,
            },
            size: if e.kind == Kind::File { e.size } else { 0 },
            len: if e.kind == Kind::File { e.size } else { 0 },
            mode: e.mode,
            mtime_unix: e.mtime_unix,
            mtime_nanos: 0,
        })
        .collect()
}

/// Processing order: descending region end (ties: descending start).
fn schedule(layout: &Layout) -> Vec<usize> {
    let mut order: Vec<usize> = (0..layout.entries.len()).collect();
    order.sort_by_key(|&i| {
        let e = &layout.entries[i];
        std::cmp::Reverse((e.region_end, e.region_start))
    });
    order
}

/// `after[pos]`: furthest region end among entries scheduled after `pos` (0 if none).
fn ends_after(layout: &Layout, order: &[usize]) -> Vec<u64> {
    let mut after = vec![0u64; order.len()];
    let mut m = 0u64;
    for pos in (0..order.len()).rev() {
        after[pos] = m;
        m = m.max(layout.entries[order[pos]].region_end);
    }
    after
}

/// Files in one group at most (each stays open until the group is flushed).
const GROUP_MAX_FILES: usize = 256;

/// Positions in `order`, grouped: entries in a group are extracted, then flushed together and
/// released with one truncation. Punch-mode entries stand alone (they release as they go);
/// other entries fill a group up to `batch_max_u` bytes of output or `GROUP_MAX_FILES` files.
/// The planner and the consumer both use this, so they agree on the peak.
fn groups(
    order: &[usize],
    layout: &Layout,
    punch: &dyn Fn(&Entry) -> bool,
    batch_max_u: u64,
) -> Vec<std::ops::Range<usize>> {
    let mut out = Vec::new();
    let (mut start, mut bytes, mut files) = (0usize, 0u64, 0usize);
    for (pos, &i) in order.iter().enumerate() {
        let e = &layout.entries[i];
        if punch(e) {
            if pos > start {
                out.push(start..pos);
            }
            out.push(pos..pos + 1);
            (start, bytes, files) = (pos + 1, 0, 0);
            continue;
        }
        let is_file = e.kind == Kind::File && e.size > 0;
        if pos > start && is_file && (bytes + e.size > batch_max_u || files >= GROUP_MAX_FILES) {
            out.push(start..pos);
            (start, bytes, files) = (pos, 0, 0);
        }
        if is_file {
            bytes += e.size;
            files += 1;
        }
    }
    if start < order.len() {
        out.push(start..order.len());
    }
    out
}

fn should_punch(layout: &Layout, e: &Entry, opts: &ConsumeOptions, can_dealloc: bool) -> bool {
    opts.zip.punch == PunchPolicy::Auto
        && can_dealloc
        && layout.overlaps.is_empty()
        && e.kind == Kind::File
        && e.compressed_size >= opts.zip.punch_min.max(1)
}

/// Space needed to consume (or extract) a ZIP from its current length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipSpace {
    pub archive_len: u64,
    pub remaining_u: u64,
    /// Free space a non-destructive extraction needs.
    pub extract_extra: u64,
    /// Highest occupancy expected while consuming (punch mode assumes compression is spread
    /// evenly through each entry).
    pub consume_peak: u64,
    /// Upper bound that holds whatever the data looks like (no credit for punching).
    pub consume_peak_guaranteed: u64,
    pub consume_extra: u64,
}

/// Simulate consumption to bound occupancy. `granularity` is the deallocation unit.
pub fn zip_space(
    layout: &Layout,
    archive_len: u64,
    opts: &ConsumeOptions,
    can_dealloc: bool,
    granularity: u64,
    params: &SpaceParams,
) -> ZipSpace {
    let order = schedule(layout);
    let after = ends_after(layout, &order);
    let all_max = order.first().map_or(0, |&i| layout.entries[i].region_end);
    let mut len = archive_len.min(all_max);
    let (mut peak, mut guaranteed) = (archive_len, archive_len);
    let mut written = 0u64;
    let mut remaining_u = 0u64;
    let mut slack = 0u64;
    let punch = |e: &Entry| should_punch(layout, e, opts, can_dealloc);
    for g in groups(&order, layout, &punch, params.batch_max_u) {
        // A group's outputs all exist before its truncation.
        let mut group_out = 0u64;
        for &i in &order[g.clone()] {
            let e = &layout.entries[i];
            if e.region_end > len {
                continue;
            }
            slack += params.per_entry_overhead;
            if e.kind != Kind::File {
                continue;
            }
            let cl = params.cluster_size.max(1);
            slack += e.size.div_ceil(cl) * cl - e.size;
            remaining_u += e.size;
            group_out += e.size;
            let entry_mode = len + written + group_out;
            guaranteed = guaranteed.max(entry_mode);
            let est = if punch(e) && e.size > 0 {
                let window = opts.zip.checkpoint_every + BLOCK_SLACK;
                let tail = u64::try_from(
                    u128::from(window) * u128::from(e.compressed_size) / u128::from(e.size),
                )
                .unwrap_or(u64::MAX);
                (len + written + e.size).saturating_sub(e.compressed_size) + tail + granularity
            } else {
                entry_mode
            };
            peak = peak.max(
                est.min(entry_mode)
                    .max(len + written + window_floor(opts, e)),
            );
        }
        written += group_out;
        len = len.min(after[g.end - 1]);
    }
    let margin = params.margin_fixed + remaining_u / 1_000_000 * params.margin_ppm;
    let consume_peak = peak + slack + margin;
    ZipSpace {
        archive_len,
        remaining_u,
        extract_extra: remaining_u + slack + margin,
        consume_peak,
        consume_peak_guaranteed: guaranteed + slack + margin,
        consume_extra: consume_peak.saturating_sub(archive_len),
    }
}

/// Punch mode still holds up to one checkpoint interval of output before freeing anything.
fn window_floor(opts: &ConsumeOptions, e: &Entry) -> u64 {
    (opts.zip.checkpoint_every + BLOCK_SLACK).min(e.size)
}

fn inflate_err(name: &str, e: InflateError, need_free: u64) -> Error {
    match e {
        InflateError::Fs(FsError::NoSpace { .. }) => {
            Error::Paused(PauseReason::NoSpace { needed: need_free })
        }
        InflateError::Fs(fe) => fe.into(),
        other => Error::Integrity(format!("{name}: {other}")),
    }
}

pub(crate) fn nospace(e: FsError, need_free: u64) -> Error {
    match e {
        FsError::NoSpace { .. } => Error::Paused(PauseReason::NoSpace { needed: need_free }),
        other => other.into(),
    }
}

/// Decode an entry, passing output to `sink`; check size and CRC.
fn decode_entry(
    archive: &dyn FileHandle,
    e: &Entry,
    sink: &mut dyn FnMut(&[u8]) -> std::result::Result<(), InflateError>,
    need_free: u64,
) -> Result<()> {
    let _prof = trunc_prof::span("zip.decode_entry").bytes(e.size);
    let (total, crc) = match e.method {
        Method::Deflate => {
            let f = Inflater::new(&Checkpoint::start(), e.size)
                .run(
                    archive,
                    e.data_offset,
                    e.compressed_size,
                    sink,
                    0,
                    &mut |_| Ok(()),
                )
                .map_err(|x| inflate_err(&e.name, x, need_free))?;
            if f.in_bits.div_ceil(8) > e.compressed_size {
                return Err(Error::Integrity(format!(
                    "{}: deflate stream overruns its entry",
                    e.name
                )));
            }
            (f.out_total, f.crc)
        }
        Method::Stored => {
            let mut h = crc32fast::Hasher::new();
            let mut buf = vec![0u8; 1 << 20];
            let mut off = 0u64;
            while off < e.size {
                let n = usize::try_from((e.size - off).min(buf.len() as u64)).expect("<= 1 MiB");
                archive.read_exact_at(&mut buf[..n], e.data_offset + off)?;
                h.update(&buf[..n]);
                sink(&buf[..n]).map_err(|x| inflate_err(&e.name, x, need_free))?;
                off += n as u64;
            }
            (off, h.finalize())
        }
    };
    if total != e.size || crc != e.crc32 {
        return Err(Error::Integrity(format!(
            "{}: CRC or size mismatch",
            e.name
        )));
    }
    Ok(())
}

/// CRC of `out[from..to)` as read back from the device, continuing from `crc`.
fn read_back_crc(
    out: &dyn FileHandle,
    from: u64,
    to: u64,
    crc: u32,
) -> std::result::Result<u32, FsError> {
    let mut h = crc32fast::Hasher::new_with_initial(crc);
    let mut buf = vec![0u8; 4 << 20];
    let mut off = from;
    while off < to {
        let n = usize::try_from((to - off).min(buf.len() as u64)).expect("<= 4 MiB");
        out.read_back(&mut buf[..n], off)?;
        h.update(&buf[..n]);
        off += n as u64;
    }
    Ok(h.finalize())
}

/// `read_back_crc`, with a short read reported as `None` (media mismatch).
fn verified_crc(out: &dyn FileHandle, from: u64, to: u64, crc: u32) -> Result<Option<u32>> {
    match read_back_crc(out, from, to, crc) {
        Ok(c) => Ok(Some(c)),
        Err(e) if crate::stage::is_short_read(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn media_mismatch(name: &str) -> Error {
    Error::Integrity(format!(
        "media verification failed for {name}: the data read back from disk differs from what was written; its source was not released"
    ))
}

/// Extract one entry into the staging area (whole entry before any of it is released). The
/// caller flushes it (with the rest of its group) and checks the media; returns the output and
/// whether it was created.
fn extract_whole(
    fs: &dyn FsBackend,
    archive: &dyn FileHandle,
    e: &Entry,
    p: &Path,
    need_free: u64,
    guard: &StageGuard<'_>,
) -> Result<(Box<dyn FileHandle>, bool)> {
    let (out, created) = open_staged_output(fs, guard, p)?;
    out.preallocate(e.size).map_err(|x| nospace(x, need_free))?;
    let mut off = 0u64;
    decode_entry(
        archive,
        e,
        &mut |b| {
            out.write_all_at(b, off)?;
            off += b.len() as u64;
            Ok(())
        },
        need_free,
    )?;
    out.set_len(e.size)?;
    out.set_modified(system_time(e.mtime_unix, 0))?;
    Ok((out, created))
}

/// Extract one entry, freeing its compressed bytes as checkpoints are reached.
#[allow(clippy::too_many_arguments)]
fn extract_punching(
    fs: &dyn FsBackend,
    archive: &dyn FileHandle,
    journal: &mut Journal,
    index: u32,
    e: &Entry,
    p: &Path,
    resume: Option<Checkpoint>,
    every: u64,
    need_free: u64,
    verify: bool,
    guard: &StageGuard<'_>,
) -> Result<()> {
    // On a fresh start, the checkpoints of a verification pass: each checkpoint of the real
    // decode must match before its input is freed (catches the input changing in between).
    let mut expected: Option<Vec<(u64, u32)>> = None;
    let start = match resume {
        Some(ck) => ck,
        None => {
            // Nothing has been punched yet: verify the whole entry before destroying any of it.
            expected = Some(verify_checkpoints(archive, e, every, need_free)?);
            let ck = Checkpoint::start();
            journal
                .write(
                    &EntryCkpt {
                        entry: index,
                        inflate: ck.clone(),
                    }
                    .encode(),
                )
                .map_err(journal_err)?;
            ck
        }
    };
    let (out, created) = open_staged_output(fs, guard, p)?;
    if created {
        fs.flush_dir(&parent_of(p))?;
    }
    // Output past the checkpoint may be partial; it is rewritten.
    out.set_len(start.out_total)?;
    out.flush_data()?;

    let punch = |ck: &Checkpoint| -> std::result::Result<(), InflateError> {
        let upto = e.data_offset + ck.in_bit / 8;
        match archive.deallocate(e.region_start, upto)? {
            Dealloc::Freed { .. } | Dealloc::Unsupported => Ok(()),
        }
    };
    let mut off = start.out_total;
    let mut journal_error: Option<trunc_journal::JournalError> = None;
    // With --verify-media, output up to each checkpoint is read back and its running CRC
    // compared before the matching input is deallocated.
    let (mut verified_to, mut running_crc) = (start.out_total, start.crc);
    let mut media_bad = false;
    let mut seen = 0usize;
    let mut on_ckpt = |ck: &Checkpoint| -> std::result::Result<(), InflateError> {
        if let Some(list) = &expected {
            if list.get(seen) != Some(&(ck.out_total, ck.crc)) {
                return Err(InflateError::Corrupt(
                    "entry changed since it was verified; nothing past the last checkpoint was released",
                ));
            }
            seen += 1;
        }
        out.flush_data()?;
        if verify {
            match read_back_crc(out.as_ref(), verified_to, ck.out_total, running_crc) {
                Ok(c) if c == ck.crc => {
                    running_crc = c;
                    verified_to = ck.out_total;
                }
                Ok(_) => media_bad = true,
                Err(e) if crate::stage::is_short_read(&e) => media_bad = true,
                Err(e) => return Err(e.into()),
            }
            if media_bad {
                return Err(InflateError::Callback("media verification failed".into()));
            }
        }
        if let Err(je) = journal.write(
            &EntryCkpt {
                entry: index,
                inflate: ck.clone(),
            }
            .encode(),
        ) {
            journal_error = Some(je);
            return Err(InflateError::Callback("journal write failed".into()));
        }
        punch(ck)
    };
    let mut sink = |b: &[u8]| -> std::result::Result<(), InflateError> {
        out.preallocate(off + b.len() as u64)?;
        out.write_all_at(b, off)?;
        off += b.len() as u64;
        Ok(())
    };
    let finished = match e.method {
        Method::Deflate => Inflater::new(&start, e.size)
            .run(
                archive,
                e.data_offset,
                e.compressed_size,
                &mut sink,
                every,
                &mut on_ckpt,
            )
            .map(|f| (f.out_total, f.crc, f.in_bits.div_ceil(8))),
        Method::Stored => copy_stored(archive, e, &start, &mut sink, every, &mut on_ckpt),
    };
    if let Some(je) = journal_error {
        return Err(journal_err(je));
    }
    if media_bad {
        return Err(media_mismatch(&e.name));
    }
    let (total, crc, used) = finished.map_err(|x| inflate_err(&e.name, x, need_free))?;
    if total != e.size || crc != e.crc32 || used > e.compressed_size {
        return Err(Error::Integrity(format!(
            "{}: CRC or size mismatch",
            e.name
        )));
    }
    out.set_len(e.size)?;
    out.set_modified(system_time(e.mtime_unix, 0))?;
    out.flush_data()?;
    if verify && verified_crc(out.as_ref(), verified_to, e.size, running_crc)? != Some(e.crc32) {
        return Err(media_mismatch(&e.name));
    }
    Ok(())
}

/// Decode an entry without writing, checking its size and CRC, and return the (output size,
/// running CRC) at every checkpoint the real decode will meet.
fn verify_checkpoints(
    archive: &dyn FileHandle,
    e: &Entry,
    every: u64,
    need_free: u64,
) -> Result<Vec<(u64, u32)>> {
    let mut list = Vec::new();
    let (total, crc, used) = match e.method {
        Method::Deflate => Inflater::new(&Checkpoint::start(), e.size)
            .run(
                archive,
                e.data_offset,
                e.compressed_size,
                &mut |_| Ok(()),
                every,
                &mut |ck| {
                    list.push((ck.out_total, ck.crc));
                    Ok(())
                },
            )
            .map(|f| (f.out_total, f.crc, f.in_bits.div_ceil(8))),
        Method::Stored => copy_stored(
            archive,
            e,
            &Checkpoint::start(),
            &mut |_| Ok(()),
            every,
            &mut |ck| {
                list.push((ck.out_total, ck.crc));
                Ok(())
            },
        ),
    }
    .map_err(|x| inflate_err(&e.name, x, need_free))?;
    if total != e.size || crc != e.crc32 || used > e.compressed_size {
        return Err(Error::Integrity(format!(
            "{}: CRC or size mismatch",
            e.name
        )));
    }
    Ok(list)
}

/// Stored entries in punch mode: plain copy with the same checkpoint protocol.
fn copy_stored(
    archive: &dyn FileHandle,
    e: &Entry,
    start: &Checkpoint,
    sink: &mut dyn FnMut(&[u8]) -> std::result::Result<(), InflateError>,
    every: u64,
    on_ckpt: &mut dyn FnMut(&Checkpoint) -> std::result::Result<(), InflateError>,
) -> std::result::Result<(u64, u32, u64), InflateError> {
    let mut crc = crc32fast::Hasher::new_with_initial(start.crc);
    let mut done = start.out_total;
    let mut since = 0u64;
    let mut window = start.window.clone();
    let mut buf = vec![0u8; 1 << 20];
    while done < e.size {
        let n = usize::try_from((e.size - done).min(buf.len() as u64)).expect("<= 1 MiB");
        archive.read_exact_at(&mut buf[..n], e.data_offset + done)?;
        crc.update(&buf[..n]);
        sink(&buf[..n])?;
        window.extend_from_slice(&buf[..n]);
        if window.len() > WINDOW {
            window.drain(..window.len() - WINDOW);
        }
        done += n as u64;
        since += n as u64;
        if every > 0 && since >= every && done < e.size {
            on_ckpt(&Checkpoint {
                in_bit: done * 8,
                out_total: done,
                crc: crc.clone().finalize(),
                window: window.clone(),
            })?;
            since = 0;
        }
    }
    Ok((done, crc.finalize(), done))
}

pub(crate) fn journal_err(e: trunc_journal::JournalError) -> Error {
    match e {
        trunc_journal::JournalError::Fs(f) => f.into(),
        other => Error::Integrity(format!("journal: {other}")),
    }
}

/// Consume a ZIP archive into `dest`. Safe to call again after any crash or pause.
pub fn consume_zip(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    opts: &ConsumeOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<ConsumeSummary> {
    let absolute = |p: &Path| std::path::absolute(p).map_err(|e| Error::Input(e.to_string()));
    let dest = absolute(dest)?;
    let archive_path = &absolute(archive_path)?;
    let jpath = journal_path(archive_path);
    let existing = match fs.metadata(&jpath)? {
        Some(_) => Some(Journal::open(fs, &jpath).map_err(journal_err)?),
        None => None,
    };

    let handle = match fs.open(archive_path, OpenMode::ReadWrite, Share::Exclusive) {
        Ok(h) => h,
        Err(FsError::NotFound { .. }) if existing.is_some() => {
            // Only the journal removal was interrupted.
            let (j, pre, _) = existing.expect("checked");
            let p = Preamble::decode(&pre)
                .ok_or_else(|| Error::Integrity("journal preamble unreadable".into()))?;
            if !same_dest(&p.dest, &dest) {
                return Err(wrong_dest(&p.dest));
            }
            if fs.metadata(&stage_dir(&dest, &p.archive_id))?.is_some() {
                return Err(Error::Refused(format!(
                    "{} is missing but its extraction into {} is unfinished",
                    archive_path.display(),
                    dest.display()
                )));
            }
            j.remove(fs, &jpath).map_err(journal_err)?;
            return Ok(ConsumeSummary {
                resumed: true,
                ..ConsumeSummary::default()
            });
        }
        Err(e) => return Err(e.into()),
    };

    let mut summary = ConsumeSummary::default();
    let (pre, mut journal, latest) = match existing {
        Some((j, pre_bytes, latest)) => {
            let pre = Preamble::decode(&pre_bytes)
                .ok_or_else(|| Error::Integrity("journal preamble unreadable".into()))?;
            if !same_dest(&pre.dest, &dest) {
                return Err(wrong_dest(&pre.dest));
            }
            if handle.file_id()? != pre.file_id || handle.size()? > pre.original_len {
                return Err(Error::Refused(format!(
                    "{} is not the archive this journal belongs to (it was replaced?)",
                    archive_path.display()
                )));
            }
            summary.resumed = true;
            (pre, j, latest.and_then(|b| EntryCkpt::decode(&b)))
        }
        None => {
            let layout = zip::parse(handle.as_ref())
                .map_err(|e| Error::Input(format!("{}: {e}", archive_path.display())))?;
            if !layout.overlaps.is_empty() && !opts.zip.allow_overlap {
                return Err(Error::Refused(format!(
                    "{} entries overlap (a zip-bomb technique); pass --allow-overlap to process them",
                    layout.overlaps.len()
                )));
            }
            let pre = Preamble {
                archive_id: trunc_hash::blake3(&layout.to_bytes())[..16]
                    .try_into()
                    .expect("16 bytes"),
                original_len: layout.file_len,
                file_id: handle.file_id()?,
                dest: dest.clone(),
                layout,
            };
            let tops = top_level_names(&items_of(&pre.layout));
            if let Some(name) = crate::stage::sidecar_conflict(archive_path, &dest, &tops) {
                return Err(Error::Refused(format!(
                    "the archive contains {name}, which is the name of trunc's own journal next \
                     to the archive; extract into another directory"
                )));
            }
            if let Some(conflict) = first_existing(fs, &dest, &tops)? {
                return Err(Error::Refused(format!(
                    "{} already exists; move it away or choose another destination",
                    conflict.display()
                )));
            }
            Journal::discard_partial(fs, &jpath).map_err(journal_err)?;
            let j = Journal::create(fs, &jpath, &pre.encode(), SLOT_CAP).map_err(journal_err)?;
            (pre, j, None)
        }
    };
    let layout = &pre.layout;
    let items = items_of(layout);
    let tops = top_level_names(&items);
    let stage = stage_dir(&dest, &pre.archive_id);

    // Safety checks on every run; the space check only before anything has been destroyed.
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.name.as_str(), e.size));
    let vc = preflight::check_volumes(fs, archive_path, &dest, largest)?;
    for f in vc
        .findings
        .iter()
        .filter(|f| f.severity() == Severity::Blocker)
    {
        match f {
            Finding::NotJournaled(_) | Finding::JournalingUnknown if opts.allow_unjournaled => {}
            Finding::ArchiveSynced(_) if opts.allow_sync => {}
            _ => return Err(Error::Refused(f.to_string())),
        }
    }
    summary.findings = vc
        .findings
        .iter()
        .filter(|f| f.severity() != Severity::Blocker)
        .cloned()
        .collect();
    let can_dealloc = vc.archive_volume.supports_sparse && vc.archive_volume.sparse_granularity > 0;
    let granularity = u64::from(vc.archive_volume.sparse_granularity.max(1));
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..opts.space
    };
    let mut len = handle.size()?;
    let space = zip_space(layout, len, opts, can_dealloc, granularity, &params);
    let need_free = if vc.same_volume {
        space.consume_extra
    } else {
        space.extract_extra
    };

    match fs.metadata(&stage)?.map(|m| m.kind) {
        Some(NodeKind::Dir) => crate::stage::flush_staging_tree(fs, &stage, &dest)?,
        Some(_) => {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                stage.display()
            )));
        }
        None if len == pre.original_len => {
            // Nothing destroyed yet (fresh start, or a crash before the first truncation).
            if !opts.skip_space_check && vc.destination.free_bytes.is_some_and(|f| f < need_free) {
                return Err(Error::Refused(format!(
                    "not enough free space at {}: consuming needs about {need_free} bytes, {} are free",
                    dest.display(),
                    vc.destination.free_bytes.unwrap_or(0)
                )));
            }
            ensure_dir(fs, &dest)?;
            fs.create_dir(&stage)?;
            fs.flush_dir(&dest)?;
        }
        None if len == 0 && all_exist(fs, &dest, &tops)? => {
            // Everything was renamed into place; only cleanup remains.
            progress(Progress::Renaming);
            finish(fs, handle, archive_path, journal, &jpath)?;
            return Ok(summary);
        }
        None => {
            return Err(Error::Refused(format!(
                "{} was partly consumed but {} has no staging directory for it",
                archive_path.display(),
                dest.display()
            )));
        }
    }

    let protected = [handle.file_id()?, journal.file_id().map_err(journal_err)?];
    let guard = StageGuard {
        root: &stage,
        protected: &|id| protected.contains(id),
    };
    let order = schedule(layout);
    let after = ends_after(layout, &order);
    progress(Progress::Started {
        resumed: summary.resumed,
        blocks_done: order
            .iter()
            .filter(|&&i| layout.entries[i].region_end > len)
            .count(),
        blocks_total: order.len(),
    });
    build_structure(fs, &items, &dest, &stage, &mut summary)?;

    // Drop the central directory and trailer (their contents are in the journal).
    let all_max = order.first().map_or(0, |&i| layout.entries[i].region_end);
    if len > all_max {
        truncate_with_retry(handle.as_ref(), all_max, opts.retry)?;
        handle.flush_data()?;
        len = all_max;
    }

    let punch = |e: &Entry| should_punch(layout, e, opts, can_dealloc);
    for g in groups(&order, layout, &punch, opts.space.batch_max_u) {
        let _group = trunc_prof::span("zip.group");
        // Outputs of this group, flushed together before its compressed bytes are released.
        let mut outs: Vec<(Box<dyn FileHandle>, &Entry)> = Vec::new();
        let mut new_dirs: BTreeSet<PathBuf> = BTreeSet::new();
        for pos in g.clone() {
            let i = order[pos];
            let e = &layout.entries[i];
            if e.region_end > len {
                continue; // consumed by an earlier run
            }
            let _entry = trunc_prof::span("zip.entry").bytes(e.size);
            if e.kind == Kind::File && e.size > 0 {
                let p = join_rel(&stage, &e.name);
                if punch(e) {
                    let index = u32::try_from(i).expect("entry count fits u32");
                    let resume = latest
                        .as_ref()
                        .filter(|c| c.entry == index)
                        .map(|c| c.inflate.clone());
                    extract_punching(
                        fs,
                        handle.as_ref(),
                        &mut journal,
                        index,
                        e,
                        &p,
                        resume,
                        opts.zip.checkpoint_every.max(1),
                        need_free,
                        opts.verify_media,
                        &guard,
                    )?;
                } else {
                    let (out, created) =
                        extract_whole(fs, handle.as_ref(), e, &p, need_free, &guard)?;
                    if created {
                        new_dirs.insert(parent_of(&p));
                    }
                    outs.push((out, e));
                }
                summary.bytes_written += e.size;
            }
        }
        // Durability before release: the group's data, then its new directory entries.
        let files: Vec<&dyn FileHandle> = outs.iter().map(|(h, _)| h.as_ref()).collect();
        let dirs: Vec<PathBuf> = new_dirs.into_iter().collect();
        fs.flush_all(&files, &dirs)?;
        if opts.verify_media {
            for (out, e) in &outs {
                if verified_crc(out.as_ref(), 0, e.size, 0)? != Some(e.crc32) {
                    return Err(media_mismatch(&e.name));
                }
            }
        }
        trunc_fs::close_all(outs.into_iter().map(|(h, _)| h).collect());
        let target = after[g.end - 1];
        if target < len {
            let _release = trunc_prof::span("zip.release");
            truncate_with_retry(handle.as_ref(), target, opts.retry)?;
            handle.flush_data()?;
            len = target;
        }
        summary.batches += 1;
        progress(Progress::Batch {
            blocks_done: g.end,
            blocks_total: order.len(),
            bytes_written: summary.bytes_written,
            archive_len: len,
        });
    }
    if len > 0 {
        // Bytes before the first entry (a self-extractor stub) go too.
        truncate_with_retry(handle.as_ref(), 0, opts.retry)?;
        handle.flush_data()?;
    }

    progress(Progress::Renaming);
    rename_into_place(fs, &items, &dest, &stage)?;
    finish(fs, handle, archive_path, journal, &jpath)?;
    Ok(summary)
}

/// Whether `dest` is the destination recorded (as text) when consumption started. Paths that
/// are not valid UTF-8 are compared in the same lossy form they were stored in; Windows paths
/// compare case-insensitively.
pub(crate) fn same_dest(recorded: &Path, dest: &Path) -> bool {
    let (a, b) = (recorded.to_string_lossy(), dest.to_string_lossy());
    if cfg!(windows) {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

pub(crate) fn wrong_dest(recorded: &Path) -> Error {
    Error::Refused(format!(
        "this archive is being extracted into {}; resume with that destination",
        recorded.display()
    ))
}

/// Remove the (now empty) archive, then the journal.
pub(crate) fn finish(
    fs: &dyn FsBackend,
    handle: Box<dyn FileHandle>,
    archive_path: &Path,
    journal: Journal,
    jpath: &Path,
) -> Result<()> {
    drop(handle);
    ignore_not_found(fs.remove_file(archive_path))?;
    fs.flush_dir(&parent_of(archive_path))?;
    journal.remove(fs, jpath).map_err(journal_err)
}

/// True if `path` looks like a ZIP (or a ZIP being consumed: its journal exists).
pub fn is_zip(fs: &dyn FsBackend, path: &Path) -> bool {
    if let Ok((_, pre, _)) = Journal::open(fs, &journal_path(path)) {
        return pre.starts_with(PREAMBLE_MAGIC);
    }
    let Ok(h) = crate::source::open_read(fs, path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if h.read_exact_at(&mut magic, 0).is_err() {
        return false;
    }
    magic == *b"PK\x03\x04" || magic == *b"PK\x05\x06" || zip::parse(h.as_ref()).is_ok()
}

/// Destination recorded in the journal of a ZIP being consumed.
pub fn journal_dest(fs: &dyn FsBackend, archive: &Path) -> Option<PathBuf> {
    let (_, pre, _) = Journal::open(fs, &journal_path(archive)).ok()?;
    Preamble::decode(&pre).map(|p| p.dest)
}

/// Parse a ZIP for inspection or planning.
pub fn open_layout(fs: &dyn FsBackend, archive: &Path) -> Result<Layout> {
    let h = crate::source::open_read(fs, archive)?;
    zip::parse(h.as_ref()).map_err(|e| Error::Input(format!("{}: {e}", archive.display())))
}

/// Check every entry's CRC without writing anything. Returns (entries, bytes) checked.
pub fn verify_zip(fs: &dyn FsBackend, archive: &Path) -> Result<(usize, u64)> {
    let h = crate::source::open_read(fs, archive)?;
    let layout =
        zip::parse(h.as_ref()).map_err(|e| Error::Input(format!("{}: {e}", archive.display())))?;
    let mut bytes = 0u64;
    for e in layout.entries.iter().filter(|e| e.kind == Kind::File) {
        decode_entry(h.as_ref(), e, &mut |_| Ok(()), 0)?;
        bytes += e.size;
    }
    Ok((layout.entries.len(), bytes))
}

/// Non-destructive extraction of a ZIP into `dest`. Symlink entries are skipped.
pub fn extract_zip(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
) -> Result<ConsumeSummary> {
    let h = crate::source::open_read(fs, archive)?;
    let layout =
        zip::parse(h.as_ref()).map_err(|e| Error::Input(format!("{}: {e}", archive.display())))?;
    if !layout.overlaps.is_empty() {
        return Err(Error::Refused(format!(
            "{} entries overlap (a zip-bomb technique)",
            layout.overlaps.len()
        )));
    }
    ensure_dir(fs, dest)?;
    let items = items_of(&layout);
    let mut summary = ConsumeSummary::default();
    let mut dirs: Vec<String> = Vec::new();
    for it in &items {
        let mut p = trunc_core::path::parent(&it.path);
        while let Some(d) = p {
            dirs.push(d.to_owned());
            p = trunc_core::path::parent(d);
        }
        if it.kind == ItemKind::Dir {
            dirs.push(it.path.clone());
        }
    }
    dirs.sort();
    dirs.dedup();
    for d in &dirs {
        let p = join_rel(dest, d);
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
        summary.dirs += 1;
    }
    summary.symlinks_skipped = layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::Symlink)
        .count();
    let files: Vec<&Entry> = layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .collect();
    let one = |e: &Entry| -> Result<u64> {
        let p = join_rel(dest, &e.name);
        // Without --overwrite, creating "new" refuses an existing file or link by itself.
        if overwrite && fs.metadata(&p)?.is_some_and(|m| m.kind != NodeKind::File) {
            return Err(Error::Refused(format!("{} already exists", p.display())));
        }
        let mode = if overwrite {
            OpenMode::CreateOrTruncate
        } else {
            OpenMode::CreateNew
        };
        let out = match fs.open(&p, mode, Share::Exclusive) {
            Ok(o) => o,
            Err(FsError::AlreadyExists { .. }) => {
                return Err(Error::Refused(format!("{} already exists", p.display())));
            }
            Err(e) => return Err(e.into()),
        };
        let mut off = 0u64;
        decode_entry(
            h.as_ref(),
            e,
            &mut |b| {
                out.write_all_at(b, off)?;
                off += b.len() as u64;
                Ok(())
            },
            0,
        )?;
        out.set_modified(system_time(e.mtime_unix, 0))?;
        drop(out);
        if let Some(m) = e.mode {
            fs.set_mode(&p, m)?;
        }
        Ok(e.size)
    };
    // Entries are independent: decode and write them on several threads where the backend
    // allows it.
    let done: Vec<Result<u64>> = if fs.parallel_io() {
        use rayon::prelude::*;
        files.par_iter().map(|e| one(e)).collect()
    } else {
        files.iter().map(|e| one(e)).collect()
    };
    for r in done {
        summary.bytes_written += r?;
        summary.files += 1;
    }
    Ok(summary)
}

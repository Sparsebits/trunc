//! Destructive extraction of compressed tarballs (`.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`)
//! and single compressed files (`.gz`, `.bz2`, `.xz`, `.zst`).
//!
//! A compressed stream can only be decoded forward, so unlike ZIP the archive is consumed from
//! the front: the compressed bytes already decoded are deallocated (punched) while the file keeps
//! its length, and the file is deleted at the end. Space is freed only on filesystems that can
//! deallocate ranges inside a file (NTFS, ext4, XFS, btrfs, ZFS); elsewhere consuming works but
//! needs as much space as extracting.
//!
//! 1. **Scan** (read-only): decode everything once, check every codec checksum, parse and
//!    validate the tar headers (or name the single output), and record a BLAKE3 hash of the file
//!    content between consecutive checkpoints. Nothing is written.
//! 2. **Journal**: the entry list, checkpoint table and hashes go into `<archive>.trncj`.
//! 3. **Consume**: decode again, routing file content into the staging directory. At each
//!    checkpoint (a safe point of the decoder, see [`trunc_legacy::stream`]) outputs are flushed,
//!    the content hash since the previous checkpoint must equal the scan's, the decoder state is
//!    journaled, and only then are the compressed bytes before it freed.
//!
//! The checkpoint positions depend only on the archive and the interval, so a resumed run meets
//! the same checkpoints as the scan. Resuming restarts the decoder from the journaled state and
//! rewrites any output past it. Decoders with a large window (xz, zstd) read it back from the
//! output already written; for a tarball, the bytes that are not file content (headers, padding)
//! are kept for this in a gap log, `<archive>.trncg`, next to the journal.
//!
//! A split archive (`name.001`, `name.002`, …) is read as one file. Once a checkpoint passes
//! the end of a part, the part is deleted; at the end an explicit record in the journal marks
//! everything as decoded before the remaining parts are deleted.
//!
//! A sparse file's stored segments are written at their offsets and the rest is left as holes.
//! Hard links are made once everything is decoded and durable, from the staged files they name
//! (a copy where the filesystem has no hard links), and made durable before anything is renamed
//! into place; a resumed run checks the links and copies an interrupted run made.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use trunc_core::path::CaseMode;
use trunc_core::space::SpaceParams;
use trunc_fs::{Dealloc, FileHandle, FileId, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_hash::Blake3Hasher;
use trunc_journal::Journal;
use trunc_legacy::gzip;
use trunc_legacy::stream::{
    self, Codec, History, Input, Limits, NoHistory, SafePoint, StreamEnd, StreamError,
};
use trunc_legacy::tar::{self, Kind};

use crate::consume::{ConsumeOptions, ConsumeSummary, Progress, stage_dir};
use crate::error::{Error, Result};
use crate::preflight::{self, Finding, Severity};
use crate::source::{self, PartRecord, Parts};
use crate::stage::{
    Item, ItemKind, StageGuard, all_exist, already_moved, build_structure, check_exact_name,
    ensure_dir, extend_hollow, first_existing, ignore_not_found, join_rel, open_staged_output,
    parent_of, rename_into_place, top_level_names, truncate_with_retry,
};
use crate::walk::system_time;
use crate::zipconsume::{finish, journal_err, journal_path, nospace, same_dest, wrong_dest};

const PREAMBLE_MAGIC: &[u8; 5] = b"TSJP1";
/// Journals written by v0.1.0, which consumed only `.tar.gz`.
const PREAMBLE_MAGIC_V1: &[u8; 5] = b"TGJP1";
/// Room in a journal slot beyond the decoder cursor, for the record fields.
const SLOT_EXTRA: usize = 64;
/// Finished files kept open (unflushed) before they are flushed early. Bounds open handles.
const MAX_PENDING: usize = 256;
/// Decoded bytes looked at to tell a tarball from a single compressed file.
const HEAD_BYTES: usize = 512;

/// How the decoded stream is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A tar archive.
    Tar,
    /// One file (the archive name without its compression suffix).
    Single,
}

/// Settings for compressed tarballs and files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamOptions {
    /// Decompress into one file even if the content is a tar archive.
    pub raw: bool,
    /// Refuse streams whose decoder window is larger than this.
    pub max_window: u64,
    /// Threads for decoding independent blocks or frames (0: one per core).
    pub threads: usize,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            raw: false,
            max_window: Limits::DEFAULT_MAX_WINDOW,
            threads: 0,
        }
    }
}

/// One checkpoint found by the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkptInfo {
    /// After this checkpoint, compressed bytes before this offset are no longer needed.
    pub free_below: u64,
    /// Offset in the decoded stream at the checkpoint.
    pub out: u64,
    /// BLAKE3 of the file content between the previous checkpoint and this one.
    pub hash: [u8; 32],
}

/// What the scan learned about an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamLayout {
    pub codec: Codec,
    pub mode: Mode,
    pub file_len: u64,
    /// gzip members, bzip2 or xz streams, or zstd frames.
    pub units: u32,
    /// Length of the decoded stream.
    pub out_len: u64,
    /// The tar entries, or the one output file.
    pub entries: Vec<tar::Entry>,
    /// Checkpoint interval the table was made with; consumption uses the same.
    pub every: u64,
    pub ckpts: Vec<CkptInfo>,
    /// BLAKE3 of the file content after the last checkpoint.
    pub tail_hash: [u8; 32],
}

impl StreamLayout {
    /// Bytes of file content in the stream (a sparse file's data only; hard links add nothing).
    pub fn content_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.kind == Kind::File)
            .map(|e| e.size)
            .sum()
    }

    /// Whether consuming keeps a gap log (see the module docs).
    fn gap_log(&self) -> bool {
        self.codec.needs_history() && self.mode == Mode::Tar
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![
            self.codec.id(),
            match self.mode {
                Mode::Tar => 0,
                Mode::Single => 1,
            },
        ];
        b.extend_from_slice(&self.v1_bytes());
        b
    }

    /// The v0.1.0 layout: everything but the codec and mode.
    fn v1_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [
            self.file_len,
            u64::from(self.units),
            self.out_len,
            self.every,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.tail_hash);
        b.extend_from_slice(&(self.ckpts.len() as u64).to_le_bytes());
        for c in &self.ckpts {
            b.extend_from_slice(&c.free_below.to_le_bytes());
            b.extend_from_slice(&c.out.to_le_bytes());
            b.extend_from_slice(&c.hash);
        }
        b.extend_from_slice(&tar::entries_to_bytes(&self.entries));
        b
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let codec = Codec::from_id(*b.first()?)?;
        let mode = match b.get(1)? {
            0 => Mode::Tar,
            1 => Mode::Single,
            _ => return None,
        };
        Self::from_v1_bytes(b.get(2..)?, codec, mode)
    }

    fn from_v1_bytes(b: &[u8], codec: Codec, mode: Mode) -> Option<Self> {
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let (file_len, units, out_len, every) = (u64_at(0)?, u64_at(8)?, u64_at(16)?, u64_at(24)?);
        let tail_hash = b.get(32..64)?.try_into().ok()?;
        let n = usize::try_from(u64_at(64)?).ok()?;
        let mut p = 72usize;
        if n > b.len() / 48 {
            return None;
        }
        let mut ckpts = Vec::with_capacity(n);
        for _ in 0..n {
            ckpts.push(CkptInfo {
                free_below: u64_at(p)?,
                out: u64_at(p + 8)?,
                hash: b.get(p + 16..p + 48)?.try_into().ok()?,
            });
            p += 48;
        }
        let (entries, used) = tar::entries_from_bytes(b.get(p..)?)?;
        (p + used == b.len()).then_some(Self {
            codec,
            mode,
            file_len,
            units: u32::try_from(units).ok()?,
            out_len,
            entries,
            every,
            ckpts,
            tail_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Preamble {
    archive_id: [u8; 16],
    file_id: trunc_fs::FileId,
    dest: PathBuf,
    layout: StreamLayout,
    /// Written by v0.1.0 (`TGJP1`); its records use the old slot layout.
    v1: bool,
    /// The parts of a split archive (empty for a single file).
    parts: Vec<PartRecord>,
}

impl Preamble {
    fn encode(&self) -> Vec<u8> {
        let mut b = if self.v1 {
            PREAMBLE_MAGIC_V1.to_vec()
        } else {
            PREAMBLE_MAGIC.to_vec()
        };
        b.extend_from_slice(&self.archive_id);
        b.extend_from_slice(&self.file_id.volume.to_le_bytes());
        b.extend_from_slice(&self.file_id.file.to_le_bytes());
        let d = self.dest.to_string_lossy();
        b.extend_from_slice(&u32::try_from(d.len()).expect("path length").to_le_bytes());
        b.extend_from_slice(d.as_bytes());
        if self.v1 {
            b.extend_from_slice(&self.layout.v1_bytes());
            return b;
        }
        b.extend_from_slice(
            &u32::try_from(self.parts.len())
                .expect("part count")
                .to_le_bytes(),
        );
        for r in &self.parts {
            b.extend_from_slice(
                &u16::try_from(r.name.len())
                    .expect("name length")
                    .to_le_bytes(),
            );
            b.extend_from_slice(r.name.as_bytes());
            b.extend_from_slice(&r.size.to_le_bytes());
            b.extend_from_slice(&r.id.volume.to_le_bytes());
            b.extend_from_slice(&r.id.file.to_le_bytes());
        }
        b.extend_from_slice(&self.layout.to_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let v1 = match b.get(..5)? {
            m if m == PREAMBLE_MAGIC => false,
            m if m == PREAMBLE_MAGIC_V1 => true,
            _ => return None,
        };
        let archive_id = b.get(5..21)?.try_into().ok()?;
        let volume = u64::from_le_bytes(b.get(21..29)?.try_into().ok()?);
        let file = u128::from_le_bytes(b.get(29..45)?.try_into().ok()?);
        let dl = u32::from_le_bytes(b.get(45..49)?.try_into().ok()?) as usize;
        let dest = PathBuf::from(std::str::from_utf8(b.get(49..49 + dl)?).ok()?);
        let mut rest = b.get(49 + dl..)?;
        let mut parts = Vec::new();
        let layout = if v1 {
            StreamLayout::from_v1_bytes(rest, Codec::Gzip, Mode::Tar)?
        } else {
            let n = u32::from_le_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            rest = &rest[4..];
            for _ in 0..n {
                let nl = usize::from(u16::from_le_bytes(rest.get(..2)?.try_into().ok()?));
                let name = std::str::from_utf8(rest.get(2..2 + nl)?).ok()?.to_owned();
                let f = rest.get(2 + nl..2 + nl + 32)?;
                parts.push(PartRecord {
                    name,
                    size: u64::from_le_bytes(f[..8].try_into().ok()?),
                    id: FileId {
                        volume: u64::from_le_bytes(f[8..16].try_into().ok()?),
                        file: u128::from_le_bytes(f[16..32].try_into().ok()?),
                    },
                });
                rest = &rest[2 + nl + 32..];
            }
            StreamLayout::from_bytes(rest)?
        };
        Some(Self {
            archive_id,
            file_id: FileId { volume, file },
            dest,
            layout,
            v1,
            parts,
        })
    }
}

/// A journaled checkpoint: where to resume, and how far the archive may be freed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    /// Checkpoints passed so far.
    seq: u32,
    free_below: u64,
    /// Decoded-stream offset at the checkpoint.
    out: u64,
    /// The decoder's cursor.
    cursor: Vec<u8>,
}

/// `seq` of the record written once everything is decoded and durable (split archives only:
/// it allows the remaining parts to be deleted).
const END_SEQ: u32 = u32::MAX;

impl Record {
    fn end(layout: &StreamLayout) -> Self {
        Self {
            seq: END_SEQ,
            free_below: layout.file_len,
            out: layout.out_len,
            cursor: Vec::new(),
        }
    }

    fn is_end(&self) -> bool {
        self.seq == END_SEQ
    }

    fn encode(&self, v1: bool) -> Vec<u8> {
        if v1 {
            return gzip::cursor_to_v1(self.seq, self.free_below, &self.cursor)
                .expect("a gzip cursor");
        }
        let mut b = self.seq.to_le_bytes().to_vec();
        b.extend_from_slice(&self.free_below.to_le_bytes());
        b.extend_from_slice(&self.out.to_le_bytes());
        b.extend_from_slice(&self.cursor);
        b
    }

    fn decode(b: &[u8], v1: bool) -> Option<Self> {
        if v1 {
            let (seq, free_below, out, cursor) = gzip::cursor_from_v1(b)?;
            return Some(Self {
                seq,
                free_below,
                out,
                cursor,
            });
        }
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        Some(Self {
            seq: u32::from_le_bytes(b.get(..4)?.try_into().ok()?),
            free_below: u64_at(4)?,
            out: u64_at(12)?,
            cursor: b.get(20..)?.to_vec(),
        })
    }
}

fn stream_err(e: StreamError) -> Error {
    match e {
        StreamError::Fs(f) => f.into(),
        StreamError::Corrupt(m) => Error::Integrity(m),
        StreamError::Format(m) | StreamError::Unsupported(m) => Error::Input(m),
        StreamError::Stopped => Error::Integrity("decoding stopped unexpectedly".into()),
    }
}

/// Run a decoder with engine-side callbacks; their errors come back as they are.
#[allow(clippy::too_many_arguments)]
fn run(
    codec: Codec,
    input: Input<'_>,
    start: Option<&[u8]>,
    history: &mut dyn History,
    limits: Limits,
    every: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    on_point: &mut dyn FnMut(SafePoint<'_>) -> Result<()>,
) -> Result<StreamEnd> {
    let failure: RefCell<Option<Error>> = RefCell::new(None);
    let stop = |e: Error| {
        *failure.borrow_mut() = Some(e);
        StreamError::Stopped
    };
    let r = stream::decode(
        codec,
        input,
        start,
        history,
        limits,
        every,
        &mut |b| sink(b).map_err(stop),
        &mut |p| on_point(p).map_err(stop),
    );
    if let Some(e) = failure.into_inner() {
        return Err(e);
    }
    r.map_err(stream_err)
}

/// Where regular-file content lies in the decoded stream; everything else is a gap.
struct ContentMap {
    /// Entry indices of the non-empty files, in stream order.
    idx: Vec<usize>,
    offs: Vec<u64>,
    sizes: Vec<u64>,
    /// `cum[k]`: content bytes in files before `idx[k]`.
    cum: Vec<u64>,
}

impl ContentMap {
    fn new(entries: &[tar::Entry]) -> Self {
        let idx: Vec<usize> = (0..entries.len())
            .filter(|&i| entries[i].kind == Kind::File && entries[i].size > 0)
            .collect();
        let offs = idx.iter().map(|&i| entries[i].data_offset).collect();
        let sizes: Vec<u64> = idx.iter().map(|&i| entries[i].size).collect();
        let mut cum = Vec::with_capacity(sizes.len() + 1);
        let mut total = 0u64;
        cum.push(0);
        for s in &sizes {
            total += s;
            cum.push(total);
        }
        Self {
            idx,
            offs,
            sizes,
            cum,
        }
    }

    /// Content bytes before stream offset `o`.
    fn data_before(&self, o: u64) -> u64 {
        let k = self.offs.partition_point(|&off| off < o);
        if k == 0 {
            return 0;
        }
        let j = k - 1;
        self.cum[j] + (o - self.offs[j]).min(self.sizes[j])
    }

    /// Non-content bytes before stream offset `o`.
    fn gaps_before(&self, o: u64) -> u64 {
        o - self.data_before(o)
    }

    /// The file holding stream offset `o` (position in `idx`, offset inside the file), or where
    /// the next file starts.
    fn locate(&self, o: u64) -> std::result::Result<(usize, u64), u64> {
        let k = self.offs.partition_point(|&off| off <= o);
        if k > 0 && o < self.offs[k - 1] + self.sizes[k - 1] {
            return Ok((k - 1, o - self.offs[k - 1]));
        }
        Err(self.offs.get(k).copied().unwrap_or(u64::MAX))
    }
}

/// Earlier output, read back from the staged files and the gap log.
struct StagedHistory<'a> {
    fs: &'a dyn FsBackend,
    root: &'a Path,
    entries: &'a [tar::Entry],
    map: &'a ContentMap,
    gap_path: Option<&'a Path>,
}

impl History for StagedHistory<'_> {
    fn read(&mut self, at: u64, buf: &mut [u8]) -> stream::Result<()> {
        let _prof = trunc_prof::span("stream.restore_window").bytes(buf.len() as u64);
        let mut done = 0usize;
        while done < buf.len() {
            let o = at + done as u64;
            let left = (buf.len() - done) as u64;
            let n = match self.map.locate(o) {
                Ok((k, within)) => {
                    let n =
                        usize::try_from((self.map.sizes[k] - within).min(left)).expect("<= buffer");
                    let e = &self.entries[self.map.idx[k]];
                    let p = join_rel(self.root, &e.name);
                    let f = self.fs.open(&p, OpenMode::Read, Share::Shared)?;
                    read_stored(f.as_ref(), e, &mut buf[done..done + n], within, false)?;
                    n
                }
                Err(next) => {
                    let n = usize::try_from((next - o).min(left)).expect("<= buffer");
                    let Some(g) = self.gap_path else {
                        return Err(StreamError::Corrupt(
                            "resuming needs the gap log, which is missing".into(),
                        ));
                    };
                    let f = self.fs.open(g, OpenMode::Read, Share::Shared)?;
                    f.read_exact_at(&mut buf[done..done + n], self.map.gaps_before(o))?;
                    n
                }
            };
            done += n;
        }
        Ok(())
    }
}

/// Read stored content `[at, at + buf.len())` of entry `e` back from its output file (for a
/// sparse file, from its segments), from the cache or, with `back`, from the device.
fn read_stored(
    f: &dyn FileHandle,
    e: &tar::Entry,
    buf: &mut [u8],
    at: u64,
    back: bool,
) -> trunc_fs::Result<()> {
    let read = |buf: &mut [u8], off| {
        if back {
            f.read_back(buf, off)
        } else {
            f.read_exact_at(buf, off)
        }
    };
    let Some(sp) = &e.sparse else {
        return read(buf, at);
    };
    let mut done = 0usize;
    for (off, n) in sp.pieces(at, buf.len() as u64) {
        let n = usize::try_from(n).expect("<= buffer");
        read(&mut buf[done..done + n], off)?;
        done += n;
    }
    Ok(())
}

fn tar_err(archive: &Path) -> impl Fn(tar::TarError) -> Error + '_ {
    move |e| Error::Input(format!("{}: {e}", archive.display()))
}

/// The codec of an open archive and how its content is laid out.
pub fn sniff(archive: &dyn FileHandle, raw: bool) -> Result<Option<(Codec, Mode)>> {
    let len = archive.size()?;
    let mut head = [0u8; 16];
    let n = usize::try_from(len.min(16)).expect("<= 16");
    archive.read_exact_at(&mut head[..n], 0)?;
    let Some(codec) = Codec::sniff(&head[..n]) else {
        return Ok(None);
    };
    if raw {
        return Ok(Some((codec, Mode::Single)));
    }
    // A stream that fails early is a single file as far as the layout goes; the scan reports
    // the real error.
    let first = stream::peek(codec, Input { src: archive, len }, HEAD_BYTES).unwrap_or_default();
    let mode = if first.len() == HEAD_BYTES && tar::looks_like_header(&first) {
        Mode::Tar
    } else {
        Mode::Single
    };
    Ok(Some((codec, mode)))
}

/// A compressed archive at `path`: its codec and layout, also while it is being consumed
/// (its journal exists and its front may already be gone).
pub fn detect(fs: &dyn FsBackend, path: &Path, raw: bool) -> Option<(Codec, Mode)> {
    if let Ok((_, pre, _)) = Journal::open(fs, &journal_path(path)) {
        return Preamble::decode(&pre).map(|p| (p.layout.codec, p.layout.mode));
    }
    let h = source::open_read(fs, path).ok()?;
    sniff(h.as_ref(), raw).ok().flatten()
}

/// The path a single decompressed output is named after: the archive, or for a split archive
/// the file its parts stand for.
fn name_path(fs: &dyn FsBackend, archive: &Path) -> Result<PathBuf> {
    Ok(source::joined_path(fs, archive)?.unwrap_or_else(|| archive.to_path_buf()))
}

/// Destination recorded in the journal of an archive being consumed.
pub fn journal_dest(fs: &dyn FsBackend, archive: &Path) -> Option<PathBuf> {
    let (_, pre, _) = Journal::open(fs, &journal_path(archive)).ok()?;
    Preamble::decode(&pre).map(|p| p.dest)
}

/// The gap log of a consume: `<archive>.trncg`.
pub fn gap_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_owned();
    s.push(".trncg");
    PathBuf::from(s)
}

/// The name of the single output of a compressed file at `path`.
fn single_name(codec: Codec, path: &Path) -> Result<String> {
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Input(format!("{} has no usable file name", path.display())))?;
    let name = codec.output_name(base);
    trunc_core::path::validate_host(&name)
        .map_err(|e| Error::Input(format!("cannot name the output {name:?}: {e}")))?;
    Ok(name)
}

/// Decode the whole archive without writing anything: check every codec checksum, parse and
/// validate the tar headers (comparing names as `case` says the destination does), and build
/// the checkpoint table for `every`.
pub fn scan(
    archive: &dyn FileHandle,
    path: &Path,
    every: u64,
    opts: &StreamOptions,
    case: CaseMode,
) -> Result<StreamLayout> {
    let file_len = archive.size()?;
    let _prof = trunc_prof::span("stream.scan").bytes(file_len);
    let (codec, mode) = sniff(archive, opts.raw)?.ok_or_else(|| {
        Error::Input(format!(
            "{} is not a gzip, bzip2, xz or zstd file",
            path.display()
        ))
    })?;
    let reader = RefCell::new(tar::Reader::with_case(case));
    let hasher = RefCell::new(Blake3Hasher::new());
    let mut ckpts = Vec::new();
    let end = run(
        codec,
        Input {
            src: archive,
            len: file_len,
        },
        None,
        &mut NoHistory,
        Limits {
            max_out: u64::MAX,
            max_window: opts.max_window,
            threads: opts.threads,
        },
        every,
        &mut |b| match mode {
            Mode::Tar => {
                let _p = trunc_prof::span("tar.parse").bytes(b.len() as u64);
                reader
                    .borrow_mut()
                    .feed_data(b, &mut |d| {
                        trunc_prof::time("hash.blake3", || {
                            hasher.borrow_mut().update(d);
                        });
                    })
                    .map_err(tar_err(path))
            }
            Mode::Single => {
                trunc_prof::time("hash.blake3", || {
                    hasher.borrow_mut().update(b);
                });
                Ok(())
            }
        },
        &mut |p| {
            let h = hasher.replace(Blake3Hasher::new());
            ckpts.push(CkptInfo {
                free_below: p.free_below,
                out: p.out,
                hash: *h.finalize().as_bytes(),
            });
            Ok(())
        },
    )?;
    let entries = match mode {
        Mode::Tar => reader.into_inner().finish().map_err(tar_err(path))?,
        Mode::Single => {
            let (mtime_unix, mtime_nanos) = archive
                .modified()?
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or((0, 0), |d| {
                    (i64::try_from(d.as_secs()).unwrap_or(0), d.subsec_nanos())
                });
            vec![tar::Entry {
                name: single_name(codec, path)?,
                kind: Kind::File,
                size: end.out_len,
                data_offset: 0,
                mode: None,
                mtime_unix,
                mtime_nanos,
                sparse: None,
            }]
        }
    };
    Ok(StreamLayout {
        codec,
        mode,
        file_len,
        units: end.units,
        out_len: end.out_len,
        entries,
        every,
        ckpts,
        tail_hash: *hasher.into_inner().finalize().as_bytes(),
    })
}

fn items_of(entries: &[tar::Entry]) -> Vec<Item> {
    entries
        .iter()
        .filter_map(|e| {
            let (kind, mode) = match e.kind {
                Kind::File => (ItemKind::File, e.mode),
                Kind::Dir => (ItemKind::Dir, e.mode),
                Kind::Symlink => (ItemKind::Symlink, e.mode),
                // The same file as its target (or a copy of it), so the same mode.
                Kind::HardLink(t) => (ItemKind::HardLink, entries[t].mode),
                Kind::Special => return None,
            };
            Some(Item {
                path: e.name.clone(),
                kind,
                size: e.size,
                len: e.file_size(),
                mode,
                mtime_unix: e.mtime_unix,
                mtime_nanos: e.mtime_nanos,
            })
        })
        .collect()
}

/// Space needed to extract or consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSpace {
    pub archive_len: u64,
    pub content: u64,
    /// Free space a non-destructive extraction needs.
    pub extract_extra: u64,
    /// Highest occupancy expected while consuming (archive plus outputs).
    pub consume_peak: u64,
    pub consume_extra: u64,
}

/// Occupancy is highest at the end of some checkpoint interval: everything decoded so far is
/// on disk and the archive has been freed only up to the previous checkpoint.
/// `parts` are the part sizes of a split archive (empty for one file): a part is freed whole
/// once a checkpoint passes its end, even where nothing can be deallocated.
/// Sparse files count only their data. Hard links cost nothing where the destination has them
/// (`hard_links`); elsewhere each is a copy of its file, made once everything is decoded.
pub fn stream_space(
    layout: &StreamLayout,
    can_dealloc: bool,
    granularity: u64,
    parts: &[u64],
    hard_links: bool,
    params: &SpaceParams,
) -> StreamSpace {
    let gran = granularity.max(1);
    let cluster = params.cluster_size.max(1);
    let content = layout.content_bytes();
    let slack: u64 = layout
        .entries
        .iter()
        .map(|e| params.per_entry_overhead + (allocated(e, cluster) - e.size))
        .sum();
    let copies: u64 = if hard_links {
        0
    } else {
        layout
            .entries
            .iter()
            .filter_map(|e| match e.kind {
                Kind::HardLink(t) => Some(allocated(&layout.entries[t], cluster)),
                _ => None,
            })
            .sum()
    };
    let map = ContentMap::new(&layout.entries);
    let gaps = layout.gap_log();
    let mut peak = layout.file_len;
    let n = layout.ckpts.len();
    for k in 0..=n {
        let end = if k < n {
            layout.ckpts[k].out
        } else {
            layout.out_len
        };
        let freed = if k == 0 {
            0
        } else {
            freed_below(layout.ckpts[k - 1].free_below, can_dealloc, gran, parts)
        };
        let gap_bytes = if gaps { map.gaps_before(end) } else { 0 };
        peak = peak
            .max(layout.file_len - freed.min(layout.file_len) + map.data_before(end) + gap_bytes);
    }
    if copies > 0 {
        // The copies are made after the archive is gone (truncated) but before the gap log is.
        let gap_bytes = if gaps {
            map.gaps_before(layout.out_len)
        } else {
            0
        };
        peak = peak.max(content + gap_bytes + copies);
    }
    let margin = params.margin_fixed + content / 1_000_000 * params.margin_ppm;
    // At a checkpoint the file being written is allocated up to a whole cluster past its
    // written length, which rounding its final size (in `slack`) does not cover. The gap log is
    // one more file, with its own metadata and rounding.
    let mut unlisted = if n > 0 { cluster - 1 } else { 0 };
    if gaps {
        unlisted += params.per_entry_overhead + cluster - 1;
    }
    let consume_peak = peak + slack + margin + unlisted;
    StreamSpace {
        archive_len: layout.file_len,
        content,
        extract_extra: content + copies + slack + margin,
        consume_peak,
        consume_extra: consume_peak.saturating_sub(layout.file_len),
    }
}

/// Disk space a file's data takes in allocation units of `cluster`: for a sparse file, its
/// segments only.
fn allocated(e: &tar::Entry, cluster: u64) -> u64 {
    match &e.sparse {
        None => e.size.div_ceil(cluster) * cluster,
        Some(sp) => sp
            .segments()
            .iter()
            .map(|&(off, len)| ((off + len).div_ceil(cluster) - off / cluster) * cluster)
            .sum(),
    }
}

/// Bytes freed once the archive is released below `below`.
fn freed_below(below: u64, can_dealloc: bool, gran: u64, parts: &[u64]) -> u64 {
    if parts.is_empty() {
        return if can_dealloc { below / gran * gran } else { 0 };
    }
    let (mut off, mut freed) = (0u64, 0u64);
    for &size in parts {
        if off + size <= below {
            freed += size;
        } else if off < below && can_dealloc {
            freed += (below - off) / gran * gran;
        }
        off += size;
    }
    freed
}

/// Where the router writes.
enum Target<'a> {
    /// The staging directory of a consume.
    Stage(&'a StageGuard<'a>),
    /// A plain destination for non-destructive extraction.
    Dest { root: &'a Path, overwrite: bool },
}

/// The gap log being appended to.
struct GapLog {
    h: Box<dyn FileHandle>,
    /// Bytes written to the file.
    len: u64,
    /// Bytes appended since, not yet written (written in one go when flushed or when large).
    buf: Vec<u8>,
    dirty: bool,
}

impl GapLog {
    fn write_out(&mut self, need_free: u64) -> Result<()> {
        if !self.buf.is_empty() {
            self.h
                .write_all_at(&self.buf, self.len)
                .map_err(|e| nospace(e, need_free))?;
            self.len += self.buf.len() as u64;
            self.buf.clear();
            self.dirty = true;
        }
        Ok(())
    }
}

/// Buffered gap-log bytes are written once this much has accumulated.
const GAP_BUFFER: usize = 4 << 20;

/// Files opened ahead of their data.
const OPEN_AHEAD: usize = 32;
/// Worker threads for opening ahead and closing behind.
const IO_WORKERS: usize = 8;

type Opened = Result<(Box<dyn FileHandle>, bool)>;

/// Open (or create) output `name` under the router's target. Returns the handle and whether it
/// was created.
fn open_output(fs: &dyn FsBackend, target: &Target<'_>, name: &str) -> Opened {
    match target {
        Target::Stage(g) => open_staged_output(fs, g, &join_rel(g.root, name)),
        Target::Dest { root, overwrite } => {
            let p = join_rel(root, name);
            if let Some(m) = fs.metadata(&p)? {
                if !*overwrite || m.kind != NodeKind::File {
                    return Err(Error::Refused(format!("{} already exists", p.display())));
                }
            }
            let mode = if *overwrite {
                OpenMode::CreateOrTruncate
            } else {
                OpenMode::CreateNew
            };
            Ok((fs.open(&p, mode, Share::Exclusive)?, true))
        }
    }
}

#[derive(Default)]
struct AheadState {
    /// Entry indices to open, in order.
    queue: std::collections::VecDeque<usize>,
    /// Opened (or failed), not yet taken.
    ready: std::collections::HashMap<usize, Opened>,
    /// Being opened right now.
    busy: std::collections::HashSet<usize>,
    /// Flushed handles to close.
    closing: Vec<Box<dyn FileHandle>>,
    stop: bool,
}

/// Opens upcoming outputs ahead of their data and closes finished ones on worker threads, so
/// the routing thread does not wait on either (each costs a fraction of a millisecond on
/// Windows). Only used where the backend allows parallel calls.
struct IoAhead<'a> {
    state: std::sync::Mutex<AheadState>,
    cv: std::sync::Condvar,
    open: &'a (dyn Fn(usize) -> Opened + Sync),
}

impl<'a> IoAhead<'a> {
    fn new(open: &'a (dyn Fn(usize) -> Opened + Sync)) -> Self {
        Self {
            state: std::sync::Mutex::new(AheadState::default()),
            cv: std::sync::Condvar::new(),
            open,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, AheadState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The worker loop: open queued entries, close handed-over handles, until stopped and idle.
    fn work(&self) {
        let mut st = self.lock();
        loop {
            if !st.closing.is_empty() {
                let batch = std::mem::take(&mut st.closing);
                drop(st);
                drop(batch);
                st = self.lock();
                continue;
            }
            if let Some(i) = st.queue.pop_front() {
                st.busy.insert(i);
                drop(st);
                let r = (self.open)(i);
                st = self.lock();
                st.busy.remove(&i);
                st.ready.insert(i, r);
                self.cv.notify_all();
                continue;
            }
            if st.stop {
                return;
            }
            st = self
                .cv
                .wait(st)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn request(&self, entries: &[usize]) {
        let mut st = self.lock();
        st.queue.extend(entries.iter().copied());
        self.cv.notify_all();
    }

    /// Entry `i`, opened ahead if it was requested; `None` means open it here.
    fn take(&self, i: usize) -> Option<Opened> {
        let mut st = self.lock();
        loop {
            if let Some(r) = st.ready.remove(&i) {
                return Some(r);
            }
            if let Some(k) = st.queue.iter().position(|&q| q == i) {
                st.queue.remove(k);
                return None;
            }
            if !st.busy.contains(&i) {
                return None;
            }
            st = self
                .cv
                .wait(st)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn close(&self, handles: Vec<Box<dyn FileHandle>>) {
        let mut st = self.lock();
        st.closing.extend(handles);
        self.cv.notify_all();
    }

    fn stop(&self) {
        let mut st = self.lock();
        st.stop = true;
        st.queue.clear();
        self.cv.notify_all();
    }
}

/// Stops the workers when dropped (also on errors), so the thread scope can end.
struct StopAhead<'r, 'a>(&'r IoAhead<'a>);

impl Drop for StopAhead<'_, '_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Run `f` with an [`IoAhead`] whose workers open outputs via `open`, when `parallel`; otherwise
/// with none. The workers have finished (every handle closed) when this returns.
fn with_io_ahead<T>(
    parallel: bool,
    open: &(dyn Fn(usize) -> Opened + Sync),
    f: impl FnOnce(Option<&IoAhead<'_>>) -> T,
) -> T {
    if !parallel {
        return f(None);
    }
    let ahead = IoAhead::new(open);
    std::thread::scope(|s| {
        for _ in 0..IO_WORKERS {
            s.spawn(|| ahead.work());
        }
        let _stop = StopAhead(&ahead);
        f(Some(&ahead))
    })
}

/// Routes the decoded stream's file content into output files (and, with a gap log, the rest
/// into the log).
struct Router<'a> {
    fs: &'a dyn FsBackend,
    target: Target<'a>,
    entries: &'a [tar::Entry],
    /// Indices of non-empty files, in stream order.
    files: Vec<usize>,
    /// Position in `files` of the first unfinished file.
    next: usize,
    /// Decoded-stream offset of the next byte.
    pos: u64,
    current: Option<Box<dyn FileHandle>>,
    /// Finished files not yet flushed.
    pending: Vec<Box<dyn FileHandle>>,
    /// Parents of files created since the last flush.
    new_dirs: BTreeSet<PathBuf>,
    gaps: Option<GapLog>,
    /// Content routed since the last checkpoint, and where it went (for read-back checks).
    hasher: Blake3Hasher,
    segments: Vec<(usize, u64, u64)>,
    written: u64,
    need_free: u64,
    /// Opens ahead and closes behind on worker threads, where the backend allows.
    ahead: Option<&'a IoAhead<'a>>,
    /// Position in `files` up to which opens have been requested.
    requested: usize,
}

impl<'a> Router<'a> {
    fn new(
        fs: &'a dyn FsBackend,
        target: Target<'a>,
        entries: &'a [tar::Entry],
        pos: u64,
        gaps: Option<GapLog>,
        need_free: u64,
    ) -> Self {
        let files: Vec<usize> = (0..entries.len())
            .filter(|&i| entries[i].kind == Kind::File && entries[i].size > 0)
            .collect();
        let next = files
            .iter()
            .position(|&i| entries[i].data_offset.saturating_add(entries[i].size) > pos)
            .unwrap_or(files.len());
        Self {
            fs,
            target,
            entries,
            files,
            next,
            pos,
            current: None,
            pending: Vec::new(),
            new_dirs: BTreeSet::new(),
            gaps,
            hasher: Blake3Hasher::new(),
            segments: Vec::new(),
            written: 0,
            need_free,
            ahead: None,
            requested: next + 1,
        }
    }

    fn with_ahead(mut self, ahead: Option<&'a IoAhead<'a>>) -> Self {
        self.ahead = ahead;
        self
    }

    fn root(&self) -> &Path {
        match &self.target {
            Target::Stage(g) => g.root,
            Target::Dest { root, .. } => root,
        }
    }

    /// Open entry `i` for writing at `at`: earlier bytes are kept, later ones discarded.
    fn open(&mut self, i: usize, at: u64) -> Result<Box<dyn FileHandle>> {
        let p = join_rel(self.root(), &self.entries[i].name);
        if let Some(a) = self.ahead {
            // Keep the next few files opening while this one is written.
            let upto = (self.next + 1 + OPEN_AHEAD).min(self.files.len());
            if self.requested < upto {
                a.request(&self.files[self.requested..upto]);
                self.requested = upto;
            }
        }
        let opened = self.ahead.and_then(|a| a.take(i));
        let (h, created) = match opened {
            Some(r) => r?,
            None => open_output(self.fs, &self.target, &self.entries[i].name)?,
        };
        if created {
            self.new_dirs.insert(parent_of(&p));
        }
        match &self.entries[i].sparse {
            None => {
                if !created || at > 0 {
                    h.set_len(at)?;
                }
            }
            Some(sp) => {
                let len = sp.file_len_at(at);
                if !created || len > 0 {
                    h.set_len(len)?;
                }
                // The rest is a hole until written. Deallocating it marks the file sparse where
                // the filesystem needs that (NTFS), so writes past the end leave holes.
                h.deallocate(len, sp.real_size())?;
            }
        }
        Ok(h)
    }

    /// Append bytes that are not file content to the gap log, if there is one.
    fn gap(&mut self, b: &[u8]) -> Result<()> {
        if let Some(g) = &mut self.gaps {
            g.buf.extend_from_slice(b);
            if g.buf.len() >= GAP_BUFFER {
                g.write_out(self.need_free)?;
            }
        }
        Ok(())
    }

    fn write(&mut self, mut b: &[u8]) -> Result<()> {
        let _prof = trunc_prof::span("stream.route").bytes(b.len() as u64);
        while !b.is_empty() {
            let Some(&i) = self.files.get(self.next) else {
                self.gap(b)?;
                self.pos += b.len() as u64;
                return Ok(());
            };
            let (data_offset, size) = (self.entries[i].data_offset, self.entries[i].size);
            if self.pos < data_offset {
                let skip =
                    usize::try_from((data_offset - self.pos).min(b.len() as u64)).expect("<= len");
                self.gap(&b[..skip])?;
                self.pos += skip as u64;
                b = &b[skip..];
                continue;
            }
            let at = self.pos - data_offset;
            let n = usize::try_from((size - at).min(b.len() as u64)).expect("<= len");
            if self.current.is_none() {
                let h = self.open(i, at)?;
                self.current = Some(h);
            }
            let h = self.current.as_ref().expect("opened above");
            // No reservation first: it would cover exactly what this write allocates anyway, and a
            // full disk fails the write the same way (and pauses).
            match &self.entries[i].sparse {
                None => h
                    .write_all_at(&b[..n], at)
                    .map_err(|e| nospace(e, self.need_free))?,
                Some(sp) => {
                    let mut done = 0usize;
                    for (off, len) in sp.pieces(at, n as u64) {
                        let len = usize::try_from(len).expect("<= n");
                        h.write_all_at(&b[done..done + len], off)
                            .map_err(|e| nospace(e, self.need_free))?;
                        done += len;
                    }
                }
            }
            trunc_prof::time("hash.blake3", || {
                self.hasher.update(&b[..n]);
            });
            match self.segments.last_mut() {
                Some((j, _, end)) if *j == i && *end == at => *end += n as u64,
                _ => self.segments.push((i, at, at + n as u64)),
            }
            self.pos += n as u64;
            self.written += n as u64;
            b = &b[n..];
            if at + n as u64 == size {
                let h = self.current.take().expect("opened above");
                let e = &self.entries[i];
                if let Some(sp) = e
                    .sparse
                    .as_ref()
                    .filter(|sp| sp.data_end() < sp.real_size())
                {
                    h.set_len(sp.real_size())?; // a hole at the end
                }
                h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                self.pending.push(h);
                self.next += 1;
                if self.pending.len() >= MAX_PENDING {
                    let pending: Vec<&dyn FileHandle> =
                        self.pending.iter().map(AsRef::as_ref).collect();
                    self.fs.flush_all(&pending, &[])?;
                    self.close_pending();
                }
            }
        }
        Ok(())
    }

    /// Close flushed files: on the workers if there are any, else here, in parallel.
    fn close_pending(&mut self) {
        let done = std::mem::take(&mut self.pending);
        match self.ahead {
            Some(a) => a.close(done),
            None => trunc_fs::close_all(done),
        }
    }

    /// Make everything written so far durable: file data and the gap log, then new directory
    /// entries.
    fn flush(&mut self) -> Result<()> {
        let _prof = trunc_prof::span("stream.flush_outputs");
        if let Some(g) = &mut self.gaps {
            g.write_out(self.need_free)?;
        }
        let mut files: Vec<&dyn FileHandle> = self.pending.iter().map(AsRef::as_ref).collect();
        files.extend(self.current.as_deref());
        if let Some(g) = self.gaps.as_ref().filter(|g| g.dirty) {
            files.push(g.h.as_ref());
        }
        let dirs: Vec<PathBuf> = std::mem::take(&mut self.new_dirs).into_iter().collect();
        self.fs.flush_all(&files, &dirs)?;
        self.close_pending();
        if let Some(g) = &mut self.gaps {
            g.dirty = false;
        }
        Ok(())
    }

    /// Hash of the content routed since the last call, and (with `read_back`) whether the same
    /// content reads back from the device.
    fn take_interval(&mut self, read_back: bool) -> Result<([u8; 32], bool)> {
        let _prof = trunc_prof::span("stream.verify_interval");
        let hash = *std::mem::replace(&mut self.hasher, Blake3Hasher::new())
            .finalize()
            .as_bytes();
        let segments = std::mem::take(&mut self.segments);
        if !read_back {
            return Ok((hash, true));
        }
        let mut h = Blake3Hasher::new();
        let mut buf = vec![0u8; 4 << 20];
        for (i, from, to) in segments {
            let e = &self.entries[i];
            let p = join_rel(self.root(), &e.name);
            let f = self.fs.open(&p, OpenMode::Read, Share::Shared)?;
            let mut off = from;
            while off < to {
                let n = usize::try_from((to - off).min(buf.len() as u64)).expect("<= 4 MiB");
                match read_stored(f.as_ref(), e, &mut buf[..n], off, true) {
                    Ok(()) => {}
                    Err(e) if crate::stage::is_short_read(&e) => return Ok((hash, false)),
                    Err(e) => return Err(e.into()),
                }
                h.update(&buf[..n]);
                off += n as u64;
            }
        }
        Ok((hash, *h.finalize().as_bytes() == hash))
    }
}

/// The file content of entry `e` (for a sparse file, its segments) as `(offset, length)`
/// ranges.
fn data_ranges(e: &tar::Entry) -> Vec<(u64, u64)> {
    match &e.sparse {
        Some(sp) => sp.segments().to_vec(),
        None => vec![(0, e.size)],
    }
}

/// Copy file entry `e` from `src` into the empty `dst`: a sparse file's segments only, the rest
/// left as holes. Returns the bytes copied.
fn copy_file(
    src: &dyn FileHandle,
    dst: &dyn FileHandle,
    e: &tar::Entry,
    need_free: u64,
) -> Result<u64> {
    if let Some(sp) = &e.sparse {
        dst.deallocate(0, sp.real_size())?; // marks the copy sparse where that is needed
    }
    let mut buf = vec![0u8; 1 << 20];
    let mut copied = 0u64;
    for (start, len) in data_ranges(e) {
        let mut off = start;
        while off < start + len {
            let n = usize::try_from((start + len - off).min(buf.len() as u64)).expect("<= 1 MiB");
            src.read_exact_at(&mut buf[..n], off)?;
            dst.write_all_at(&buf[..n], off)
                .map_err(|x| nospace(x, need_free))?;
            off += n as u64;
        }
        copied += len;
    }
    if e.sparse
        .as_ref()
        .is_some_and(|sp| sp.data_end() < sp.real_size())
    {
        dst.set_len(e.file_size())?;
    }
    Ok(copied)
}

/// Whether `dst` already is a complete copy of file entry `e` as `src` holds it.
fn same_copy(src: &dyn FileHandle, dst: &dyn FileHandle, e: &tar::Entry) -> Result<bool> {
    if dst.size()? != e.file_size() {
        return Ok(false);
    }
    let (mut a, mut b) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    for (start, len) in data_ranges(e) {
        let mut off = start;
        while off < start + len {
            let n = usize::try_from((start + len - off).min(a.len() as u64)).expect("<= 1 MiB");
            src.read_exact_at(&mut a[..n], off)?;
            dst.read_exact_at(&mut b[..n], off)?;
            if a[..n] != b[..n] {
                return Ok(false);
            }
            off += n as u64;
        }
    }
    Ok(true)
}

/// Make every hard link of the archive under `target`, once every file is complete: a real link
/// where the filesystem has them, else a copy, then flush them. Resuming in the staging
/// directory, what an interrupted run made is checked: a real link is the very file and stays,
/// a copy stays if complete and is redone otherwise. Returns the bytes copied.
fn make_links(
    fs: &dyn FsBackend,
    target: &Target<'_>,
    entries: &[tar::Entry],
    need_free: u64,
) -> Result<u64> {
    let _prof = trunc_prof::span("stream.hard_links");
    let unprotected = |_: &FileId| false;
    let (root, protected): (&Path, &(dyn Fn(&FileId) -> bool + Sync)) = match target {
        Target::Stage(g) => (g.root, g.protected),
        Target::Dest { root, .. } => (root, &unprotected),
    };
    let refuse = |p: &Path| {
        Error::Refused(format!(
            "{} is the archive (or its journal) under another name; refusing to write to it",
            p.display()
        ))
    };
    let mut copies: Vec<Box<dyn FileHandle>> = Vec::new();
    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut copied = 0u64;
    for e in entries {
        let Kind::HardLink(t) = e.kind else {
            continue;
        };
        let te = &entries[t];
        let (src, dst) = (join_rel(root, &te.name), join_rel(root, &e.name));
        let s = fs.open_beneath(root, &src, OpenMode::Read, Share::Shared)?;
        let sid = s.file_id()?;
        if protected(&sid) {
            return Err(refuse(&src));
        }
        let mtime = system_time(e.mtime_unix, e.mtime_nanos);
        match (fs.metadata(&dst)?.map(|m| m.kind), target) {
            (None, _) => {}
            (Some(NodeKind::File), Target::Stage(_)) => {
                // Left by an interrupted run. It can be read-only only if modes were applied,
                // which happens once every link is made and durable.
                check_exact_name(fs, &dst)?;
                let (d, writable) =
                    match fs.open_beneath(root, &dst, OpenMode::ReadWrite, Share::Exclusive) {
                        Ok(d) => (d, true),
                        Err(_) => (
                            fs.open_beneath(root, &dst, OpenMode::Read, Share::Shared)?,
                            false,
                        ),
                    };
                let did = d.file_id()?;
                if did == sid {
                    continue;
                }
                if protected(&did) {
                    return Err(refuse(&dst));
                }
                if !same_copy(s.as_ref(), d.as_ref(), te)? {
                    d.set_len(0)?;
                    copied += copy_file(s.as_ref(), d.as_ref(), te, need_free)?;
                    d.set_modified(mtime)?;
                    copies.push(d);
                } else if writable {
                    copies.push(d); // complete, but maybe not yet durable
                }
                continue;
            }
            (
                Some(NodeKind::File),
                Target::Dest {
                    overwrite: true, ..
                },
            ) => fs.remove_file(&dst)?,
            _ => {
                return Err(Error::Refused(format!("{} already exists", dst.display())));
            }
        }
        match fs.hard_link_beneath(root, &src, &dst) {
            Ok(()) => {
                // Check where the new name leads: a junction on the way, or a source swapped
                // since it was opened, would show here.
                let id = fs
                    .open_beneath(root, &dst, OpenMode::Read, Share::Shared)
                    .and_then(|d| d.file_id());
                if !matches!(id, Ok(id) if id == sid) {
                    let _ = fs.remove_file(&dst);
                    id?;
                    return Err(Error::Refused(format!(
                        "{} does not lead to {} after linking; refusing it",
                        dst.display(),
                        src.display()
                    )));
                }
            }
            Err(FsError::Unsupported { .. }) => {
                let d = fs.open_beneath(root, &dst, OpenMode::CreateNew, Share::Exclusive)?;
                if protected(&d.file_id()?) {
                    return Err(refuse(&dst));
                }
                copied += copy_file(s.as_ref(), d.as_ref(), te, need_free)?;
                d.set_modified(mtime)?;
                copies.push(d);
            }
            Err(e) => return Err(e.into()),
        }
        dirs.insert(parent_of(&dst));
        if copies.len() >= MAX_PENDING {
            let files: Vec<&dyn FileHandle> = copies.iter().map(AsRef::as_ref).collect();
            fs.flush_all(&files, &[])?;
            trunc_fs::close_all(std::mem::take(&mut copies));
        }
    }
    let files: Vec<&dyn FileHandle> = copies.iter().map(AsRef::as_ref).collect();
    let dirs: Vec<PathBuf> = dirs.into_iter().collect();
    fs.flush_all(&files, &dirs)?;
    Ok(copied)
}

fn media_mismatch() -> Error {
    Error::Integrity(
        "media verification failed: data read back from disk differs from what was written; \
         the archive bytes it came from were not released"
            .into(),
    )
}

fn limits(layout: &StreamLayout, opts: &StreamOptions) -> Limits {
    Limits {
        max_out: layout.out_len,
        max_window: opts.max_window,
        threads: opts.threads,
    }
}

/// The archive being consumed: one file, or the parts of a split archive.
enum Held {
    One(Box<dyn FileHandle>),
    Parts(Parts),
}

impl Held {
    fn input(&self) -> &dyn FileHandle {
        match self {
            Held::One(h) => h.as_ref(),
            Held::Parts(p) => p,
        }
    }

    fn ids(&self) -> Result<Vec<FileId>> {
        match self {
            Held::One(h) => Ok(vec![h.file_id()?]),
            Held::Parts(p) => Ok(p.ids()),
        }
    }

    fn sizes(&self) -> Vec<u64> {
        match self {
            Held::One(_) => Vec::new(),
            Held::Parts(p) => p.sizes(),
        }
    }

    /// Release `[from, below)` of the archive.
    fn free(&self, fs: &dyn FsBackend, from: u64, below: u64, gran: u64) -> Result<()> {
        match self {
            Held::One(h) => {
                let below = below.min(h.size()?);
                match h.deallocate(from.min(below) / gran * gran, below)? {
                    Dealloc::Freed { .. } | Dealloc::Unsupported => {}
                }
                Ok(())
            }
            Held::Parts(p) => p.free(fs, from, below, gran),
        }
    }

    /// Remove the archive and then the journal: the last step.
    fn finish(
        self,
        fs: &dyn FsBackend,
        archive: &Path,
        journal: Journal,
        jpath: &Path,
    ) -> Result<()> {
        match self {
            Held::One(h) => finish(fs, h, archive, journal, jpath),
            Held::Parts(p) => {
                p.remove_all(fs)?;
                journal.remove(fs, jpath).map_err(journal_err)
            }
        }
    }
}

/// Remove the gap log if there is one; its directory entry is flushed by [`finish`].
fn remove_gap_log(fs: &dyn FsBackend, archive: &Path) -> Result<()> {
    ignore_not_found(fs.remove_file(&gap_path(archive)))
}

/// Consume a compressed tarball or file into `dest`. Safe to call again after any crash or
/// pause.
#[allow(clippy::too_many_lines)]
pub fn consume_stream(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    opts: &ConsumeOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<ConsumeSummary> {
    let _prof = trunc_prof::span("stream.consume");
    let absolute = |p: &Path| std::path::absolute(p).map_err(|e| Error::Input(e.to_string()));
    let dest = absolute(dest)?;
    let archive_path = &absolute(archive_path)?;
    let jpath = journal_path(archive_path);
    let gpath = gap_path(archive_path);
    let existing = match fs.metadata(&jpath)? {
        Some(_) => Some(Journal::open(fs, &jpath).map_err(journal_err)?),
        None => None,
    };

    let mut summary = ConsumeSummary::default();
    let (pre, mut journal, latest, held) = match existing {
        Some((j, pre_bytes, latest)) => {
            let pre = Preamble::decode(&pre_bytes)
                .ok_or_else(|| Error::Integrity("journal preamble unreadable".into()))?;
            if !same_dest(&pre.dest, &dest) {
                return Err(wrong_dest(&pre.dest));
            }
            let latest = match latest {
                Some(b) => Some(Record::decode(&b, pre.v1).ok_or_else(|| {
                    Error::Integrity("journal checkpoint record unreadable".into())
                })?),
                None => None,
            };
            let held = if pre.parts.is_empty() {
                match fs.open(archive_path, OpenMode::ReadWrite, Share::Exclusive) {
                    Ok(h) => {
                        let len = h.size()?;
                        if h.file_id()? != pre.file_id || (len != pre.layout.file_len && len != 0) {
                            return Err(Error::Refused(format!(
                                "{} is not the archive this journal belongs to (it was replaced?)",
                                archive_path.display()
                            )));
                        }
                        Held::One(h)
                    }
                    Err(FsError::NotFound { .. }) => {
                        // Only the journal removal was interrupted.
                        if fs.metadata(&stage_dir(&dest, &pre.archive_id))?.is_some() {
                            return Err(Error::Refused(format!(
                                "{} is missing but its extraction into {} is unfinished",
                                archive_path.display(),
                                dest.display()
                            )));
                        }
                        remove_gap_log(fs, archive_path)?;
                        fs.flush_dir(&parent_of(archive_path))?;
                        j.remove(fs, &jpath).map_err(journal_err)?;
                        return Ok(ConsumeSummary {
                            resumed: true,
                            ..ConsumeSummary::default()
                        });
                    }
                    Err(e) => return Err(e.into()),
                }
            } else {
                let ended = latest.as_ref().is_some_and(Record::is_end);
                let freed = latest.as_ref().map_or(0, |r| r.free_below);
                Held::Parts(Parts::reopen(fs, archive_path, &pre.parts, freed, ended)?)
            };
            summary.resumed = true;
            (pre, j, latest, held)
        }
        None => {
            let (held, named) = match source::split_parts(fs, archive_path)? {
                Some(paths) => {
                    let named = name_path(fs, archive_path)?;
                    (Held::Parts(Parts::open_for_consume(fs, &paths)?), named)
                }
                None => (
                    Held::One(fs.open(archive_path, OpenMode::ReadWrite, Share::Exclusive)?),
                    archive_path.clone(),
                ),
            };
            // A resume needs no probe: these names were checked against this destination
            // before the journal existed.
            let layout = scan(
                held.input(),
                &named,
                opts.zip.checkpoint_every.max(1),
                &opts.stream,
                crate::stage::dest_case(fs, &dest)?,
            )?;
            let parts = match &held {
                Held::One(_) => Vec::new(),
                Held::Parts(p) => p.records(),
            };
            let pre = Preamble {
                archive_id: trunc_hash::blake3(&layout.to_bytes())[..16]
                    .try_into()
                    .expect("16 bytes"),
                file_id: held.ids()?[0],
                dest: dest.clone(),
                layout,
                v1: false,
                parts,
            };
            let tops = top_level_names(&items_of(&pre.layout.entries));
            if let Some(name) = crate::stage::sidecar_conflict(archive_path, &dest, &tops) {
                return Err(Error::Refused(format!(
                    "the archive contains {name}, which is the name of one of trunc's own files \
                     next to the archive; extract into another directory"
                )));
            }
            if same_dest(&parent_of(archive_path), &dest) {
                if let Some(r) = pre
                    .parts
                    .iter()
                    .find(|r| tops.iter().any(|t| t.eq_ignore_ascii_case(&r.name)))
                {
                    return Err(Error::Refused(format!(
                        "the archive contains {}, which is the name of one of its own parts; \
                         extract into another directory",
                        r.name
                    )));
                }
            }
            if let Some(conflict) = first_existing(fs, &dest, &tops)? {
                return Err(Error::Refused(format!(
                    "{} already exists; move it away or choose another destination",
                    conflict.display()
                )));
            }
            Journal::discard_partial(fs, &jpath).map_err(journal_err)?;
            let slot_cap = u32::try_from(pre.layout.codec.max_cursor() + SLOT_EXTRA)
                .expect("cursor sizes are small");
            let j = Journal::create(fs, &jpath, &pre.encode(), slot_cap).map_err(journal_err)?;
            (pre, j, None, held)
        }
    };
    let layout = &pre.layout;
    let items = items_of(&layout.entries);
    let tops = top_level_names(&items);
    let stage = stage_dir(&dest, &pre.archive_id);
    let map = ContentMap::new(&layout.entries);

    // Safety checks on every run; the space check only before anything has been destroyed.
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.file_size())
        .map(|e| (e.name.as_str(), e.file_size()));
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
    summary.specials_skipped = layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::Special)
        .count();
    let can_dealloc = vc.archive_volume.supports_sparse && vc.archive_volume.sparse_granularity > 0;
    let granularity = u64::from(vc.archive_volume.sparse_granularity.max(1));
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..opts.space
    };
    let space = stream_space(
        layout,
        can_dealloc,
        granularity,
        &held.sizes(),
        vc.destination.fs.hard_links(),
        &params,
    );
    let need_free = if vc.same_volume {
        space.consume_extra
    } else {
        space.extract_extra
    };
    // Nothing destroyed yet / everything decoded and durable.
    let (untouched, decoded) = match &held {
        Held::One(h) => {
            let len = h.size()?;
            (latest.is_none() && len == layout.file_len, len == 0)
        }
        Held::Parts(p) => (
            latest.is_none() && p.all_present(),
            latest.as_ref().is_some_and(Record::is_end),
        ),
    };

    match fs.metadata(&stage)?.map(|m| m.kind) {
        Some(NodeKind::Dir) => crate::stage::flush_staging_tree(fs, &stage, &dest)?,
        Some(_) => {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                stage.display()
            )));
        }
        None if untouched => {
            // Nothing destroyed yet (fresh start, or a crash before the first checkpoint).
            if !opts.skip_space_check && vc.destination.free_bytes.is_some_and(|f| f < need_free) {
                return Err(Error::Refused(format!(
                    "not enough free space at {}: consuming needs about {need_free} bytes, {} are free",
                    dest.display(),
                    vc.destination.free_bytes.unwrap_or(0)
                )));
            }
            if layout.gap_log() {
                fs.open(&gpath, OpenMode::CreateOrTruncate, Share::Shared)?;
                fs.flush_dir(&parent_of(archive_path))?;
            }
            ensure_dir(fs, &dest)?;
            fs.create_dir(&stage)?;
            fs.flush_dir(&dest)?;
        }
        None if decoded && all_exist(fs, &dest, &tops)? => {
            // Everything was renamed into place; only cleanup remains.
            progress(Progress::Renaming);
            remove_gap_log(fs, archive_path)?;
            held.finish(fs, archive_path, journal, &jpath)?;
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

    let total = layout.ckpts.len() + 1;
    trunc_prof::time("stage.build", || {
        build_structure(fs, &items, &dest, &stage, &mut summary)
    })?;
    if let Some(r) = latest.as_ref().filter(|r| !r.is_end()) {
        // A crash between journaling a checkpoint and freeing its bytes leaves them allocated
        // (or, for a split archive, leaves parts that should be gone).
        held.free(fs, 0, r.free_below, granularity)?;
    }

    // Outputs must never turn out to be the journal or the archive.
    let journal_id = journal.file_id().map_err(journal_err)?;
    let archive_ids = |id: &FileId| match &held {
        Held::One(h) => h.file_id().is_ok_and(|a| a == *id),
        Held::Parts(p) => p.ids().contains(id),
    };
    // Once decoded (a zero-length archive, or the end record of a split one) every byte was
    // made durable before the archive was released.
    if !decoded {
        let start_out = latest.as_ref().map_or(0, |r| r.out);
        let gaps = if layout.gap_log() {
            let h = match fs.open(&gpath, OpenMode::ReadWrite, Share::Shared) {
                Ok(h) => h,
                Err(FsError::NotFound { .. }) if latest.is_none() => {
                    let h = fs.open(&gpath, OpenMode::CreateOrTruncate, Share::Shared)?;
                    fs.flush_dir(&parent_of(archive_path))?;
                    h
                }
                Err(e) => return Err(e.into()),
            };
            let keep = map.gaps_before(start_out);
            if h.size()? < keep {
                return Err(Error::Refused(format!(
                    "{} is shorter than the journal says; cannot resume",
                    gpath.display()
                )));
            }
            h.set_len(keep)?;
            Some(GapLog {
                h,
                len: keep,
                buf: Vec::new(),
                dirty: true,
            })
        } else {
            None
        };
        // The journal, the gap log, and whatever is left of the archive.
        let mut sidecars = vec![journal_id];
        if let Some(g) = &gaps {
            sidecars.push(g.h.file_id()?);
        }
        let guard = StageGuard {
            root: &stage,
            protected: &|id| sidecars.contains(id) || archive_ids(id),
        };
        progress(Progress::Started {
            resumed: summary.resumed,
            blocks_done: latest.as_ref().map_or(0, |r| r.seq as usize),
            blocks_total: total,
        });
        let mut freed_to = latest.as_ref().map_or(0, |r| r.free_below);
        let mut seq = latest.as_ref().map_or(0, |r| r.seq);
        let open_target = Target::Stage(&guard);
        let open_one = |i: usize| open_output(fs, &open_target, &layout.entries[i].name);
        with_io_ahead(fs.parallel_io(), &open_one, |ahead| -> Result<()> {
            let router = RefCell::new(
                Router::new(
                    fs,
                    Target::Stage(&guard),
                    &layout.entries,
                    start_out,
                    gaps,
                    need_free,
                )
                .with_ahead(ahead),
            );
            let mut history = StagedHistory {
                fs,
                root: &stage,
                entries: &layout.entries,
                map: &map,
                gap_path: layout.gap_log().then_some(gpath.as_path()),
            };
            let verify = opts.verify_media;
            run(
                layout.codec,
                Input {
                    src: held.input(),
                    len: layout.file_len,
                },
                latest.as_ref().map(|r| r.cursor.as_slice()),
                &mut history,
                limits(layout, &opts.stream),
                layout.every,
                &mut |b| router.borrow_mut().write(b),
                &mut |p| {
                    let _ckpt = trunc_prof::span("stream.checkpoint");
                    seq += 1;
                    let mut r = router.borrow_mut();
                    r.flush()?;
                    let expected = (seq as usize)
                        .checked_sub(1)
                        .and_then(|i| layout.ckpts.get(i))
                        .ok_or_else(|| {
                            Error::Integrity("more checkpoints than the scan found".into())
                        })?;
                    let (hash, media_ok) = r.take_interval(verify)?;
                    if hash != expected.hash
                        || p.out != expected.out
                        || p.free_below != expected.free_below
                    {
                        return Err(Error::Integrity(format!(
                            "decoded content differs from the verified scan before checkpoint {seq}; \
                         nothing past the previous checkpoint was released"
                        )));
                    }
                    if !media_ok {
                        return Err(media_mismatch());
                    }
                    journal
                        .write(
                            &Record {
                                seq,
                                free_below: p.free_below,
                                out: p.out,
                                cursor: p.cursor.to_vec(),
                            }
                            .encode(pre.v1),
                        )
                        .map_err(journal_err)?;
                    trunc_prof::time("stream.free", || {
                        held.free(fs, freed_to, p.free_below, granularity)
                    })?;
                    freed_to = p.free_below;
                    progress(Progress::Batch {
                        blocks_done: seq as usize,
                        blocks_total: total,
                        bytes_written: r.written,
                        archive_len: layout.file_len - p.free_below,
                    });
                    Ok(())
                },
            )?;
            let mut r = router.into_inner();
            r.flush()?;
            let (hash, media_ok) = r.take_interval(verify)?;
            if hash != layout.tail_hash {
                return Err(Error::Integrity(
                    "decoded content differs from the verified scan after the last checkpoint"
                        .into(),
                ));
            }
            if !media_ok {
                return Err(media_mismatch());
            }
            summary.bytes_written = r.written;
            summary.batches = total;
            drop(r);
            Ok(())
        })?;
        match &held {
            Held::One(h) => {
                truncate_with_retry(h.as_ref(), 0, opts.retry)?;
                h.flush_data()?;
            }
            Held::Parts(p) => {
                journal
                    .write(&Record::end(layout).encode(false))
                    .map_err(journal_err)?;
                p.remove_all(fs)?;
            }
        }
    } else if let Held::Parts(p) = &held {
        p.remove_all(fs)?;
    }

    // Renaming starts only once every link is made and durable: if it began, they were.
    if items.iter().any(|i| i.kind == ItemKind::HardLink)
        && !tops.iter().try_fold(false, |moved, t| -> Result<bool> {
            Ok(moved || already_moved(fs, &dest, &stage, t)?)
        })?
    {
        let protected = |id: &FileId| *id == journal_id || archive_ids(id);
        let guard = StageGuard {
            root: &stage,
            protected: &protected,
        };
        summary.bytes_written +=
            make_links(fs, &Target::Stage(&guard), &layout.entries, need_free)?;
    }

    progress(Progress::Renaming);
    trunc_prof::time("stage.rename", || {
        rename_into_place(fs, &items, &dest, &stage)
    })?;
    let _finish = trunc_prof::span("stream.finish");
    remove_gap_log(fs, archive_path)?;
    held.finish(fs, archive_path, journal, &jpath)?;
    Ok(summary)
}

/// Check every codec checksum and every tar header without writing anything.
pub fn verify_stream(
    fs: &dyn FsBackend,
    archive: &Path,
    opts: &StreamOptions,
) -> Result<StreamLayout> {
    let h = source::open_read(fs, archive)?;
    scan(
        h.as_ref(),
        &name_path(fs, archive)?,
        0,
        opts,
        CaseMode::host(),
    )
}

/// Non-destructive extraction into `dest`. The archive is scanned (and every name validated)
/// before anything is written. Symlinks and special files are skipped.
pub fn extract_stream(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    opts: &StreamOptions,
) -> Result<ConsumeSummary> {
    let _prof = trunc_prof::span("stream.extract");
    let h = source::open_read(fs, archive)?;
    let case = crate::stage::dest_case(fs, dest)?;
    let layout = scan(h.as_ref(), &name_path(fs, archive)?, 0, opts, case)?;
    ensure_dir(fs, dest)?;
    let mut summary = ConsumeSummary::default();
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for e in &layout.entries {
        let mut p = trunc_core::path::parent(&e.name);
        while let Some(d) = p {
            dirs.insert(d.to_owned());
            p = trunc_core::path::parent(d);
        }
        if e.kind == Kind::Dir {
            dirs.insert(e.name.clone());
        }
    }
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
    // Empty files (and sparse files that are all hole) carry no data for the router to write.
    for e in layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::File && e.size == 0)
    {
        let p = join_rel(dest, &e.name);
        if fs.metadata(&p)?.is_some() && !overwrite {
            return Err(Error::Refused(format!("{} already exists", p.display())));
        }
        let mode = if overwrite {
            OpenMode::CreateOrTruncate
        } else {
            OpenMode::CreateNew
        };
        let f = fs.open(&p, mode, Share::Exclusive)?;
        if e.file_size() > 0 {
            extend_hollow(f.as_ref(), e.file_size())?;
        }
        f.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
    }
    let open_target = Target::Dest {
        root: dest,
        overwrite,
    };
    let open_one = |i: usize| open_output(fs, &open_target, &layout.entries[i].name);
    // With --overwrite, opening ahead would truncate existing files before their data is
    // decoded, losing them if extraction then fails.
    let ahead_ok = fs.parallel_io() && !overwrite;
    let written = with_io_ahead(ahead_ok, &open_one, |ahead| -> Result<u64> {
        let router = RefCell::new(
            Router::new(
                fs,
                Target::Dest {
                    root: dest,
                    overwrite,
                },
                &layout.entries,
                0,
                None,
                0,
            )
            .with_ahead(ahead),
        );
        run(
            layout.codec,
            Input {
                src: h.as_ref(),
                len: layout.file_len,
            },
            None,
            &mut NoHistory,
            limits(&layout, opts),
            0,
            &mut |b| router.borrow_mut().write(b),
            &mut |_| Ok(()),
        )?;
        let mut r = router.into_inner();
        r.flush()?;
        if r.take_interval(false)?.0 != layout.tail_hash {
            return Err(Error::Integrity(
                "decoded content changed between the scan and extraction".into(),
            ));
        }
        Ok(r.written)
    })?;
    let copied = make_links(fs, &open_target, &layout.entries, 0)?;
    for e in &layout.entries {
        match e.kind {
            Kind::File => {
                summary.files += 1;
                if let Some(m) = e.mode {
                    fs.set_mode(&join_rel(dest, &e.name), m)?;
                }
            }
            Kind::HardLink(t) => {
                summary.files += 1;
                if let Some(m) = layout.entries[t].mode {
                    fs.set_mode(&join_rel(dest, &e.name), m)?;
                }
            }
            Kind::Symlink => summary.symlinks_skipped += 1,
            Kind::Special => summary.specials_skipped += 1,
            Kind::Dir => {}
        }
    }
    summary.bytes_written = written + copied;
    Ok(summary)
}

/// Scan an archive for inspection or planning.
pub fn open_layout(
    fs: &dyn FsBackend,
    archive: &Path,
    every: u64,
    opts: &StreamOptions,
) -> Result<StreamLayout> {
    let h = source::open_read(fs, archive)?;
    scan(
        h.as_ref(),
        &name_path(fs, archive)?,
        every,
        opts,
        CaseMode::host(),
    )
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use trunc_testkit::Rng;

    use super::*;

    fn file(name: &str, off: u64, size: u64) -> tar::Entry {
        tar::Entry {
            name: name.into(),
            kind: Kind::File,
            size,
            data_offset: off,
            mode: None,
            mtime_unix: 0,
            mtime_nanos: 0,
            sparse: None,
        }
    }

    #[test]
    fn records_and_layouts_round_trip() {
        let r = Record {
            seq: 7,
            free_below: 1500,
            out: 1 << 33,
            cursor: vec![1, 2, 3],
        };
        assert_eq!(Record::decode(&r.encode(false), false), Some(r));

        let l = StreamLayout {
            codec: Codec::Zstd,
            mode: Mode::Single,
            file_len: 10,
            units: 2,
            out_len: 3072,
            entries: vec![file("a", 0, 3072)],
            every: 64 << 20,
            ckpts: vec![CkptInfo {
                free_below: 4,
                out: 1024,
                hash: [9; 32],
            }],
            tail_hash: [3; 32],
        };
        assert_eq!(StreamLayout::from_bytes(&l.to_bytes()), Some(l.clone()));
        assert_eq!(StreamLayout::from_bytes(&l.to_bytes()[1..]), None);
        let pre = Preamble {
            archive_id: [5; 16],
            file_id: trunc_fs::FileId { volume: 1, file: 2 },
            dest: PathBuf::from("/out"),
            layout: l,
            v1: false,
            parts: vec![
                PartRecord {
                    name: "a.tar.zst.001".into(),
                    size: 100,
                    id: FileId { volume: 1, file: 9 },
                },
                PartRecord {
                    name: "a.tar.zst.002".into(),
                    size: 7,
                    id: FileId {
                        volume: 1,
                        file: 10,
                    },
                },
            ],
        };
        assert_eq!(Preamble::decode(&pre.encode()), Some(pre));
    }

    #[test]
    fn v1_journals_still_decode() {
        let l = StreamLayout {
            codec: Codec::Gzip,
            mode: Mode::Tar,
            file_len: 10,
            units: 1,
            out_len: 2048,
            entries: Vec::new(),
            every: 1024,
            ckpts: Vec::new(),
            tail_hash: [0; 32],
        };
        let pre = Preamble {
            archive_id: [1; 16],
            file_id: trunc_fs::FileId { volume: 3, file: 4 },
            dest: PathBuf::from("/d"),
            layout: l,
            v1: true,
            parts: Vec::new(),
        };
        let bytes = pre.encode();
        assert!(bytes.starts_with(PREAMBLE_MAGIC_V1));
        assert_eq!(Preamble::decode(&bytes), Some(pre));
        // A v1 slot: seq | data offset | output base | free-below | inflate checkpoint.
        let mut slot = 3u32.to_le_bytes().to_vec();
        for v in [20u64, 100, 77] {
            slot.extend_from_slice(&v.to_le_bytes());
        }
        let ck = trunc_legacy::inflate::Checkpoint {
            in_bit: 400,
            out_total: 5,
            crc: 9,
            window: vec![1, 2, 3, 4, 5],
        };
        slot.extend_from_slice(&ck.to_bytes());
        let r = Record::decode(&slot, true).unwrap();
        assert_eq!((r.seq, r.free_below, r.out), (3, 77, 105));
        assert_eq!(r.encode(true), slot);
    }

    #[test]
    fn content_map_finds_files_and_gaps() {
        // header 512 | a: 100 bytes | pad + header | b: 1000 bytes | end
        let entries = [
            file("a", 512, 100),
            file("empty", 1024, 0),
            file("b", 1536, 1000),
        ];
        let m = ContentMap::new(&entries);
        assert_eq!(m.data_before(0), 0);
        assert_eq!(m.data_before(512), 0);
        assert_eq!(m.data_before(562), 50);
        assert_eq!(m.data_before(1536), 100);
        assert_eq!(m.data_before(4096), 1100);
        assert_eq!(m.gaps_before(1536), 1436);
        assert_eq!(m.locate(0), Err(512));
        assert_eq!(m.locate(600), Ok((0, 88)));
        assert_eq!(m.locate(612), Err(1536));
        assert_eq!(m.locate(2535), Ok((1, 999)));
        assert_eq!(m.locate(2536), Err(u64::MAX));
    }

    // Randomized checks of `stream_space` against a simulation of the consume loop.

    fn pick<T: Copy>(rng: &mut Rng, xs: &[T]) -> T {
        xs[usize::try_from(rng.below(xs.len() as u64)).unwrap()]
    }

    /// Inclusive range `lo..=hi`.
    fn between(rng: &mut Rng, lo: u64, hi: u64) -> u64 {
        lo + rng.below(hi - lo + 1)
    }

    fn round_up(x: u64, unit: u64) -> u64 {
        x.div_ceil(unit) * unit
    }

    fn random_size(rng: &mut Rng) -> u64 {
        match rng.below(20) {
            0..=2 => 0,
            3..=8 => between(rng, 1, 600),
            9..=14 => between(rng, 1, 64 << 10),
            15..=18 => between(rng, 1, 8 << 20),
            _ => between(rng, 8 << 20, 1536 << 20),
        }
    }

    struct StreamCase {
        layout: StreamLayout,
        can_dealloc: bool,
        gran: u64,
        parts: Vec<u64>,
        params: SpaceParams,
    }

    /// Sorted values drawn from `lo..=hi`, without repeats.
    fn sorted_distinct(rng: &mut Rng, n: u64, lo: u64, hi: u64) -> Vec<u64> {
        let mut v: Vec<u64> = (0..n).map(|_| between(rng, lo, hi)).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// A random tarball (512-byte headers, padded content, long-name and pax headers,
    /// directories, links and specials) or single file, with a random checkpoint table.
    fn random_stream_case(rng: &mut Rng) -> StreamCase {
        let mode = if rng.below(4) == 0 {
            Mode::Single
        } else {
            Mode::Tar
        };
        let mut entries = Vec::new();
        let out_len = match mode {
            Mode::Single => {
                let size = random_size(rng);
                entries.push(file("single", 0, size));
                size
            }
            Mode::Tar => {
                let n = match rng.below(4) {
                    0 => between(rng, 0, 5),
                    1 => between(rng, 1, 2000),
                    _ => between(rng, 1, 200),
                };
                let mut pos = 0u64;
                for i in 0..n {
                    let kind = match rng.below(20) {
                        0..=1 => Kind::Dir,
                        2 => Kind::Symlink,
                        3 => Kind::Special,
                        _ => Kind::File,
                    };
                    let size = if kind == Kind::File {
                        random_size(rng)
                    } else {
                        0
                    };
                    let data_offset = pos + 512 * pick(rng, &[1, 1, 1, 2, 3]);
                    entries.push(tar::Entry {
                        kind,
                        ..file(&format!("e{i}"), data_offset, size)
                    });
                    pos = data_offset + size.div_ceil(512) * 512;
                }
                let padding = between(rng, 0, 18) * 512;
                pos + 1024 + pick(rng, &[0, padding])
            }
        };
        let file_len = match rng.below(3) {
            0 => between(rng, 1, out_len / 100 + 64),
            1 => between(rng, 1, out_len + 64),
            _ => between(rng, out_len / 2 + 1, out_len + out_len / 64 + 64),
        };
        let n_ckpts = match rng.below(3) {
            0 => between(rng, 0, 3),
            1 => between(rng, 0, 30),
            _ => between(rng, 0, 400),
        };
        // Checkpoint outputs and release points, both non-decreasing.
        let outs = sorted_distinct(rng, n_ckpts, 1, out_len.max(1));
        let mut frees: Vec<u64> = (0..outs.len()).map(|_| between(rng, 0, file_len)).collect();
        frees.sort_unstable();
        let ckpts = outs
            .iter()
            .zip(&frees)
            .map(|(&out, &free_below)| CkptInfo {
                free_below,
                out,
                hash: [0; 32],
            })
            .collect();
        let parts = if rng.below(3) == 0 && file_len > 1 {
            let n = between(rng, 1, 12);
            let mut cuts = sorted_distinct(rng, n, 1, file_len - 1);
            cuts.push(file_len);
            let mut prev = 0;
            cuts.iter()
                .map(|&c| {
                    let s = c - prev;
                    prev = c;
                    s
                })
                .collect()
        } else {
            Vec::new()
        };
        StreamCase {
            layout: StreamLayout {
                codec: pick(rng, &Codec::ALL),
                mode,
                file_len,
                units: 1,
                out_len,
                entries,
                every: 1 << 20,
                ckpts,
                tail_hash: [0; 32],
            },
            can_dealloc: rng.below(3) != 0,
            gran: pick(rng, &[1, 512, 4096, 65536]),
            parts,
            params: SpaceParams {
                cluster_size: pick(rng, &[1, 512, 4096, 65536]),
                per_entry_overhead: pick(rng, &[0, 0, 1, 256, 4096]),
                margin_fixed: pick(rng, &[0, 0, 0, 4096]),
                margin_ppm: pick(rng, &[0, 0, 5_000]),
                batch_max_u: 1,
            },
        }
    }

    /// One archive file (the whole archive, or one part): offset in the archive, size, whether
    /// it still exists, and the ranges deallocated inside it.
    struct HeldFile {
        off: u64,
        size: u64,
        present: bool,
        holes: Vec<Range<u64>>,
    }

    impl HeldFile {
        fn occupied(&self) -> u64 {
            if !self.present {
                return 0;
            }
            self.size - self.holes.iter().map(|h| h.end - h.start).sum::<u64>()
        }

        /// What `deallocate(start, end)` frees: the whole units inside the range.
        fn deallocate(&mut self, start: u64, end: u64, gran: u64) {
            let (s, e) = (
                start.div_ceil(gran) * gran,
                end.min(self.size) / gran * gran,
            );
            if s >= e {
                return;
            }
            let mut merged = s..e;
            self.holes.retain(|h| {
                let touches = h.start <= merged.end && merged.start <= h.end;
                if touches {
                    merged = merged.start.min(h.start)..merged.end.max(h.end);
                }
                !touches
            });
            self.holes.push(merged);
        }
    }

    /// Mirror of `Held::free` (and `Parts::free`) for `[from, below)`.
    fn release(
        files: &mut [HeldFile],
        split: bool,
        dealloc: bool,
        from: u64,
        below: u64,
        gran: u64,
    ) {
        for f in files {
            if !split {
                let below = below.min(f.size);
                if dealloc {
                    f.deallocate(from.min(below) / gran * gran, below, gran);
                }
            } else if f.off + f.size <= below {
                f.present = false;
            } else if f.off < below && dealloc && f.present {
                let start = from.max(f.off) - f.off;
                f.deallocate(start / gran * gran, below - f.off, gran);
            }
        }
    }

    /// Replay `consume_stream` from the start and return its highest occupancy: what is left
    /// of the archive, plus each output's allocation (written length rounded up to whole
    /// clusters; nothing is preallocated), plus the gap log, plus per-entry metadata.
    /// Occupancy can only grow between checkpoints, so it is sampled at each one (after the
    /// flush, before the release) and at the end.
    fn simulate_stream(c: &StreamCase) -> u64 {
        let l = &c.layout;
        let cluster = c.params.cluster_size.max(1);
        let gran = c.gran.max(1);
        let split = !c.parts.is_empty();
        let mut files: Vec<HeldFile> = Vec::new();
        let mut off = 0;
        let whole = [l.file_len];
        for &size in if split { &c.parts[..] } else { &whole[..] } {
            files.push(HeldFile {
                off,
                size,
                present: true,
                holes: Vec::new(),
            });
            off += size;
        }
        assert_eq!(off, l.file_len);
        let gap_log = l.codec.needs_history() && l.mode == Mode::Tar;
        let created = l.entries.iter().filter(|e| e.kind != Kind::Special).count() as u64;
        let meta = (created + u64::from(gap_log)) * c.params.per_entry_overhead;

        // Non-empty files in stream order; `done` of them are complete.
        let data: Vec<&tar::Entry> = l
            .entries
            .iter()
            .filter(|e| e.kind == Kind::File && e.size > 0)
            .collect();
        let (mut done, mut done_alloc, mut done_bytes) = (0usize, 0u64, 0u64);
        let mut peak = l.file_len + meta;
        let mut freed_to = 0u64;
        for k in 0..=l.ckpts.len() {
            let end = l.ckpts.get(k).map_or(l.out_len, |p| p.out);
            while done < data.len() && data[done].data_offset + data[done].size <= end {
                done_alloc += round_up(data[done].size, cluster);
                done_bytes += data[done].size;
                done += 1;
            }
            let partial = data
                .get(done)
                .map_or(0, |e| end.saturating_sub(e.data_offset));
            let gaps = if gap_log {
                round_up(end - done_bytes - partial, cluster)
            } else {
                0
            };
            let archive: u64 = files.iter().map(HeldFile::occupied).sum();
            let occ = archive + done_alloc + round_up(partial, cluster) + gaps + meta;
            peak = peak.max(occ);
            if let Some(p) = l.ckpts.get(k) {
                release(
                    &mut files,
                    split,
                    c.can_dealloc,
                    freed_to,
                    p.free_below,
                    gran,
                );
                freed_to = p.free_below;
            }
        }
        assert_eq!(done, data.len(), "every file completes");
        peak
    }

    fn run_stream_case(seed: u64) {
        let mut rng = Rng::new(seed);
        let c = random_stream_case(&mut rng);
        let sp = stream_space(&c.layout, c.can_dealloc, c.gran, &c.parts, true, &c.params);
        assert_eq!(sp.consume_extra, sp.consume_peak - c.layout.file_len);
        let peak = simulate_stream(&c);
        assert!(
            peak <= sp.consume_peak,
            "seed {seed}: simulated peak {peak} > planned {} ({:?} {:?}, {} entries, {} \
             checkpoints, archive {} -> {}, parts {:?}, dealloc {} gran {}, {:?})",
            sp.consume_peak,
            c.layout.codec,
            c.layout.mode,
            c.layout.entries.len(),
            c.layout.ckpts.len(),
            c.layout.file_len,
            c.layout.out_len,
            c.parts,
            c.can_dealloc,
            c.gran,
            c.params
        );
    }

    #[test]
    fn stream_planner_never_underestimates_the_consume_peak() {
        for seed in 0..3000 {
            run_stream_case(seed);
        }
    }

    /// Regression: at a checkpoint inside a file, the file is allocated a whole cluster past
    /// its written length; and an xz/zstd tarball also keeps a gap log, a file the entry list
    /// does not include. Neither was in the bound.
    #[test]
    fn stream_bound_covers_the_open_file_and_the_gap_log() {
        // header | "a": 8192 bytes | end-of-archive blocks. One checkpoint, 1 byte into "a",
        // after which the whole archive can go: occupancy peaks at that checkpoint.
        let len = 24 * 4096;
        let layout = StreamLayout {
            codec: Codec::Zstd,
            mode: Mode::Tar,
            file_len: len,
            units: 1,
            out_len: 512 + 8192 + 1024,
            entries: vec![file("a", 512, 8192)],
            every: 1 << 20,
            ckpts: vec![CkptInfo {
                free_below: len,
                out: 513,
                hash: [0; 32],
            }],
            tail_hash: [0; 32],
        };
        let params = SpaceParams {
            cluster_size: 4096,
            per_entry_overhead: 100,
            margin_fixed: 0,
            margin_ppm: 0,
            batch_max_u: 1,
        };
        let c = StreamCase {
            layout,
            can_dealloc: true,
            gran: 4096,
            parts: Vec::new(),
            params,
        };
        // The archive, 1 byte of "a" in one cluster, 512 header bytes in a one-cluster gap log,
        // and metadata for "a" and the gap log.
        let peak = simulate_stream(&c);
        assert_eq!(peak, len + 4096 + 4096 + 200);
        let sp = stream_space(&c.layout, true, 4096, &[], true, &params);
        assert!(
            peak <= sp.consume_peak,
            "planned {} is short by {}",
            sp.consume_peak,
            peak.saturating_sub(sp.consume_peak)
        );
    }
}

//! Destructive extraction of `.tar.gz` archives.
//!
//! gzip can only be decoded forward, so unlike ZIP the archive is consumed from the front: the
//! compressed bytes already decoded are deallocated (punched) while the file keeps its length,
//! and the file is deleted at the end. Space is freed only on filesystems that can deallocate
//! ranges inside a file (NTFS, ext4, XFS, btrfs, ZFS); elsewhere consuming works but needs as
//! much space as extracting.
//!
//! 1. **Scan** (read-only): decode everything once, check each gzip member's CRC-32 and size,
//!    parse and validate the tar headers, and record a BLAKE3 hash of the file content between
//!    consecutive checkpoints. Nothing is written.
//! 2. **Journal**: the entry list, checkpoint table and hashes go into `<archive>.trncj`.
//! 3. **Consume**: decode again, routing file content into the staging directory. At each
//!    checkpoint (a DEFLATE block boundary after `checkpoint_every` bytes, or a member boundary)
//!    outputs are flushed, the content hash since the previous checkpoint must equal the scan's,
//!    the decoder state is journaled, and only then are the compressed bytes before it freed.
//!
//! The checkpoint positions depend only on the archive and the interval, so a resumed run meets
//! the same checkpoints as the scan. Resuming restarts the decoder from the journaled state and
//! rewrites any output past it.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use trunc_core::space::SpaceParams;
use trunc_fs::{Dealloc, FileHandle, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_hash::Blake3Hasher;
use trunc_journal::Journal;
use trunc_legacy::gzip::{self, GzipError};
use trunc_legacy::inflate::{Checkpoint, InflateError, Inflater, WINDOW};
use trunc_legacy::tar::{self, Kind};

use crate::consume::{ConsumeOptions, ConsumeSummary, Progress, stage_dir};
use crate::error::{Error, Result};
use crate::preflight::{self, Finding, Severity};
use crate::stage::{
    Item, ItemKind, StageGuard, all_exist, build_structure, ensure_dir, first_existing, join_rel,
    open_staged_output, parent_of, rename_into_place, top_level_names, truncate_with_retry,
};
use crate::walk::system_time;
use crate::zipconsume::{finish, journal_err, journal_path, nospace, same_dest, wrong_dest};

const PREAMBLE_MAGIC: &[u8; 5] = b"TGJP1";
/// Room in a journal slot for an inflate checkpoint plus the cursor fields.
const SLOT_CAP: u32 = 32 * 1024 + 96;
const _: () = assert!(WINDOW == 32 * 1024, "SLOT_CAP assumes a 32 KiB window");
/// Finished files kept open (unflushed) before they are flushed early. Bounds open handles.
const MAX_PENDING: usize = 256;

/// One checkpoint found by the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CkptInfo {
    /// After this checkpoint, compressed bytes before this offset are no longer needed.
    pub free_below: u64,
    /// Offset in the tar stream at the checkpoint.
    pub out: u64,
    /// BLAKE3 of the file content between the previous checkpoint and this one.
    pub hash: [u8; 32],
}

/// What the scan learned about an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgzLayout {
    pub file_len: u64,
    pub members: u32,
    /// Length of the decompressed tar stream.
    pub tar_len: u64,
    pub entries: Vec<tar::Entry>,
    /// Checkpoint interval the table was made with; consumption uses the same.
    pub every: u64,
    pub ckpts: Vec<CkptInfo>,
    /// BLAKE3 of the file content after the last checkpoint.
    pub tail_hash: [u8; 32],
}

impl TgzLayout {
    /// Total size of all files.
    pub fn content_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.size).sum()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [
            self.file_len,
            u64::from(self.members),
            self.tar_len,
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
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let (file_len, members, tar_len, every) =
            (u64_at(0)?, u64_at(8)?, u64_at(16)?, u64_at(24)?);
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
            file_len,
            members: u32::try_from(members).ok()?,
            tar_len,
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
    layout: TgzLayout,
}

impl Preamble {
    fn encode(&self) -> Vec<u8> {
        let mut b = PREAMBLE_MAGIC.to_vec();
        b.extend_from_slice(&self.archive_id);
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
        let volume = u64::from_le_bytes(b.get(21..29)?.try_into().ok()?);
        let file = u128::from_le_bytes(b.get(29..45)?.try_into().ok()?);
        let dl = u32::from_le_bytes(b.get(45..49)?.try_into().ok()?) as usize;
        let dest = PathBuf::from(std::str::from_utf8(b.get(49..49 + dl)?).ok()?);
        let layout = TgzLayout::from_bytes(b.get(49 + dl..)?)?;
        Some(Self {
            archive_id,
            file_id: trunc_fs::FileId { volume, file },
            dest,
            layout,
        })
    }
}

/// Where decoding is, or resumes from: inside the DEFLATE data of one gzip member.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Cursor {
    /// Checkpoints passed so far.
    seq: u32,
    /// Offset of the member's DEFLATE data.
    data_start: u64,
    /// Tar-stream offset where the member's output begins.
    out_base: u64,
    inflate: Checkpoint,
}

impl Cursor {
    fn out(&self) -> u64 {
        self.out_base + self.inflate.out_total
    }
}

/// A journaled checkpoint: the cursor and how far the archive may be freed.
#[derive(Debug, Clone)]
struct Record {
    cursor: Cursor,
    free_below: u64,
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let c = &self.cursor;
        let mut b = c.seq.to_le_bytes().to_vec();
        for v in [c.data_start, c.out_base, self.free_below] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&c.inflate.to_bytes());
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        Some(Self {
            cursor: Cursor {
                seq: u32::from_le_bytes(b.get(..4)?.try_into().ok()?),
                data_start: u64_at(4)?,
                out_base: u64_at(12)?,
                inflate: Checkpoint::from_bytes(b.get(28..)?)?,
            },
            free_below: u64_at(20)?,
        })
    }
}

fn gz_err(e: GzipError) -> Error {
    match e {
        GzipError::Fs(f) => f.into(),
        other => Error::Input(other.to_string()),
    }
}

/// Decode from `cur` to the end of the last member. `sink` receives the tar stream in order;
/// `on_ckpt` receives each checkpoint (`every > 0`) and the offset below which the archive is no
/// longer needed. Errors from the callbacks are returned as they are.
fn drive(
    archive: &dyn FileHandle,
    file_len: u64,
    mut cur: Cursor,
    every: u64,
    max_out: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    on_ckpt: &mut dyn FnMut(&Cursor, u64) -> Result<()>,
) -> Result<(u32, u64)> {
    let since = Cell::new(0u64);
    let failure: RefCell<Option<Error>> = RefCell::new(None);
    let fail = |e: Error| {
        *failure.borrow_mut() = Some(e);
        InflateError::Callback(String::new())
    };
    let mut members = 0u32;
    loop {
        let (data_start, out_base) = (cur.data_start, cur.out_base);
        let seq = Cell::new(cur.seq);
        let budget = max_out.saturating_sub(out_base);
        let finished = Inflater::new(&cur.inflate, budget).run(
            archive,
            data_start,
            file_len.saturating_sub(data_start),
            &mut |b| {
                since.set(since.get() + b.len() as u64);
                sink(b).map_err(fail)
            },
            every,
            &mut |ck| {
                since.set(0);
                seq.set(seq.get() + 1);
                let c = Cursor {
                    seq: seq.get(),
                    data_start,
                    out_base,
                    inflate: ck.clone(),
                };
                on_ckpt(&c, data_start + ck.in_bit / 8).map_err(fail)
            },
        );
        if let Some(e) = failure.borrow_mut().take() {
            return Err(e);
        }
        let f = finished.map_err(|e| match e {
            InflateError::Fs(fe) => fe.into(),
            other => Error::Integrity(format!("gzip member at byte {data_start}: {other}")),
        })?;
        members += 1;
        let trailer = data_start + f.in_bits.div_ceil(8);
        if trailer + gzip::TRAILER_LEN > file_len {
            return Err(Error::Integrity(format!(
                "gzip member at byte {data_start} has no trailer (truncated download?)"
            )));
        }
        let (crc, size_mod) = gzip::read_trailer(archive, trailer).map_err(gz_err)?;
        #[allow(clippy::cast_possible_truncation)] // the trailer stores the size mod 2^32
        let expected_size = f.out_total as u32;
        if crc != f.crc || size_mod != expected_size {
            return Err(Error::Integrity(format!(
                "gzip member at byte {data_start}: CRC or size mismatch"
            )));
        }
        let next = trailer + gzip::TRAILER_LEN;
        let out_base = out_base + f.out_total;
        if next >= file_len || gzip::only_padding_after(archive, next, file_len).map_err(gz_err)? {
            return Ok((members, out_base));
        }
        let next_data = gzip::read_header(archive, next, file_len).map_err(gz_err)?;
        cur = Cursor {
            seq: seq.get(),
            data_start: next_data,
            out_base,
            inflate: Checkpoint::start(),
        };
        // A member boundary is a checkpoint too, once enough has been produced since the last
        // one (archives made of many small members still free space as they go).
        if every > 0 && since.get() >= every {
            since.set(0);
            cur.seq += 1;
            on_ckpt(&cur, next)?;
        }
    }
}

fn start_cursor(archive: &dyn FileHandle, file_len: u64) -> Result<Cursor> {
    Ok(Cursor {
        seq: 0,
        data_start: gzip::read_header(archive, 0, file_len).map_err(gz_err)?,
        out_base: 0,
        inflate: Checkpoint::start(),
    })
}

fn tar_err(archive: &Path) -> impl Fn(tar::TarError) -> Error + '_ {
    move |e| Error::Input(format!("{}: {e}", archive.display()))
}

/// Decode the whole archive without writing anything: check every member's CRC, parse and
/// validate the tar headers, and build the checkpoint table for `every`.
pub fn scan(archive: &dyn FileHandle, path: &Path, every: u64) -> Result<TgzLayout> {
    let file_len = archive.size()?;
    let reader = RefCell::new(tar::Reader::new());
    let hasher = RefCell::new(Blake3Hasher::new());
    let mut ckpts = Vec::new();
    let (members, tar_len) = drive(
        archive,
        file_len,
        start_cursor(archive, file_len)?,
        every,
        u64::MAX,
        &mut |b| {
            reader
                .borrow_mut()
                .feed_data(b, &mut |d| {
                    hasher.borrow_mut().update(d);
                })
                .map_err(tar_err(path))
        },
        &mut |c, free_below| {
            let h = hasher.replace(Blake3Hasher::new());
            ckpts.push(CkptInfo {
                free_below,
                out: c.out(),
                hash: *h.finalize().as_bytes(),
            });
            Ok(())
        },
    )?;
    let entries = reader.into_inner().finish().map_err(tar_err(path))?;
    Ok(TgzLayout {
        file_len,
        members,
        tar_len,
        entries,
        every,
        ckpts,
        tail_hash: *hasher.into_inner().finalize().as_bytes(),
    })
}

/// True if `path` starts with a gzip member whose output begins with a tar header, or is a
/// `.tar.gz` being consumed (its journal exists).
pub fn is_tgz(fs: &dyn FsBackend, path: &Path) -> bool {
    if let Ok((_, pre, _)) = Journal::open(fs, &journal_path(path)) {
        return pre.starts_with(PREAMBLE_MAGIC);
    }
    let Ok(h) = fs.open(path, OpenMode::Read, Share::Shared) else {
        return false;
    };
    let Ok(len) = h.size() else { return false };
    let Ok(data_start) = gzip::read_header(h.as_ref(), 0, len) else {
        return false;
    };
    let mut first = Vec::with_capacity(512);
    // The decoder hands output over in chunks, so allow a few MiB and stop at 512 bytes.
    let _ = Inflater::new(&Checkpoint::start(), 4 << 20).run(
        h.as_ref(),
        data_start,
        len - data_start,
        &mut |b| {
            let take = (512 - first.len()).min(b.len());
            first.extend_from_slice(&b[..take]);
            if first.len() == 512 {
                Err(InflateError::Callback(String::new()))
            } else {
                Ok(())
            }
        },
        0,
        &mut |_| Ok(()),
    );
    first.len() == 512 && tar::looks_like_header(&first)
}

/// Destination recorded in the journal of a `.tar.gz` being consumed.
pub fn journal_dest(fs: &dyn FsBackend, archive: &Path) -> Option<PathBuf> {
    let (_, pre, _) = Journal::open(fs, &journal_path(archive)).ok()?;
    Preamble::decode(&pre).map(|p| p.dest)
}

fn items_of(entries: &[tar::Entry]) -> Vec<Item> {
    entries
        .iter()
        .filter_map(|e| {
            let kind = match e.kind {
                Kind::File => ItemKind::File,
                Kind::Dir => ItemKind::Dir,
                Kind::Symlink => ItemKind::Symlink,
                Kind::Special => return None,
            };
            Some(Item {
                path: e.name.clone(),
                kind,
                size: e.size,
                mode: e.mode,
                mtime_unix: e.mtime_unix,
                mtime_nanos: e.mtime_nanos,
            })
        })
        .collect()
}

/// Space needed to extract or consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TgzSpace {
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
pub fn tgz_space(
    layout: &TgzLayout,
    can_dealloc: bool,
    granularity: u64,
    params: &SpaceParams,
) -> TgzSpace {
    let gran = granularity.max(1);
    let cluster = params.cluster_size.max(1);
    let files: Vec<&tar::Entry> = layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .collect();
    let content: u64 = files.iter().map(|e| e.size).sum();
    let slack: u64 = layout
        .entries
        .iter()
        .map(|e| params.per_entry_overhead + (e.size.div_ceil(cluster) * cluster - e.size))
        .sum();
    // Content bytes that precede tar offset `o`. Files are in stream order.
    let data_before = |o: u64| -> u64 {
        files
            .iter()
            .take_while(|e| e.data_offset < o)
            .map(|e| (o - e.data_offset).min(e.size))
            .sum()
    };
    let mut peak = layout.file_len;
    let n = layout.ckpts.len();
    for k in 0..=n {
        let end = if k < n {
            layout.ckpts[k].out
        } else {
            layout.tar_len
        };
        let freed = if k == 0 || !can_dealloc {
            0
        } else {
            layout.ckpts[k - 1].free_below / gran * gran
        };
        peak = peak.max(layout.file_len - freed.min(layout.file_len) + data_before(end));
    }
    let margin = params.margin_fixed + content / 1_000_000 * params.margin_ppm;
    let consume_peak = peak + slack + margin;
    TgzSpace {
        archive_len: layout.file_len,
        content,
        extract_extra: content + slack + margin,
        consume_peak,
        consume_extra: consume_peak.saturating_sub(layout.file_len),
    }
}

/// Where the router writes.
enum Target<'a> {
    /// The staging directory of a consume.
    Stage(&'a StageGuard<'a>),
    /// A plain destination for non-destructive extraction.
    Dest { root: &'a Path, overwrite: bool },
}

/// Routes the tar stream's file content into output files.
struct Router<'a> {
    fs: &'a dyn FsBackend,
    target: Target<'a>,
    entries: &'a [tar::Entry],
    /// Indices of non-empty files, in stream order.
    files: Vec<usize>,
    /// Position in `files` of the first unfinished file.
    next: usize,
    /// Tar-stream offset of the next byte.
    pos: u64,
    current: Option<Box<dyn FileHandle>>,
    /// Finished files not yet flushed.
    pending: Vec<Box<dyn FileHandle>>,
    /// Parents of files created since the last flush.
    new_dirs: BTreeSet<PathBuf>,
    /// Content routed since the last checkpoint, and where it went (for read-back checks).
    hasher: Blake3Hasher,
    segments: Vec<(usize, u64, u64)>,
    written: u64,
    need_free: u64,
}

impl<'a> Router<'a> {
    fn new(
        fs: &'a dyn FsBackend,
        target: Target<'a>,
        entries: &'a [tar::Entry],
        pos: u64,
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
            hasher: Blake3Hasher::new(),
            segments: Vec::new(),
            written: 0,
            need_free,
        }
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
        let (h, created) = match &self.target {
            Target::Stage(g) => open_staged_output(self.fs, g, &p)?,
            Target::Dest { overwrite, .. } => {
                if let Some(m) = self.fs.metadata(&p)? {
                    if !*overwrite || m.kind != NodeKind::File {
                        return Err(Error::Refused(format!("{} already exists", p.display())));
                    }
                }
                let mode = if *overwrite {
                    OpenMode::CreateOrTruncate
                } else {
                    OpenMode::CreateNew
                };
                (self.fs.open(&p, mode, Share::Exclusive)?, true)
            }
        };
        if created {
            self.new_dirs.insert(parent_of(&p));
        }
        if !created || at > 0 {
            h.set_len(at)?;
        }
        Ok(h)
    }

    fn write(&mut self, mut b: &[u8]) -> Result<()> {
        while !b.is_empty() {
            let Some(&i) = self.files.get(self.next) else {
                self.pos += b.len() as u64;
                return Ok(());
            };
            let (data_offset, size) = (self.entries[i].data_offset, self.entries[i].size);
            if self.pos < data_offset {
                let skip =
                    usize::try_from((data_offset - self.pos).min(b.len() as u64)).expect("<= len");
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
            h.preallocate(at + n as u64)
                .map_err(|e| nospace(e, self.need_free))?;
            h.write_all_at(&b[..n], at)
                .map_err(|e| nospace(e, self.need_free))?;
            self.hasher.update(&b[..n]);
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
                h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                self.pending.push(h);
                self.next += 1;
                if self.pending.len() >= MAX_PENDING {
                    for h in self.pending.drain(..) {
                        h.flush_data()?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Make everything written so far durable: file data, then new directory entries.
    fn flush(&mut self) -> Result<()> {
        if let Some(h) = &self.current {
            h.flush_data()?;
        }
        for h in self.pending.drain(..) {
            h.flush_data()?;
        }
        for d in std::mem::take(&mut self.new_dirs) {
            self.fs.flush_dir(&d)?;
        }
        Ok(())
    }

    /// Hash of the content routed since the last call, and (with `read_back`) whether the same
    /// content reads back from the device.
    fn take_interval(&mut self, read_back: bool) -> Result<([u8; 32], bool)> {
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
            let p = join_rel(self.root(), &self.entries[i].name);
            let f = self.fs.open(&p, OpenMode::Read, Share::Shared)?;
            let mut off = from;
            while off < to {
                let n = usize::try_from((to - off).min(buf.len() as u64)).expect("<= 4 MiB");
                match f.read_back(&mut buf[..n], off) {
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

fn media_mismatch() -> Error {
    Error::Integrity(
        "media verification failed: data read back from disk differs from what was written; \
         the archive bytes it came from were not released"
            .into(),
    )
}

/// Consume a `.tar.gz` into `dest`. Safe to call again after any crash or pause.
pub fn consume_tgz(
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
            let len = handle.size()?;
            if handle.file_id()? != pre.file_id || (len != pre.layout.file_len && len != 0) {
                return Err(Error::Refused(format!(
                    "{} is not the archive this journal belongs to (it was replaced?)",
                    archive_path.display()
                )));
            }
            summary.resumed = true;
            (pre, j, latest.and_then(|b| Record::decode(&b)))
        }
        None => {
            let layout = scan(
                handle.as_ref(),
                archive_path,
                opts.zip.checkpoint_every.max(1),
            )?;
            let pre = Preamble {
                archive_id: trunc_hash::blake3(&layout.to_bytes())[..16]
                    .try_into()
                    .expect("16 bytes"),
                file_id: handle.file_id()?,
                dest: dest.clone(),
                layout,
            };
            let tops = top_level_names(&items_of(&pre.layout.entries));
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
    let items = items_of(&layout.entries);
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
    let space = tgz_space(layout, can_dealloc, granularity, &params);
    let need_free = if vc.same_volume {
        space.consume_extra
    } else {
        space.extract_extra
    };
    let len = handle.size()?;

    match fs.metadata(&stage)?.map(|m| m.kind) {
        Some(NodeKind::Dir) => crate::stage::flush_staging_tree(fs, &stage, &dest)?,
        Some(_) => {
            return Err(Error::Refused(format!(
                "{} exists and is not a directory",
                stage.display()
            )));
        }
        None if latest.is_none() && len == layout.file_len => {
            // Nothing destroyed yet (fresh start, or a crash before the first checkpoint).
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
        protected: &protected,
    };
    let total = layout.ckpts.len() + 1;
    build_structure(fs, &items, &dest, &stage, &mut summary)?;
    if let Some(r) = &latest {
        // A crash between journaling a checkpoint and freeing its bytes leaves them allocated.
        match handle.deallocate(0, r.free_below.min(len))? {
            Dealloc::Freed { .. } | Dealloc::Unsupported => {}
        }
    }

    // A zero-length archive means every byte was decoded and made durable before it was cut.
    if len > 0 {
        let cursor = match &latest {
            Some(r) => r.cursor.clone(),
            None => start_cursor(handle.as_ref(), layout.file_len)?,
        };
        progress(Progress::Started {
            resumed: summary.resumed,
            blocks_done: cursor.seq as usize,
            blocks_total: total,
        });
        let mut freed_to = latest.as_ref().map_or(0, |r| r.free_below);
        let router = RefCell::new(Router::new(
            fs,
            Target::Stage(&guard),
            &layout.entries,
            cursor.out(),
            need_free,
        ));
        let verify = opts.verify_media;
        drive(
            handle.as_ref(),
            layout.file_len,
            cursor,
            layout.every,
            layout.tar_len,
            &mut |b| router.borrow_mut().write(b),
            &mut |c, free_below| {
                let mut r = router.borrow_mut();
                r.flush()?;
                let expected = (c.seq as usize)
                    .checked_sub(1)
                    .and_then(|i| layout.ckpts.get(i))
                    .ok_or_else(|| {
                        Error::Integrity("more checkpoints than the scan found".into())
                    })?;
                let (hash, media_ok) = r.take_interval(verify)?;
                if hash != expected.hash
                    || c.out() != expected.out
                    || free_below != expected.free_below
                {
                    return Err(Error::Integrity(format!(
                        "decoded content differs from the verified scan before checkpoint {}; \
                         nothing past the previous checkpoint was released",
                        c.seq
                    )));
                }
                if !media_ok {
                    return Err(media_mismatch());
                }
                journal
                    .write(
                        &Record {
                            cursor: c.clone(),
                            free_below,
                        }
                        .encode(),
                    )
                    .map_err(journal_err)?;
                match handle.deallocate(freed_to / granularity * granularity, free_below)? {
                    Dealloc::Freed { .. } | Dealloc::Unsupported => {}
                }
                freed_to = free_below;
                progress(Progress::Batch {
                    blocks_done: c.seq as usize,
                    blocks_total: total,
                    bytes_written: r.written,
                    archive_len: layout.file_len - free_below,
                });
                Ok(())
            },
        )?;
        let mut r = router.into_inner();
        r.flush()?;
        let (hash, media_ok) = r.take_interval(verify)?;
        if hash != layout.tail_hash {
            return Err(Error::Integrity(
                "decoded content differs from the verified scan after the last checkpoint".into(),
            ));
        }
        if !media_ok {
            return Err(media_mismatch());
        }
        summary.bytes_written = r.written;
        summary.batches = total;
        truncate_with_retry(handle.as_ref(), 0, opts.retry)?;
        handle.flush_data()?;
    }

    progress(Progress::Renaming);
    rename_into_place(fs, &items, &dest, &stage)?;
    finish(fs, handle, archive_path, journal, &jpath)?;
    Ok(summary)
}

/// Check every member's CRC and every tar header without writing anything.
pub fn verify_tgz(fs: &dyn FsBackend, archive: &Path) -> Result<TgzLayout> {
    let h = fs.open(archive, OpenMode::Read, Share::Shared)?;
    scan(h.as_ref(), archive, 0)
}

/// Non-destructive extraction into `dest`. The archive is scanned (and every name validated)
/// before anything is written. Symlinks and special files are skipped.
pub fn extract_tgz(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
) -> Result<ConsumeSummary> {
    let h = fs.open(archive, OpenMode::Read, Share::Shared)?;
    let layout = scan(h.as_ref(), archive, 0)?;
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
    // Empty files carry no data for the router to write.
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
        f.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
    }
    let router = RefCell::new(Router::new(
        fs,
        Target::Dest {
            root: dest,
            overwrite,
        },
        &layout.entries,
        0,
        0,
    ));
    drive(
        h.as_ref(),
        layout.file_len,
        start_cursor(h.as_ref(), layout.file_len)?,
        0,
        layout.tar_len,
        &mut |b| router.borrow_mut().write(b),
        &mut |_, _| Ok(()),
    )?;
    let mut r = router.into_inner();
    r.flush()?;
    if r.take_interval(false)?.0 != layout.tail_hash {
        return Err(Error::Integrity(
            "decoded content changed between the scan and extraction".into(),
        ));
    }
    for e in &layout.entries {
        match e.kind {
            Kind::File => {
                summary.files += 1;
                if let Some(m) = e.mode {
                    fs.set_mode(&join_rel(dest, &e.name), m)?;
                }
            }
            Kind::Symlink => summary.symlinks_skipped += 1,
            Kind::Special => summary.specials_skipped += 1,
            Kind::Dir => {}
        }
    }
    summary.bytes_written = r.written;
    Ok(summary)
}

/// Scan an archive for inspection or planning.
pub fn open_layout(fs: &dyn FsBackend, archive: &Path, every: u64) -> Result<TgzLayout> {
    let h = fs.open(archive, OpenMode::Read, Share::Shared)?;
    scan(h.as_ref(), archive, every)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_layouts_round_trip() {
        let r = Record {
            cursor: Cursor {
                seq: 7,
                data_start: 20,
                out_base: 1 << 33,
                inflate: Checkpoint {
                    in_bit: 12345,
                    out_total: 99,
                    crc: 0xDEAD_BEEF,
                    window: [1u8, 2, 3].repeat(33),
                },
            },
            free_below: 1500,
        };
        let back = Record::decode(&r.encode()).unwrap();
        assert_eq!((back.cursor, back.free_below), (r.cursor, r.free_below));

        let l = TgzLayout {
            file_len: 10,
            members: 2,
            tar_len: 3072,
            entries: Vec::new(),
            every: 64 << 20,
            ckpts: vec![CkptInfo {
                free_below: 4,
                out: 1024,
                hash: [9; 32],
            }],
            tail_hash: [3; 32],
        };
        assert_eq!(TgzLayout::from_bytes(&l.to_bytes()), Some(l.clone()));
        assert_eq!(TgzLayout::from_bytes(&l.to_bytes()[1..]), None);
    }
}

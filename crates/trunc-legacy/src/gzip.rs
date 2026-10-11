//! gzip (RFC 1952) member framing. The compressed data inside a member is a raw DEFLATE stream,
//! decoded by [`crate::inflate`]. A `.tar.gz` may hold several members back to back (`pigz -i`,
//! `cat a.gz b.gz`); their outputs concatenate.
//!
//! BGZF files (`bgzip`, samtools, htslib) are made of small members whose headers give their
//! size. Those members are decoded whole, several at a time on worker threads; see
//! [`bgzf_walk`].

use std::cell::{Cell, RefCell};
use std::ops::Range;
use std::path::Path;
use std::time::SystemTime;

use trunc_fs::{Dealloc, FileHandle, FileId};

use crate::inflate::{Checkpoint, InflateError, Inflater};
use crate::stream::{
    self, Fields, Input, Limits, OnPoint, SafePoint, Sink, StreamEnd, StreamError,
};

pub const MAGIC: [u8; 2] = [0x1f, 0x8b];
const CM_DEFLATE: u8 = 8;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;
const FLAGS_RESERVED: u8 = 0xE0;
/// Headers longer than this (huge names, comments or extra fields) are refused.
const MAX_HEADER: usize = 64 * 1024;
pub const TRAILER_LEN: u64 = 8;
/// A BGZF member header: the fixed ten bytes, the extra field length, and the `BC` subfield.
const BGZF_HEADER: u64 = 18;
/// Output of the BGZF members one worker job decodes (at least one member).
const BATCH_OUT: u64 = 2 << 20;
/// BGZF members producing more than this (real ones produce at most 64 KiB) are left to the
/// decoding loop.
const MAX_WHOLE_MEMBER: u32 = 1 << 20;
/// BGZF members looked at by the first walk, and by any walk.
const WALK_FIRST: usize = 256;
const WALK_MAX: usize = 1 << 16;

#[derive(Debug, thiserror::Error)]
pub enum GzipError {
    #[error("not a gzip file")]
    NotGzip,
    #[error("corrupt gzip header at byte {0}: {1}")]
    Header(u64, &'static str),
    #[error(transparent)]
    Fs(#[from] trunc_fs::FsError),
}

/// Parse the member header at `at`; returns where its DEFLATE data starts.
pub fn read_header(src: &dyn FileHandle, at: u64, file_len: u64) -> Result<u64, GzipError> {
    Ok(header(src, at, file_len)?.data)
}

/// A member header: where the member's DEFLATE data starts, and the member's size if it is a
/// BGZF header.
#[derive(Debug, Clone, Copy)]
struct Head {
    data: u64,
    bgzf: Option<u64>,
}

fn header(src: &dyn FileHandle, at: u64, file_len: u64) -> Result<Head, GzipError> {
    let avail =
        usize::try_from(file_len.saturating_sub(at).min(MAX_HEADER as u64)).expect("<= 64 KiB");
    if avail < 10 {
        return Err(if at == 0 {
            GzipError::NotGzip
        } else {
            GzipError::Header(at, "truncated")
        });
    }
    let mut b = vec![0u8; avail];
    src.read_exact_at(&mut b, at)?;
    if b[..2] != MAGIC {
        return Err(if at == 0 {
            GzipError::NotGzip
        } else {
            GzipError::Header(at, "bad magic")
        });
    }
    let bad = |why| GzipError::Header(at, why);
    if b[2] != CM_DEFLATE {
        return Err(bad("compression method is not deflate"));
    }
    let flags = b[3];
    if flags & FLAGS_RESERVED != 0 {
        return Err(bad("reserved flag bits set"));
    }
    let mut p = 10usize;
    if flags & FEXTRA != 0 {
        let xlen = usize::from(u16::from_le_bytes(
            b.get(p..p + 2)
                .ok_or(bad("truncated"))?
                .try_into()
                .expect("2"),
        ));
        p += 2 + xlen;
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let rest = b.get(p..).ok_or(bad("truncated"))?;
            let nul = rest
                .iter()
                .position(|&c| c == 0)
                .ok_or(bad("name or comment too long"))?;
            p += nul + 1;
        }
    }
    if flags & FHCRC != 0 {
        let stored = u16::from_le_bytes(
            b.get(p..p + 2)
                .ok_or(bad("truncated"))?
                .try_into()
                .expect("2"),
        );
        // The header CRC is the low 16 bits of the CRC-32 by definition.
        #[allow(clippy::cast_possible_truncation)]
        let actual = crc32fast::hash(&b[..p]) as u16;
        if stored != actual {
            return Err(bad("header checksum mismatch"));
        }
        p += 2;
    }
    if p > b.len() {
        return Err(bad("truncated"));
    }
    Ok(Head {
        data: at + p as u64,
        bgzf: bgzf_size(&b),
    })
}

/// The member size a BGZF header at the start of `h` declares. The header has no flag but the
/// extra field, which holds only a `BC` subfield with the size minus one; like htslib, nothing
/// else counts as BGZF.
fn bgzf_size(h: &[u8]) -> Option<u64> {
    match h {
        [
            0x1f,
            0x8b,
            CM_DEFLATE,
            FEXTRA,
            _,
            _,
            _,
            _,
            _,
            _,
            6,
            0,
            b'B',
            b'C',
            2,
            0,
            lo,
            hi,
            ..,
        ] => {
            let size = u64::from(u16::from_le_bytes([*lo, *hi])) + 1;
            (size > BGZF_HEADER + TRAILER_LEN).then_some(size)
        }
        _ => None,
    }
}

/// The member trailer at `at`: CRC-32 and size (mod 2^32) of the member's output.
pub fn read_trailer(src: &dyn FileHandle, at: u64) -> Result<(u32, u32), GzipError> {
    let mut b = [0u8; 8];
    src.read_exact_at(&mut b, at)?;
    Ok((
        u32::from_le_bytes(b[..4].try_into().expect("4")),
        u32::from_le_bytes(b[4..].try_into().expect("4")),
    ))
}

/// True if `[from, file_len)` is empty or all zeros (padding some tools add after the last member).
pub fn only_padding_after(
    src: &dyn FileHandle,
    from: u64,
    file_len: u64,
) -> Result<bool, GzipError> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = from;
    while off < file_len {
        let n = usize::try_from((file_len - off).min(buf.len() as u64)).expect("<= 64 KiB");
        src.read_exact_at(&mut buf[..n], off)?;
        if buf[..n].iter().any(|&c| c != 0) {
            return Ok(false);
        }
        off += n as u64;
    }
    Ok(true)
}

/// Where decoding is, or resumes from: inside the DEFLATE data of one member.
///
/// Cursor bytes: `member data offset u64 | output base u64 | inflate checkpoint`. At the start
/// of a BGZF member the offset is the member's header instead, and the checkpoint has consumed
/// the header's bits but produced nothing (see [`boundary_cursor`]).
fn cursor_bytes(data_start: u64, out_base: u64, ck: &Checkpoint) -> Vec<u8> {
    let mut b = data_start.to_le_bytes().to_vec();
    b.extend_from_slice(&out_base.to_le_bytes());
    b.extend_from_slice(&ck.to_bytes());
    b
}

fn parse_cursor(b: &[u8]) -> stream::Result<(u64, u64, Checkpoint)> {
    let mut f = Fields::new(b);
    let (Some(data_start), Some(out_base)) = (f.u64(), f.u64()) else {
        return Err(stream::bad_cursor());
    };
    let ck = Checkpoint::from_bytes(f.rest()).ok_or_else(stream::bad_cursor)?;
    Ok((data_start, out_base, ck))
}

/// The cursor for the start of the member at `at`. A BGZF member's cursor points at its header,
/// so that a resumed run knows it is one, as the first run did.
fn boundary_cursor(at: u64, h: &Head, out_base: u64) -> Vec<u8> {
    match h.bgzf {
        Some(_) => cursor_bytes(
            at,
            out_base,
            &Checkpoint {
                in_bit: (h.data - at) * 8,
                ..Checkpoint::start()
            },
        ),
        None => cursor_bytes(h.data, out_base, &Checkpoint::start()),
    }
}

/// Where a cursor resumes: `(data offset, output base, checkpoint, BGZF member size)`, the size
/// only when resuming at the start of a BGZF member.
fn resume(
    src: &dyn FileHandle,
    file_len: u64,
    c: &[u8],
) -> stream::Result<(u64, u64, Checkpoint, Option<u64>)> {
    let (at, out_base, ck) = parse_cursor(c)?;
    // Inside a member, a checkpoint has produced something.
    if ck.out_total > 0 || ck.in_bit == 0 {
        return Ok((at, out_base, ck, None));
    }
    let h = header(src, at, file_len).map_err(|e| match e {
        GzipError::Fs(f) => StreamError::Fs(f),
        _ => stream::bad_cursor(),
    })?;
    if h.bgzf.is_none() || at + ck.in_bit / 8 != h.data || ck.in_bit % 8 != 0 {
        return Err(stream::bad_cursor());
    }
    Ok((h.data, out_base, Checkpoint::start(), h.bgzf))
}

fn gz_err(e: GzipError) -> StreamError {
    match e {
        GzipError::Fs(f) => StreamError::Fs(f),
        other => StreamError::Format(other.to_string()),
    }
}

/// Output and members so far.
struct Progress {
    out: u64,
    /// Output since the last safe point.
    since: u64,
    units: u32,
}

/// Decode a gzip file (one or more members). Safe points are DEFLATE block boundaries after
/// `every` bytes of a member's output, and member boundaries once `every` bytes have been
/// produced since the previous safe point.
///
/// A BGZF member has no safe points inside the size its header gives, so it is always decoded
/// whole: workers can decode it ahead, and the safe points are the same with or without them.
/// One whose data runs past that size (not really BGZF) has safe points from there on, so a
/// lying header cannot hold up freeing for more than one small member's worth of input.
pub fn decode(
    input: Input<'_>,
    start: Option<&[u8]>,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let Input { src, len: file_len } = input;
    let (mut data_start, out_base, mut ck, mut bgzf) = match start {
        Some(c) => resume(src, file_len, c)?,
        None => {
            let h = header(src, 0, file_len).map_err(gz_err)?;
            (h.data, 0, Checkpoint::start(), h.bgzf)
        }
    };
    let mut p = Progress {
        out: out_base + ck.out_total,
        since: 0,
        units: 0,
    };
    // Without safe points or threads, members decoded whole would change nothing.
    let walk = every > 0 || limits.workers() > 1;
    let mut walk_max = WALK_FIRST;
    // The member at `data_start` must be decoded here (a worker could not).
    let mut here = false;
    // Members the previous run found while its own were decoding.
    let mut found: Option<Walk> = None;
    loop {
        if let (Some(size), true, false) = (bgzf, walk, here) {
            let start = data_start - BGZF_HEADER;
            let w = match found.take() {
                Some(w) if w.members.first().is_some_and(|m| m.start == start) => w,
                _ => bgzf_walk(src, file_len, start, size, walk_max),
            };
            walk_max = (walk_max * 2).min(WALK_MAX);
            if !w.members.is_empty() {
                let run = Run {
                    walk: &w,
                    walk_max,
                    limits,
                    every,
                };
                match bgzf_run(src, file_len, &run, &mut p, sink, on_point)? {
                    Next::End => {
                        return Ok(StreamEnd {
                            out_len: p.out,
                            units: p.units,
                        });
                    }
                    Next::At(h, decode_here, next) => {
                        (data_start, bgzf, ck) = (h.data, h.bgzf, Checkpoint::start());
                        (here, found) = (decode_here, next);
                        continue;
                    }
                }
            }
        }
        here = false;
        let next = member(
            src, file_len, data_start, &ck, bgzf, limits, every, &mut p, sink, on_point,
        )?;
        let Some(h) = next_member(src, file_len, next, None, every, &mut p, on_point)? else {
            return Ok(StreamEnd {
                out_len: p.out,
                units: p.units,
            });
        };
        (data_start, bgzf, ck) = (h.data, h.bgzf, Checkpoint::start());
    }
}

/// Decode one member from `ck` (its data starts at `data_start`; `bgzf`: it is a BGZF member of
/// that size, decoded from its start) and check its trailer. Returns where the member ends.
#[allow(clippy::too_many_arguments)]
fn member(
    src: &dyn FileHandle,
    file_len: u64,
    data_start: u64,
    ck: &Checkpoint,
    bgzf: Option<u64>,
    limits: Limits,
    every: u64,
    p: &mut Progress,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<u64> {
    let out_base = p.out - ck.out_total;
    // Block boundaries before this many bytes of data are not safe points.
    let whole = bgzf.map_or(0, |size| size - BGZF_HEADER - TRAILER_LEN);
    let since = Cell::new(p.since);
    let failure: RefCell<Option<StreamError>> = RefCell::new(None);
    let fail = |e: StreamError| {
        *failure.borrow_mut() = Some(e);
        InflateError::Callback(String::new())
    };
    let budget = limits.max_out.saturating_sub(out_base);
    let finished = Inflater::new(ck, budget).run(
        src,
        data_start,
        file_len.saturating_sub(data_start),
        &mut |b| {
            since.set(since.get() + b.len() as u64);
            sink(b).map_err(fail)
        },
        every,
        &mut |c| {
            if c.in_bit / 8 < whole {
                return Ok(());
            }
            since.set(0);
            let cursor = cursor_bytes(data_start, out_base, c);
            on_point(SafePoint {
                cursor: &cursor,
                out: out_base + c.out_total,
                free_below: data_start + c.in_bit / 8,
            })
            .map_err(fail)
        },
    );
    if let Some(e) = failure.borrow_mut().take() {
        return Err(e);
    }
    let f = finished.map_err(|e| match e {
        InflateError::Fs(fe) => StreamError::Fs(fe),
        other => StreamError::Corrupt(format!("gzip member at byte {data_start}: {other}")),
    })?;
    p.units += 1;
    let trailer = data_start + f.in_bits.div_ceil(8);
    if trailer + TRAILER_LEN > file_len {
        return Err(StreamError::Corrupt(format!(
            "gzip member at byte {data_start} has no trailer (truncated download?)"
        )));
    }
    let (crc, size_mod) = read_trailer(src, trailer).map_err(gz_err)?;
    #[allow(clippy::cast_possible_truncation)] // the trailer stores the size mod 2^32
    let expected_size = f.out_total as u32;
    if crc != f.crc || size_mod != expected_size {
        return Err(StreamError::Corrupt(format!(
            "gzip member at byte {data_start}: CRC or size mismatch"
        )));
    }
    p.out = out_base + f.out_total;
    p.since = since.get();
    Ok(trailer + TRAILER_LEN)
}

/// After a member that ends at `next`: the next member's header (`known` if already parsed), or
/// `None` at the end of the file. A member boundary is a safe point too, once enough has been
/// produced since the last one (archives made of many small members still free space as they
/// go).
fn next_member(
    src: &dyn FileHandle,
    file_len: u64,
    next: u64,
    known: Option<Head>,
    every: u64,
    p: &mut Progress,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<Option<Head>> {
    let h = match known {
        Some(h) => h,
        None => {
            if next >= file_len || only_padding_after(src, next, file_len).map_err(gz_err)? {
                return Ok(None);
            }
            header(src, next, file_len).map_err(gz_err)?
        }
    };
    if every > 0 && p.since >= every {
        p.since = 0;
        let cursor = boundary_cursor(next, &h, p.out);
        on_point(SafePoint {
            cursor: &cursor,
            out: p.out,
            free_below: next,
        })?;
    }
    Ok(Some(h))
}

/// A BGZF member found by [`bgzf_walk`].
#[derive(Debug, Clone, Copy)]
struct Member {
    start: u64,
    size: u64,
    crc: u32,
    isize: u32,
}

impl Member {
    fn head(&self) -> Head {
        Head {
            data: self.start + BGZF_HEADER,
            bgzf: Some(self.size),
        }
    }
}

/// Up to `max` BGZF members from the one at `start` (of `size` bytes), found from their headers
/// and trailers alone: one small read per member, of one member's trailer and the next one's
/// header. Stops quietly at anything else; the decoding loop takes over there and checks
/// everything as usual.
fn bgzf_walk(
    src: &dyn FileHandle,
    file_len: u64,
    mut start: u64,
    mut size: u64,
    max: usize,
) -> Walk {
    let _prof = trunc_prof::span("gzip.bgzf_walk");
    let mut members = Vec::new();
    let mut more = None;
    // A trailer and a header.
    let mut b = [0u8; 8 + 18];
    loop {
        let end = start + size;
        if end > file_len {
            break;
        }
        let n = usize::try_from((file_len - end).min(BGZF_HEADER)).expect("small") + 8;
        if src.read_exact_at(&mut b[..n], end - TRAILER_LEN).is_err() {
            break;
        }
        let crc = u32::from_le_bytes(b[..4].try_into().expect("4"));
        let isize = u32::from_le_bytes(b[4..8].try_into().expect("4"));
        if isize > MAX_WHOLE_MEMBER {
            break;
        }
        members.push(Member {
            start,
            size,
            crc,
            isize,
        });
        let Some(next) = bgzf_size(&b[8..n]) else {
            break;
        };
        if members.len() == max {
            more = Some((end, next));
            break;
        }
        (start, size) = (end, next);
    }
    Walk { members, more }
}

/// BGZF members found by [`bgzf_walk`].
struct Walk {
    members: Vec<Member>,
    /// Where the walk stopped at `max` members: the next member's start and size.
    more: Option<(u64, u64)>,
}

/// Members decoded on a worker: their output, and how many of them decoded and checked out.
struct Decoded {
    out: Vec<u8>,
    ok: usize,
}

/// Decode `members` whole, stopping at the first one that fails (its data does not end where
/// its size says, or its trailer does not match).
fn decode_members(src: &dyn FileHandle, members: &[Member]) -> Decoded {
    let total: u64 = members.iter().map(|m| u64::from(m.isize)).sum();
    let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let mut ok = 0;
    // One read for all of them (members are at most 64 KiB).
    let (first, last) = (members[0], members[members.len() - 1]);
    let mut bytes = vec![0u8; usize::try_from(last.start + last.size - first.start).unwrap_or(0)];
    if src.read_exact_at(&mut bytes, first.start).is_err() {
        return Decoded { out, ok };
    }
    let src = &Held {
        src,
        base: first.start,
        bytes,
    };
    for m in members {
        let before = out.len();
        let len = m.size - BGZF_HEADER - TRAILER_LEN;
        let r = Inflater::new(&Checkpoint::start(), u64::from(m.isize)).run(
            src,
            m.start + BGZF_HEADER,
            len,
            &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            },
            0,
            &mut |_| Ok(()),
        );
        match r {
            Ok(f)
                if f.in_bits.div_ceil(8) == len
                    && f.crc == m.crc
                    && f.out_total == u64::from(m.isize) => {}
            _ => {
                out.truncate(before);
                break;
            }
        }
        ok += 1;
    }
    Decoded { out, ok }
}

/// Bytes `[base, base + bytes.len())` of `src`, read once for a worker job; everything else
/// goes to `src`.
#[derive(Debug)]
struct Held<'a> {
    src: &'a dyn FileHandle,
    base: u64,
    bytes: Vec<u8>,
}

impl FileHandle for Held<'_> {
    fn path(&self) -> &Path {
        self.src.path()
    }

    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> trunc_fs::Result<()> {
        let held = off
            .checked_sub(self.base)
            .and_then(|at| usize::try_from(at).ok())
            .and_then(|at| self.bytes.get(at..at.checked_add(buf.len())?));
        match held {
            Some(b) => {
                buf.copy_from_slice(b);
                Ok(())
            }
            None => self.src.read_exact_at(buf, off),
        }
    }

    fn write_all_at(&self, buf: &[u8], off: u64) -> trunc_fs::Result<()> {
        self.src.write_all_at(buf, off)
    }

    fn size(&self) -> trunc_fs::Result<u64> {
        self.src.size()
    }

    fn set_len(&self, len: u64) -> trunc_fs::Result<()> {
        self.src.set_len(len)
    }

    fn preallocate(&self, len: u64) -> trunc_fs::Result<()> {
        self.src.preallocate(len)
    }

    fn flush_data(&self) -> trunc_fs::Result<()> {
        self.src.flush_data()
    }

    fn deallocate(&self, start: u64, end: u64) -> trunc_fs::Result<Dealloc> {
        self.src.deallocate(start, end)
    }

    fn allocated_ranges(&self) -> trunc_fs::Result<Vec<Range<u64>>> {
        self.src.allocated_ranges()
    }

    fn file_id(&self) -> trunc_fs::Result<FileId> {
        self.src.file_id()
    }

    fn set_modified(&self, t: SystemTime) -> trunc_fs::Result<()> {
        self.src.set_modified(t)
    }
}

/// How a run of BGZF members ended.
enum Next {
    End,
    /// At the start of this member; `true`: the decoding loop must decode it. With the members
    /// from there on, if they were found during the run.
    At(Head, bool, Option<Walk>),
}

/// A run of BGZF members to decode.
struct Run<'a> {
    walk: &'a Walk,
    /// Members to look for after these, while they decode.
    walk_max: usize,
    limits: Limits,
    every: u64,
}

/// Decode a run of BGZF members found by [`bgzf_walk`], in batches on worker threads. A member
/// a worker could not decode (or that does not fit in the output limit) is left to the decoding
/// loop, which then reports any error the same way as without threads.
fn bgzf_run(
    src: &dyn FileHandle,
    file_len: u64,
    run: &Run<'_>,
    p: &mut Progress,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<Next> {
    let Run {
        walk,
        walk_max,
        limits,
        every,
    } = *run;
    let members = &walk.members[..];
    let mut batches: Vec<Range<usize>> = Vec::new();
    let mut first = 0;
    let mut out = 0u64;
    for (i, m) in members.iter().enumerate() {
        out += u64::from(m.isize);
        if out >= BATCH_OUT || i + 1 == members.len() {
            batches.push(first..i + 1);
            (first, out) = (i + 1, 0);
        }
    }
    let threads = limits.workers().min(batches.len());
    let work = |k: usize| decode_members(src, &members[batches[k].clone()]);
    stream::with_ahead(batches.len(), threads, threads + 2, &work, |pre| {
        // Workers are busy: find the next members now rather than between runs.
        let mut found = pre
            .and(walk.more)
            .map(|(start, size)| bgzf_walk(src, file_len, start, size, walk_max));
        for (k, batch) in batches.iter().enumerate() {
            let d = match pre {
                Some(a) => a.get(k),
                None => work(k),
            };
            let mut at = 0usize;
            for (i, m) in members.iter().enumerate().take(batch.end).skip(batch.start) {
                let n = m.isize as usize;
                if i - batch.start >= d.ok || n as u64 > limits.max_out.saturating_sub(p.out) {
                    return Ok(Next::At(m.head(), true, None));
                }
                if n > 0 {
                    sink(&d.out[at..at + n])?;
                }
                at += n;
                p.out += n as u64;
                p.since += n as u64;
                p.units += 1;
                let known = members.get(i + 1).map(Member::head);
                match next_member(src, file_len, m.start + m.size, known, every, p, on_point)? {
                    None => return Ok(Next::End),
                    Some(h) if i + 1 == members.len() => {
                        return Ok(Next::At(h, false, found.take()));
                    }
                    Some(_) => {}
                }
            }
        }
        unreachable!("the last member returns")
    })
}

/// Convert a cursor to the slot layout of v0.1.0 `.tar.gz` journals (`TGJP1`):
/// `seq u32 | data offset u64 | output base u64 | free-below u64 | inflate checkpoint`.
pub fn cursor_to_v1(seq: u32, free_below: u64, cursor: &[u8]) -> Option<Vec<u8>> {
    let mut b = seq.to_le_bytes().to_vec();
    b.extend_from_slice(cursor.get(..16)?);
    b.extend_from_slice(&free_below.to_le_bytes());
    b.extend_from_slice(cursor.get(16..)?);
    Some(b)
}

/// The inverse of [`cursor_to_v1`]: `(seq, free_below, out, cursor)`.
pub fn cursor_from_v1(b: &[u8]) -> Option<(u32, u64, u64, Vec<u8>)> {
    let mut f = Fields::new(b);
    let seq = f.u32()?;
    let data_start = f.u64()?;
    let out_base = f.u64()?;
    let free_below = f.u64()?;
    let ck = Checkpoint::from_bytes(f.rest())?;
    let out = out_base + ck.out_total;
    Some((
        seq,
        free_below,
        out,
        cursor_bytes(data_start, out_base, &ck),
    ))
}

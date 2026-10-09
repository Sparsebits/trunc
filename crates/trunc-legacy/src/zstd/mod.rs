//! zstd decoding (RFC 8878), resumable at block and frame boundaries.
//!
//! A `.zst` file is one or more frames (skippable frames are ignored). Inside a frame, blocks
//! may refer back up to the frame's window size and reuse the previous block's Huffman tree,
//! sequence tables and repeat offsets. A safe point therefore stores that entropy state (a few
//! KB: Huffman weights and normalized counts, from which the tables are rebuilt) and reads the
//! window back through [`History`] on resume. Frames that need a dictionary are refused.
//!
//! Frames are independent. A frame that declares its size (up to 128 MiB) and is followed by
//! more of the file is decoded whole, on a worker thread when there are several such frames;
//! its only safe point is at its end. The rule depends on the file alone, so the scan, the
//! consume pass and a resume agree whatever the thread count.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

mod bits;
mod block;
mod fse;
mod huffman;

use trunc_fs::FileHandle;

use self::block::{Desc, Entropy, Kind, SeqTable};
use self::huffman::Huffman;
use crate::checks::Xxh64;
use crate::stream::{
    self, Fields, History, Input, Limits, OnPoint, SafePoint, Sink, StreamEnd, StreamError,
};

const MAGIC: u32 = 0xFD2F_B528;
const BLOCK_MAX: u64 = 128 * 1024;
const READ_CHUNK: usize = 256 * 1024;
/// Output is handed on once this much has accumulated beyond the window.
const FLUSH_AT: usize = 1 << 20;
/// Frames declaring more output than this are decoded a block at a time instead.
const MAX_WHOLE_FRAME: u64 = 128 << 20;
/// Output of frames decoded ahead but not yet taken, at most (but always two frames).
const AHEAD_BYTES: u64 = 512 << 20;

pub(crate) fn corrupt(why: &str) -> StreamError {
    StreamError::Corrupt(format!("corrupt zstd data: {why}"))
}

/// Positional reads with a buffer.
struct Reader<'a> {
    src: &'a dyn FileHandle,
    len: u64,
    buf: Vec<u8>,
    buf_start: u64,
    pos: u64,
    /// Bytes read from the file at a time.
    chunk: usize,
}

impl<'a> Reader<'a> {
    fn new(src: &'a dyn FileHandle, len: u64, pos: u64, chunk: usize) -> Self {
        Self {
            src,
            len,
            buf: Vec::new(),
            buf_start: 0,
            pos,
            chunk,
        }
    }

    fn take(&mut self, out: &mut [u8]) -> stream::Result<()> {
        let n = out.len() as u64;
        if self.pos + n > self.len {
            return Err(corrupt("unexpected end of file (truncated download?)"));
        }
        let end = self.buf_start + self.buf.len() as u64;
        if self.pos < self.buf_start || self.pos + n > end {
            let want = (self.len - self.pos).min(n.max(self.chunk as u64));
            self.buf
                .resize(usize::try_from(want).expect("<= chunk or n"), 0);
            self.src.read_exact_at(&mut self.buf, self.pos)?;
            self.buf_start = self.pos;
        }
        let at = usize::try_from(self.pos - self.buf_start).expect("in buffer");
        out.copy_from_slice(&self.buf[at..at + out.len()]);
        self.pos += n;
        Ok(())
    }
}

/// The frame being decoded.
#[derive(Debug)]
struct Frame {
    window: u64,
    checksum: Option<Xxh64>,
    content_size: Option<u64>,
    /// Output of this frame so far.
    out: u64,
    ent: Entropy,
    /// Window followed by output not yet handed on (`win[flushed..]`).
    win: Vec<u8>,
    flushed: usize,
    /// Decoded whole: no safe points inside.
    whole: bool,
}

impl Frame {
    fn window_len(&self) -> u64 {
        self.out.min(self.window)
    }

    fn emit(&mut self, sink: &mut Sink<'_>) -> stream::Result<()> {
        if self.flushed < self.win.len() {
            let data = &self.win[self.flushed..];
            if let Some(x) = &mut self.checksum {
                trunc_prof::time("zstd.checksum", || x.update(data));
            }
            sink(data)?;
            self.flushed = self.win.len();
        }
        // Drop history beyond the window, but only once it is as large again, so each byte is
        // moved about once.
        let keep = usize::try_from(self.window).unwrap_or(usize::MAX).max(1);
        if self.win.len() > keep.saturating_add(keep.max(FLUSH_AT)) {
            let drop = self.win.len() - keep;
            self.win.drain(..drop);
            self.flushed = self.win.len();
        }
        Ok(())
    }
}

#[derive(Debug)]
enum Phase {
    /// A frame (or skippable frame) starts here.
    Frames,
    InFrame(Box<Frame>),
}

fn put_desc(b: &mut Vec<u8>, t: Option<&SeqTable>) {
    match t.map(|t| &t.desc) {
        None => b.push(0),
        Some(Desc::Predefined) => b.push(1),
        Some(Desc::Rle(s)) => b.extend_from_slice(&[2, *s]),
        Some(Desc::Counts(log, norm)) => {
            b.extend_from_slice(&[3, *log as u8, norm.len() as u8]);
            for c in norm {
                b.extend_from_slice(&c.to_le_bytes());
            }
        }
    }
}

fn get_desc(f: &mut Fields<'_>, kind: Kind) -> stream::Result<Option<SeqTable>> {
    let bad = stream::bad_cursor;
    let desc = match f.u8().ok_or_else(bad)? {
        0 => return Ok(None),
        1 => Desc::Predefined,
        2 => Desc::Rle(f.u8().ok_or_else(bad)?),
        3 => {
            let log = u32::from(f.u8().ok_or_else(bad)?);
            let n = usize::from(f.u8().ok_or_else(bad)?);
            let mut norm = Vec::with_capacity(n);
            for _ in 0..n {
                norm.push(f.u16().ok_or_else(bad)? as i16);
            }
            Desc::Counts(log, norm)
        }
        _ => return Err(bad()),
    };
    SeqTable::build(kind, desc).map(Some).map_err(|_| bad())
}

/// Cursor bytes: `phase u8 | position u64 | output u64`, then inside a frame `window u64 |
/// checksum u8 (+ XXH64 state) | content size u64 (u64::MAX: absent) | frame output u64 | reps
/// 3×u32 | Huffman weights (count u16 + bytes) | LL, OF, ML table descriptions | window length
/// u64 | window CRC u32`.
fn encode(phase: &Phase, pos: u64, out: u64) -> Vec<u8> {
    let mut b = vec![u8::from(matches!(phase, Phase::InFrame(_)))];
    b.extend_from_slice(&pos.to_le_bytes());
    b.extend_from_slice(&out.to_le_bytes());
    if let Phase::InFrame(f) = phase {
        b.extend_from_slice(&f.window.to_le_bytes());
        match &f.checksum {
            Some(x) => {
                b.push(1);
                b.extend_from_slice(&x.to_bytes());
            }
            None => b.push(0),
        }
        b.extend_from_slice(&f.content_size.unwrap_or(u64::MAX).to_le_bytes());
        b.extend_from_slice(&f.out.to_le_bytes());
        for r in f.ent.reps {
            b.extend_from_slice(&r.to_le_bytes());
        }
        let w = f.ent.huffman.as_ref().map_or(&[][..], |h| &h.weights);
        b.extend_from_slice(&(w.len() as u16).to_le_bytes());
        b.extend_from_slice(w);
        put_desc(&mut b, f.ent.ll.as_ref());
        put_desc(&mut b, f.ent.of.as_ref());
        put_desc(&mut b, f.ent.ml.as_ref());
        let n = usize::try_from(f.window_len()).expect("in memory");
        let window = &f.win[f.win.len() - n..];
        b.extend_from_slice(&(n as u64).to_le_bytes());
        b.extend_from_slice(&stream::window_crc(window).to_le_bytes());
    }
    b
}

fn decode_cursor(
    c: &[u8],
    history: &mut dyn History,
    max_window: u64,
) -> stream::Result<(Phase, u64, u64)> {
    let mut f = Fields::new(c);
    let bad = stream::bad_cursor;
    let tag = f.u8().ok_or_else(bad)?;
    let pos = f.u64().ok_or_else(bad)?;
    let out = f.u64().ok_or_else(bad)?;
    let phase = match tag {
        0 => Phase::Frames,
        1 => {
            let window = f.u64().ok_or_else(bad)?;
            let checksum = match f.u8().ok_or_else(bad)? {
                0 => None,
                1 => Some(Xxh64::from_bytes(&mut f).ok_or_else(bad)?),
                _ => return Err(bad()),
            };
            let cs = f.u64().ok_or_else(bad)?;
            let frame_out = f.u64().ok_or_else(bad)?;
            let reps = [
                f.u32().ok_or_else(bad)?,
                f.u32().ok_or_else(bad)?,
                f.u32().ok_or_else(bad)?,
            ];
            let wn = usize::from(f.u16().ok_or_else(bad)?);
            let weights = f.bytes(wn).ok_or_else(bad)?.to_vec();
            let huffman = if wn == 0 {
                None
            } else {
                Some(Huffman::from_weights(weights).map_err(|_| bad())?)
            };
            let ll = get_desc(&mut f, Kind::Ll)?;
            let of = get_desc(&mut f, Kind::Of)?;
            let ml = get_desc(&mut f, Kind::Ml)?;
            let wlen = f.u64().ok_or_else(bad)?;
            let wcrc = f.u32().ok_or_else(bad)?;
            if window > max_window || wlen != frame_out.min(window) || wlen > out {
                return Err(bad());
            }
            let win = stream::restore_window(history, out, wlen, wcrc)?;
            Phase::InFrame(Box::new(Frame {
                window,
                checksum,
                content_size: (cs != u64::MAX).then_some(cs),
                out: frame_out,
                ent: Entropy {
                    huffman,
                    ll,
                    of,
                    ml,
                    reps,
                },
                flushed: win.len(),
                win,
                whole: false,
            }))
        }
        _ => return Err(bad()),
    };
    if !f.done() {
        return Err(bad());
    }
    Ok((phase, pos, out))
}

/// Parse a frame header after its magic number.
fn frame_header(rd: &mut Reader<'_>, max_window: u64) -> stream::Result<Frame> {
    let mut d = [0u8; 1];
    rd.take(&mut d)?;
    let d = d[0];
    let fcs_code = d >> 6;
    let single = d & 0x20 != 0;
    if d & 0x08 != 0 {
        return Err(corrupt("reserved frame header bit set"));
    }
    let checksum = d & 0x04 != 0;
    let dict_len = [0usize, 1, 2, 4][usize::from(d & 3)];
    let mut window = 0u64;
    if !single {
        let mut w = [0u8; 1];
        rd.take(&mut w)?;
        let exp = u32::from(w[0] >> 3);
        let mant = u64::from(w[0] & 7);
        let base = 1u64 << (10 + exp);
        window = base + base / 8 * mant;
    }
    let mut dict = [0u8; 4];
    rd.take(&mut dict[..dict_len])?;
    if u32::from_le_bytes(dict) != 0 {
        return Err(StreamError::Unsupported(
            "zstd frames that need a dictionary are not supported".into(),
        ));
    }
    let fcs_len = match fcs_code {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut fcs = [0u8; 8];
    rd.take(&mut fcs[..fcs_len])?;
    let content_size = match fcs_len {
        0 => None,
        2 => Some(u64::from(u16::from_le_bytes([fcs[0], fcs[1]])) + 256),
        _ => Some(u64::from_le_bytes(fcs)),
    };
    if single {
        window = content_size.expect("single-segment frames have a size");
    }
    if window > max_window {
        return Err(StreamError::Unsupported(format!(
            "zstd window of {} MiB exceeds the window limit of {} MiB (--max-window)",
            window >> 20,
            max_window >> 20
        )));
    }
    Ok(Frame {
        window,
        checksum: checksum.then(Xxh64::new),
        content_size,
        out: 0,
        ent: Entropy {
            reps: [1, 4, 8],
            ..Entropy::default()
        },
        win: Vec::new(),
        flushed: 0,
        whole: false,
    })
}

/// Decode the frame's next block (`out` bytes having been produced before it, at most `max_out`
/// allowed). Returns the bytes produced and whether the frame ended (its checksum and size then
/// checked).
fn block_step(
    rd: &mut Reader<'_>,
    f: &mut Frame,
    data: &mut Vec<u8>,
    (out, max_out): (u64, u64),
    sink: &mut Sink<'_>,
) -> stream::Result<(u64, bool)> {
    let mut h = [0u8; 3];
    rd.take(&mut h)?;
    let h = u32::from(h[0]) | (u32::from(h[1]) << 8) | (u32::from(h[2]) << 16);
    let last = h & 1 != 0;
    let kind = (h >> 1) & 3;
    let size = u64::from(h >> 3);
    let max_block = f.window.clamp(1, BLOCK_MAX);
    if size > max_block {
        return Err(corrupt("block larger than allowed"));
    }
    let size = usize::try_from(size).expect("<= 128 KiB");
    let mut prof = trunc_prof::span("zstd.block");
    let before = f.win.len();
    match kind {
        0 => {
            data.resize(size, 0);
            rd.take(data)?;
            f.win.extend_from_slice(data);
        }
        1 => {
            let mut b = [0u8; 1];
            rd.take(&mut b)?;
            f.win.resize(f.win.len() + size, b[0]);
        }
        2 => {
            data.resize(size, 0);
            rd.take(data)?;
            block::decompress(
                data,
                &mut f.ent,
                &mut f.win,
                f.out,
                f.window,
                usize::try_from(max_block).expect("<= 128 KiB"),
            )?;
        }
        _ => return Err(corrupt("reserved block type")),
    }
    let n = (f.win.len() - before) as u64;
    prof.add_bytes(n);
    drop(prof);
    f.out += n;
    if out + n > max_out {
        return Err(StreamError::Corrupt(format!(
            "decoded more than the expected {max_out} bytes"
        )));
    }
    if f.content_size.is_some_and(|c| f.out > c) {
        return Err(corrupt("frame larger than its declared content size"));
    }
    if f.win.len() - f.flushed >= FLUSH_AT {
        f.emit(sink)?;
    }
    if last {
        f.emit(sink)?;
        if let Some(x) = &f.checksum {
            let mut c = [0u8; 4];
            rd.take(&mut c)?;
            #[allow(clippy::cast_possible_truncation)] // the low 32 bits are stored
            let want = x.finish() as u32;
            if u32::from_le_bytes(c) != want {
                return Err(corrupt("content checksum mismatch"));
            }
        }
        if f.content_size.is_some_and(|c| f.out != c) {
            return Err(corrupt("frame smaller than its declared content size"));
        }
    }
    Ok((n, last))
}

/// A frame decoded whole.
#[derive(Clone, Copy, Debug)]
struct Job {
    start: u64,
    size: u64,
}

/// A frame decoded on a worker thread.
struct Decoded {
    out: Vec<u8>,
    /// Position just past the frame.
    end: u64,
}

fn decode_frame(
    src: &dyn FileHandle,
    len: u64,
    job: Job,
    max_window: u64,
) -> stream::Result<Decoded> {
    let mut rd = Reader::new(src, len, job.start, READ_CHUNK);
    let mut m = [0u8; 4];
    rd.take(&mut m)?;
    if u32::from_le_bytes(m) != MAGIC {
        return Err(corrupt("expected a frame"));
    }
    let mut f = frame_header(&mut rd, max_window)?;
    f.win.reserve(usize::try_from(job.size).unwrap_or(0));
    let mut v = Vec::new();
    let mut sink = |d: &[u8]| -> stream::Result<()> {
        if v.is_empty() {
            v.reserve(usize::try_from(job.size).unwrap_or(0));
        }
        v.extend_from_slice(d);
        Ok(())
    };
    let mut data = Vec::new();
    while !block_step(&mut rd, &mut f, &mut data, (0, u64::MAX), &mut sink)?.1 {}
    let end = rd.pos;
    Ok(Decoded { out: v, end })
}

/// Read a block header at `rd.pos` and skip the block; true if it was the frame's last.
fn skip_block(rd: &mut Reader<'_>, window: u64) -> Option<bool> {
    let mut h = [0u8; 3];
    rd.take(&mut h).ok()?;
    let h = u32::from(h[0]) | (u32::from(h[1]) << 8) | (u32::from(h[2]) << 16);
    let size = u64::from(h >> 3);
    let stored = match (h >> 1) & 3 {
        0 | 2 => size,
        1 => 1,
        _ => return None,
    };
    if size > window.clamp(1, BLOCK_MAX) || rd.pos + stored > rd.len {
        return None;
    }
    rd.pos += stored;
    Some(h & 1 != 0)
}

/// The frames from `pos` on that are decoded whole, found from frame and block headers alone
/// (`inside`: `pos` is a block boundary in this frame). Stops quietly at anything unexpected;
/// decoding then checks everything as usual. Also stops at a frame whose header already rules
/// it out (it does not declare a small enough size), so a large frame is not walked block by
/// block for nothing; the walk resumes after it (the returned position: once decoding is past
/// it).
fn whole_frames(
    src: &dyn FileHandle,
    len: u64,
    pos: u64,
    inside: Option<&Frame>,
    max_window: u64,
) -> (Vec<Job>, Option<u64>) {
    let _prof = trunc_prof::span("zstd.frame_scan");
    // Small reads: only headers are looked at.
    let mut rd = Reader::new(src, len, pos, 4096);
    let mut jobs = Vec::new();
    let finish = |rd: &mut Reader<'_>, window: u64, checksum: bool| -> Option<()> {
        while !skip_block(rd, window)? {}
        rd.pos += if checksum { 4 } else { 0 };
        (rd.pos <= rd.len).then_some(())
    };
    let small = |f: &Frame| f.content_size.is_some_and(|c| c <= MAX_WHOLE_FRAME);
    if let Some(f) = inside {
        if !small(f) {
            return (jobs, Some(pos));
        }
        if finish(&mut rd, f.window, f.checksum.is_some()).is_none() {
            return (jobs, None);
        }
    }
    while rd.pos + 4 <= len {
        let start = rd.pos;
        let mut m = [0u8; 4];
        if rd.take(&mut m).is_err() {
            break;
        }
        let magic = u32::from_le_bytes(m);
        if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
            let mut s = [0u8; 4];
            if rd.take(&mut s).is_err() {
                break;
            }
            rd.pos += u64::from(u32::from_le_bytes(s));
            continue;
        }
        if magic != MAGIC {
            break;
        }
        let Ok(f) = frame_header(&mut rd, max_window) else {
            break;
        };
        if !small(&f) {
            return (jobs, Some(start));
        }
        if finish(&mut rd, f.window, f.checksum.is_some()).is_none() {
            break;
        }
        if rd.pos < len {
            jobs.push(Job {
                start,
                size: f.content_size.unwrap_or(0),
            });
        }
    }
    (jobs, None)
}

/// Decoding progress carried across rounds of [`drive`].
struct Run {
    pos: u64,
    out: u64,
    since: u64,
    units: u32,
    first: bool,
}

/// Decode a zstd file (one or more frames). Safe points are block boundaries (outside frames
/// decoded whole) and frame boundaries once `every` bytes have been produced since the previous
/// one.
pub fn decode(
    input: Input<'_>,
    start: Option<&[u8]>,
    history: &mut dyn History,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let Input { src, len } = input;
    let (phase, pos, out) = match start {
        Some(c) => decode_cursor(c, history, limits.max_window)?,
        None => (Phase::Frames, 0, 0),
    };
    let mut phase = Some(phase);
    let mut run = Run {
        pos,
        out,
        since: 0,
        units: 0,
        first: start.is_none(),
    };
    // Without safe points or threads, frames decoded whole would change nothing.
    let walk = every > 0 || limits.workers() > 1;
    loop {
        let inside = match &phase {
            Some(Phase::InFrame(f)) => Some(&**f),
            _ => None,
        };
        let (jobs, stop) = if walk {
            whole_frames(src, len, run.pos, inside, limits.max_window)
        } else {
            (Vec::new(), None)
        };
        let threads = limits.workers().min(jobs.len());
        let biggest = jobs.iter().map(|j| j.size).max().unwrap_or(0).max(1);
        let ahead = usize::try_from(AHEAD_BYTES / biggest)
            .unwrap_or(usize::MAX)
            .clamp(2, threads + 2);
        let work = |k: usize| decode_frame(src, len, jobs[k], limits.max_window);
        let phase_now = phase.take().unwrap_or(Phase::Frames);
        let end = stream::with_ahead(jobs.len(), threads.min(ahead), ahead, &work, |pre| {
            drive(
                phase_now, &mut run, stop, src, len, &jobs, pre, limits, every, sink, on_point,
            )
        })?;
        if let Some(end) = end {
            return Ok(end);
        }
    }
}

/// The decoding loop. Frames decoded whole come from `pre` where it has them. Returns `None`
/// on reaching a frame boundary past `stop`, for the frames after it to be looked at.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn drive(
    mut phase: Phase,
    run: &mut Run,
    stop: Option<u64>,
    src: &dyn FileHandle,
    len: u64,
    jobs: &[Job],
    pre: Option<&stream::Ahead<'_, stream::Result<Decoded>>>,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<Option<StreamEnd>> {
    let mut rd = Reader::new(src, len, run.pos, READ_CHUNK);
    let Run {
        mut out,
        mut since,
        mut units,
        mut first,
        ..
    } = *run;
    let mut data = Vec::new();
    loop {
        let inside_whole = matches!(&phase, Phase::InFrame(f) if f.whole);
        if every > 0 && since >= every && !inside_whole {
            if let Phase::InFrame(f) = &mut phase {
                f.emit(sink)?;
            }
            since = 0;
            let cursor = encode(&phase, rd.pos, out);
            on_point(SafePoint {
                cursor: &cursor,
                out,
                free_below: rd.pos,
            })?;
        }
        match &mut phase {
            Phase::Frames => {
                let at = rd.pos;
                if rd.pos == len && !first {
                    return Ok(Some(StreamEnd {
                        out_len: out,
                        units,
                    }));
                }
                if stop.is_some_and(|s| at > s) {
                    *run = Run {
                        pos: at,
                        out,
                        since,
                        units,
                        first,
                    };
                    return Ok(None);
                }
                let mut m = [0u8; 4];
                if rd.pos + 4 > len {
                    return Err(if first {
                        StreamError::Format("not a zstd file".into())
                    } else {
                        corrupt("data after a frame is not another frame")
                    });
                }
                rd.take(&mut m)?;
                let magic = u32::from_le_bytes(m);
                if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
                    let mut s = [0u8; 4];
                    rd.take(&mut s)?;
                    let skip = u64::from(u32::from_le_bytes(s));
                    if rd.pos + skip > len {
                        return Err(corrupt("skippable frame runs past the end of the file"));
                    }
                    rd.pos += skip;
                    first = false;
                    continue;
                }
                if magic != MAGIC {
                    return Err(if first {
                        StreamError::Format("not a zstd file".into())
                    } else {
                        corrupt("data after a frame is not another frame")
                    });
                }
                first = false;
                let k = jobs.binary_search_by_key(&at, |j| j.start).ok();
                if let Some(d) =
                    k.and_then(|k| pre_decoded(pre, k, limits.max_out.saturating_sub(out)))
                {
                    sink(&d.out)?;
                    let n = d.out.len() as u64;
                    out += n;
                    since += n;
                    units += 1;
                    rd = Reader::new(src, len, d.end, READ_CHUNK);
                    continue;
                }
                let mut f = frame_header(&mut rd, limits.max_window)?;
                f.whole = k.is_some();
                phase = Phase::InFrame(Box::new(f));
            }
            Phase::InFrame(f) => {
                let (n, last) = block_step(&mut rd, f, &mut data, (out, limits.max_out), sink)?;
                out += n;
                since += n;
                if last {
                    units += 1;
                    phase = Phase::Frames;
                }
            }
        }
    }
}

/// Frame `k` as a worker decoded it, if it fits in `room`. Anything else, including a failure,
/// leaves the frame to the decoding loop, which then reports any error the same way as without
/// threads.
fn pre_decoded(
    pre: Option<&stream::Ahead<'_, stream::Result<Decoded>>>,
    k: usize,
    room: u64,
) -> Option<Decoded> {
    let d = pre?.get(k).ok()?;
    (d.out.len() as u64 <= room).then_some(d)
}

//! xz decoding, resumable at LZMA2 chunk, block and stream boundaries.
//!
//! An `.xz` file is one or more streams (with zero padding between them). A stream is a header,
//! blocks, an index listing every block's sizes, and a footer. Each block has a header naming
//! its filters, LZMA2 data, padding to four bytes and a check (none, CRC-32, CRC-64 or SHA-256)
//! of its output. Only the LZMA2 filter is supported; files using BCJ or delta filters (rare in
//! tarballs) are refused.
//!
//! Everything a safe point needs is small except the LZMA2 dictionary, which is read back
//! through [`History`] on resume and checked against a CRC-32 in the cursor.
//!
//! Blocks are independent, and a stream's index (at its end) gives every block's sizes, so
//! streams with several blocks (what `xz -T` writes) are decoded a block per thread. Safe points
//! in such streams are at block boundaries only (no window to restore), whatever the thread
//! count: the choice depends on the file alone, so the scan, the consume pass and a resume agree.

use trunc_fs::FileHandle;

use crate::checks::{Crc64, Sha256};
use crate::lzma::Lzma2;
use crate::stream::{
    self, Fields, History, Input, Limits, OnPoint, SafePoint, Sink, StreamEnd, StreamError,
};

const MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0];
const FOOTER_MAGIC: [u8; 2] = *b"YZ";
const FILTER_LZMA2: u64 = 0x21;
const READ_CHUNK: usize = 256 * 1024;
/// Streams with a block producing more than this are decoded one chunk at a time instead.
const MAX_WHOLE_BLOCK: u64 = 256 << 20;
/// Output of blocks decoded ahead but not yet taken, at most (but always two blocks).
const AHEAD_BYTES: u64 = 512 << 20;

fn corrupt(at: u64, why: &str) -> StreamError {
    StreamError::Corrupt(format!("corrupt xz data near byte {at}: {why}"))
}

/// Positional reads with a buffer.
struct Reader<'a> {
    src: &'a dyn FileHandle,
    len: u64,
    buf: Vec<u8>,
    buf_start: u64,
    pos: u64,
}

impl<'a> Reader<'a> {
    fn new(src: &'a dyn FileHandle, len: u64, pos: u64) -> Self {
        Self {
            src,
            len,
            buf: Vec::new(),
            buf_start: 0,
            pos,
        }
    }

    fn take(&mut self, out: &mut [u8]) -> stream::Result<()> {
        let n = out.len() as u64;
        if self.pos + n > self.len {
            return Err(corrupt(
                self.pos,
                "unexpected end of file (truncated download?)",
            ));
        }
        let end = self.buf_start + self.buf.len() as u64;
        if self.pos < self.buf_start || self.pos + n > end {
            let want = (self.len - self.pos).min(n.max(READ_CHUNK as u64));
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

    fn u8(&mut self) -> stream::Result<u8> {
        let mut b = [0u8; 1];
        self.take(&mut b)?;
        Ok(b[0])
    }

    fn peek(&mut self) -> stream::Result<u8> {
        let b = self.u8()?;
        self.pos -= 1;
        Ok(b)
    }
}

/// Read a variable-length integer from `b` at `*p`.
fn vli(b: &[u8], p: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let c = *b.get(*p)?;
        *p += 1;
        if i > 0 && c == 0 {
            return None;
        }
        v |= u64::from(c & 0x7F) << (7 * i);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Read a variable-length integer from the file, feeding its bytes to `crc`.
fn vli_from(rd: &mut Reader<'_>, crc: &mut crc32fast::Hasher) -> stream::Result<u64> {
    let at = rd.pos;
    let mut v = 0u64;
    for i in 0..9 {
        let c = rd.u8()?;
        crc.update(&[c]);
        if i > 0 && c == 0 {
            break;
        }
        v |= u64::from(c & 0x7F) << (7 * i);
        if c & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(corrupt(at, "bad variable-length integer"))
}

/// A block's integrity check.
#[derive(Clone, Debug)]
enum Check {
    None,
    Crc32(crc32fast::Hasher),
    Crc64(Crc64),
    Sha256(Box<Sha256>),
}

impl Check {
    fn new(kind: u8) -> Self {
        match kind {
            1 => Check::Crc32(crc32fast::Hasher::new()),
            4 => Check::Crc64(Crc64::new()),
            10 => Check::Sha256(Box::default()),
            _ => Check::None,
        }
    }

    fn size(kind: u8) -> usize {
        match kind {
            1 => 4,
            4 => 8,
            10 => 32,
            _ => 0,
        }
    }

    fn update(&mut self, b: &[u8]) {
        match self {
            Check::None => {}
            Check::Crc32(h) => h.update(b),
            Check::Crc64(h) => h.update(b),
            Check::Sha256(h) => h.update(b),
        }
    }

    fn finish(&self) -> Vec<u8> {
        match self {
            Check::None => Vec::new(),
            Check::Crc32(h) => h.clone().finalize().to_le_bytes().to_vec(),
            Check::Crc64(h) => h.finish().to_le_bytes().to_vec(),
            Check::Sha256(h) => h.finish().to_vec(),
        }
    }

    fn encode(&self, b: &mut Vec<u8>) {
        match self {
            Check::None => {}
            Check::Crc32(h) => b.extend_from_slice(&h.clone().finalize().to_le_bytes()),
            Check::Crc64(h) => b.extend_from_slice(&h.to_bytes()),
            Check::Sha256(h) => b.extend_from_slice(&h.to_bytes()),
        }
    }

    fn decode(kind: u8, f: &mut Fields<'_>) -> Option<Self> {
        Some(match kind {
            1 => Check::Crc32(crc32fast::Hasher::new_with_initial(f.u32()?)),
            4 => Check::Crc64(Crc64::from_bytes(f.bytes(8)?.try_into().ok()?)),
            10 => Check::Sha256(Box::new(Sha256::from_bytes(f)?)),
            _ => Check::None,
        })
    }
}

/// What the index must list, accumulated from the blocks decoded.
#[derive(Clone, Debug)]
struct Records {
    count: u64,
    unpadded: u64,
    uncompressed: u64,
    crc: crc32fast::Hasher,
}

impl Records {
    fn new() -> Self {
        Self {
            count: 0,
            unpadded: 0,
            uncompressed: 0,
            crc: crc32fast::Hasher::new(),
        }
    }

    fn add(&mut self, unpadded: u64, uncompressed: u64) {
        self.count += 1;
        self.unpadded = self.unpadded.wrapping_add(unpadded);
        self.uncompressed = self.uncompressed.wrapping_add(uncompressed);
        self.crc.update(&unpadded.to_le_bytes());
        self.crc.update(&uncompressed.to_le_bytes());
    }

    fn same(&self, o: &Self) -> bool {
        (self.count, self.unpadded, self.uncompressed) == (o.count, o.unpadded, o.uncompressed)
            && self.crc.clone().finalize() == o.crc.clone().finalize()
    }
}

/// The block being decoded.
#[derive(Debug)]
struct Block {
    start: u64,
    header_size: u64,
    declared_compressed: Option<u64>,
    declared_uncompressed: Option<u64>,
    out: u64,
    check: Check,
    lz: Lzma2,
}

/// Where decoding is.
#[derive(Debug)]
enum Phase {
    /// A stream header is next.
    Stream,
    /// A block header or the index is next.
    Blocks,
    /// Inside a block, at an LZMA2 chunk boundary.
    InBlock(Box<Block>),
}

/// Cursor bytes: `phase u8 | position u64 | output u64`, then for phases 1 to 3 `check type u8
/// | records (count, unpadded, uncompressed u64; crc u32)`, then for phase 2 `block start u64 |
/// header size u64 | declared compressed u64 | declared uncompressed u64 (u64::MAX: absent) |
/// block output u64 | check state | LZMA2 state | window length u64 | window CRC u32`. Phase 3 is
/// phase 1 in a stream decoded whole blocks at a time.
fn encode(
    phase: &Phase,
    pos: u64,
    out: u64,
    check_kind: u8,
    rec: &Records,
    whole: bool,
) -> Vec<u8> {
    let tag = match phase {
        Phase::Stream => 0u8,
        Phase::Blocks if whole => 3,
        Phase::Blocks => 1,
        Phase::InBlock(_) => 2,
    };
    let mut b = vec![tag];
    b.extend_from_slice(&pos.to_le_bytes());
    b.extend_from_slice(&out.to_le_bytes());
    if tag == 0 {
        return b;
    }
    b.push(check_kind);
    for v in [rec.count, rec.unpadded, rec.uncompressed] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&rec.crc.clone().finalize().to_le_bytes());
    if let Phase::InBlock(blk) = phase {
        for v in [
            blk.start,
            blk.header_size,
            blk.declared_compressed.unwrap_or(u64::MAX),
            blk.declared_uncompressed.unwrap_or(u64::MAX),
            blk.out,
        ] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        blk.check.encode(&mut b);
        blk.lz.encode(&mut b);
        let w = blk.lz.window();
        b.extend_from_slice(&(w.len() as u64).to_le_bytes());
        b.extend_from_slice(&stream::window_crc(w).to_le_bytes());
    }
    b
}

struct Restored {
    phase: Phase,
    pos: u64,
    out: u64,
    check_kind: u8,
    rec: Records,
    /// The current stream is decoded whole blocks at a time (safe points between blocks only).
    whole: bool,
}

fn decode_cursor(c: &[u8], history: &mut dyn History, max_window: u64) -> stream::Result<Restored> {
    let mut f = Fields::new(c);
    let bad = stream::bad_cursor;
    let tag = f.u8().ok_or_else(bad)?;
    let pos = f.u64().ok_or_else(bad)?;
    let out = f.u64().ok_or_else(bad)?;
    if tag == 0 {
        return if f.done() {
            Ok(Restored {
                phase: Phase::Stream,
                pos,
                out,
                check_kind: 0,
                rec: Records::new(),
                whole: false,
            })
        } else {
            Err(bad())
        };
    }
    let check_kind = f.u8().ok_or_else(bad)?;
    let (count, unpadded, uncompressed, crc) = (
        f.u64().ok_or_else(bad)?,
        f.u64().ok_or_else(bad)?,
        f.u64().ok_or_else(bad)?,
        f.u32().ok_or_else(bad)?,
    );
    let rec = Records {
        count,
        unpadded,
        uncompressed,
        crc: crc32fast::Hasher::new_with_initial(crc),
    };
    let phase = match tag {
        1 | 3 => Phase::Blocks,
        2 => {
            let mut v = [0u64; 5];
            for x in &mut v {
                *x = f.u64().ok_or_else(bad)?;
            }
            let check = Check::decode(check_kind, &mut f).ok_or_else(bad)?;
            let mut lz = Lzma2::decode(&mut f).ok_or_else(bad)?;
            let wlen = f.u64().ok_or_else(bad)?;
            let wcrc = f.u32().ok_or_else(bad)?;
            if wlen != lz.window_len() || wlen > max_window || wlen > out {
                return Err(bad());
            }
            lz.restore(stream::restore_window(history, out, wlen, wcrc)?);
            let opt = |x: u64| (x != u64::MAX).then_some(x);
            Phase::InBlock(Box::new(Block {
                start: v[0],
                header_size: v[1],
                declared_compressed: opt(v[2]),
                declared_uncompressed: opt(v[3]),
                out: v[4],
                check,
                lz,
            }))
        }
        _ => return Err(bad()),
    };
    if !f.done() {
        return Err(bad());
    }
    Ok(Restored {
        phase,
        pos,
        out,
        check_kind,
        rec,
        whole: tag == 3,
    })
}

/// Parse a block header whose first byte (`size_byte`, non-zero) was just read at `start`.
fn block_header(
    rd: &mut Reader<'_>,
    start: u64,
    size_byte: u8,
    check_kind: u8,
    max_window: u64,
) -> stream::Result<Block> {
    let size = (usize::from(size_byte) + 1) * 4;
    let mut h = vec![0u8; size];
    h[0] = size_byte;
    rd.take(&mut h[1..])?;
    let stored = u32::from_le_bytes(h[size - 4..].try_into().expect("4"));
    if crc32fast::hash(&h[..size - 4]) != stored {
        return Err(corrupt(start, "block header CRC mismatch"));
    }
    let flags = h[1];
    if flags & 0x3C != 0 {
        return Err(StreamError::Unsupported(format!(
            "xz block at byte {start} uses reserved flags"
        )));
    }
    let body = &h[..size - 4];
    let mut p = 2usize;
    let bad = || corrupt(start, "bad block header");
    let declared_compressed = if flags & 0x40 != 0 {
        Some(vli(body, &mut p).ok_or_else(bad)?)
    } else {
        None
    };
    let declared_uncompressed = if flags & 0x80 != 0 {
        Some(vli(body, &mut p).ok_or_else(bad)?)
    } else {
        None
    };
    let filters = usize::from(flags & 3) + 1;
    let mut dict = None;
    for _ in 0..filters {
        let id = vli(body, &mut p).ok_or_else(bad)?;
        let plen = usize::try_from(vli(body, &mut p).ok_or_else(bad)?).map_err(|_| bad())?;
        let props = body
            .get(p..p.checked_add(plen).ok_or_else(bad)?)
            .ok_or_else(bad)?;
        p += plen;
        if id != FILTER_LZMA2 || filters != 1 {
            return Err(StreamError::Unsupported(format!(
                "xz filter 0x{id:x} is not supported (only LZMA2; BCJ and delta filters are not)"
            )));
        }
        if plen != 1 || props[0] > 40 {
            return Err(bad());
        }
        let bits = u32::from(props[0]);
        dict = Some(if bits == 40 {
            u32::MAX
        } else {
            (2 | (bits & 1)) << (bits / 2 + 11)
        });
    }
    if body[p..].iter().any(|&c| c != 0) {
        return Err(bad());
    }
    let dict = dict.ok_or_else(bad)?;
    if u64::from(dict) > max_window {
        return Err(StreamError::Unsupported(format!(
            "xz dictionary of {} MiB exceeds the window limit of {} MiB (--max-window)",
            u64::from(dict) >> 20,
            max_window >> 20
        )));
    }
    Ok(Block {
        start,
        header_size: size as u64,
        declared_compressed,
        declared_uncompressed,
        out: 0,
        check: Check::new(check_kind),
        lz: Lzma2::new(dict),
    })
}

/// Hand the block's pending output to the sink and the check.
fn emit(blk: &mut Block, sink: &mut Sink<'_>) -> stream::Result<()> {
    let lz = &mut blk.lz;
    if lz.flushed < lz.win.len() {
        let data = &lz.win[lz.flushed..];
        trunc_prof::time("xz.check", || blk.check.update(data));
        sink(data)?;
        lz.flushed = lz.win.len();
    }
    lz.trim();
    Ok(())
}

/// What one step inside a block did.
enum Step {
    /// Decoded an LZMA2 chunk of this many bytes.
    Chunk(u64),
    /// Reached the block's end and checked it; its unpadded size.
    End(u64),
}

/// Decode the block's next LZMA2 chunk (allowing `room` more bytes of output), or finish it:
/// sizes, padding and check.
fn block_step(
    rd: &mut Reader<'_>,
    blk: &mut Block,
    chunk: &mut Vec<u8>,
    room: u64,
    check_kind: u8,
    sink: &mut Sink<'_>,
) -> stream::Result<Step> {
    let at = rd.pos;
    let c = rd.u8()?;
    let Some(more) = blk.lz.control(c).map_err(|e| at_err(e, at))? else {
        // End of the block's LZMA2 data.
        emit(blk, sink)?;
        let compressed = rd.pos - blk.start - blk.header_size;
        if blk.declared_compressed.is_some_and(|d| d != compressed)
            || blk.declared_uncompressed.is_some_and(|d| d != blk.out)
        {
            return Err(corrupt(blk.start, "block sizes differ from its header"));
        }
        while (rd.pos - blk.start) % 4 != 0 {
            if rd.u8()? != 0 {
                return Err(corrupt(rd.pos, "bad block padding"));
            }
        }
        let mut stored = vec![0u8; Check::size(check_kind)];
        rd.take(&mut stored)?;
        if stored != blk.check.finish() {
            return Err(corrupt(blk.start, "block check mismatch"));
        }
        return Ok(Step::End(
            blk.header_size + compressed + stored.len() as u64,
        ));
    };
    let mut head = vec![c; 1 + more];
    rd.take(&mut head[1..])?;
    let packed = if c >= 0x80 {
        usize::from(u16::from_be_bytes([head[3], head[4]])) + 1
    } else {
        usize::from(u16::from_be_bytes([head[1], head[2]])) + 1
    };
    chunk.resize(packed, 0);
    rd.take(chunk)?;
    let mut prof = trunc_prof::span("xz.chunk");
    let n = blk
        .lz
        .chunk(&head, chunk, room)
        .map_err(|e| at_err(e, at))? as u64;
    prof.add_bytes(n);
    drop(prof);
    blk.out += n;
    if blk.declared_uncompressed.is_some_and(|d| blk.out > d) {
        return Err(corrupt(blk.start, "block larger than its header says"));
    }
    if blk.lz.win.len() - blk.lz.flushed >= crate::lzma::FLUSH_AT {
        emit(blk, sink)?;
    }
    Ok(Step::Chunk(n))
}

/// A block listed in a stream's index, to be decoded on its own.
#[derive(Clone, Copy, Debug)]
struct Job {
    start: u64,
    check_kind: u8,
    uncompressed: u64,
}

/// A block decoded on a worker thread.
struct Decoded {
    out: Vec<u8>,
    unpadded: u64,
    /// Position just past the block.
    end: u64,
}

fn decode_block(
    src: &dyn FileHandle,
    len: u64,
    job: Job,
    max_window: u64,
) -> stream::Result<Decoded> {
    let mut rd = Reader::new(src, len, job.start);
    let b = rd.u8()?;
    if b == 0 {
        return Err(corrupt(job.start, "expected a block"));
    }
    let mut blk = block_header(&mut rd, job.start, b, job.check_kind, max_window)?;
    let mut v = Vec::with_capacity(usize::try_from(job.uncompressed).unwrap_or(0));
    let mut sink = |d: &[u8]| -> stream::Result<()> {
        v.extend_from_slice(d);
        Ok(())
    };
    let mut chunk = Vec::new();
    let unpadded = loop {
        if let Step::End(u) = block_step(
            &mut rd,
            &mut blk,
            &mut chunk,
            u64::MAX,
            job.check_kind,
            &mut sink,
        )? {
            break u;
        }
    };
    let end = rd.pos;
    Ok(Decoded {
        out: v,
        unpadded,
        end,
    })
}

/// The streams of the file whose blocks can be decoded whole: read from the end (footer, then
/// index) back to the stream holding `from`. Returns the start of each stream found (whether it
/// qualifies or not) and the blocks of those that do, in file order. Stops quietly at anything
/// unexpected; decoding then checks everything as usual.
fn whole_block_streams(
    src: &dyn FileHandle,
    len: u64,
    from: u64,
) -> (std::collections::HashMap<u64, bool>, Vec<Job>) {
    let _prof = trunc_prof::span("xz.index_scan");
    let mut starts = std::collections::HashMap::new();
    let mut streams: Vec<Vec<Job>> = Vec::new();
    let mut end = len;
    let read = |at: u64, n: usize| -> Option<Vec<u8>> {
        let mut b = vec![0u8; n];
        src.read_exact_at(&mut b, at).ok()?;
        Some(b)
    };
    'walk: loop {
        // Stream padding: zeros in multiples of four.
        let mut pad = 0u64;
        while end >= 4 && end > from {
            let w = match read(end - 4, 4) {
                Some(w) => w,
                None => break 'walk,
            };
            if w != [0; 4] {
                break;
            }
            end -= 4;
            pad += 4;
            if pad > 1 << 20 {
                break 'walk;
            }
        }
        if end < 24 || end <= from {
            break;
        }
        let Some(f) = read(end - 12, 12) else { break };
        let check_kind = f[9];
        if f[10..] != FOOTER_MAGIC
            || f[8] != 0
            || !matches!(check_kind, 0 | 1 | 4 | 10)
            || crc32fast::hash(&f[4..10]) != u32::from_le_bytes(f[..4].try_into().expect("4"))
        {
            break;
        }
        let index_size = (u64::from(u32::from_le_bytes(f[4..8].try_into().expect("4"))) + 1) * 4;
        if index_size > 64 << 20 || index_size + 24 > end {
            break;
        }
        let index_start = end - 12 - index_size;
        let Some(ix) = read(index_start, usize::try_from(index_size).expect("<= 64 MiB")) else {
            break;
        };
        let body = &ix[..ix.len() - 4];
        if ix[0] != 0
            || crc32fast::hash(body)
                != u32::from_le_bytes(ix[ix.len() - 4..].try_into().expect("4"))
        {
            break;
        }
        let mut p = 1usize;
        let Some(count) = vli(body, &mut p) else {
            break;
        };
        let mut blocks = Vec::new();
        let mut total = 0u64;
        for _ in 0..count {
            let (Some(unpadded), Some(uncompressed)) = (vli(body, &mut p), vli(body, &mut p))
            else {
                break 'walk;
            };
            if unpadded < 5 {
                break 'walk;
            }
            let Some(t) = unpadded
                .checked_add(3)
                .map(|u| u & !3)
                .and_then(|u| total.checked_add(u))
            else {
                break 'walk;
            };
            blocks.push((total, uncompressed));
            total = t;
        }
        if body[p..].iter().any(|&c| c != 0) || total + 12 > index_start {
            break;
        }
        let start = index_start - total - 12;
        let whole = blocks.len() >= 2 && blocks.iter().all(|&(_, u)| u <= MAX_WHOLE_BLOCK);
        starts.insert(start, whole);
        if whole {
            streams.push(
                blocks
                    .iter()
                    .map(|&(off, uncompressed)| Job {
                        start: start + 12 + off,
                        check_kind,
                        uncompressed,
                    })
                    .collect(),
            );
        }
        if start <= from {
            break;
        }
        end = start;
    }
    streams.reverse();
    (starts, streams.into_iter().flatten().collect())
}

/// Decode an xz file (one or more streams). Safe points are LZMA2 chunk boundaries (in
/// single-block streams), block boundaries and stream boundaries once `every` bytes have been
/// produced since the last one.
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
    let st = match start {
        Some(c) => decode_cursor(c, history, limits.max_window)?,
        None => Restored {
            phase: Phase::Stream,
            pos: 0,
            out: 0,
            check_kind: 0,
            rec: Records::new(),
            whole: false,
        },
    };
    let (starts, jobs) = whole_block_streams(src, len, st.pos);
    let threads = limits.workers().min(jobs.len());
    let biggest = jobs
        .iter()
        .map(|j| j.uncompressed)
        .max()
        .unwrap_or(0)
        .max(1);
    let ahead = usize::try_from(AHEAD_BYTES / biggest)
        .unwrap_or(usize::MAX)
        .clamp(2, threads + 2);
    let work = |k: usize| decode_block(src, len, jobs[k], limits.max_window);
    stream::with_ahead(jobs.len(), threads.min(ahead), ahead, &work, |pre| {
        drive(
            src,
            len,
            st,
            start.is_none(),
            &starts,
            &jobs,
            pre,
            limits,
            every,
            sink,
            on_point,
        )
    })
}

/// The decoding loop. Blocks of whole-block streams come from `pre` where it has them.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn drive(
    src: &dyn FileHandle,
    len: u64,
    mut st: Restored,
    mut first: bool,
    starts: &std::collections::HashMap<u64, bool>,
    jobs: &[Job],
    pre: Option<&stream::Ahead<'_, stream::Result<Decoded>>>,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let mut rd = Reader::new(src, len, st.pos);
    let mut since = 0u64;
    let mut units = 0u32;
    let mut out = st.out;
    let mut chunk = Vec::new();
    loop {
        // A safe point here is wherever the loop is between steps.
        let inside_whole = st.whole && matches!(st.phase, Phase::InBlock(_));
        if every > 0 && since >= every && !inside_whole {
            if let Phase::InBlock(blk) = &mut st.phase {
                emit(blk, sink)?;
            }
            since = 0;
            let cursor = encode(&st.phase, rd.pos, out, st.check_kind, &st.rec, st.whole);
            on_point(SafePoint {
                cursor: &cursor,
                out,
                free_below: rd.pos,
            })?;
        }
        match &mut st.phase {
            Phase::Stream => {
                let at = rd.pos;
                let mut h = [0u8; 12];
                if rd.pos + 12 > len {
                    return Err(if first {
                        StreamError::Format("not an xz file".into())
                    } else {
                        corrupt(at, "truncated stream header")
                    });
                }
                rd.take(&mut h)?;
                if h[..6] != MAGIC {
                    return Err(if first {
                        StreamError::Format("not an xz file".into())
                    } else {
                        corrupt(at, "data after a stream is not another stream")
                    });
                }
                first = false;
                if crc32fast::hash(&h[6..8]) != u32::from_le_bytes(h[8..12].try_into().expect("4"))
                {
                    return Err(corrupt(at, "stream header CRC mismatch"));
                }
                if h[6] != 0 || h[7] & 0xF0 != 0 {
                    return Err(StreamError::Unsupported(
                        "xz stream uses reserved flags".into(),
                    ));
                }
                let kind = h[7] & 0x0F;
                if !matches!(kind, 0 | 1 | 4 | 10) {
                    return Err(StreamError::Unsupported(format!(
                        "xz check type {kind} is not supported"
                    )));
                }
                st.check_kind = kind;
                st.rec = Records::new();
                st.whole = starts.get(&at).copied().unwrap_or(false);
                st.phase = Phase::Blocks;
            }
            Phase::Blocks => {
                let at = rd.pos;
                if st.whole {
                    if let Some(d) = pre_decoded(
                        pre,
                        jobs,
                        at,
                        st.check_kind,
                        limits.max_out.saturating_sub(out),
                    ) {
                        sink(&d.out)?;
                        let n = d.out.len() as u64;
                        out += n;
                        since += n;
                        st.rec.add(d.unpadded, n);
                        rd = Reader::new(src, len, d.end);
                        continue;
                    }
                }
                let b = rd.u8()?;
                if b != 0 {
                    let blk = block_header(&mut rd, at, b, st.check_kind, limits.max_window)?;
                    st.phase = Phase::InBlock(Box::new(blk));
                    continue;
                }
                // The index.
                let mut crc = crc32fast::Hasher::new();
                crc.update(&[0]);
                let count = vli_from(&mut rd, &mut crc)?;
                let mut listed = Records::new();
                for _ in 0..count {
                    let unpadded = vli_from(&mut rd, &mut crc)?;
                    let uncompressed = vli_from(&mut rd, &mut crc)?;
                    listed.add(unpadded, uncompressed);
                }
                while (rd.pos - at) % 4 != 0 {
                    let c = rd.u8()?;
                    if c != 0 {
                        return Err(corrupt(rd.pos, "bad index padding"));
                    }
                    crc.update(&[c]);
                }
                let mut tail = [0u8; 4];
                rd.take(&mut tail)?;
                if crc.finalize() != u32::from_le_bytes(tail) {
                    return Err(corrupt(at, "index CRC mismatch"));
                }
                if !listed.same(&st.rec) {
                    return Err(corrupt(at, "index does not match the blocks"));
                }
                let index_size = rd.pos - at;
                let mut f = [0u8; 12];
                rd.take(&mut f)?;
                let backward = u64::from(u32::from_le_bytes(f[4..8].try_into().expect("4")));
                if crc32fast::hash(&f[4..10]) != u32::from_le_bytes(f[..4].try_into().expect("4"))
                    || f[10..] != FOOTER_MAGIC
                    || f[8..10] != [0, st.check_kind]
                    || (backward + 1) * 4 != index_size
                {
                    return Err(corrupt(rd.pos - 12, "bad stream footer"));
                }
                units += 1;
                // Stream padding: zeros in multiples of four, then another stream or the end.
                let pad_start = rd.pos;
                while rd.pos < len && rd.peek()? == 0 {
                    rd.pos += 1;
                }
                if (rd.pos - pad_start) % 4 != 0 {
                    return Err(corrupt(pad_start, "bad stream padding"));
                }
                if rd.pos >= len {
                    return Ok(StreamEnd {
                        out_len: out,
                        units,
                    });
                }
                st.phase = Phase::Stream;
            }
            Phase::InBlock(blk) => {
                let room = limits.max_out.saturating_sub(out);
                match block_step(&mut rd, blk, &mut chunk, room, st.check_kind, sink)? {
                    Step::Chunk(n) => {
                        out += n;
                        since += n;
                    }
                    Step::End(unpadded) => {
                        st.rec.add(unpadded, blk.out);
                        st.phase = Phase::Blocks;
                    }
                }
            }
        }
    }
}

/// The block starting at `at`, if a worker decoded it (and it fits in `room`). Anything else,
/// including a failure, leaves the block to the decoding loop, which then reports any error the
/// same way as without threads.
fn pre_decoded(
    pre: Option<&stream::Ahead<'_, stream::Result<Decoded>>>,
    jobs: &[Job],
    at: u64,
    check_kind: u8,
    room: u64,
) -> Option<Decoded> {
    let pre = pre?;
    let k = jobs.binary_search_by_key(&at, |j| j.start).ok()?;
    if jobs[k].check_kind != check_kind {
        return None;
    }
    let d = pre.get(k).ok()?;
    (d.out.len() as u64 <= room).then_some(d)
}

fn at_err(e: StreamError, at: u64) -> StreamError {
    match e {
        StreamError::Corrupt(m) => StreamError::Corrupt(format!("{m} (chunk at byte {at})")),
        other => other,
    }
}

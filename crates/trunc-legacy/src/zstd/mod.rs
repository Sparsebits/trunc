//! zstd decoding (RFC 8878), resumable at block and frame boundaries.
//!
//! A `.zst` file is one or more frames (skippable frames are ignored). Inside a frame, blocks
//! may refer back up to the frame's window size and reuse the previous block's Huffman tree,
//! sequence tables and repeat offsets. A safe point therefore stores that entropy state (a few
//! KB: Huffman weights and normalized counts, from which the tables are rebuilt) and reads the
//! window back through [`History`] on resume. Frames that need a dictionary are refused.

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
}

impl<'a> Reader<'a> {
    fn take(&mut self, out: &mut [u8]) -> stream::Result<()> {
        let n = out.len() as u64;
        if self.pos + n > self.len {
            return Err(corrupt("unexpected end of file (truncated download?)"));
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
}

impl Frame {
    fn window_len(&self) -> u64 {
        self.out.min(self.window)
    }

    fn emit(&mut self, sink: &mut Sink<'_>) -> stream::Result<()> {
        if self.flushed < self.win.len() {
            let data = &self.win[self.flushed..];
            if let Some(x) = &mut self.checksum {
                x.update(data);
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
    })
}

/// Decode a zstd file (one or more frames). Safe points are block and frame boundaries once
/// `every` bytes have been produced since the previous one.
#[allow(clippy::too_many_lines)]
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
    let (mut phase, pos, mut out) = match start {
        Some(c) => decode_cursor(c, history, limits.max_window)?,
        None => (Phase::Frames, 0, 0),
    };
    let mut rd = Reader {
        src,
        len,
        buf: Vec::new(),
        buf_start: 0,
        pos,
    };
    let mut first = start.is_none();
    let mut since = 0u64;
    let mut units = 0u32;
    let mut data = Vec::new();
    loop {
        if every > 0 && since >= every {
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
                if rd.pos == len && !first {
                    return Ok(StreamEnd {
                        out_len: out,
                        units,
                    });
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
                phase = Phase::InFrame(Box::new(frame_header(&mut rd, limits.max_window)?));
            }
            Phase::InFrame(f) => {
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
                let before = f.win.len();
                match kind {
                    0 => {
                        data.resize(size, 0);
                        rd.take(&mut data)?;
                        f.win.extend_from_slice(&data);
                    }
                    1 => {
                        let mut b = [0u8; 1];
                        rd.take(&mut b)?;
                        f.win.resize(f.win.len() + size, b[0]);
                    }
                    2 => {
                        data.resize(size, 0);
                        rd.take(&mut data)?;
                        block::decompress(
                            &data,
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
                f.out += n;
                out += n;
                since += n;
                if out > limits.max_out {
                    return Err(StreamError::Corrupt(format!(
                        "decoded more than the expected {} bytes",
                        limits.max_out
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
                    units += 1;
                    phase = Phase::Frames;
                }
            }
        }
    }
}

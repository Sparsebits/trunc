//! Shared code of the multi-unit stream targets (`parallel_equiv`, `resume_equiv`) and the
//! deflate differential target.
//!
//! A fuzz input is a small header of parameter bytes and a payload. The header picks the codec
//! and the shape: by default the payload is cut into several units (gzip members, bzip2 streams,
//! xz blocks and streams, zstd frames with and without a declared size, skippable frames) built
//! with the reference encoders, so the paths that need more than one unit are reached: threads
//! decoding blocks or frames ahead, safe points between units, the index and frame walks. The
//! payload can first be expanded with long matches at short distances, and one bit of the result
//! can be flipped. Otherwise the payload is decoded as it is.

#![allow(dead_code)]

use std::path::Path;

use flate2::{Compress, Compression, FlushCompress, Status};
use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::stream::{self, Codec, History, Input, Limits, StreamEnd};
use trunc_testkit::tarbuild::{self, XzCheck};
use trunc_testkit::{CrashModel, FaultFs};

pub const MAX_OUT: u64 = 8 << 20;
/// Largest expanded payload: enough for several 100 kB bzip2 blocks.
const MAX_EXPANDED: usize = 384 << 10;
/// bzip2 decodes blocks on threads only in files at least this large (`bzip2::decode`).
const BZIP2_PARALLEL_MIN: usize = 2 << 20;

/// Output written earlier, read back on resume. A read past what was written is a decoder bug.
pub struct VecHistory<'a>(pub &'a [u8]);

impl History for VecHistory<'_> {
    fn read(&mut self, at: u64, buf: &mut [u8]) -> stream::Result<()> {
        let at = usize::try_from(at).unwrap();
        assert!(
            at + buf.len() <= self.0.len(),
            "history read [{at}, {}) past the {} bytes written",
            at + buf.len(),
            self.0.len()
        );
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }
}

pub fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/d"), bytes);
    let h = fs
        .open(Path::new("/d"), OpenMode::Read, Share::Shared)
        .unwrap();
    (fs, h)
}

/// Safe points as (cursor, out, free_below).
pub type Points = Vec<(Vec<u8>, u64, u64)>;

/// Everything a decode produced, up to where it stopped.
pub struct Run {
    pub out: Vec<u8>,
    pub points: Points,
    pub end: Result<StreamEnd, String>,
}

pub fn decode(
    codec: Codec,
    input: &[u8],
    start: Option<&[u8]>,
    history: &mut dyn History,
    threads: usize,
    every: u64,
) -> Run {
    let (_fs, h) = host(input);
    let mut out = Vec::new();
    let mut points = Vec::new();
    let end = stream::decode(
        codec,
        Input {
            src: h.as_ref(),
            len: input.len() as u64,
        },
        start,
        history,
        Limits {
            max_out: MAX_OUT,
            max_window: 16 << 20,
            threads,
        },
        every,
        &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        },
        &mut |p| {
            points.push((p.cursor.to_vec(), p.out, p.free_below));
            Ok(())
        },
    )
    .map_err(|e| e.to_string());
    assert!(
        out.len() as u64 <= MAX_OUT,
        "{codec:?}: output over the limit"
    );
    Run { out, points, end }
}

/// One of `a` and `b` is a prefix of the other.
pub fn prefix_consistent<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    let n = a.len().min(b.len());
    a[..n] == b[..n]
}

/// Safe points go forward, stay within the input and the output written, and fit the codec's
/// cursor bound.
pub fn check_points(codec: Codec, points: &Points, input_len: usize, out_len: usize) {
    let mut prev = (0u64, 0u64);
    for (cursor, at, free_below) in points {
        assert!(
            *at > prev.0 && *free_below >= prev.1,
            "{codec:?}: safe points go backwards at {at}"
        );
        assert!(
            *free_below <= input_len as u64,
            "{codec:?}: free_below {free_below} past the input"
        );
        assert!(
            *at <= out_len as u64,
            "{codec:?}: safe point at {at} past the {out_len} bytes written"
        );
        assert!(
            cursor.len() <= codec.max_cursor(),
            "{codec:?}: cursor of {} bytes, over max_cursor",
            cursor.len()
        );
        prev = (*at, *free_below);
    }
}

/// Parameter bytes, read in order (zero once they run out).
pub struct Params<'a>(&'a [u8]);

impl Params<'_> {
    pub fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }
}

/// A fuzz input taken apart.
pub struct Case {
    pub codec: Codec,
    pub input: Vec<u8>,
    pub every: u64,
    /// Free parameter bits for the target (thread counts, which safe point).
    pub extra: u8,
}

pub const HEADER: usize = 6;

/// Header: `[sel, units, level, flip, every, extra]`, then the payload.
/// - `sel` bits 0-1: codec; bit 2: decode the payload as it is; bit 3: expand the payload;
///   bit 4: flip one bit; bits 5-7: codec-specific shape.
pub fn build(data: &[u8]) -> Option<Case> {
    if data.len() < HEADER {
        return None;
    }
    let (head, payload) = data.split_at(HEADER);
    let mut p = Params(head);
    let sel = p.byte();
    let units = p.byte();
    let level = p.byte();
    let flip = p.byte();
    let every = p.byte();
    let extra = p.byte();
    let codec = [Codec::Gzip, Codec::Bzip2, Codec::Xz, Codec::Zstd][usize::from(sel & 3)];
    let raw = sel & 0x04 != 0;
    let shape = sel >> 5;
    let mut input = if raw {
        payload.to_vec()
    } else {
        let expanded;
        let data = if sel & 0x08 != 0 {
            expanded = expand(payload);
            &expanded[..]
        } else {
            payload
        };
        let n = usize::from(units % 16) + 1;
        match codec {
            Codec::Gzip => gzip(data, n, level, shape),
            Codec::Bzip2 => bzip2(data, n, level),
            Codec::Xz => xz(data, n, level, shape),
            Codec::Zstd => zstd(data, n, level, shape),
        }
    };
    if sel & 0x10 != 0 && !input.is_empty() {
        let at = (usize::from(flip) * 7919 + payload.len()) % input.len();
        input[at] ^= 1 << (flip % 8);
    }
    // Trailing zeros after the last bzip2 stream are accepted, and make the file large enough
    // for the threaded path without compressing megabytes.
    if codec == Codec::Bzip2 && shape & 1 != 0 && input.len() < BZIP2_PARALLEL_MIN {
        input.resize(BZIP2_PARALLEL_MIN, 0);
    }
    let every = match every & 7 {
        0 => 0,
        1 => 1,
        2 => 100,
        3 => 1000,
        4 => 4096,
        5 => 32 << 10,
        6 => 128 << 10,
        _ => 1 << 20,
    };
    Some(Case {
        codec,
        input,
        every,
        extra,
    })
}

/// Expand `p` as pairs `(ctl, v)`: with the top bit of `ctl` set, a match of up to 2 KiB at a
/// distance of 1-16 (the copies decoders do in overlapping chunks); otherwise two literals.
pub fn expand(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in p.chunks(2) {
        let ctl = c[0];
        let v = c.get(1).copied().unwrap_or(0);
        if ctl & 0x80 != 0 && !out.is_empty() {
            let dist = (usize::from(ctl & 15) + 1).min(out.len());
            let len = (usize::from(v) + 1) * (usize::from((ctl >> 4) & 7) + 1);
            for _ in 0..len {
                out.push(out[out.len() - dist]);
            }
        } else {
            out.push(ctl);
            out.push(v);
        }
        if out.len() >= MAX_EXPANDED {
            out.truncate(MAX_EXPANDED);
            break;
        }
    }
    out
}

/// `data` cut into `n` pieces (at least one, possibly empty).
fn pieces(data: &[u8], n: usize) -> Vec<&[u8]> {
    if data.is_empty() {
        return vec![data];
    }
    data.chunks(data.len().div_ceil(n)).collect()
}

/// Feed `input` to `c` with `flush`, growing `out` as needed.
fn compress(c: &mut Compress, mut input: &[u8], out: &mut Vec<u8>, flush: FlushCompress) {
    loop {
        out.reserve(input.len() / 2 + 1024);
        let before = c.total_in();
        let st = c.compress_vec(input, out, flush).unwrap();
        input = &input[usize::try_from(c.total_in() - before).unwrap()..];
        let done = match flush {
            FlushCompress::Finish => st == Status::StreamEnd,
            FlushCompress::None => input.is_empty(),
            // A flush is complete once the encoder stops filling the room it was given.
            _ => input.is_empty() && out.len() < out.capacity(),
        };
        if done {
            return;
        }
    }
}

/// Raw DEFLATE of `data` at `level` (0 writes stored blocks). With `flush`, the encoder is
/// flushed every `step` bytes, which ends the block there: many short blocks.
pub fn deflate(data: &[u8], level: u32, flush: Option<(usize, FlushCompress)>) -> Vec<u8> {
    let mut c = Compress::new(Compression::new(level.min(9)), false);
    let mut out = Vec::new();
    if let Some((step, how)) = flush {
        for chunk in data.chunks(step.max(1)) {
            compress(&mut c, chunk, &mut out, how);
        }
    } else {
        compress(&mut c, data, &mut out, FlushCompress::None);
    }
    compress(&mut c, &[], &mut out, FlushCompress::Finish);
    out
}

/// The flush pattern `b` selects: none, or a sync, full or partial flush every 8-1016 bytes.
pub fn flush_pattern(b: u8) -> Option<(usize, FlushCompress)> {
    let step = usize::from(b >> 2) * 16 + 8;
    match b & 3 {
        0 => None,
        1 => Some((step, FlushCompress::Sync)),
        2 => Some((step, FlushCompress::Full)),
        _ => Some((step, FlushCompress::Partial)),
    }
}

/// gzip members, one per piece, with optional header fields (`shape`) and many short blocks
/// when `level` asks for flushes.
fn gzip(data: &[u8], n: usize, level: u8, shape: u8) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, piece) in pieces(data, n).into_iter().enumerate() {
        let start = out.len();
        let flags = (if i % 2 == 0 {
            shape
        } else {
            shape.rotate_left(1)
        }) & 7;
        // FTEXT is ignored; use the bits for FEXTRA, FNAME, FCOMMENT (and FHCRC on all three).
        let mut fl = 0u8;
        if flags & 1 != 0 {
            fl |= 1 << 2;
        }
        if flags & 2 != 0 {
            fl |= 1 << 3;
        }
        if flags & 4 != 0 {
            fl |= 1 << 4;
        }
        if flags == 7 {
            fl |= 1 << 1;
        }
        out.extend_from_slice(&[0x1f, 0x8b, 8, fl, 0, 0, 0, 0, 0, 255]);
        if fl & (1 << 2) != 0 {
            out.extend_from_slice(&[4, 0, b'x', b'y', 0, 0]);
        }
        if fl & (1 << 3) != 0 {
            out.extend_from_slice(b"name\0");
        }
        if fl & (1 << 4) != 0 {
            out.extend_from_slice(b"comment\0");
        }
        if fl & (1 << 1) != 0 {
            let crc = crc32(&out[start..]);
            out.extend_from_slice(&(crc as u16).to_le_bytes());
        }
        out.extend(deflate(
            piece,
            u32::from(level % 10),
            flush_pattern(level / 10),
        ));
        out.extend_from_slice(&crc32(piece).to_le_bytes());
        out.extend_from_slice(&(piece.len() as u32).to_le_bytes());
    }
    out
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// bzip2 streams, one per piece (each with as many blocks as its size needs).
fn bzip2(data: &[u8], n: usize, level: u8) -> Vec<u8> {
    pieces(data, n)
        .into_iter()
        .flat_map(|piece| tarbuild::bzip2(piece, u32::from(level % 9) + 1))
        .collect()
}

/// xz: up to two streams (`shape` bit 1), each multi-block with an index when the payload is
/// cut in more than one piece, with stream padding between them.
fn xz(data: &[u8], n: usize, level: u8, shape: u8) -> Vec<u8> {
    let preset = u32::from(level % 4);
    let check = [
        XzCheck::None,
        XzCheck::Crc32,
        XzCheck::Crc64,
        XzCheck::Sha256,
    ][usize::from((level >> 2) % 4)];
    let block = |d: &[u8]| (n > 1).then(|| (d.len().div_ceil(n) as u64).max(1));
    if shape & 2 == 0 {
        return tarbuild::xz_with(data, preset, check, block(data));
    }
    let (a, b) = data.split_at(data.len() / 2);
    let mut out = tarbuild::xz_with(a, preset, check, block(a));
    out.resize(out.len() + usize::from(shape & 4), 0);
    // The second stream alternates between multi-block and single-block.
    let second = if level & 0x40 != 0 { None } else { block(b) };
    out.extend(tarbuild::xz_with(b, preset, check, second));
    out
}

/// zstd frames, one per piece; per frame, bits of `shape` and the piece index pick whether it
/// declares its size (which lets it be decoded whole) and carries a checksum, and skippable
/// frames go between some of them.
fn zstd(data: &[u8], n: usize, level: u8, shape: u8) -> Vec<u8> {
    let lvl = i32::from(level % 8) - 1;
    let mut out = Vec::new();
    for (i, piece) in pieces(data, n).into_iter().enumerate() {
        let bits = level.rotate_right(i as u32 % 8);
        let sized = shape & 1 == 0 || bits & 0x10 != 0;
        let mut e = zstd::stream::write::Encoder::new(Vec::new(), lvl).unwrap();
        e.include_checksum(bits & 0x20 != 0).unwrap();
        e.include_contentsize(sized).unwrap();
        if sized {
            e.set_pledged_src_size(Some(piece.len() as u64)).unwrap();
        }
        std::io::Write::write_all(&mut e, piece).unwrap();
        out.extend(e.finish().unwrap());
        if shape & 2 != 0 && bits & 0x40 != 0 {
            let len = usize::from(shape & 4) + i % 3;
            out.extend_from_slice(&(0x184D_2A50u32 | (i as u32 & 15)).to_le_bytes());
            out.extend_from_slice(&(len as u32).to_le_bytes());
            out.resize(out.len() + len, 0xA5);
        }
    }
    out
}

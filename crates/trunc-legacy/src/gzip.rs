//! gzip (RFC 1952) member framing. The compressed data inside a member is a raw DEFLATE stream,
//! decoded by [`crate::inflate`]. A `.tar.gz` may hold several members back to back (`pigz -i`,
//! `cat a.gz b.gz`); their outputs concatenate.

use std::cell::{Cell, RefCell};

use trunc_fs::FileHandle;

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
    Ok(at + p as u64)
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
/// Cursor bytes: `member data offset u64 | output base u64 | inflate checkpoint`.
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

fn gz_err(e: GzipError) -> StreamError {
    match e {
        GzipError::Fs(f) => StreamError::Fs(f),
        other => StreamError::Format(other.to_string()),
    }
}

/// Decode a gzip file (one or more members). Safe points are DEFLATE block boundaries after
/// `every` bytes of a member's output, and member boundaries once `every` bytes have been
/// produced since the previous safe point.
pub fn decode(
    input: Input<'_>,
    start: Option<&[u8]>,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let Input { src, len: file_len } = input;
    let (mut data_start, mut out_base, mut ck) = match start {
        Some(c) => parse_cursor(c)?,
        None => (
            read_header(src, 0, file_len).map_err(gz_err)?,
            0,
            Checkpoint::start(),
        ),
    };
    let since = Cell::new(0u64);
    let failure: RefCell<Option<StreamError>> = RefCell::new(None);
    let fail = |e: StreamError| {
        *failure.borrow_mut() = Some(e);
        InflateError::Callback(String::new())
    };
    let mut members = 0u32;
    loop {
        let budget = limits.max_out.saturating_sub(out_base);
        let finished = Inflater::new(&ck, budget).run(
            src,
            data_start,
            file_len.saturating_sub(data_start),
            &mut |b| {
                since.set(since.get() + b.len() as u64);
                sink(b).map_err(fail)
            },
            every,
            &mut |c| {
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
        members += 1;
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
        let next = trailer + TRAILER_LEN;
        out_base += f.out_total;
        if next >= file_len || only_padding_after(src, next, file_len).map_err(gz_err)? {
            return Ok(StreamEnd {
                out_len: out_base,
                units: members,
            });
        }
        data_start = read_header(src, next, file_len).map_err(gz_err)?;
        ck = Checkpoint::start();
        // A member boundary is a safe point too, once enough has been produced since the last
        // one (archives made of many small members still free space as they go).
        if every > 0 && since.get() >= every {
            since.set(0);
            let cursor = cursor_bytes(data_start, out_base, &ck);
            on_point(SafePoint {
                cursor: &cursor,
                out: out_base,
                free_below: next,
            })?;
        }
    }
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

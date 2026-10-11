//! Decoding a folder: its packed stream pulled through the coder chain, output in order.
//!
//! Each coder is a stage that pulls from the one before it, so memory stays at the LZMA window
//! plus a few buffers whatever the folder's size. Every stage checks that it produces exactly
//! the size the header declares for it.

// The BCJ filter works on 32-bit positions and addresses by definition.
#![allow(clippy::cast_possible_truncation)]

use trunc_fs::FileHandle;

use super::{Coder, Entry, Folder, Kind, Layout, Method, Result, SevenZError, corrupt};
use crate::lzma::{FLUSH_AT, LZMA1_LOOKAHEAD, Lzma1, Lzma2};
use crate::stream::StreamError;

/// Bytes read from the file, or from the previous stage, at a time.
const CHUNK: usize = 1 << 20;

trait Stage {
    /// Fill the front of `buf`; 0 only at the end, once the stage has checked its size.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
}

fn lzma_err(e: StreamError) -> SevenZError {
    match e {
        StreamError::Fs(f) => SevenZError::Fs(f),
        StreamError::Unsupported(m) => SevenZError::Unsupported(m),
        other => corrupt(other.to_string()),
    }
}

/// Read exactly `buf.len()` bytes from a stage.
fn read_exact(s: &mut dyn Stage, buf: &mut [u8]) -> Result<()> {
    let mut at = 0;
    while at < buf.len() {
        let n = s.read(&mut buf[at..])?;
        if n == 0 {
            return Err(corrupt("compressed data ends early"));
        }
        at += n;
    }
    Ok(())
}

/// The packed stream, read from the file.
struct Packed<'a> {
    src: &'a dyn FileHandle,
    pos: u64,
    end: u64,
}

impl Stage for Packed<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = usize::try_from((self.end - self.pos).min(buf.len() as u64)).expect("<= len");
        if n > 0 {
            self.src.read_exact_at(&mut buf[..n], self.pos)?;
            self.pos += n as u64;
        }
        Ok(n)
    }
}

/// Copy, BCJ and Delta: the output is the input transformed in place, size for size.
struct Filter<'a> {
    input: Box<dyn Stage + 'a>,
    kind: FilterKind,
    /// Declared output size still to come.
    left: u64,
    /// Input read but not yet handed on; `buf[..ready]` is final.
    buf: Vec<u8>,
    ready: usize,
    eof: bool,
}

enum FilterKind {
    Copy,
    Bcj(Bcj),
    Delta {
        dist: usize,
        hist: [u8; 256],
        pos: u8,
    },
}

impl Stage for Filter<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            if self.ready > 0 {
                let n = self.ready.min(out.len());
                out[..n].copy_from_slice(&self.buf[..n]);
                self.buf.drain(..n);
                self.ready -= n;
                return Ok(n);
            }
            if self.eof {
                if self.left != 0 {
                    return Err(corrupt("coder output shorter than declared"));
                }
                return Ok(0);
            }
            let old = self.buf.len();
            self.buf.resize(old + CHUNK, 0);
            let n = self.input.read(&mut self.buf[old..])?;
            self.buf.truncate(old + n);
            if n as u64 > self.left {
                return Err(corrupt("coder output longer than declared"));
            }
            self.left -= n as u64;
            if n == 0 {
                // The end: what the BCJ filter held back goes out as it is.
                self.eof = true;
                self.ready = self.buf.len();
                continue;
            }
            match &mut self.kind {
                FilterKind::Copy => self.ready = self.buf.len(),
                FilterKind::Bcj(b) => self.ready = b.decode(&mut self.buf),
                FilterKind::Delta { dist, hist, pos } => {
                    for b in &mut self.buf[old..] {
                        *b = b.wrapping_add(hist[usize::from(pos.wrapping_add(*dist as u8))]);
                        hist[usize::from(*pos)] = *b;
                        *pos = pos.wrapping_sub(1);
                    }
                    self.ready = self.buf.len();
                }
            }
        }
    }
}

/// The x86 BCJ decoder (as in xz and the LZMA SDK).
struct Bcj {
    prev_mask: u32,
    prev_pos: u32,
    now_pos: u32,
}

impl Bcj {
    fn new() -> Self {
        Self {
            prev_mask: 0,
            prev_pos: 0u32.wrapping_sub(5),
            now_pos: 0,
        }
    }

    /// Convert what can be converted at the front of `buf`; returns how many bytes are final.
    fn decode(&mut self, buf: &mut [u8]) -> usize {
        const ALLOWED: [bool; 8] = [true, true, true, false, true, false, false, false];
        const BIT: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];
        let ms = |b: u8| b == 0 || b == 0xFF;
        if buf.len() < 5 {
            return 0;
        }
        let now = self.now_pos;
        let mut prev_mask = self.prev_mask;
        let mut prev_pos = self.prev_pos;
        if now.wrapping_sub(prev_pos) > 5 {
            prev_pos = now.wrapping_sub(5);
        }
        let limit = buf.len() - 5;
        let mut i = 0usize;
        while i <= limit {
            let b = buf[i];
            if b != 0xE8 && b != 0xE9 {
                i += 1;
                continue;
            }
            let offset = now.wrapping_add(i as u32).wrapping_sub(prev_pos);
            prev_pos = now.wrapping_add(i as u32);
            if offset > 5 {
                prev_mask = 0;
            } else {
                for _ in 0..offset {
                    prev_mask &= 0x77;
                    prev_mask <<= 1;
                }
            }
            let b4 = buf[i + 4];
            if ms(b4) && ALLOWED[((prev_mask >> 1) & 7) as usize] && (prev_mask >> 1) < 0x10 {
                let mut src = u32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], b4]);
                let mut dest;
                loop {
                    dest = src.wrapping_sub(now.wrapping_add(i as u32).wrapping_add(5));
                    if prev_mask == 0 {
                        break;
                    }
                    let k = BIT[(prev_mask >> 1) as usize];
                    if !ms((dest >> (24 - k * 8)) as u8) {
                        break;
                    }
                    src = dest ^ ((1u32 << (32 - k * 8)) - 1);
                }
                buf[i + 4] = !(((dest >> 24) & 1).wrapping_sub(1)) as u8;
                buf[i + 3] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 1] = dest as u8;
                i += 5;
                prev_mask = 0;
            } else {
                i += 1;
                prev_mask |= 1;
                if ms(b4) {
                    prev_mask |= 0x10;
                }
            }
        }
        self.prev_mask = prev_mask;
        self.prev_pos = prev_pos;
        self.now_pos = now.wrapping_add(i as u32);
        i
    }
}

/// Hand pending window bytes to `out`.
fn drain_window(lz: &mut Lzma2, out: &mut [u8]) -> usize {
    let n = (lz.win.len() - lz.flushed).min(out.len());
    out[..n].copy_from_slice(&lz.win[lz.flushed..lz.flushed + n]);
    lz.flushed += n;
    lz.trim();
    n
}

struct LzmaStage<'a> {
    input: Box<dyn Stage + 'a>,
    dec: Lzma1,
    left: u64,
    inbuf: Vec<u8>,
    inpos: usize,
    in_eof: bool,
    done: bool,
}

impl LzmaStage<'_> {
    fn fill(&mut self) -> Result<()> {
        self.inbuf.drain(..self.inpos);
        self.inpos = 0;
        let old = self.inbuf.len();
        self.inbuf.resize(old + CHUNK, 0);
        let n = self.input.read(&mut self.inbuf[old..])?;
        self.inbuf.truncate(old + n);
        self.in_eof = n == 0;
        Ok(())
    }
}

impl Stage for LzmaStage<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            if self.dec.lz.flushed < self.dec.lz.win.len() {
                return Ok(drain_window(&mut self.dec.lz, out));
            }
            if self.done {
                return Ok(0);
            }
            if !self.in_eof && self.inbuf.len() - self.inpos < 4 * LZMA1_LOOKAHEAD {
                self.fill()?;
            }
            let before = self.dec.lz.win.len();
            let used = self
                .dec
                .step(&self.inbuf[self.inpos..], self.in_eof, FLUSH_AT, self.left)
                .map_err(lzma_err)?;
            self.inpos += used;
            let made = (self.dec.lz.win.len() - before) as u64;
            self.left -= made;
            if made > 0 || used > 0 {
                continue;
            }
            if self.dec.saw_marker() && self.left != 0 {
                return Err(corrupt("LZMA data ends before its declared size"));
            }
            if self.dec.saw_marker() || (self.left == 0 && self.in_eof) {
                self.done = true;
            } else if self.in_eof {
                return Err(corrupt("LZMA data ends early"));
            } else {
                self.fill()?;
            }
        }
    }
}

struct Lzma2Stage<'a> {
    input: Box<dyn Stage + 'a>,
    lz: Lzma2,
    left: u64,
    chunk: Vec<u8>,
    done: bool,
}

impl Stage for Lzma2Stage<'_> {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        loop {
            if self.lz.flushed < self.lz.win.len() {
                return Ok(drain_window(&mut self.lz, out));
            }
            if self.done {
                return Ok(0);
            }
            let mut c = [0u8];
            read_exact(self.input.as_mut(), &mut c)?;
            let Some(more) = self.lz.control(c[0]).map_err(lzma_err)? else {
                if self.left != 0 {
                    return Err(corrupt("LZMA2 data ends before its declared size"));
                }
                self.done = true;
                continue;
            };
            let mut head = vec![c[0]; 1 + more];
            read_exact(self.input.as_mut(), &mut head[1..])?;
            let packed = if c[0] >= 0x80 {
                usize::from(u16::from_be_bytes([head[3], head[4]])) + 1
            } else {
                usize::from(u16::from_be_bytes([head[1], head[2]])) + 1
            };
            self.chunk.resize(packed, 0);
            read_exact(self.input.as_mut(), &mut self.chunk)?;
            let n = self
                .lz
                .chunk(&head, &self.chunk, self.left)
                .map_err(lzma_err)?;
            self.left -= n as u64;
        }
    }
}

fn stage<'a>(input: Box<dyn Stage + 'a>, c: &Coder) -> Result<Box<dyn Stage + 'a>> {
    let filter = |input, kind| -> Box<dyn Stage + 'a> {
        Box::new(Filter {
            input,
            kind,
            left: c.unpack_size,
            buf: Vec::new(),
            ready: 0,
            eof: false,
        })
    };
    Ok(match c.method {
        Method::Copy => filter(input, FilterKind::Copy),
        Method::BcjX86 => filter(input, FilterKind::Bcj(Bcj::new())),
        Method::Delta => filter(
            input,
            FilterKind::Delta {
                dist: usize::from(c.props[0]) + 1,
                hist: [0; 256],
                pos: 0,
            },
        ),
        Method::Lzma => Box::new(LzmaStage {
            input,
            dec: Lzma1::new(&c.props).map_err(lzma_err)?,
            left: c.unpack_size,
            inbuf: Vec::new(),
            inpos: 0,
            in_eof: false,
            done: false,
        }),
        Method::Lzma2 => {
            let bits = u32::from(c.props[0]);
            let dict = if bits == 40 {
                u32::MAX
            } else {
                (2 | (bits & 1)) << (bits / 2 + 11)
            };
            Box::new(Lzma2Stage {
                input,
                lz: Lzma2::new(dict),
                left: c.unpack_size,
                chunk: Vec::new(),
                done: false,
            })
        }
    })
}

/// Decode a folder's whole output into `sink`, checking its size and (if recorded) its CRC.
pub(super) fn decode(
    src: &dyn FileHandle,
    f: &Folder,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut s: Box<dyn Stage + '_> = Box::new(Packed {
        src,
        pos: f.pack_offset,
        end: f.pack_offset + f.pack_size,
    });
    for c in &f.coders {
        s = stage(s, c)?;
    }
    let mut buf = vec![0u8; CHUNK];
    let mut crc = crc32fast::Hasher::new();
    let mut total = 0u64;
    loop {
        let n = s.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if f.crc.is_some() {
            crc.update(&buf[..n]);
        }
        sink(&buf[..n])?;
    }
    if total != f.unpack_size {
        return Err(corrupt("folder output size differs from the header"));
    }
    if f.crc.is_some_and(|c| c != crc.finalize()) {
        return Err(SevenZError::Crc("folder CRC mismatch".into()));
    }
    Ok(())
}

/// Decode folder `index` of `layout`, handing each entry's content to `data(entry, bytes)` and
/// checking each entry's CRC. `begin(entry)` is called before an entry's first byte (also for
/// an entry with no content) and `end(entry)` once all of it has passed and its CRC matched.
pub fn decode_folder(
    src: &dyn FileHandle,
    layout: &Layout,
    index: usize,
    begin: &mut dyn FnMut(usize) -> Result<()>,
    data: &mut dyn FnMut(usize, &[u8]) -> Result<()>,
    end: &mut dyn FnMut(usize) -> Result<()>,
) -> Result<()> {
    let f = &layout.folders[index];
    let entries: Vec<(usize, &Entry)> =
        f.entries.iter().map(|&i| (i, &layout.entries[i])).collect();
    let mut cur = 0usize;
    let mut at = 0u64;
    let mut crc = crc32fast::Hasher::new();
    let mut started = false;
    // Entries are contiguous from offset 0 (the header parser built them so).
    let mut finish = |i: usize, e: &Entry, crc: &mut crc32fast::Hasher| -> Result<()> {
        let got = std::mem::take(crc).finalize();
        if e.crc.is_some_and(|c| c != got) {
            return Err(SevenZError::Crc(format!("{}: CRC mismatch", e.name)));
        }
        end(i)
    };
    decode(src, f, &mut |mut b: &[u8]| {
        while !b.is_empty() {
            // Skip past finished entries (empty ones finish without data).
            while let Some(&(i, e)) = entries.get(cur) {
                if !started {
                    begin(i)?;
                    started = true;
                }
                if at < e.size {
                    break;
                }
                finish(i, e, &mut crc)?;
                cur += 1;
                at = 0;
                started = false;
            }
            let Some(&(i, e)) = entries.get(cur) else {
                return Err(corrupt("folder output longer than its files"));
            };
            let n = usize::try_from((e.size - at).min(b.len() as u64)).expect("<= len");
            crc.update(&b[..n]);
            if e.kind != Kind::Dir {
                data(i, &b[..n])?;
            }
            at += n as u64;
            b = &b[n..];
        }
        Ok(())
    })?;
    // Entries at the very end (the last one, and any empty ones after it).
    while let Some(&(i, e)) = entries.get(cur) {
        if !started {
            begin(i)?;
        }
        if at != e.size {
            return Err(corrupt("folder output shorter than its files"));
        }
        finish(i, e, &mut crc)?;
        cur += 1;
        at = 0;
        started = false;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bcj_leaves_plain_bytes_alone() {
        let mut b = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let orig = b.clone();
        let n = Bcj::new().decode(&mut b);
        assert_eq!(n, 4);
        assert_eq!(b, orig);
    }
}

//! DEFLATE (RFC 1951) decoder that can stop at any block boundary and later resume from a
//! saved [`Checkpoint`].
//!
//! Existing inflate libraries keep their state private, so it cannot be written to disk. Punch
//! mode needs exactly that: once the compressed bytes before a checkpoint have been deallocated,
//! the only way to continue is from the saved bit position, the last 32 KiB of output (the
//! LZ77 window) and the running CRC-32. At a block boundary there is no other decoder state.
//!
//! Decoding uses an 11-bit primary lookup table per Huffman code with a canonical slow path for
//! longer codes. Correctness is tested against flate2 (`tests/inflate.rs`).

use std::fmt;

use trunc_fs::{FileHandle, FsError};

/// Size of the LZ77 history window.
pub const WINDOW: usize = 32 * 1024;
const FAST_BITS: u32 = 11;
const MAX_BITS: usize = 15;
/// Pending output is handed to the sink once this much has accumulated beyond the window.
const FLUSH_AT: usize = 1 << 20;
const READ_CHUNK: usize = 256 * 1024;

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

#[derive(Debug, thiserror::Error)]
pub enum InflateError {
    #[error("corrupt deflate stream: {0}")]
    Corrupt(&'static str),
    #[error("deflate stream continues past the entry's compressed size")]
    Overrun,
    #[error("decoded more than the expected {0} bytes")]
    TooLong(u64),
    #[error(transparent)]
    Fs(#[from] FsError),
    /// Returned by a sink or checkpoint callback to abort decoding.
    #[error("{0}")]
    Callback(String),
}

type Result<T> = std::result::Result<T, InflateError>;

/// Decoder state at a block boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Bits of the compressed stream consumed so far.
    pub in_bit: u64,
    /// Bytes of output produced (and handed to the sink) so far.
    pub out_total: u64,
    /// CRC-32 (IEEE) of all output so far.
    pub crc: u32,
    /// The last `min(WINDOW, out_total)` bytes of output.
    pub window: Vec<u8>,
}

impl fmt::Debug for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checkpoint")
            .field("in_bit", &self.in_bit)
            .field("out_total", &self.out_total)
            .field("crc", &format_args!("{:08x}", self.crc))
            .field("window_len", &self.window.len())
            .finish()
    }
}

impl Checkpoint {
    /// The state before any input: used to start (and to restart) an entry.
    pub fn start() -> Self {
        Self {
            in_bit: 0,
            out_total: 0,
            crc: 0,
            window: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(24 + self.window.len());
        b.extend_from_slice(&self.in_bit.to_le_bytes());
        b.extend_from_slice(&self.out_total.to_le_bytes());
        b.extend_from_slice(&self.crc.to_le_bytes());
        b.extend_from_slice(
            &u32::try_from(self.window.len())
                .expect("window <= 32 KiB")
                .to_le_bytes(),
        );
        b.extend_from_slice(&self.window);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let u32_at = |i: usize| Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?));
        let (in_bit, out_total, crc, wl) =
            (u64_at(0)?, u64_at(8)?, u32_at(16)?, u32_at(20)? as usize);
        let window = b.get(24..24 + wl)?.to_vec();
        let expected = usize::try_from(out_total.min(WINDOW as u64)).ok()?;
        (wl == expected && b.len() == 24 + wl).then_some(Self {
            in_bit,
            out_total,
            crc,
            window,
        })
    }
}

/// Result of decoding a complete stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    pub out_total: u64,
    pub crc: u32,
    /// Compressed bits consumed (the stream occupied `in_bits.div_ceil(8)` bytes).
    pub in_bits: u64,
}

/// Reads bits LSB-first from `[base, base + len)` of a file.
struct BitReader<'a> {
    src: &'a dyn FileHandle,
    base: u64,
    len: u64,
    buf: Vec<u8>,
    buf_pos: usize,
    /// Offset (relative to `base`) of the byte after the buffer's contents.
    next: u64,
    bits: u64,
    nbits: u32,
    consumed: u64,
}

impl<'a> BitReader<'a> {
    fn new(src: &'a dyn FileHandle, base: u64, len: u64, start_bit: u64) -> Result<Self> {
        let mut r = Self {
            src,
            base,
            len,
            buf: Vec::new(),
            buf_pos: 0,
            next: start_bit / 8,
            bits: 0,
            nbits: 0,
            consumed: start_bit / 8 * 8,
        };
        if start_bit / 8 > len {
            return Err(InflateError::Overrun);
        }
        let skip = u32::try_from(start_bit % 8).expect("< 8");
        if skip > 0 {
            r.get(skip)?;
        }
        Ok(r)
    }

    fn next_byte(&mut self) -> Result<u8> {
        if self.buf_pos == self.buf.len() {
            if self.next >= self.len {
                // Past the end: feed zeros; `finish` rejects streams that actually used them.
                return Ok(0);
            }
            let n = usize::try_from((self.len - self.next).min(READ_CHUNK as u64)).expect("small");
            self.buf.resize(n, 0);
            self.src
                .read_exact_at(&mut self.buf, self.base + self.next)?;
            self.next += n as u64;
            self.buf_pos = 0;
        }
        let b = self.buf[self.buf_pos];
        self.buf_pos += 1;
        Ok(b)
    }

    fn fill(&mut self) -> Result<()> {
        // Fast path: eight bytes at once while the buffer has them.
        if self.buf_pos + 8 <= self.buf.len() {
            let w = u64::from_le_bytes(
                self.buf[self.buf_pos..self.buf_pos + 8]
                    .try_into()
                    .expect("8 bytes"),
            );
            self.bits |= w << self.nbits;
            let n = (63 - self.nbits) / 8;
            self.buf_pos += n as usize;
            self.nbits += n * 8;
            return Ok(());
        }
        while self.nbits <= 56 {
            let b = self.next_byte()?;
            self.bits |= u64::from(b) << self.nbits;
            self.nbits += 8;
        }
        Ok(())
    }

    fn consume(&mut self, n: u32) {
        self.bits >>= n;
        self.nbits -= n;
        self.consumed += u64::from(n);
    }

    fn get(&mut self, n: u32) -> Result<u32> {
        if n == 0 {
            return Ok(0);
        }
        if self.nbits < n {
            self.fill()?;
        }
        let v = u32::try_from(self.bits & ((1u64 << n) - 1)).expect("n <= 32");
        self.consume(n);
        if self.consumed > self.len.saturating_mul(8) {
            return Err(InflateError::Overrun);
        }
        Ok(v)
    }

    /// `n` bits that are known to be in the buffer already.
    fn take(&mut self, n: u32) -> u32 {
        debug_assert!(n <= self.nbits && n <= 32);
        #[allow(clippy::cast_possible_truncation)] // n <= 32
        let v = (self.bits & ((1u64 << n) - 1)) as u32;
        self.consume(n);
        v
    }

    fn align(&mut self) -> Result<()> {
        let r = u32::try_from(self.consumed % 8).expect("< 8");
        if r != 0 {
            self.get(8 - r)?;
        }
        Ok(())
    }
}

struct Huffman {
    /// `symbol << 4 | length`, or 0 when the code is longer than `FAST_BITS`.
    fast: Vec<u16>,
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    /// The canonical code of `lengths`. As in zlib, the code must be complete, except that a
    /// code with no symbols is allowed (it fails when used) and, with `allow_single`, so is a
    /// code with a single symbol of length 1 (the other one-bit code fails when used).
    fn new(lengths: &[u8], allow_single: bool) -> Result<Self> {
        let mut counts = [0u16; MAX_BITS + 1];
        for &l in lengths {
            counts[usize::from(l)] += 1;
        }
        counts[0] = 0;
        let mut left: i32 = 1;
        for &c in &counts[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err(InflateError::Corrupt("over-subscribed Huffman code"));
            }
        }
        if left > 0 {
            let max = counts.iter().rposition(|&c| c != 0).unwrap_or(0);
            if max != 0 && (max != 1 || !allow_single) {
                return Err(InflateError::Corrupt("incomplete Huffman code"));
            }
        }
        let mut offs = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            offs[len + 1] = offs[len] + counts[len];
        }
        let mut symbols = vec![0u16; usize::from(offs[MAX_BITS + 1])];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let o = &mut offs[usize::from(l)];
                symbols[usize::from(*o)] = u16::try_from(sym).expect("< 320 symbols");
                *o += 1;
            }
        }
        // Canonical codes (first code of each length), then the reversed-bit fast table.
        let mut next = [0u32; MAX_BITS + 1];
        let mut code = 0u32;
        for len in 1..=MAX_BITS {
            next[len] = code;
            code = (code + u32::from(counts[len])) << 1;
        }
        let mut fast = vec![0u16; 1 << FAST_BITS];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let len = usize::from(l);
            let c = next[len];
            next[len] += 1;
            if u32::from(l) <= FAST_BITS {
                let rev = c.reverse_bits() >> (32 - u32::from(l));
                let entry = (u16::try_from(sym).expect("< 320") << 4) | u16::from(l);
                let mut i = rev as usize;
                while i < fast.len() {
                    fast[i] = entry;
                    i += 1 << len;
                }
            }
        }
        Ok(Self {
            fast,
            counts,
            symbols,
        })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16> {
        if br.nbits < 16 {
            br.fill()?;
        }
        let e = self.fast[usize::try_from(br.bits & ((1 << FAST_BITS) - 1)).expect("small")];
        if e != 0 {
            br.consume(u32::from(e & 15));
            if br.consumed > br.len.saturating_mul(8) {
                return Err(InflateError::Overrun);
            }
            return Ok(e >> 4);
        }
        self.slow(br)
    }

    /// Decode with at least 15 bits in the buffer (no refill on the fast path).
    #[inline]
    fn decode_filled(&self, br: &mut BitReader<'_>) -> Result<u16> {
        let e = self.fast[(br.bits & ((1 << FAST_BITS) - 1)) as usize];
        if e != 0 {
            br.consume(u32::from(e & 15));
            return Ok(e >> 4);
        }
        self.slow(br)
    }

    #[cold]
    fn slow(&self, br: &mut BitReader<'_>) -> Result<u16> {
        // Canonical decoding, one bit at a time (codes longer than FAST_BITS).
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=MAX_BITS {
            code |= i32::try_from(br.get(1)?).expect("bit");
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return Ok(self.symbols[usize::try_from(index + (code - first)).expect(">= 0")]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::Corrupt("invalid Huffman code"))
    }
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut l = [0u8; 288];
    l[..144].fill(8);
    l[144..256].fill(9);
    l[256..280].fill(7);
    l[280..].fill(8);
    // All 32 codes, so the code is complete; symbols 30 and 31 are refused when decoded.
    let d = [5u8; 32];
    (
        Huffman::new(&l, false).expect("fixed table"),
        Huffman::new(&d, false).expect("fixed table"),
    )
}

/// A resumable inflater for one compressed stream.
pub struct Inflater {
    out: Vec<u8>,
    flushed: usize,
    total: u64,
    crc: crc32fast::Hasher,
    max_out: u64,
    start_bit: u64,
    last_ckpt: u64,
}

impl fmt::Debug for Inflater {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inflater")
            .field("total", &self.total)
            .field("max_out", &self.max_out)
            .finish()
    }
}

impl Inflater {
    /// Start (or resume) decoding at `ck`, refusing to produce more than `max_out` bytes.
    pub fn new(ck: &Checkpoint, max_out: u64) -> Self {
        Self {
            out: ck.window.clone(),
            flushed: ck.window.len(),
            total: ck.out_total,
            crc: crc32fast::Hasher::new_with_initial(ck.crc),
            max_out,
            start_bit: ck.in_bit,
            last_ckpt: ck.out_total,
        }
    }

    fn emit(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.flushed < self.out.len() {
            let pending = &self.out[self.flushed..];
            self.crc.update(pending);
            sink(pending)?;
            self.flushed = self.out.len();
        }
        if self.out.len() > WINDOW + FLUSH_AT {
            let drop = self.out.len() - WINDOW;
            self.out.drain(..drop);
            self.flushed = self.out.len();
        }
        Ok(())
    }

    fn push(&mut self, b: u8) -> Result<()> {
        self.total += 1;
        if self.total > self.max_out {
            return Err(InflateError::TooLong(self.max_out));
        }
        self.out.push(b);
        Ok(())
    }

    fn checkpoint(&self, in_bit: u64) -> Checkpoint {
        let w = self.out.len().min(WINDOW);
        Checkpoint {
            in_bit,
            out_total: self.total,
            crc: self.crc.clone().finalize(),
            window: self.out[self.out.len() - w..].to_vec(),
        }
    }

    /// Decode `[base, base + len)` of `src` to the end of the stream.
    ///
    /// Output is passed to `sink` in order. After a block boundary where at least `ckpt_every`
    /// bytes (if non-zero) have been produced since the last checkpoint, all output so far is
    /// passed to `sink` and then `on_ckpt` receives the state to resume from.
    pub fn run(
        mut self,
        src: &dyn FileHandle,
        base: u64,
        len: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        ckpt_every: u64,
        on_ckpt: &mut dyn FnMut(&Checkpoint) -> Result<()>,
    ) -> Result<Finished> {
        let mut br = BitReader::new(src, base, len, self.start_bit)?;
        let mut fixed: Option<(Huffman, Huffman)> = None;
        loop {
            let mut prof = trunc_prof::span("inflate.block");
            let before = self.total;
            let last = br.get(1)? == 1;
            match br.get(2)? {
                0 => self.stored(&mut br)?,
                1 => {
                    let (l, d) = fixed.get_or_insert_with(fixed_tables);
                    let (l, d) = (&*l, &*d);
                    self.codes(&mut br, l, d, sink)?;
                }
                2 => {
                    let (l, d) = dynamic_tables(&mut br)?;
                    self.codes(&mut br, &l, &d, sink)?;
                }
                _ => return Err(InflateError::Corrupt("invalid block type")),
            }
            prof.add_bytes(self.total - before);
            drop(prof);
            if self.out.len() - self.flushed >= FLUSH_AT {
                self.emit(sink)?;
            }
            if last {
                break;
            }
            if ckpt_every > 0 && self.total - self.last_ckpt >= ckpt_every {
                self.emit(sink)?;
                let ck = self.checkpoint(br.consumed);
                on_ckpt(&ck)?;
                self.last_ckpt = self.total;
            }
        }
        self.emit(sink)?;
        Ok(Finished {
            out_total: self.total,
            crc: self.crc.finalize(),
            in_bits: br.consumed,
        })
    }

    fn stored(&mut self, br: &mut BitReader<'_>) -> Result<()> {
        br.align()?;
        let n = br.get(16)?;
        let nn = br.get(16)?;
        if n != !nn & 0xFFFF {
            return Err(InflateError::Corrupt("stored block length check failed"));
        }
        for _ in 0..n {
            let b = u8::try_from(br.get(8)?).expect("8 bits");
            self.push(b)?;
        }
        Ok(())
    }

    fn codes(
        &mut self,
        br: &mut BitReader<'_>,
        lit: &Huffman,
        dist: &Huffman,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        // Decode into room beyond the output (`out[..op]` is real), so literals and matches are
        // plain stores and copies can go in 16-byte chunks that overshoot into the room.
        let mut op = self.out.len();
        let r = self.codes_into(br, lit, dist, sink, &mut op);
        self.out.truncate(op);
        r
    }

    fn codes_into(
        &mut self,
        br: &mut BitReader<'_>,
        lit: &Huffman,
        dist: &Huffman,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
        op: &mut usize,
    ) -> Result<()> {
        // Longest match plus a chunk's overshoot.
        const ROOM: usize = 258 + 16;
        const GROW: usize = 64 * 1024;
        let limit = br.len.saturating_mul(8);
        let mut o = *op;
        loop {
            if o + ROOM > self.out.len() {
                self.out.truncate(o);
                if self.out.len() - self.flushed >= FLUSH_AT + WINDOW {
                    self.emit(sink)?;
                }
                o = self.out.len();
                self.out.resize(o + GROW, 0);
            }
            // One refill covers a whole length/distance pair: at most 15 + 5 + 15 + 13 bits.
            if br.nbits < 48 {
                br.fill()?;
            }
            let sym = lit.decode_filled(br)?;
            if br.consumed > limit {
                *op = o;
                return Err(InflateError::Overrun);
            }
            if sym < 256 {
                self.total += 1;
                if self.total > self.max_out {
                    *op = o;
                    return Err(InflateError::TooLong(self.max_out));
                }
                #[allow(clippy::cast_possible_truncation)] // below 256
                let b = sym as u8;
                self.out[o] = b;
                o += 1;
                continue;
            }
            if sym == 256 {
                *op = o;
                return Ok(());
            }
            if sym > 285 {
                *op = o;
                return Err(InflateError::Corrupt("invalid literal/length symbol"));
            }
            let i = usize::from(sym - 257);
            if br.nbits < 40 {
                br.fill()?;
            }
            let len = usize::from(LBASE[i]) + br.take(u32::from(LEXT[i])) as usize;
            let ds = usize::from(dist.decode_filled(br)?);
            if ds >= 30 {
                *op = o;
                return Err(InflateError::Corrupt("invalid distance symbol"));
            }
            if br.nbits < 13 {
                br.fill()?;
            }
            let d = usize::from(DBASE[ds]) + br.take(u32::from(DEXT[ds])) as usize;
            if br.consumed > limit {
                *op = o;
                return Err(InflateError::Overrun);
            }
            if d > o || d as u64 > self.total {
                *op = o;
                return Err(InflateError::Corrupt("distance too far back"));
            }
            self.total += len as u64;
            if self.total > self.max_out {
                *op = o;
                return Err(InflateError::TooLong(self.max_out));
            }
            let src = o - d;
            let buf = self.out.as_mut_slice();
            if d >= 16 {
                // Each chunk reads only bytes already written.
                let mut k = 0;
                while k < len {
                    let t: [u8; 16] = buf[src + k..src + k + 16].try_into().expect("16");
                    buf[o + k..o + k + 16].copy_from_slice(&t);
                    k += 16;
                }
            } else {
                // A short period: copy whole periods from the start of the match, doubling.
                let mut done = 0;
                while done < len {
                    let n = (len - done).min(d + done);
                    buf.copy_within(src..src + n, o + done);
                    done += n;
                }
            }
            o += len;
        }
    }
}

fn dynamic_tables(br: &mut BitReader<'_>) -> Result<(Huffman, Huffman)> {
    let hlit = br.get(5)? as usize + 257;
    let hdist = br.get(5)? as usize + 1;
    let hclen = br.get(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::Corrupt("too many length or distance codes"));
    }
    let mut cl = [0u8; 19];
    for &i in &CL_ORDER[..hclen] {
        cl[i] = u8::try_from(br.get(3)?).expect("3 bits");
    }
    let clh = Huffman::new(&cl, false)?;
    let mut lengths = vec![0u8; hlit + hdist];
    let mut i = 0;
    while i < lengths.len() {
        let sym = clh.decode(br)?;
        let (val, rep) = match sym {
            0..=15 => (u8::try_from(sym).expect("< 16"), 1),
            16 => {
                if i == 0 {
                    return Err(InflateError::Corrupt("repeat with no previous length"));
                }
                (lengths[i - 1], 3 + br.get(2)? as usize)
            }
            17 => (0, 3 + br.get(3)? as usize),
            18 => (0, 11 + br.get(7)? as usize),
            _ => return Err(InflateError::Corrupt("invalid code-length symbol")),
        };
        if i + rep > lengths.len() {
            return Err(InflateError::Corrupt("code lengths overflow"));
        }
        lengths[i..i + rep].fill(val);
        i += rep;
    }
    if lengths[256] == 0 {
        return Err(InflateError::Corrupt("no end-of-block code"));
    }
    Ok((
        Huffman::new(&lengths[..hlit], true)?,
        Huffman::new(&lengths[hlit..], true)?,
    ))
}

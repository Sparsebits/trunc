//! bzip2 decoder that can resume at any block boundary.
//!
//! A bzip2 stream is a header (`BZh` and the block size, `1`-`9` hundred kB) followed by
//! blocks and an end-of-stream marker, all bit-aligned. Each block is independent: Huffman-coded
//! move-to-front symbols, a Burrows–Wheeler transform and a run-length pass, checked by a
//! CRC-32. The streams' CRCs combine into one per stream. Files made by `pbzip2` hold several
//! streams back to back; their outputs concatenate.
//!
//! Because blocks are independent, the decoder state between blocks is only the bit position,
//! the output total and the running combined CRC, so a safe point needs no window.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use trunc_fs::FileHandle;

use crate::stream::{
    self, Fields, Input, Limits, OnPoint, SafePoint, Sink, StreamEnd, StreamError,
};

const BLOCK_MAGIC: u64 = 0x3141_5926_5359;
const EOS_MAGIC: u64 = 0x1772_4538_5090;
const READ_CHUNK: usize = 256 * 1024;
/// Output is handed to the sink once this much has accumulated.
const FLUSH_AT: usize = 1 << 20;
const MAX_GROUPS: usize = 6;
const MAX_CODE_LEN: u32 = 20;
const GROUP_SIZE: usize = 50;
/// Selectors beyond this are read and ignored, as bzip2 1.0.8 does.
const MAX_SELECTORS: usize = 18_002;
const FAST_BITS: u32 = 10;

fn corrupt(at_bit: u64, why: &str) -> StreamError {
    StreamError::Corrupt(format!(
        "corrupt bzip2 data near byte {}: {why}",
        at_bit / 8
    ))
}

/// CRC-32 with the polynomial 0x04C11DB7, most significant bit first (as bzip2 uses it), with
/// slicing-by-8 tables (`table[k][i]`: byte `i` followed by `k` zero bytes).
struct Crc {
    table: Box<[[u32; 256]; 8]>,
}

impl Crc {
    fn new() -> Self {
        let mut table = Box::new([[0u32; 256]; 8]);
        for i in 0..256 {
            let mut c = (i as u32) << 24;
            for _ in 0..8 {
                c = if c & 0x8000_0000 != 0 {
                    (c << 1) ^ 0x04C1_1DB7
                } else {
                    c << 1
                };
            }
            table[0][i] = c;
        }
        for k in 1..8 {
            for i in 0..256 {
                let prev = table[k - 1][i];
                table[k][i] = (prev << 8) ^ table[0][(prev >> 24) as usize];
            }
        }
        Self { table }
    }

    fn update(&self, mut crc: u32, data: &[u8]) -> u32 {
        let t = &*self.table;
        let mut words = data.chunks_exact(8);
        for w in &mut words {
            let hi = crc ^ u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
            crc = t[7][(hi >> 24) as usize]
                ^ t[6][((hi >> 16) & 0xFF) as usize]
                ^ t[5][((hi >> 8) & 0xFF) as usize]
                ^ t[4][(hi & 0xFF) as usize]
                ^ t[3][usize::from(w[4])]
                ^ t[2][usize::from(w[5])]
                ^ t[1][usize::from(w[6])]
                ^ t[0][usize::from(w[7])];
        }
        for &b in words.remainder() {
            crc = (crc << 8) ^ t[0][((crc >> 24) as u8 ^ b) as usize];
        }
        crc
    }

    /// `n` copies of `b`.
    fn update_run(&self, mut crc: u32, b: u8, n: usize) -> u32 {
        let block = [b; 64];
        let mut left = n;
        while left >= 64 {
            crc = self.update(crc, &block);
            left -= 64;
        }
        self.update(crc, &block[..left])
    }
}

/// Reads bits most-significant first from `[0, len)` of a file, from any bit position.
struct Bits<'a> {
    src: &'a dyn FileHandle,
    len: u64,
    buf: Vec<u8>,
    buf_pos: usize,
    /// File offset of the next byte to load into `buf`.
    next_load: u64,
    acc: u64,
    n: u32,
    /// Bits handed out so far (absolute position in the file).
    pos: u64,
    /// Bytes read from the file at a time.
    chunk: usize,
}

impl<'a> Bits<'a> {
    fn new(src: &'a dyn FileHandle, len: u64, start_bit: u64) -> stream::Result<Self> {
        Self::with_chunk(src, len, start_bit, READ_CHUNK)
    }

    /// A reader that loads `chunk` bytes at a time (small for a reader that only looks at
    /// headers between blocks decoded elsewhere).
    fn with_chunk(
        src: &'a dyn FileHandle,
        len: u64,
        start_bit: u64,
        chunk: usize,
    ) -> stream::Result<Self> {
        let mut b = Self {
            src,
            len,
            buf: Vec::new(),
            buf_pos: 0,
            next_load: start_bit / 8,
            acc: 0,
            n: 0,
            pos: start_bit / 8 * 8,
            chunk,
        };
        if start_bit / 8 > len {
            return Err(corrupt(start_bit, "position past the end of the file"));
        }
        let skip = u32::try_from(start_bit % 8).expect("< 8");
        if skip > 0 {
            b.get(skip)?;
        }
        Ok(b)
    }

    /// Top up the accumulator to at least `k` bits (k <= 56) if the file has them.
    fn fill(&mut self, k: u32) -> stream::Result<()> {
        while self.n < k {
            if self.buf_pos == self.buf.len() {
                if self.next_load >= self.len {
                    return Ok(());
                }
                let n = usize::try_from((self.len - self.next_load).min(self.chunk as u64))
                    .expect("<= chunk");
                self.buf.resize(n, 0);
                self.src.read_exact_at(&mut self.buf, self.next_load)?;
                self.next_load += n as u64;
                self.buf_pos = 0;
            }
            self.acc = (self.acc << 8) | u64::from(self.buf[self.buf_pos]);
            self.buf_pos += 1;
            self.n += 8;
        }
        Ok(())
    }

    fn get(&mut self, k: u32) -> stream::Result<u32> {
        debug_assert!(k <= 32);
        self.fill(k)?;
        if self.n < k {
            return Err(corrupt(
                self.pos,
                "unexpected end of file (truncated download?)",
            ));
        }
        self.n -= k;
        self.pos += u64::from(k);
        Ok(((self.acc >> self.n) & ((1u64 << k) - 1)) as u32)
    }

    fn get64(&mut self, k: u32) -> stream::Result<u64> {
        let hi = self.get(k - 32)?;
        let lo = self.get(32)?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    /// The next `k` bits without consuming them; missing bits past the end read as zero.
    fn peek(&mut self, k: u32) -> stream::Result<u32> {
        self.fill(k)?;
        let v = if self.n >= k {
            self.acc >> (self.n - k)
        } else {
            self.acc << (k - self.n)
        };
        Ok((v & ((1u64 << k) - 1)) as u32)
    }

    fn skip(&mut self, k: u32) -> stream::Result<()> {
        if self.n < k {
            return Err(corrupt(
                self.pos,
                "unexpected end of file (truncated download?)",
            ));
        }
        self.n -= k;
        self.pos += u64::from(k);
        Ok(())
    }

    fn align(&mut self) -> stream::Result<()> {
        let r = u32::try_from(self.pos % 8).expect("< 8");
        if r > 0 {
            self.get(8 - r)?;
        }
        Ok(())
    }
}

/// A canonical Huffman code over at most 258 symbols, codes of 1 to 20 bits.
struct Huffman {
    min_len: u32,
    max_len: u32,
    /// `(symbol, length)` for codes of up to `FAST_BITS` bits, indexed by the next bits.
    fast: Vec<(u16, u8)>,
    /// Per length: first code, last code (or -1), and index of its first symbol in `perm`.
    first: [i64; 21],
    last: [i64; 21],
    offset: [usize; 21],
    perm: Vec<u16>,
}

impl Huffman {
    fn new(lens: &[u8], at: u64) -> stream::Result<Self> {
        let mut count = [0usize; 21];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        let min_len = (1..=20).find(|&l| count[l] > 0).unwrap_or(1) as u32;
        let max_len = (1..=20).rev().find(|&l| count[l] > 0).unwrap_or(1) as u32;
        let mut perm = Vec::with_capacity(lens.len());
        let mut first = [0i64; 21];
        let mut last = [-1i64; 21];
        let mut offset = [0usize; 21];
        let mut code = 0i64;
        for len in 1..=20usize {
            offset[len] = perm.len();
            for (sym, &l) in lens.iter().enumerate() {
                if usize::from(l) == len {
                    perm.push(sym as u16);
                }
            }
            first[len] = code;
            code += count[len] as i64;
            last[len] = code - 1;
            if code > 1i64 << len {
                return Err(corrupt(at, "Huffman code lengths are over-subscribed"));
            }
            code <<= 1;
        }
        let mut fast = vec![(0u16, 0u8); 1 << FAST_BITS];
        for len in 1..=FAST_BITS as usize {
            for k in 0..count[len] {
                let c = (first[len] + k as i64) as usize;
                let sym = perm[offset[len] + k];
                let shift = FAST_BITS as usize - len;
                for e in &mut fast[c << shift..(c + 1) << shift] {
                    *e = (sym, len as u8);
                }
            }
        }
        Ok(Self {
            min_len,
            max_len,
            fast,
            first,
            last,
            offset,
            perm,
        })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> stream::Result<u16> {
        let p = bits.peek(FAST_BITS)?;
        let (sym, len) = self.fast[p as usize];
        if len > 0 {
            bits.skip(u32::from(len))?;
            return Ok(sym);
        }
        let v = i64::from(bits.peek(self.max_len)?);
        for len in self.min_len.max(FAST_BITS + 1)..=self.max_len {
            let c = v >> (self.max_len - len);
            let l = len as usize;
            if c <= self.last[l] && c >= self.first[l] {
                bits.skip(len)?;
                return Ok(self.perm[self.offset[l] + (c - self.first[l]) as usize]);
            }
        }
        Err(corrupt(bits.pos, "invalid Huffman code"))
    }
}

/// Decoder state between blocks.
///
/// Cursor bytes: `bit position u64 | output total u64 | combined CRC u32 | block size u8`, where
/// a block size of 0 means the next thing to read is a stream header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    bit: u64,
    out: u64,
    combined: u32,
    level: u8,
}

impl State {
    fn encode(&self) -> Vec<u8> {
        let mut b = self.bit.to_le_bytes().to_vec();
        b.extend_from_slice(&self.out.to_le_bytes());
        b.extend_from_slice(&self.combined.to_le_bytes());
        b.push(self.level);
        b
    }

    fn decode(b: &[u8]) -> stream::Result<Self> {
        let mut f = Fields::new(b);
        let s = (|| {
            Some(Self {
                bit: f.u64()?,
                out: f.u64()?,
                combined: f.u32()?,
                level: f.u8()?,
            })
        })()
        .ok_or_else(stream::bad_cursor)?;
        if !f.done() || s.level > 9 {
            return Err(stream::bad_cursor());
        }
        Ok(s)
    }
}

/// Collects output and hands it to the sink in large pieces.
struct Out<'s, 'a> {
    sink: &'s mut Sink<'a>,
    buf: Vec<u8>,
    total: u64,
    max_out: u64,
}

impl Out<'_, '_> {
    fn push(&mut self, data: &[u8]) -> stream::Result<()> {
        self.total += data.len() as u64;
        if self.total > self.max_out {
            return Err(StreamError::Corrupt(format!(
                "decoded more than the expected {} bytes",
                self.max_out
            )));
        }
        self.buf.extend_from_slice(data);
        if self.buf.len() >= FLUSH_AT {
            self.flush()?;
        }
        Ok(())
    }

    fn push_run(&mut self, b: u8, n: usize) -> stream::Result<()> {
        self.total += n as u64;
        if self.total > self.max_out {
            return Err(StreamError::Corrupt(format!(
                "decoded more than the expected {} bytes",
                self.max_out
            )));
        }
        self.buf.resize(self.buf.len() + n, b);
        if self.buf.len() >= FLUSH_AT {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> stream::Result<()> {
        if !self.buf.is_empty() {
            (self.sink)(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
}

/// Scratch space reused across blocks.
struct Scratch {
    block: Vec<u8>,
    next: Vec<u32>,
    crc: Crc,
}

/// Decode one block (after its magic) and emit its output. Returns the block's CRC and its
/// size before the final run-length pass (at most `level` hundred kB).
fn block(
    bits: &mut Bits<'_>,
    level: u8,
    s: &mut Scratch,
    out: &mut Out<'_, '_>,
) -> stream::Result<(u32, usize)> {
    let mut prof = trunc_prof::span("bzip2.block");
    let start_out = out.total;
    let at = bits.pos;
    let stored_crc = bits.get(32)?;
    if bits.get(1)? == 1 {
        return Err(StreamError::Unsupported(
            "bzip2 blocks in the obsolete randomised format are not supported".into(),
        ));
    }
    let orig_ptr = bits.get(24)? as usize;

    // Which byte values occur.
    let used = bits.get(16)?;
    let mut seq = Vec::with_capacity(256);
    for i in 0..16 {
        if used & (0x8000 >> i) != 0 {
            let m = bits.get(16)?;
            for j in 0..16 {
                if m & (0x8000 >> j) != 0 {
                    seq.push((i * 16 + j) as u8);
                }
            }
        }
    }
    if seq.is_empty() {
        return Err(corrupt(at, "block uses no byte values"));
    }
    let alpha = seq.len() + 2;

    let n_groups = bits.get(3)? as usize;
    if !(2..=MAX_GROUPS).contains(&n_groups) {
        return Err(corrupt(at, "bad number of Huffman tables"));
    }
    let n_sel = bits.get(15)? as usize;
    if n_sel == 0 {
        return Err(corrupt(at, "no selectors"));
    }
    let mut mtf_groups: Vec<u8> = (0..n_groups as u8).collect();
    let mut selectors = Vec::with_capacity(n_sel.min(MAX_SELECTORS));
    for _ in 0..n_sel {
        let mut j = 0usize;
        while bits.get(1)? == 1 {
            j += 1;
            if j >= n_groups {
                return Err(corrupt(at, "bad selector"));
            }
        }
        let v = mtf_groups[j];
        mtf_groups.copy_within(0..j, 1);
        mtf_groups[0] = v;
        if selectors.len() < MAX_SELECTORS {
            selectors.push(v);
        }
    }

    let mut tables = Vec::with_capacity(n_groups);
    for _ in 0..n_groups {
        let mut lens = vec![0u8; alpha];
        let mut cur = bits.get(5)?;
        for l in &mut lens {
            loop {
                if !(1..=MAX_CODE_LEN).contains(&cur) {
                    return Err(corrupt(at, "bad Huffman code length"));
                }
                if bits.get(1)? == 0 {
                    break;
                }
                if bits.get(1)? == 0 {
                    cur += 1;
                } else {
                    cur -= 1;
                }
            }
            *l = cur as u8;
        }
        tables.push(Huffman::new(&lens, at)?);
    }

    // Huffman + run-length + move-to-front decoding into the BWT block.
    let huff = trunc_prof::span("bzip2.huffman");
    let max_block = usize::from(level) * 100_000;
    let eob = (alpha - 1) as u16;
    // All 256 byte values may occur, so count in usize before narrowing.
    let mut mtf: Vec<u8> = (0..seq.len()).map(|i| i as u8).collect();
    let block = &mut s.block;
    block.clear();
    let mut counts = [0usize; 256];
    let (mut run, mut run_bit) = (0usize, 0u32);
    let mut sel_i = 0usize;
    let mut left = 0usize;
    let mut table = &tables[0];
    loop {
        if left == 0 {
            let &g = selectors
                .get(sel_i)
                .ok_or_else(|| corrupt(at, "ran out of selectors"))?;
            table = &tables[usize::from(g)];
            sel_i += 1;
            left = GROUP_SIZE;
        }
        left -= 1;
        let sym = table.decode(bits)?;
        if sym <= 1 {
            // RUNA / RUNB: a bijective base-2 run length of the front symbol.
            if run_bit > 24 {
                return Err(corrupt(at, "run too long"));
            }
            run += (usize::from(sym) + 1) << run_bit;
            run_bit += 1;
            if run > max_block {
                return Err(corrupt(at, "block larger than its declared size"));
            }
            continue;
        }
        if run > 0 {
            let b = seq[usize::from(mtf[0])];
            if block.len() + run > max_block {
                return Err(corrupt(at, "block larger than its declared size"));
            }
            counts[usize::from(b)] += run;
            block.resize(block.len() + run, b);
            run = 0;
            run_bit = 0;
        }
        if sym == eob {
            break;
        }
        let idx = usize::from(sym - 1);
        if idx >= mtf.len() {
            return Err(corrupt(at, "symbol out of range"));
        }
        let v = mtf[idx];
        mtf.copy_within(0..idx, 1);
        mtf[0] = v;
        let b = seq[usize::from(v)];
        if block.len() >= max_block {
            return Err(corrupt(at, "block larger than its declared size"));
        }
        counts[usize::from(b)] += 1;
        block.push(b);
    }
    let n = block.len();
    if n == 0 || orig_ptr >= n {
        return Err(corrupt(at, "bad BWT origin pointer"));
    }

    drop(huff);
    // Inverse Burrows–Wheeler transform.
    let bwt = trunc_prof::span("bzip2.bwt");
    let mut cf = [0usize; 256];
    let mut sum = 0usize;
    for (c, &k) in counts.iter().enumerate() {
        cf[c] = sum;
        sum += k;
    }
    let next = &mut s.next;
    next.clear();
    next.resize(n, 0);
    for (i, &b) in block.iter().enumerate() {
        next[cf[usize::from(b)]] = i as u32;
        cf[usize::from(b)] += 1;
    }

    drop(bwt);
    let _rle = trunc_prof::span("bzip2.rle_crc");
    // Undo the initial run-length pass while emitting: after four equal bytes, the next byte
    // is a count of further copies.
    let mut crc = 0xFFFF_FFFFu32;
    let mut pos = next[orig_ptr] as usize;
    let (mut last, mut same) = (256u16, 0u32);
    let mut lit = Vec::with_capacity(4096);
    for _ in 0..n {
        let b = block[pos];
        pos = next[pos] as usize;
        if same == 4 {
            crc = s.crc.update(crc, &lit);
            out.push(&lit)?;
            lit.clear();
            let reps = usize::from(b);
            crc = s.crc.update_run(crc, last as u8, reps);
            out.push_run(last as u8, reps)?;
            same = 0;
            continue;
        }
        lit.push(b);
        if u16::from(b) == last {
            same += 1;
        } else {
            last = u16::from(b);
            same = 1;
        }
        if lit.len() == lit.capacity() {
            crc = s.crc.update(crc, &lit);
            out.push(&lit)?;
            lit.clear();
        }
    }
    crc = s.crc.update(crc, &lit);
    out.push(&lit)?;
    let crc = !crc;
    if crc != stored_crc {
        return Err(corrupt(at, "block CRC mismatch"));
    }
    prof.add_bytes(out.total - start_out);
    Ok((crc, n))
}

/// A block decoded on a worker thread, from where its magic starts.
struct Decoded {
    out: Vec<u8>,
    crc: u32,
    /// Size before the final run-length pass (checked against the stream's block size).
    n: usize,
    /// Bit position just past the block.
    end_bit: u64,
}

/// Decode the block whose magic starts at bit `at`. The block size is not known here (it
/// belongs to the stream), so the largest is allowed and the caller checks.
fn decode_at(src: &dyn FileHandle, len: u64, at: u64) -> stream::Result<Decoded> {
    let mut bits = Bits::new(src, len, at)?;
    if bits.get64(48)? != BLOCK_MAGIC {
        return Err(corrupt(at, "bad block magic"));
    }
    thread_local! {
        // Reused by each worker thread: fresh multi-megabyte buffers per block would be zeroed
        // and page-faulted in every time, and threads doing that at once contend in the kernel.
        static SCRATCH: std::cell::RefCell<Option<Scratch>> = const { std::cell::RefCell::new(None) };
    }
    let mut v = Vec::with_capacity(4 << 20);
    let mut sink = |b: &[u8]| -> stream::Result<()> {
        v.extend_from_slice(b);
        Ok(())
    };
    let mut out = Out {
        sink: &mut sink,
        buf: Vec::with_capacity(FLUSH_AT + 64 * 1024),
        total: 0,
        max_out: u64::MAX,
    };
    let (crc, n) = SCRATCH.with(|cell| {
        let mut slot = cell.borrow_mut();
        let scratch = slot.get_or_insert_with(|| Scratch {
            block: Vec::new(),
            next: Vec::new(),
            crc: Crc::new(),
        });
        block(&mut bits, 9, scratch, &mut out)
    })?;
    out.flush()?;
    let end_bit = bits.pos;
    drop(out);
    Ok(Decoded {
        out: v,
        crc,
        n,
        end_bit,
    })
}

/// Bit positions at or after `from_bit` where the block magic appears. Some may be inside
/// compressed data rather than real block starts; the decoder only uses the one at the position
/// it expects. A file with implausibly many (a crafted one: the magic over and over) gets none,
/// and is decoded on one thread; candidates never change the output or the safe points.
fn find_blocks(
    src: &dyn FileHandle,
    len: u64,
    from_bit: u64,
    threads: usize,
) -> stream::Result<Vec<u64>> {
    let _prof = trunc_prof::span("bzip2.find_blocks");
    const CHUNK: u64 = 8 << 20;
    const MASK: u64 = (1 << 48) - 1;
    /// At most this many candidates in all (32 MiB), and per chunk.
    const MAX: usize = 1 << 22;
    const MAX_PER_CHUNK: usize = 1 << 18;
    let first = from_bit / 8;
    let chunks = usize::try_from(len.saturating_sub(first).div_ceil(CHUNK)).unwrap_or(0);
    let mut found = Vec::new();
    let scan = |c: usize| -> stream::Result<Vec<u64>> {
        let start = first + c as u64 * CHUNK;
        let own = (len - start).min(CHUNK);
        // Read a little past the chunk so a magic straddling the edge is seen.
        let n = usize::try_from((len - start).min(CHUNK + 8)).expect("<= chunk");
        let mut buf = vec![0u8; n + 8];
        src.read_exact_at(&mut buf[..n], start)?;
        let mut hits = Vec::new();
        for i in 0..usize::try_from(own).expect("<= chunk") {
            let w = u64::from_be_bytes(buf[i..i + 8].try_into().expect("8"));
            for shift in 0..8u64 {
                if (w >> (16 - shift)) & MASK == BLOCK_MAGIC {
                    let bit = (start + i as u64) * 8 + shift;
                    if bit >= from_bit {
                        if hits.len() == MAX_PER_CHUNK {
                            return Err(StreamError::Stopped);
                        }
                        hits.push(bit);
                    }
                }
            }
        }
        Ok(hits)
    };
    let r = stream::ordered_parallel(chunks, threads, threads * 2, &scan, &mut |_, hits| {
        if found.len() + hits.len() > MAX {
            return Err(StreamError::Stopped);
        }
        found.extend(hits);
        Ok(())
    });
    match r {
        Ok(()) => Ok(found),
        Err(StreamError::Stopped) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// True if `[from, len)` of the file is empty or all zeros.
fn only_zeros(src: &dyn FileHandle, from: u64, len: u64) -> stream::Result<bool> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = from;
    while off < len {
        let n = usize::try_from((len - off).min(buf.len() as u64)).expect("<= 64 KiB");
        src.read_exact_at(&mut buf[..n], off)?;
        if buf[..n].iter().any(|&c| c != 0) {
            return Ok(false);
        }
        off += n as u64;
    }
    Ok(true)
}

/// Decode a bzip2 file (one or more streams). Safe points are block boundaries (and stream
/// boundaries) once `every` bytes have been produced since the previous one.
pub fn decode(
    input: Input<'_>,
    start: Option<&[u8]>,
    limits: Limits,
    every: u64,
    sink: &mut Sink<'_>,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let Input { src, len } = input;
    let mut st = match start {
        Some(c) => State::decode(c)?,
        None => State {
            bit: 0,
            out: 0,
            combined: 0,
            level: 0,
        },
    };
    let mut bits = Bits::new(src, len, st.bit)?;
    let mut scratch = Scratch {
        block: Vec::new(),
        next: Vec::new(),
        crc: Crc::new(),
    };
    let mut out = Out {
        sink,
        buf: Vec::with_capacity(FLUSH_AT + 64 * 1024),
        total: st.out,
        max_out: limits.max_out,
    };
    // Decode blocks ahead on worker threads: every block is independent. Files smaller than a
    // couple of blocks are not worth the threads.
    let threads = if len >= 2 << 20 { limits.workers() } else { 1 };
    let cands = {
        #[allow(unused_mut)]
        let mut c = if threads > 1 {
            find_blocks(src, len, st.bit, threads)?
        } else {
            Vec::new()
        };
        #[cfg(test)]
        BOGUS.with(|b| {
            // Tests plant false magic positions to check they are ignored.
            c.extend(b.borrow().iter().copied());
            c.sort_unstable();
            c.dedup();
        });
        c
    };
    let work = |k: usize| decode_at(src, len, cands[k]);
    stream::with_ahead(cands.len(), threads, threads + 2, &work, |ahead| {
        drive(
            src,
            len,
            &mut bits,
            &mut st,
            &mut scratch,
            &mut out,
            &cands,
            ahead,
            start.is_none(),
            every,
            on_point,
        )
    })
}

/// The decoding loop: stream headers, blocks (pre-decoded by `ahead` where it has them) and
/// end-of-stream markers.
#[allow(clippy::too_many_arguments)]
fn drive<'f>(
    src: &'f dyn FileHandle,
    len: u64,
    bits: &mut Bits<'f>,
    st: &mut State,
    scratch: &mut Scratch,
    out: &mut Out<'_, '_>,
    cands: &[u64],
    ahead: Option<&stream::Ahead<'_, stream::Result<Decoded>>>,
    mut first: bool,
    every: u64,
    on_point: &mut OnPoint<'_>,
) -> stream::Result<StreamEnd> {
    let mut since = 0u64;
    let mut units = 0u32;
    loop {
        if st.level == 0 {
            // A stream header, byte-aligned.
            let at = bits.pos;
            let ok = bits.fill(32).is_ok() && bits.n >= 32;
            let head = if ok { bits.peek(32)? } else { 0 };
            if head >> 8 != 0x42_5A_68
                || !(u32::from(b'1')..=u32::from(b'9')).contains(&(head & 0xFF))
            {
                return Err(if first {
                    StreamError::Format("not a bzip2 file".into())
                } else {
                    corrupt(at, "data after the end of a stream is not another stream")
                });
            }
            bits.skip(32)?;
            st.level = (head & 0xFF) as u8 - b'0';
            st.combined = 0;
            first = false;
        }
        let at = bits.pos;
        let magic = bits.get64(48)?;
        if magic == BLOCK_MAGIC {
            let before = out.total;
            let k = ahead.and_then(|_| cands.binary_search(&at).ok());
            let crc = match (ahead, k) {
                (Some(a), Some(k)) => {
                    let d = a.get(k)?;
                    if d.n > usize::from(st.level) * 100_000 {
                        return Err(corrupt(at, "block larger than its declared size"));
                    }
                    out.push(&d.out)?;
                    *bits = Bits::with_chunk(src, len, d.end_bit, 4096)?;
                    d.crc
                }
                _ => block(bits, st.level, scratch, out)?.0,
            };
            st.combined = st.combined.rotate_left(1) ^ crc;
            since += out.total - before;
            if every > 0 && since >= every {
                out.flush()?;
                since = 0;
                st.bit = bits.pos;
                st.out = out.total;
                let cursor = st.encode();
                on_point(SafePoint {
                    cursor: &cursor,
                    out: st.out,
                    free_below: st.bit / 8,
                })?;
            }
        } else if magic == EOS_MAGIC {
            let stored = bits.get(32)?;
            if stored != st.combined {
                return Err(corrupt(at, "stream CRC mismatch"));
            }
            units += 1;
            bits.align()?;
            let next = bits.pos / 8;
            if next >= len || only_zeros(src, next, len)? {
                out.flush()?;
                return Ok(StreamEnd {
                    out_len: out.total,
                    units,
                });
            }
            st.level = 0;
            if every > 0 && since >= every {
                out.flush()?;
                since = 0;
                st.bit = bits.pos;
                st.out = out.total;
                let cursor = st.encode();
                on_point(SafePoint {
                    cursor: &cursor,
                    out: st.out,
                    free_below: next,
                })?;
            }
        } else {
            return Err(corrupt(at, "bad block magic"));
        }
    }
}

#[cfg(test)]
thread_local! {
    static BOGUS: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_magic_positions_are_ignored() {
        use std::path::Path;
        use trunc_fs::{FsBackend, OpenMode, Share};
        let mut rng = trunc_testkit::Rng::new(5);
        let data = trunc_testkit::fixtures::noise_bytes(&mut rng, 3 << 20);
        let bytes = trunc_testkit::tarbuild::bzip2(&data, 1);
        let fs = trunc_testkit::FaultFs::new(trunc_testkit::CrashModel::WriteThrough);
        fs.put_file(Path::new("/b"), &bytes);
        let h = fs
            .open(Path::new("/b"), OpenMode::Read, Share::Shared)
            .unwrap();
        let len = bytes.len() as u64;
        let real = find_blocks(h.as_ref(), len, 0, 4).unwrap();
        assert!(real.len() > 10, "{} blocks", real.len());
        // Positions inside blocks, one bit off a real start, and near the end.
        let bogus: Vec<u64> = real
            .iter()
            .flat_map(|&b| [b + 1, b + 777, b.saturating_sub(3)])
            .chain([len * 8 - 60])
            .collect();
        BOGUS.with(|b| *b.borrow_mut() = bogus);
        let mut out = Vec::new();
        let limits = Limits {
            threads: 4,
            ..Limits::new(u64::MAX)
        };
        let r = decode(
            Input {
                src: h.as_ref(),
                len,
            },
            None,
            limits,
            0,
            &mut |b| {
                out.extend_from_slice(b);
                Ok(())
            },
            &mut |_| Ok(()),
        );
        BOGUS.with(|b| b.borrow_mut().clear());
        r.unwrap();
        assert!(out == data);
    }

    #[test]
    fn crc_matches_the_reference_check_value() {
        // CRC-32/BZIP2 of "123456789" is 0xFC891918.
        let c = Crc::new();
        assert_eq!(!c.update(0xFFFF_FFFF, b"123456789"), 0xFC89_1918);
        // Sliced and bytewise agree at every length, and runs equal repeated bytes.
        let data: Vec<u8> = (0..200u32).map(|i| (i * 13 + i / 5) as u8).collect();
        for n in 0..data.len() {
            let mut slow = 0xFFFF_FFFFu32;
            for &b in &data[..n] {
                slow = (slow << 8) ^ c.table[0][((slow >> 24) as u8 ^ b) as usize];
            }
            assert_eq!(c.update(0xFFFF_FFFF, &data[..n]), slow, "length {n}");
            assert_eq!(
                c.update_run(7, 0x5A, n),
                c.update(7, &vec![0x5A; n]),
                "run {n}"
            );
        }
    }

    #[test]
    fn cursors_round_trip() {
        let s = State {
            bit: 12345,
            out: 1 << 40,
            combined: 0xDEAD_BEEF,
            level: 9,
        };
        assert_eq!(State::decode(&s.encode()).unwrap(), s);
        assert!(State::decode(&s.encode()[1..]).is_err());
    }
}

//! The two bit orders zstd uses: forward, least significant bit first (FSE table
//! descriptions), and backward from a final marker bit (Huffman and sequence bitstreams).

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use super::corrupt;
use crate::stream;

/// Reads bits least-significant first from the start of a slice.
pub(super) struct Forward<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Forward<'a> {
    pub(super) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    /// The next `n` bits (n <= 32) without consuming them; bits past the end read as zero.
    pub(super) fn peek(&self, n: u32) -> u32 {
        let mut v = 0u64;
        let byte = self.pos / 8;
        for i in 0..5 {
            if let Some(&c) = self.b.get(byte + i) {
                v |= u64::from(c) << (8 * i);
            }
        }
        ((v >> (self.pos % 8)) & ((1u64 << n) - 1)) as u32
    }

    pub(super) fn skip(&mut self, n: u32) -> stream::Result<()> {
        self.pos += n as usize;
        if self.pos > self.b.len() * 8 {
            return Err(corrupt("table description runs past its block"));
        }
        Ok(())
    }

    pub(super) fn read(&mut self, n: u32) -> stream::Result<u32> {
        let v = self.peek(n);
        self.skip(n)?;
        Ok(v)
    }

    /// Bytes used so far, counting a partly used byte.
    pub(super) fn bytes_used(&self) -> usize {
        self.pos.div_ceil(8)
    }
}

/// Reads a bitstream backward: it starts at the highest set bit of the last byte (a marker)
/// and each read takes the next bits below. Reading past the start yields zeros and is
/// detected with [`Backward::overflowed`].
///
/// The bits just below the read position are kept left-aligned in a 64-bit accumulator, so a
/// read is two shifts; the accumulator is refilled from memory once fewer than 57 bits remain.
pub(super) struct Backward<'a> {
    b: &'a [u8],
    /// Bits not yet read: they are `[0, pos)`.
    pos: i64,
    /// The bits just below `pos`, most significant first.
    acc: u64,
    /// How many of `acc`'s top bits are valid (below the start of the stream they read as zeros).
    avail: u32,
}

impl<'a> Backward<'a> {
    pub(super) fn new(b: &'a [u8]) -> stream::Result<Self> {
        let &last = b.last().ok_or_else(|| corrupt("empty bitstream"))?;
        if last == 0 {
            return Err(corrupt("bitstream has no end marker"));
        }
        let pos = (b.len() as i64 - 1) * 8 + i64::from(7 - last.leading_zeros());
        let mut s = Self {
            b,
            pos,
            acc: 0,
            avail: 0,
        };
        s.refill();
        Ok(s)
    }

    #[inline]
    fn refill(&mut self) {
        if self.pos <= 0 {
            self.acc = 0;
            self.avail = 64;
            return;
        }
        let pos = self.pos as usize;
        let end = pos.div_ceil(8);
        let start = end.saturating_sub(8);
        let w = if end - start == 8 {
            u64::from_le_bytes(self.b[start..end].try_into().expect("8"))
        } else {
            let mut w = [0u8; 8];
            w[..end - start].copy_from_slice(&self.b[start..end]);
            u64::from_le_bytes(w)
        };
        // Bits [8 * start, pos) of the stream, with bit pos - 1 moved to the top.
        let have = pos - 8 * start;
        self.acc = if have == 64 { w } else { w << (64 - have) };
        self.avail = if start == 0 { 64 } else { have as u32 };
    }

    /// The next `n` bits (n <= 56), most significant first.
    #[inline]
    pub(super) fn read(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        if self.avail < n {
            self.refill();
        }
        let v = self.acc >> (64 - n);
        self.acc <<= n;
        self.avail -= n;
        self.pos -= i64::from(n);
        v
    }

    /// Make sure at least `n` (<= 57) bits are buffered for [`Backward::take`].
    #[inline]
    pub(super) fn ensure(&mut self, n: u32) {
        if self.avail < n {
            self.refill();
        }
    }

    /// The next `n` bits (0 <= n, and no more than [`Backward::ensure`] made sure of), without
    /// branching on `n`.
    #[inline]
    pub(super) fn take(&mut self, n: u32) -> u64 {
        let v = (self.acc >> (63 - n)) >> 1;
        self.acc <<= n;
        self.avail -= n;
        self.pos -= i64::from(n);
        v
    }

    /// The next `n` bits (1 <= n <= 56) without consuming them.
    #[inline]
    pub(super) fn peek(&mut self, n: u32) -> u64 {
        if self.avail < n {
            self.refill();
        }
        self.acc >> (64 - n)
    }

    /// The next `n` bits (1 <= n, and no more than [`Backward::ensure`] made sure of) without
    /// consuming them.
    #[inline]
    pub(super) fn peek_filled(&self, n: u32) -> u64 {
        self.acc >> (64 - n)
    }

    /// Consume `n` bits after a [`Backward::peek`] of at least `n`.
    #[inline]
    pub(super) fn skip(&mut self, n: u32) {
        self.acc <<= n;
        self.avail -= n;
        self.pos -= i64::from(n);
    }

    pub(super) fn overflowed(&self) -> bool {
        self.pos < 0
    }

    pub(super) fn finished(&self) -> bool {
        self.pos == 0
    }
}

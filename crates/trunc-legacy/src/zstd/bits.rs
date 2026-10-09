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
pub(super) struct Backward<'a> {
    b: &'a [u8],
    /// Bits not yet read: they are `[0, pos)`.
    pos: i64,
}

impl<'a> Backward<'a> {
    pub(super) fn new(b: &'a [u8]) -> stream::Result<Self> {
        let &last = b.last().ok_or_else(|| corrupt("empty bitstream"))?;
        if last == 0 {
            return Err(corrupt("bitstream has no end marker"));
        }
        let pos = (b.len() as i64 - 1) * 8 + i64::from(7 - last.leading_zeros());
        Ok(Self { b, pos })
    }

    /// The next `n` bits (n <= 56), most significant first.
    #[inline]
    pub(super) fn read(&mut self, n: u32) -> u64 {
        if n == 0 {
            return 0;
        }
        self.pos -= i64::from(n);
        if self.pos < 0 {
            // Reading below bit 0: what exists, shifted up over zeros.
            let have = i64::from(n) + self.pos;
            if have <= 0 {
                return 0;
            }
            return (self.word(0) & ((1u64 << have) - 1)) << (-self.pos);
        }
        let start = usize::try_from(self.pos / 8).expect("non-negative");
        let shift = (self.pos % 8) as u32;
        (self.word(start) >> shift) & ((1u64 << n) - 1)
    }

    /// Eight bytes from `start`, little-endian, zero past the end.
    #[inline]
    fn word(&self, start: usize) -> u64 {
        if start + 8 <= self.b.len() {
            u64::from_le_bytes(self.b[start..start + 8].try_into().expect("8"))
        } else {
            let mut w = [0u8; 8];
            let n = self.b.len().saturating_sub(start).min(8);
            w[..n].copy_from_slice(&self.b[start..start + n]);
            u64::from_le_bytes(w)
        }
    }

    /// The next `n` bits without consuming them.
    #[inline]
    pub(super) fn peek(&self, n: u32) -> u64 {
        let mut c = Backward {
            b: self.b,
            pos: self.pos,
        };
        c.read(n)
    }

    #[inline]
    pub(super) fn skip(&mut self, n: u32) {
        self.pos -= i64::from(n);
    }

    pub(super) fn overflowed(&self) -> bool {
        self.pos < 0
    }

    pub(super) fn finished(&self) -> bool {
        self.pos == 0
    }
}

//! Huffman-coded literals: the tree description (direct or FSE-compressed weights) and the
//! one- or four-stream decoders.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use super::bits::Backward;
use super::corrupt;
use super::fse::{self, Table};
use crate::stream;

const MAX_BITS: u32 = 11;

/// A Huffman decoding table, kept with the weights it came from (cursors store the weights).
#[derive(Debug, Clone)]
pub(super) struct Huffman {
    pub(super) weights: Vec<u8>,
    max_bits: u32,
    /// `(symbol, bits)` indexed by the next `max_bits` bits.
    table: Vec<(u8, u8)>,
}

impl Huffman {
    /// Build from the weights of every symbol (the implicit last one included).
    pub(super) fn from_weights(weights: Vec<u8>) -> stream::Result<Self> {
        let mut total = 0u32;
        let mut max_w = 0u8;
        for &w in &weights {
            if u32::from(w) > MAX_BITS {
                return Err(corrupt("Huffman weight too large"));
            }
            if w > 0 {
                total += 1 << (w - 1);
                max_w = max_w.max(w);
            }
        }
        if total == 0 || !total.is_power_of_two() {
            return Err(corrupt("Huffman weights do not form a complete code"));
        }
        // As the reference decoder requires: a real tree has at least two leaves of weight 1.
        if weights.iter().filter(|&&w| w == 1).count() < 2 {
            return Err(corrupt("Huffman tree has fewer than two weight-1 symbols"));
        }
        let max_bits = total.trailing_zeros();
        if max_bits > MAX_BITS || u32::from(max_w) > max_bits {
            return Err(corrupt("Huffman code too long"));
        }
        let mut table = vec![(0u8, 0u8); 1 << max_bits];
        let mut pos = 0usize;
        for w in 1..=max_w {
            for (s, _) in weights.iter().enumerate().filter(|&(_, &x)| x == w) {
                let n = 1usize << (w - 1);
                let bits = (max_bits + 1 - u32::from(w)) as u8;
                for e in &mut table[pos..pos + n] {
                    *e = (s as u8, bits);
                }
                pos += n;
            }
        }
        Ok(Self {
            weights,
            max_bits,
            table,
        })
    }

    /// Read a tree description from the start of `b`; returns the table and the bytes used.
    pub(super) fn read(b: &[u8]) -> stream::Result<(Self, usize)> {
        let &h = b.first().ok_or_else(|| corrupt("missing Huffman tree"))?;
        let mut weights;
        let used;
        if h >= 128 {
            let n = usize::from(h) - 127;
            let bytes = n.div_ceil(2);
            let d = b
                .get(1..1 + bytes)
                .ok_or_else(|| corrupt("Huffman tree runs past its block"))?;
            weights = (0..n)
                .map(|i| {
                    let c = d[i / 2];
                    if i % 2 == 0 { c >> 4 } else { c & 15 }
                })
                .collect::<Vec<u8>>();
            used = 1 + bytes;
        } else {
            let size = usize::from(h);
            let d = b
                .get(1..1 + size)
                .ok_or_else(|| corrupt("Huffman tree runs past its block"))?;
            let (norm, log, n) = fse::read_counts(d, 6, 255)?;
            let table = Table::build(&norm, log)?;
            let mut bs = Backward::new(d.get(n..).ok_or_else(|| corrupt("bad Huffman tree"))?)?;
            weights = Vec::new();
            let mut s1 = bs.read(log) as usize;
            let mut s2 = bs.read(log) as usize;
            loop {
                let step = |bs: &mut Backward<'_>, s: &mut usize, w: &mut Vec<u8>| {
                    let e = table.entries[*s];
                    w.push(e.symbol);
                    *s = usize::from(e.base) + bs.read(u32::from(e.bits)) as usize;
                };
                step(&mut bs, &mut s1, &mut weights);
                if bs.overflowed() {
                    weights.push(table.entries[s2].symbol);
                    break;
                }
                step(&mut bs, &mut s2, &mut weights);
                if bs.overflowed() {
                    weights.push(table.entries[s1].symbol);
                    break;
                }
                if weights.len() > 255 {
                    return Err(corrupt("too many Huffman weights"));
                }
            }
            used = 1 + size;
        }
        if weights.len() > 255 {
            return Err(corrupt("too many Huffman weights"));
        }
        // The last symbol's weight is implied: it completes the code to a power of two.
        let total: u32 = weights
            .iter()
            .filter(|&&w| w > 0)
            .map(|&w| 1u32.checked_shl(u32::from(w) - 1).unwrap_or(u32::MAX))
            .fold(0u32, u32::saturating_add);
        if total == 0 || total > 1 << MAX_BITS {
            return Err(corrupt("bad Huffman weights"));
        }
        let next = total.next_power_of_two().max(2);
        let next = if next == total { next * 2 } else { next };
        let rest = next - total;
        if !rest.is_power_of_two() {
            return Err(corrupt("Huffman weights do not form a complete code"));
        }
        weights.push(rest.trailing_zeros() as u8 + 1);
        Ok((Self::from_weights(weights)?, used))
    }

    /// Decode `out.len()` symbols from one stream, which must then be exactly consumed.
    fn stream(&self, b: &[u8], out: &mut [u8]) -> stream::Result<()> {
        let mut bs = Backward::new(b)?;
        for o in out.iter_mut() {
            let (s, n) = self.table[bs.peek(self.max_bits) as usize];
            bs.skip(u32::from(n));
            *o = s;
        }
        if !bs.finished() {
            return Err(corrupt("Huffman stream not consumed exactly"));
        }
        Ok(())
    }

    /// Decode `n` literals from `b` (one stream, or four with a jump table). The four streams
    /// are decoded in step, which lets the processor overlap their work.
    pub(super) fn decode(&self, b: &[u8], n: usize, four: bool) -> stream::Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        if !four {
            self.stream(b, &mut out)?;
            return Ok(out);
        }
        if b.len() < 6 {
            return Err(corrupt("missing jump table"));
        }
        let sizes = [
            usize::from(u16::from_le_bytes([b[0], b[1]])),
            usize::from(u16::from_le_bytes([b[2], b[3]])),
            usize::from(u16::from_le_bytes([b[4], b[5]])),
        ];
        let seg = n.div_ceil(4);
        if 3 * seg > n {
            return Err(corrupt("too few literals for four streams"));
        }
        let mut streams = Vec::with_capacity(4);
        let mut at = 6usize;
        for (i, &size) in sizes.iter().chain(std::iter::once(&0)).enumerate() {
            let len = if i < 3 {
                size
            } else {
                b.len()
                    .checked_sub(at)
                    .ok_or_else(|| corrupt("bad jump table"))?
            };
            let data = b
                .get(at..at + len)
                .ok_or_else(|| corrupt("bad jump table"))?;
            streams.push(Backward::new(data)?);
            at += len;
        }
        let [mut s0, mut s1, mut s2, mut s3]: [Backward<'_>; 4] =
            streams.try_into().map_err(|_| corrupt("bad jump table"))?;
        let last = n - 3 * seg;
        let (o0, rest) = out.split_at_mut(seg);
        let (o1, rest) = rest.split_at_mut(seg);
        let (o2, o3) = rest.split_at_mut(seg);
        let mb = self.max_bits;
        let t = &self.table;
        let sym = |bs: &mut Backward<'_>| {
            let (s, k) = t[bs.peek(mb) as usize];
            bs.skip(u32::from(k));
            s
        };
        for k in 0..last {
            o0[k] = sym(&mut s0);
            o1[k] = sym(&mut s1);
            o2[k] = sym(&mut s2);
            o3[k] = sym(&mut s3);
        }
        for k in last..seg {
            o0[k] = sym(&mut s0);
            o1[k] = sym(&mut s1);
            o2[k] = sym(&mut s2);
        }
        if !(s0.finished() && s1.finished() && s2.finished() && s3.finished()) {
            return Err(corrupt("Huffman stream not consumed exactly"));
        }
        Ok(out)
    }
}

//! Finite State Entropy tables: reading a table description (normalized counts) and building
//! the decoding table.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use super::bits::Forward;
use super::corrupt;
use crate::stream;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Entry {
    pub(super) symbol: u8,
    pub(super) bits: u8,
    pub(super) base: u16,
}

#[derive(Debug, Clone)]
pub(super) struct Table {
    pub(super) log: u32,
    pub(super) entries: Vec<Entry>,
}

impl Table {
    /// A table that always yields `symbol` and reads nothing.
    pub(super) fn rle(symbol: u8) -> Self {
        Self {
            log: 0,
            entries: vec![Entry {
                symbol,
                bits: 0,
                base: 0,
            }],
        }
    }

    /// Build a decoding table from normalized counts (`-1` means "less than one").
    pub(super) fn build(norm: &[i16], log: u32) -> stream::Result<Self> {
        let size = 1usize << log;
        let mut entries = vec![Entry::default(); size];
        let mut next = vec![0u32; norm.len()];
        let mut high = size - 1;
        for (s, &c) in norm.iter().enumerate() {
            if c == -1 {
                entries[high].symbol = s as u8;
                high = high.wrapping_sub(1);
                next[s] = 1;
            } else {
                next[s] = u32::try_from(c.max(0)).expect("non-negative");
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mask = size - 1;
        let mut pos = 0usize;
        for (s, &c) in norm.iter().enumerate() {
            for _ in 0..c.max(0) {
                entries[pos].symbol = s as u8;
                loop {
                    pos = (pos + step) & mask;
                    if pos <= high || high == usize::MAX {
                        break;
                    }
                }
            }
        }
        if pos != 0 {
            return Err(corrupt("FSE table does not fill evenly"));
        }
        for e in &mut entries {
            let s = usize::from(e.symbol);
            let n = next[s];
            next[s] += 1;
            let bits = log - (31 - n.leading_zeros());
            e.bits = bits as u8;
            e.base = ((n << bits) as usize - size) as u16;
        }
        Ok(Self { log, entries })
    }
}

/// Read a table description; returns the normalized counts, the accuracy log and the bytes
/// it took.
pub(super) fn read_counts(
    b: &[u8],
    max_log: u32,
    max_symbol: usize,
) -> stream::Result<(Vec<i16>, u32, usize)> {
    let mut f = Forward::new(b);
    let log = f.read(4)? + 5;
    if log > max_log {
        return Err(corrupt("FSE accuracy too high"));
    }
    let mut remaining = (1i32 << log) + 1;
    let mut threshold = 1i32 << log;
    let mut nbits = log + 1;
    let mut norm: Vec<i16> = Vec::new();
    while remaining > 1 {
        if norm.len() > max_symbol {
            return Err(corrupt("FSE table has too many symbols"));
        }
        let max = 2 * threshold - 1 - remaining;
        let v = f.peek(nbits) as i32;
        let low = v & (threshold - 1);
        let count = if low < max {
            f.skip(nbits - 1)?;
            low
        } else {
            f.skip(nbits)?;
            let full = v & (2 * threshold - 1);
            if full >= threshold { full - max } else { full }
        } - 1;
        remaining -= count.abs();
        norm.push(count as i16);
        if count == 0 {
            loop {
                let rep = f.read(2)?;
                norm.extend(std::iter::repeat_n(0, rep as usize));
                if rep != 3 {
                    break;
                }
            }
        }
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 || norm.len() > max_symbol + 1 {
        return Err(corrupt("bad FSE table description"));
    }
    Ok((norm, log, f.bytes_used()))
}

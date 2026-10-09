//! Compressed blocks: the literals section and the sequences section.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use super::bits::Backward;
use super::corrupt;
use super::fse::{self, Table};
use super::huffman::Huffman;
use crate::stream;

const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
const LL_DEFAULT: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
const ML_DEFAULT: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
const OF_DEFAULT: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];

/// How a sequence table was given; kept so a cursor can rebuild it for repeat mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Desc {
    Predefined,
    Rle(u8),
    Counts(u32, Vec<i16>),
}

/// The three sequence tables, by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Ll,
    Of,
    Ml,
}

impl Kind {
    fn max_log(self) -> u32 {
        match self {
            Kind::Ll | Kind::Ml => 9,
            Kind::Of => 8,
        }
    }

    fn max_symbol(self) -> usize {
        match self {
            Kind::Ll => 35,
            Kind::Ml => 52,
            Kind::Of => 31,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SeqTable {
    pub(super) desc: Desc,
    table: Table,
}

impl SeqTable {
    pub(super) fn build(kind: Kind, desc: Desc) -> stream::Result<Self> {
        let table = match &desc {
            Desc::Predefined => match kind {
                Kind::Ll => Table::build(&LL_DEFAULT, 6)?,
                Kind::Ml => Table::build(&ML_DEFAULT, 6)?,
                Kind::Of => Table::build(&OF_DEFAULT, 5)?,
            },
            Desc::Rle(s) => {
                if usize::from(*s) > kind.max_symbol() {
                    return Err(corrupt("sequence symbol out of range"));
                }
                Table::rle(*s)
            }
            Desc::Counts(log, norm) => {
                if *log > kind.max_log() || norm.len() > kind.max_symbol() + 1 {
                    return Err(corrupt("bad sequence table"));
                }
                Table::build(norm, *log)?
            }
        };
        Ok(Self { desc, table })
    }
}

/// Entropy state carried from block to block within a frame.
#[derive(Debug, Clone, Default)]
pub(super) struct Entropy {
    pub(super) huffman: Option<Huffman>,
    pub(super) ll: Option<SeqTable>,
    pub(super) of: Option<SeqTable>,
    pub(super) ml: Option<SeqTable>,
    pub(super) reps: [u32; 3],
}

/// Decode a compressed block, appending its output to `win`. `produced` is the frame output
/// before this block (bounds offsets), `window` the frame's window size.
pub(super) fn decompress(
    b: &[u8],
    ent: &mut Entropy,
    win: &mut Vec<u8>,
    produced: u64,
    window: u64,
    max_block: usize,
) -> stream::Result<()> {
    let (lits, used) = literals(b, ent, max_block)?;
    let rest = &b[used..];
    let start = win.len();
    sequences(rest, ent, &lits, win, produced, window)?;
    if win.len() - start > max_block {
        return Err(corrupt("block output larger than allowed"));
    }
    Ok(())
}

fn literals(b: &[u8], ent: &mut Entropy, max_block: usize) -> stream::Result<(Vec<u8>, usize)> {
    let &h0 = b.first().ok_or_else(|| corrupt("empty block"))?;
    let kind = h0 & 3;
    let fmt = (h0 >> 2) & 3;
    let byte = |i: usize| -> stream::Result<usize> {
        b.get(i)
            .map(|&c| usize::from(c))
            .ok_or_else(|| corrupt("literals header runs past its block"))
    };
    if kind <= 1 {
        let (size, hl) = match fmt {
            0 | 2 => (usize::from(h0 >> 3), 1),
            1 => ((usize::from(h0) >> 4) | (byte(1)? << 4), 2),
            _ => (
                (usize::from(h0) >> 4) | (byte(1)? << 4) | (byte(2)? << 12),
                3,
            ),
        };
        if size > max_block {
            return Err(corrupt("too many literals"));
        }
        return if kind == 0 {
            let d = b
                .get(hl..hl + size)
                .ok_or_else(|| corrupt("literals run past their block"))?;
            Ok((d.to_vec(), hl + size))
        } else {
            Ok((vec![byte(hl)? as u8; size], hl + 1))
        };
    }
    let (regen, comp, hl, four) = match fmt {
        0 | 1 => {
            let v = usize::from(h0) | (byte(1)? << 8) | (byte(2)? << 16);
            ((v >> 4) & 0x3FF, (v >> 14) & 0x3FF, 3, fmt == 1)
        }
        2 => {
            let v = usize::from(h0) | (byte(1)? << 8) | (byte(2)? << 16) | (byte(3)? << 24);
            ((v >> 4) & 0x3FFF, (v >> 18) & 0x3FFF, 4, true)
        }
        _ => {
            let v = (usize::from(h0) as u64)
                | ((byte(1)? as u64) << 8)
                | ((byte(2)? as u64) << 16)
                | ((byte(3)? as u64) << 24)
                | ((byte(4)? as u64) << 32);
            (
                ((v >> 4) & 0x3FFFF) as usize,
                ((v >> 22) & 0x3FFFF) as usize,
                5,
                true,
            )
        }
    };
    if regen > max_block {
        return Err(corrupt("too many literals"));
    }
    // The reference decoder's minimum for four streams.
    if four && regen < 6 {
        return Err(corrupt("too few literals for four streams"));
    }
    let d = b
        .get(hl..hl + comp)
        .ok_or_else(|| corrupt("literals run past their block"))?;
    let (table_used, tree) = if kind == 2 {
        let (t, used) = Huffman::read(d)?;
        ent.huffman = Some(t);
        (used, ent.huffman.as_ref().expect("just set"))
    } else {
        (
            0,
            ent.huffman
                .as_ref()
                .ok_or_else(|| corrupt("treeless literals without a previous tree"))?,
        )
    };
    let lits = tree.decode(&d[table_used..], regen, four)?;
    Ok((lits, hl + comp))
}

fn table_for(
    kind: Kind,
    mode: u8,
    b: &[u8],
    at: &mut usize,
    slot: &mut Option<SeqTable>,
) -> stream::Result<()> {
    match mode {
        0 => *slot = Some(SeqTable::build(kind, Desc::Predefined)?),
        1 => {
            let &s = b
                .get(*at)
                .ok_or_else(|| corrupt("sequences header runs past its block"))?;
            *at += 1;
            *slot = Some(SeqTable::build(kind, Desc::Rle(s))?);
        }
        2 => {
            let (norm, log, used) = fse::read_counts(&b[*at..], kind.max_log(), kind.max_symbol())?;
            *at += used;
            *slot = Some(SeqTable::build(kind, Desc::Counts(log, norm))?);
        }
        _ => {
            if slot.is_none() {
                return Err(corrupt("repeated sequence table without a previous one"));
            }
        }
    }
    Ok(())
}

fn sequences(
    b: &[u8],
    ent: &mut Entropy,
    lits: &[u8],
    win: &mut Vec<u8>,
    produced: u64,
    window: u64,
) -> stream::Result<()> {
    let block_start = win.len();
    let n = match b.first() {
        None => return Err(corrupt("missing sequences section")),
        Some(&0) => 0,
        Some(&c) if c < 128 => usize::from(c),
        Some(&c) if c < 255 => {
            let d = *b.get(1).ok_or_else(|| corrupt("bad sequence count"))?;
            ((usize::from(c) - 128) << 8) + usize::from(d)
        }
        Some(_) => {
            let (d, e) = (
                *b.get(1).ok_or_else(|| corrupt("bad sequence count"))?,
                *b.get(2).ok_or_else(|| corrupt("bad sequence count"))?,
            );
            usize::from(d) + (usize::from(e) << 8) + 0x7F00
        }
    };
    if n == 0 {
        if b.len() > 1 {
            return Err(corrupt("data after an empty sequences section"));
        }
        win.extend_from_slice(lits);
        return Ok(());
    }
    let mut at = match b[0] {
        c if c < 128 => 1,
        c if c < 255 => 2,
        _ => 3,
    };
    let &modes = b.get(at).ok_or_else(|| corrupt("missing sequence modes"))?;
    at += 1;
    if modes & 3 != 0 {
        return Err(corrupt("reserved sequence mode bits set"));
    }
    table_for(Kind::Ll, modes >> 6, b, &mut at, &mut ent.ll)?;
    table_for(Kind::Of, (modes >> 4) & 3, b, &mut at, &mut ent.of)?;
    table_for(Kind::Ml, (modes >> 2) & 3, b, &mut at, &mut ent.ml)?;
    let ll = &ent.ll.as_ref().expect("set above").table;
    let of = &ent.of.as_ref().expect("set above").table;
    let ml = &ent.ml.as_ref().expect("set above").table;
    let mut bs = Backward::new(b.get(at..).ok_or_else(|| corrupt("missing sequences"))?)?;
    let mut sl = bs.read(ll.log) as usize;
    let mut so = bs.read(of.log) as usize;
    let mut sm = bs.read(ml.log) as usize;
    let mut lit_at = 0usize;
    let reps = &mut ent.reps;
    for i in 0..n {
        let (le, oe, me) = (ll.entries[sl], of.entries[so], ml.entries[sm]);
        let of_code = u32::from(oe.symbol);
        if of_code > 31 {
            return Err(corrupt("offset code too large"));
        }
        let ov = (1u64 << of_code) + bs.read(of_code);
        let ml_code = usize::from(me.symbol);
        let ll_code = usize::from(le.symbol);
        if ml_code >= ML_BASE.len() || ll_code >= LL_BASE.len() {
            return Err(corrupt("length code out of range"));
        }
        let mlen = ML_BASE[ml_code] as usize + bs.read(u32::from(ML_BITS[ml_code])) as usize;
        let llen = LL_BASE[ll_code] as usize + bs.read(u32::from(LL_BITS[ll_code])) as usize;
        let offset = if ov > 3 {
            let o = u32::try_from(ov - 3).map_err(|_| corrupt("offset too large"))?;
            *reps = [o, reps[0], reps[1]];
            o
        } else {
            let idx = if llen == 0 {
                ov as usize
            } else {
                ov as usize - 1
            };
            match idx {
                0 => reps[0],
                1 => {
                    let o = reps[1];
                    *reps = [o, reps[0], reps[2]];
                    o
                }
                _ => {
                    let o = if idx == 3 {
                        reps[0].wrapping_sub(1)
                    } else {
                        reps[2]
                    };
                    if o == 0 {
                        return Err(corrupt("zero offset"));
                    }
                    *reps = [o, reps[0], reps[1]];
                    o
                }
            }
        };
        // Literals, then the match.
        let lend = lit_at + llen;
        if lend > lits.len() {
            return Err(corrupt("sequence uses more literals than the block has"));
        }
        win.extend_from_slice(&lits[lit_at..lend]);
        lit_at = lend;
        let made = produced + (win.len() - block_start) as u64;
        let d = offset as usize;
        if u64::from(offset) > made || u64::from(offset) > window || d > win.len() {
            return Err(corrupt("offset too far back"));
        }
        let from = win.len() - d;
        if d >= mlen {
            win.extend_from_within(from..from + mlen);
        } else {
            for k in 0..mlen {
                let c = win[from + k];
                win.push(c);
            }
        }
        if i + 1 < n {
            sl = usize::from(le.base) + bs.read(u32::from(le.bits)) as usize;
            sm = usize::from(me.base) + bs.read(u32::from(me.bits)) as usize;
            so = usize::from(oe.base) + bs.read(u32::from(oe.bits)) as usize;
        }
        if win.len() - block_start > 128 * 1024 + lits.len() {
            return Err(corrupt("block output larger than allowed"));
        }
    }
    if !bs.finished() {
        return Err(corrupt("sequence bitstream not consumed exactly"));
    }
    win.extend_from_slice(&lits[lit_at..]);
    Ok(())
}

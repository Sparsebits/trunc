//! LZMA2 decoding (the compression inside `.xz`), resumable at chunk boundaries.
//!
//! LZMA2 is a sequence of chunks, each either stored or LZMA-compressed with a fresh range
//! coder. Between chunks the decoder state is the LZMA probabilities, the state machine and the
//! four repeat distances, plus the dictionary (the last `dict_size` bytes of output). The state
//! fits in a cursor (about 28 KB at most); the dictionary is read back from the output on
//! resume. The rules for which chunk may reset what follow xz-embedded.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use crate::stream::{self, Fields, StreamError};

const IS_MATCH: usize = 0;
const IS_REP: usize = IS_MATCH + 12 * 16;
const IS_REP_G0: usize = IS_REP + 12;
const IS_REP_G1: usize = IS_REP_G0 + 12;
const IS_REP_G2: usize = IS_REP_G1 + 12;
const IS_REP0_LONG: usize = IS_REP_G2 + 12;
const POS_SLOT: usize = IS_REP0_LONG + 12 * 16;
const SPEC_POS: usize = POS_SLOT + 4 * 64;
const ALIGN: usize = SPEC_POS + 114;
const LEN: usize = ALIGN + 16;
const REP_LEN: usize = LEN + LEN_PROBS;
const LITERAL: usize = REP_LEN + LEN_PROBS;
const LEN_PROBS: usize = 2 + 16 * 8 + 16 * 8 + 256;
const PROB_INIT: u16 = 1024;
/// Output is handed on once this much has accumulated beyond the dictionary.
pub(crate) const FLUSH_AT: usize = 1 << 20;

fn corrupt(why: &str) -> StreamError {
    StreamError::Corrupt(format!("corrupt LZMA2 data: {why}"))
}

/// Range decoder over one chunk's compressed bytes. Reading past the end yields zeros and sets
/// `overrun`, checked once the chunk is done, so decoding a bit cannot fail.
struct Rc<'a> {
    data: &'a [u8],
    ip: usize,
    range: u32,
    code: u32,
    overrun: bool,
}

impl<'a> Rc<'a> {
    fn new(data: &'a [u8]) -> stream::Result<Self> {
        if data.len() < 5 || data[0] != 0 {
            return Err(corrupt("bad range coder start"));
        }
        Ok(Self {
            data,
            ip: 5,
            range: u32::MAX,
            code: u32::from_be_bytes(data[1..5].try_into().expect("4")),
            overrun: false,
        })
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < 1 << 24 {
            let b = match self.data.get(self.ip) {
                Some(&b) => b,
                None => {
                    self.overrun = true;
                    0
                }
            };
            self.ip += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(b);
        }
    }

    #[inline]
    fn bit(&mut self, p: &mut u16) -> u32 {
        self.normalize();
        let bound = (self.range >> 11) * u32::from(*p);
        if self.code < bound {
            self.range = bound;
            *p += (2048 - *p) >> 5;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *p -= *p >> 5;
            1
        }
    }

    fn tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        for _ in 0..bits {
            m = (m << 1) | self.bit(&mut probs[m]) as usize;
        }
        m as u32 - (1 << bits)
    }

    fn reverse_tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1usize;
        let mut sym = 0u32;
        for i in 0..bits {
            let b = self.bit(&mut probs[m]);
            m = (m << 1) | b as usize;
            sym |= b << i;
        }
        sym
    }

    fn direct(&mut self, bits: u32) -> u32 {
        let mut v = 0u32;
        for _ in 0..bits {
            self.normalize();
            self.range >>= 1;
            let b = u32::from(self.code >= self.range);
            if b == 1 {
                self.code -= self.range;
            }
            v = (v << 1) | b;
        }
        v
    }
}

/// LZMA2 decoder state, the output window, and output not yet handed on.
pub(crate) struct Lzma2 {
    dict_size: u32,
    lc: u32,
    lp: u32,
    pb: u32,
    state: usize,
    reps: [u32; 4],
    probs: Vec<u16>,
    need_props: bool,
    need_dict_reset: bool,
    /// Bytes produced since the last dictionary reset.
    pos: u64,
    /// The window followed by output not yet handed on (`win[flushed..]`).
    pub(crate) win: Vec<u8>,
    pub(crate) flushed: usize,
}

impl std::fmt::Debug for Lzma2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lzma2")
            .field("dict_size", &self.dict_size)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl Lzma2 {
    /// A decoder at the start of an LZMA2 stream with the given dictionary size.
    pub(crate) fn new(dict_size: u32) -> Self {
        Self {
            dict_size,
            lc: 0,
            lp: 0,
            pb: 0,
            state: 0,
            reps: [0; 4],
            probs: Vec::new(),
            need_props: true,
            need_dict_reset: true,
            pos: 0,
            win: Vec::new(),
            flushed: 0,
        }
    }

    /// Bytes of history the decoder needs to continue: `min(dict_size, pos)`.
    pub(crate) fn window_len(&self) -> u64 {
        self.pos.min(u64::from(self.dict_size))
    }

    /// The current window (everything must have been handed on).
    pub(crate) fn window(&self) -> &[u8] {
        let n = usize::try_from(self.window_len()).expect("in memory");
        &self.win[self.win.len() - n..]
    }

    fn reset_state(&mut self) {
        self.state = 0;
        self.reps = [0; 4];
        let n = LITERAL + (0x300 << (self.lc + self.lp));
        self.probs.clear();
        self.probs.resize(n, PROB_INIT);
    }

    fn set_props(&mut self, b: u8) -> stream::Result<()> {
        if b > (4 * 5 + 4) * 9 + 8 {
            return Err(corrupt("bad lc/lp/pb"));
        }
        let b = u32::from(b);
        self.lc = b % 9;
        self.lp = (b / 9) % 5;
        self.pb = b / 45;
        if self.lc + self.lp > 4 {
            return Err(corrupt("lc + lp exceeds 4"));
        }
        self.reset_state();
        Ok(())
    }

    /// Drop window bytes that are no longer needed (all handed on).
    pub(crate) fn trim(&mut self) {
        // Only once the excess is as large as the dictionary, so each byte is moved about once.
        let keep = (self.dict_size as usize).max(1);
        if self.flushed == self.win.len()
            && self.win.len() > keep.saturating_add(keep.max(FLUSH_AT))
        {
            let drop = self.win.len() - keep;
            self.win.drain(..drop);
            self.flushed = self.win.len();
        }
    }

    /// Handle one chunk control byte. Returns `None` at the end of the LZMA2 data, otherwise how
    /// many more header bytes the chunk has (2 for stored, 4 or 5 for LZMA).
    pub(crate) fn control(&mut self, c: u8) -> stream::Result<Option<usize>> {
        if c == 0 {
            return Ok(None);
        }
        if c >= 0xE0 || c == 1 {
            self.need_props = true;
            self.need_dict_reset = false;
            self.pos = 0;
        } else if self.need_dict_reset {
            return Err(corrupt("first chunk does not reset the dictionary"));
        }
        if c >= 0x80 {
            if c >= 0xC0 {
                return Ok(Some(5));
            }
            if self.need_props {
                return Err(corrupt("chunk needs new properties but has none"));
            }
            Ok(Some(4))
        } else if c > 2 {
            Err(corrupt("bad control byte"))
        } else {
            Ok(Some(2))
        }
    }

    /// Decode a chunk whose control byte and header are `head` and whose payload is `data`.
    /// Returns the bytes it produced. `room` caps the output (the caller's limit).
    pub(crate) fn chunk(&mut self, head: &[u8], data: &[u8], room: u64) -> stream::Result<usize> {
        let c = head[0];
        if c < 0x80 {
            let n = (usize::from(u16::from_be_bytes([head[1], head[2]]))) + 1;
            if data.len() != n {
                return Err(corrupt("stored chunk size mismatch"));
            }
            if n as u64 > room {
                return Err(StreamError::Corrupt("output larger than allowed".into()));
            }
            self.win.extend_from_slice(data);
            self.pos += n as u64;
            return Ok(n);
        }
        let unpacked = ((usize::from(c & 0x1F) << 16)
            | usize::from(u16::from_be_bytes([head[1], head[2]])))
            + 1;
        if c >= 0xC0 {
            self.set_props(head[5])?;
            self.need_props = false;
        } else if c >= 0xA0 {
            self.reset_state();
        }
        if unpacked as u64 > room {
            return Err(StreamError::Corrupt("output larger than allowed".into()));
        }
        self.lzma(data, unpacked)?;
        Ok(unpacked)
    }

    fn lzma(&mut self, data: &[u8], unpacked: usize) -> stream::Result<()> {
        let mut rc = Rc::new(data)?;
        let pb_mask = (1u64 << self.pb) - 1;
        let lp_mask = (1u64 << self.lp) - 1;
        let lc = self.lc;
        let end = self.win.len() + unpacked;
        self.win.reserve(unpacked);
        let dict = u64::from(self.dict_size);
        while self.win.len() < end {
            let pos_state = (self.pos & pb_mask) as usize;
            let s = self.state;
            if rc.bit(&mut self.probs[IS_MATCH + s * 16 + pos_state]) == 0 {
                // Literal.
                let prev = if self.pos > 0 {
                    u32::from(*self.win.last().expect("pos > 0"))
                } else {
                    0
                };
                let base = LITERAL
                    + 0x300
                        * ((((self.pos & lp_mask) as usize) << lc) + (prev >> (8 - lc)) as usize);
                // A fixed-size view: indexes below 0x100 need no check.
                let probs: &mut [u16; 0x300] = (&mut self.probs[base..base + 0x300])
                    .try_into()
                    .expect("0x300 literal probabilities");
                let mut sym = 1usize;
                if s >= 7 {
                    let d = self.reps[0] as usize + 1;
                    let mut mb = u32::from(self.win[self.win.len() - d]);
                    loop {
                        let mbit = ((mb >> 7) & 1) as usize;
                        mb <<= 1;
                        let b = rc.bit(&mut probs[((1 + mbit) << 8) + sym]) as usize;
                        sym = (sym << 1) | b;
                        if mbit != b || sym >= 0x100 {
                            break;
                        }
                    }
                }
                while sym < 0x100 {
                    sym = (sym << 1) | rc.bit(&mut probs[sym & 0xFF]) as usize;
                }
                self.win.push(sym as u8);
                self.pos += 1;
                self.state = if s < 4 {
                    0
                } else if s < 10 {
                    s - 3
                } else {
                    s - 6
                };
                continue;
            }
            let len;
            if rc.bit(&mut self.probs[IS_REP + s]) == 0 {
                // A new match.
                len = self.length(&mut rc, LEN, pos_state);
                self.state = if s < 7 { 7 } else { 10 };
                let dist = self.distance(&mut rc, len);
                if dist == u32::MAX {
                    return Err(corrupt("end marker inside a chunk"));
                }
                self.reps = [dist, self.reps[0], self.reps[1], self.reps[2]];
            } else if rc.bit(&mut self.probs[IS_REP_G0 + s]) == 0 {
                if rc.bit(&mut self.probs[IS_REP0_LONG + s * 16 + pos_state]) == 0 {
                    // Short rep: one byte at rep0.
                    self.state = if s < 7 { 9 } else { 11 };
                    self.copy(1, dict)?;
                    continue;
                }
                len = self.length(&mut rc, REP_LEN, pos_state);
                self.state = if s < 7 { 8 } else { 11 };
            } else {
                let d;
                if rc.bit(&mut self.probs[IS_REP_G1 + s]) == 0 {
                    d = self.reps[1];
                } else {
                    if rc.bit(&mut self.probs[IS_REP_G2 + s]) == 0 {
                        d = self.reps[2];
                    } else {
                        d = self.reps[3];
                        self.reps[3] = self.reps[2];
                    }
                    self.reps[2] = self.reps[1];
                }
                self.reps[1] = self.reps[0];
                self.reps[0] = d;
                len = self.length(&mut rc, REP_LEN, pos_state);
                self.state = if s < 7 { 8 } else { 11 };
            }
            let n = len as usize + 2;
            if self.win.len() + n > end {
                return Err(corrupt("match runs past the end of the chunk"));
            }
            self.copy(n, dict)?;
        }
        // Normalization is lazy (before each bit), so the last byte may still be pending.
        rc.normalize();
        if rc.overrun || rc.ip != data.len() || rc.code != 0 {
            return Err(corrupt("chunk does not end where its header says"));
        }
        Ok(())
    }

    fn copy(&mut self, n: usize, dict: u64) -> stream::Result<()> {
        let d = self.reps[0] as usize + 1;
        if d as u64 > self.pos || d as u64 > dict || d > self.win.len() {
            return Err(corrupt("distance too far back"));
        }
        let start = self.win.len() - d;
        if d >= n {
            self.win.extend_from_within(start..start + n);
        } else {
            // Overlapping: copy whole periods of `d` bytes, doubling.
            let mut left = n;
            while left > 0 {
                let k = left.min(self.win.len() - start);
                self.win.extend_from_within(start..start + k);
                left -= k;
            }
        }
        self.pos += n as u64;
        Ok(())
    }

    fn length(&mut self, rc: &mut Rc<'_>, base: usize, pos_state: usize) -> u32 {
        let p = &mut self.probs[base..base + LEN_PROBS];
        if rc.bit(&mut p[0]) == 0 {
            let o = 2 + pos_state * 8;
            return rc.tree(&mut p[o..o + 8], 3);
        }
        if rc.bit(&mut p[1]) == 0 {
            let o = 2 + 128 + pos_state * 8;
            return 8 + rc.tree(&mut p[o..o + 8], 3);
        }
        16 + rc.tree(&mut p[2 + 256..2 + 256 + 256], 8)
    }

    fn distance(&mut self, rc: &mut Rc<'_>, len: u32) -> u32 {
        let ls = len.min(3) as usize;
        let o = POS_SLOT + ls * 64;
        let slot = rc.tree(&mut self.probs[o..o + 64], 6);
        if slot < 4 {
            return slot;
        }
        let nbits = (slot >> 1) - 1;
        let mut dist = (2 | (slot & 1)) << nbits;
        if slot < 14 {
            // Reverse bit tree over SPEC_POS, offset so that its index 1 lands at
            // `dist - slot`.
            let base = SPEC_POS + (dist - slot) as usize - 1;
            dist += rc.reverse_tree(&mut self.probs[base..base + (1 << nbits)], nbits);
        } else {
            dist += rc.direct(nbits - 4) << 4;
            dist += rc.reverse_tree(&mut self.probs[ALIGN..ALIGN + 16], 4);
        }
        dist
    }

    /// State at a chunk boundary: `dict u32 | lc lp pb state u8 | reps 4×u32 | need_props u8 |
    /// need_dict_reset u8 | pos u64 | probs count u32 | probs u16...`.
    pub(crate) fn encode(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.dict_size.to_le_bytes());
        b.extend_from_slice(&[
            self.lc as u8,
            self.lp as u8,
            self.pb as u8,
            self.state as u8,
        ]);
        for r in self.reps {
            b.extend_from_slice(&r.to_le_bytes());
        }
        b.push(u8::from(self.need_props));
        b.push(u8::from(self.need_dict_reset));
        b.extend_from_slice(&self.pos.to_le_bytes());
        b.extend_from_slice(&(self.probs.len() as u32).to_le_bytes());
        for p in &self.probs {
            b.extend_from_slice(&p.to_le_bytes());
        }
    }

    pub(crate) fn decode(f: &mut Fields<'_>) -> Option<Self> {
        let dict_size = f.u32()?;
        let (lc, lp, pb, state) = (
            u32::from(f.u8()?),
            u32::from(f.u8()?),
            u32::from(f.u8()?),
            usize::from(f.u8()?),
        );
        let reps = [f.u32()?, f.u32()?, f.u32()?, f.u32()?];
        let need_props = f.u8()? != 0;
        let need_dict_reset = f.u8()? != 0;
        let pos = f.u64()?;
        let n = f.u32()? as usize;
        if lc > 8 || lp > 4 || pb > 4 || lc + lp > 4 || state > 11 {
            return None;
        }
        let expect = if need_props && n == 0 {
            0
        } else {
            LITERAL + (0x300 << (lc + lp))
        };
        if n != expect {
            return None;
        }
        let raw = f.bytes(n.checked_mul(2)?)?;
        let probs = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<_>>();
        if probs.iter().any(|&p| p == 0 || p >= 2048) {
            return None;
        }
        Some(Self {
            dict_size,
            lc,
            lp,
            pb,
            state,
            reps,
            probs,
            need_props,
            need_dict_reset,
            pos,
            win: Vec::new(),
            flushed: 0,
        })
    }

    /// Put the window back after [`Lzma2::decode`].
    pub(crate) fn restore(&mut self, window: Vec<u8>) {
        self.flushed = window.len();
        self.win = window;
    }
}

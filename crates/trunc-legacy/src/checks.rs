//! Checksums whose running state can be saved in a decoder cursor and restored: CRC-64
//! (xz), SHA-256 (xz) and XXH64 (zstd). Library implementations keep their state private.

// Bit-level decoding narrows values whose range the format already bounds (symbols below 256,
// code lengths below 32, sizes below 2^17); input-controlled values are checked before use.
#![allow(clippy::cast_possible_truncation)]

use crate::stream::Fields;

/// CRC-64/XZ (ECMA-182 polynomial, reflected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc64 {
    state: u64,
}

const fn crc64_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xC96C_5795_D787_0F42
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC64: [u64; 256] = crc64_table();

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    pub fn new() -> Self {
        Self { state: !0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut c = self.state;
        for &b in data {
            c = CRC64[((c as u8) ^ b) as usize] ^ (c >> 8);
        }
        self.state = c;
    }

    pub fn finish(&self) -> u64 {
        !self.state
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        self.state.to_le_bytes()
    }

    pub fn from_bytes(b: [u8; 8]) -> Self {
        Self {
            state: u64::from_le_bytes(b),
        }
    }
}

const SHA_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 (FIPS 180-4).
#[derive(Clone, PartialEq, Eq)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl std::fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sha256")
            .field("total", &self.total)
            .finish()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Serialized size.
    pub const STATE_BYTES: usize = 32 + 8 + 64;

    pub fn new() -> Self {
        Self {
            h: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buf: [0; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn compress(h: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, c) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(c.try_into().expect("4"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(v);
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            let block = self.buf;
            Self::compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for b in &mut blocks {
            Self::compress(&mut self.h, b);
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finish(&self) -> [u8; 32] {
        let mut s = self.clone();
        let bits = self.total.wrapping_mul(8);
        s.total = 0;
        s.update(&[0x80]);
        while s.buf_len != 56 {
            s.update(&[0]);
        }
        s.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (o, v) in out.chunks_exact_mut(4).zip(s.h) {
            o.copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::STATE_BYTES);
        for v in self.h {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.total.to_le_bytes());
        b.extend_from_slice(&self.buf);
        b
    }

    pub(crate) fn from_bytes(f: &mut Fields<'_>) -> Option<Self> {
        let mut h = [0u32; 8];
        for x in &mut h {
            *x = f.u32()?;
        }
        let total = f.u64()?;
        let buf: [u8; 64] = f.bytes(64)?.try_into().ok()?;
        Some(Self {
            h,
            buf,
            buf_len: usize::try_from(total % 64).ok()?,
            total,
        })
    }
}

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

/// XXH64 with seed 0 (zstd's content checksum is its low 32 bits).
#[derive(Clone, PartialEq, Eq)]
pub struct Xxh64 {
    v: [u64; 4],
    buf: [u8; 32],
    buf_len: usize,
    total: u64,
}

impl std::fmt::Debug for Xxh64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Xxh64").field("total", &self.total).finish()
    }
}

impl Default for Xxh64 {
    fn default() -> Self {
        Self::new()
    }
}

fn xround(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn xmerge(acc: u64, v: u64) -> u64 {
    (acc ^ xround(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

impl Xxh64 {
    /// Serialized size.
    pub const STATE_BYTES: usize = 32 + 8 + 32;

    pub fn new() -> Self {
        Self {
            v: [P1.wrapping_add(P2), P2, 0, 0u64.wrapping_sub(P1)],
            buf: [0; 32],
            buf_len: 0,
            total: 0,
        }
    }

    fn stripe(v: &mut [u64; 4], s: &[u8]) {
        for (i, c) in s.chunks_exact(8).enumerate() {
            v[i] = xround(v[i], u64::from_le_bytes(c.try_into().expect("8")));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buf_len > 0 {
            let take = (32 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 32 {
                return;
            }
            let b = self.buf;
            Self::stripe(&mut self.v, &b);
            self.buf_len = 0;
        }
        let mut stripes = data.chunks_exact(32);
        for s in &mut stripes {
            Self::stripe(&mut self.v, s);
        }
        let rest = stripes.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finish(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let [v1, v2, v3, v4] = self.v;
            let mut h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
            for v in self.v {
                h = xmerge(h, v);
            }
            h
        } else {
            P5
        };
        h = h.wrapping_add(self.total);
        let mut rest = &self.buf[..self.buf_len];
        while rest.len() >= 8 {
            let k = xround(0, u64::from_le_bytes(rest[..8].try_into().expect("8")));
            h = (h ^ k).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            let k = u64::from(u32::from_le_bytes(rest[..4].try_into().expect("4")));
            h = (h ^ k.wrapping_mul(P1))
                .rotate_left(23)
                .wrapping_mul(P2)
                .wrapping_add(P3);
            rest = &rest[4..];
        }
        for &b in rest {
            h = (h ^ u64::from(b).wrapping_mul(P5))
                .rotate_left(11)
                .wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::STATE_BYTES);
        for v in self.v {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.total.to_le_bytes());
        b.extend_from_slice(&self.buf);
        b
    }

    pub(crate) fn from_bytes(f: &mut Fields<'_>) -> Option<Self> {
        let mut v = [0u64; 4];
        for x in &mut v {
            *x = f.u64()?;
        }
        let total = f.u64()?;
        let buf: [u8; 32] = f.bytes(32)?.try_into().ok()?;
        Some(Self {
            v,
            buf,
            buf_len: usize::try_from(total % 32).ok()?,
            total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_values() {
        let mut c = Crc64::new();
        c.update(b"123456789");
        assert_eq!(c.finish(), 0x995D_C9BB_DF19_39FA);

        let mut s = Sha256::new();
        s.update(b"abc");
        assert_eq!(
            s.finish(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let mut e = Sha256::new();
        e.update(b"");
        assert_eq!(e.finish()[..4], [0xe3, 0xb0, 0xc4, 0x42]);

        assert_eq!(Xxh64::new().finish(), 0xEF46_DB37_51D8_E999);
        let mut x = Xxh64::new();
        x.update(b"a");
        assert_eq!(x.finish(), 0xD24E_C4F1_A98C_6E5B);
    }

    #[test]
    fn states_survive_serialization_at_any_point() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        let (mut s, mut x) = (Sha256::new(), Xxh64::new());
        s.update(&data);
        x.update(&data);
        for cut in [0, 1, 31, 32, 33, 63, 64, 65, 500, 999] {
            let (mut s2, mut x2) = (Sha256::new(), Xxh64::new());
            s2.update(&data[..cut]);
            x2.update(&data[..cut]);
            let sb = s2.to_bytes();
            let xb = x2.to_bytes();
            let mut s3 = Sha256::from_bytes(&mut Fields::new(&sb)).unwrap();
            let mut x3 = Xxh64::from_bytes(&mut Fields::new(&xb)).unwrap();
            s3.update(&data[cut..]);
            x3.update(&data[cut..]);
            assert_eq!(s3.finish(), s.finish(), "sha at {cut}");
            assert_eq!(x3.finish(), x.finish(), "xxh at {cut}");
        }
        let mut long = Xxh64::new();
        long.update(&data[..100]);
        let mut parts = Xxh64::new();
        for c in data[..100].chunks(7) {
            parts.update(c);
        }
        assert_eq!(long.finish(), parts.finish());
    }
}

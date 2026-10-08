//! Test support for trunc.
//!
//! - [`fixtures`] writes deterministic input trees (many small files, one large file, empty
//!   files and directories, incompressible and all-zero data).
//! - [`tree`] snapshots and compares directory trees byte for byte.
//!
//! Phase 2 adds `FaultFs` (crash, torn-write, volatile-cache, ENOSPC and mapped-file injection)
//! and phase 3 the crash harness that sweeps every operation index.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

pub mod fixtures;
pub mod tree;

/// Small deterministic PRNG (xorshift64*), so fixtures are identical on every run and platform.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish value in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

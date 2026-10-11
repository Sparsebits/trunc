//! Hashing primitives used across trunc.
//!
//! Each algorithm has one job (see `docs/spec/trnc-format-v1.md`):
//! - **CRC32C** detects torn or corrupted fixed-size records (header, footer, journal records).
//! - **BLAKE3** fingerprints block payloads, decoded block contents and entries, and builds the
//!   Merkle tree over decoded blocks.
//! - **SHA-256** exists only to compare against checksums published by third parties.

use std::io::{self, Write};

pub mod merkle;

/// A 32-byte BLAKE3 digest.
pub type Digest = [u8; 32];

/// BLAKE3 of `data`.
pub fn blake3(data: &[u8]) -> Digest {
    *::blake3::hash(data).as_bytes()
}

/// Incremental BLAKE3 hasher.
pub use ::blake3::Hasher as Blake3Hasher;

/// CRC32C (Castagnoli) of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    ::crc32c::crc32c(data)
}

/// Continue a CRC32C computation.
pub fn crc32c_append(crc: u32, data: &[u8]) -> u32 {
    ::crc32c::crc32c_append(crc, data)
}

/// SHA-256 of `data`, for interop with externally published checksums.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

/// Incremental SHA-256, for content addressed by others (container image digests).
#[derive(Debug, Clone, Default)]
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.0.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        use sha2::Digest as _;
        self.0.finalize().into()
    }
}

/// A writer adapter that BLAKE3-hashes everything written through it.
#[derive(Debug)]
pub struct HashSink<W> {
    inner: W,
    hasher: Blake3Hasher,
    written: u64,
}

impl<W: Write> HashSink<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Blake3Hasher::new(),
            written: 0,
        }
    }

    /// Bytes successfully written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Finish, returning the inner writer and the digest of everything written.
    pub fn finish(self) -> (W, Digest) {
        (self.inner, *self.hasher.finalize().as_bytes())
    }
}

impl<W: Write> Write for HashSink<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_known_vector() {
        // RFC 3720 test vector: 32 bytes of zeros.
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(
            crc32c_append(crc32c(b"hello "), b"world"),
            crc32c(b"hello world")
        );
    }

    #[test]
    fn blake3_empty_vector() {
        assert_eq!(
            blake3(b""),
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62
            ]
        );
    }

    #[test]
    fn sha256_incremental_matches_one_shot() {
        let mut h = Sha256Hasher::new();
        h.update(b"ab");
        h.update(b"c");
        assert_eq!(h.finalize(), sha256(b"abc"));
        assert_eq!(sha256(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn hash_sink_matches_one_shot() {
        let mut sink = HashSink::new(Vec::new());
        sink.write_all(b"abc").unwrap();
        sink.write_all(b"def").unwrap();
        assert_eq!(sink.written(), 6);
        let (out, digest) = sink.finish();
        assert_eq!(out, b"abcdef");
        assert_eq!(digest, blake3(b"abcdef"));
    }
}

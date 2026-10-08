//! Chunkers that decide block boundaries in the logical stream.
//!
//! v1 ships the fixed-size chunker. A content-defined chunker (FastCDC) for dedup-friendly
//! boundaries is planned for phase 7.

use std::ops::Range;

/// Default block size: 8 MiB of decoded data.
pub const DEFAULT_BLOCK_SIZE: u64 = 8 << 20;
/// Smallest block size the producer accepts.
pub const MIN_BLOCK_SIZE: u64 = 64 << 10;
/// Largest block size the producer accepts.
pub const MAX_BLOCK_SIZE: u64 = 256 << 20;

/// Splits `[0, total)` into consecutive ranges of `size` bytes (the last may be shorter).
#[derive(Debug, Clone)]
pub struct FixedChunker {
    size: u64,
    pos: u64,
    total: u64,
}

impl FixedChunker {
    pub fn new(total: u64, size: u64) -> Self {
        assert!(size > 0, "chunk size must be positive");
        Self {
            size,
            pos: 0,
            total,
        }
    }
}

impl Iterator for FixedChunker {
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Range<u64>> {
        if self.pos >= self.total {
            return None;
        }
        let end = (self.pos + self.size).min(self.total);
        let r = self.pos..end;
        self.pos = end;
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_exactly() {
        assert_eq!(
            FixedChunker::new(10, 4).collect::<Vec<_>>(),
            vec![0..4, 4..8, 8..10]
        );
        assert_eq!(
            FixedChunker::new(8, 4).collect::<Vec<_>>(),
            vec![0..4, 4..8]
        );
        assert_eq!(FixedChunker::new(0, 4).count(), 0);
    }
}

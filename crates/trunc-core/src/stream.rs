//! Mapping between ranges of the logical stream and entry contents.

use crate::{EntryKind, Manifest};

/// A piece of a stream range that falls inside one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    /// Index into `Manifest::entries`.
    pub entry: usize,
    /// Offset within the entry's content.
    pub entry_off: u64,
    /// Offset within the requested stream range (i.e. within the block's decoded buffer).
    pub buf_off: u64,
    pub len: u64,
}

/// Index of non-empty file entries sorted by stream offset, for range lookups.
#[derive(Debug, Clone)]
pub struct LogicalStream {
    /// (stream_off, size, entry index) for files with size > 0, ascending by stream_off.
    files: Vec<(u64, u64, usize)>,
}

impl LogicalStream {
    pub fn new(m: &Manifest) -> Self {
        let files = m
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e.kind, EntryKind::File) && e.size > 0)
            .map(|(i, e)| (e.stream_off, e.size, i))
            .collect();
        Self { files }
    }

    /// Split stream range `[off, off + len)` into per-entry runs, in stream order.
    /// The manifest must be validated (entries tile the stream).
    pub fn runs(&self, off: u64, len: u64) -> Vec<Run> {
        let mut out = Vec::new();
        if len == 0 {
            return out;
        }
        let end = off + len;
        // First file whose range ends after `off`.
        let mut i = self.files.partition_point(|&(s, sz, _)| s + sz <= off);
        while i < self.files.len() {
            let (s, sz, entry) = self.files[i];
            if s >= end {
                break;
            }
            let from = s.max(off);
            let to = (s + sz).min(end);
            out.push(Run {
                entry,
                entry_off: from - s,
                buf_off: from - off,
                len: to - from,
            });
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::tests::sample;

    #[test]
    fn runs_cover_ranges_exactly() {
        let m = sample(); // files: d/a [0,100), d/b [100,150), c empty
        let s = LogicalStream::new(&m);
        assert_eq!(
            s.runs(0, 64),
            vec![Run {
                entry: 1,
                entry_off: 0,
                buf_off: 0,
                len: 64
            }]
        );
        assert_eq!(
            s.runs(64, 64),
            vec![
                Run {
                    entry: 1,
                    entry_off: 64,
                    buf_off: 0,
                    len: 36
                },
                Run {
                    entry: 2,
                    entry_off: 0,
                    buf_off: 36,
                    len: 28
                },
            ]
        );
        assert_eq!(
            s.runs(128, 22),
            vec![Run {
                entry: 2,
                entry_off: 28,
                buf_off: 0,
                len: 22
            }]
        );
        assert!(s.runs(150, 0).is_empty());
    }

    #[test]
    fn every_block_is_fully_covered() {
        let m = sample();
        let s = LogicalStream::new(&m);
        for b in &m.blocks {
            let total: u64 = s.runs(b.stream_off, b.u_len).iter().map(|r| r.len).sum();
            assert_eq!(total, b.u_len);
        }
    }
}

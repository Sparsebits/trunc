//! Conservative disk-space model for extraction and consumption.
//!
//! The model counts logical bytes plus explicit allowances for cluster rounding, per-entry
//! filesystem metadata and a safety margin. It is an upper bound, not an exact prediction: other
//! processes, filesystem compression, quotas and snapshots are outside its view (the engine
//! handles running out of space by pausing safely).
//!
//! Consumption is modelled batch by batch, matching what the engine does: for each batch the
//! outputs are preallocated while the batch's source blocks are still present, then the archive
//! is truncated past the batch.

use std::ops::Range;

use crate::Manifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceParams {
    /// Allocation unit of the destination filesystem.
    pub cluster_size: u64,
    /// Allowance per entry for filesystem metadata (MFT record, inode, directory index growth).
    pub per_entry_overhead: u64,
    /// Fixed safety margin.
    pub margin_fixed: u64,
    /// Proportional safety margin, in parts per million of the decoded size.
    pub margin_ppm: u64,
    /// Upper bound on decoded bytes per consume batch (one flush + truncate per batch).
    pub batch_max_u: u64,
}

impl Default for SpaceParams {
    fn default() -> Self {
        Self {
            cluster_size: 4096,
            per_entry_overhead: 4096,
            margin_fixed: 16 << 20,
            margin_ppm: 5_000,
            batch_max_u: 256 << 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceBound {
    /// Current archive file length (accounts for blocks already consumed).
    pub archive_len: u64,
    /// Decoded bytes still to be written.
    pub remaining_u: u64,
    /// Rounding + metadata allowance for the whole output.
    pub slack: u64,
    pub margin: u64,
    /// Free space a non-destructive extraction needs.
    pub extract_extra: u64,
    /// Highest occupancy (archive remainder + new outputs) during consumption, incl. allowances.
    pub consume_peak: u64,
    /// Free space consumption needs: `consume_peak - archive_len`.
    pub consume_extra: u64,
    pub batches: usize,
}

/// Group blocks `from..n` into consecutive batches of at most `batch_max_u` decoded bytes
/// (a batch always holds at least one block).
pub fn batches(m: &Manifest, from: usize, batch_max_u: u64) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = from;
    let mut acc = 0u64;
    for i in from..m.blocks.len() {
        let u = m.blocks[i].u_len;
        if i > start && acc + u > batch_max_u {
            out.push(start..i);
            start = i;
            acc = 0;
        }
        acc += u;
    }
    if start < m.blocks.len() {
        out.push(start..m.blocks.len());
    }
    out
}

fn round_up(x: u64, unit: u64) -> u64 {
    if unit <= 1 {
        x
    } else {
        x.div_ceil(unit) * unit
    }
}

/// Compute the space bound for an archive with `consumed` blocks already consumed.
pub fn bound(m: &Manifest, first_block_off: u64, consumed: usize, p: &SpaceParams) -> SpaceBound {
    let archive_len = m.len_after_consuming(first_block_off, consumed);
    let remaining_u: u64 = m.blocks[consumed..].iter().map(|b| b.u_len).sum();

    let files_rounding: u64 = m
        .entries
        .iter()
        .map(|e| round_up(e.size, p.cluster_size) - e.size)
        .sum();
    let slack = files_rounding + m.entries.len() as u64 * p.per_entry_overhead;
    let margin = p.margin_fixed
        + remaining_u / 1_000_000 * p.margin_ppm
        + (remaining_u % 1_000_000) * p.margin_ppm / 1_000_000;

    let mut peak = archive_len; // before anything happens
    let mut written = 0u64;
    let groups = batches(m, consumed, p.batch_max_u);
    // Offsets once: asking `len_after_consuming` per group would make this quadratic.
    let offs = m.block_offsets(first_block_off);
    for g in &groups {
        let before = if g.start == 0 {
            m.archive_len(first_block_off)
        } else {
            offs[g.start - 1]
        };
        let batch_u: u64 = m.blocks[g.clone()].iter().map(|b| b.u_len).sum();
        // Outputs for this batch are allocated while its source blocks still exist.
        peak = peak.max(before + written + batch_u);
        written += batch_u;
    }
    let consume_peak = peak + slack + margin;
    SpaceBound {
        archive_len,
        remaining_u,
        slack,
        margin,
        extract_extra: remaining_u + slack + margin,
        consume_peak,
        consume_extra: consume_peak.saturating_sub(archive_len),
        batches: groups.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::tests::sample;

    fn no_allowances(batch: u64) -> SpaceParams {
        SpaceParams {
            cluster_size: 1,
            per_entry_overhead: 0,
            margin_fixed: 0,
            margin_ppm: 0,
            batch_max_u: batch,
        }
    }

    #[test]
    fn batching() {
        let m = sample(); // u_len 64, 64, 22
        assert_eq!(batches(&m, 0, 1), vec![0..1, 1..2, 2..3]);
        assert_eq!(batches(&m, 0, 128), vec![0..2, 2..3]);
        assert_eq!(batches(&m, 0, 1 << 30), vec![0..3]);
        assert_eq!(batches(&m, 2, 1), vec![2..3]);
        assert!(batches(&m, 3, 1).is_empty());
    }

    #[test]
    fn per_block_bound_matches_hand_computation() {
        let m = sample();
        let fbo = 1000;
        let f = crate::FOOTER_LEN as u64;
        let b = bound(&m, fbo, 0, &no_allowances(1));
        let full = m.archive_len(fbo);
        assert_eq!(b.archive_len, full);
        // Step 0: full archive + 64. Step 1: (full - 30 - f) + 64 + 64. Step 2: fbo+22+f + 128 + 22.
        let s0 = full + 64;
        let s1 = full - 30 - f + 128;
        let s2 = fbo + 22 + f + 150;
        assert_eq!(b.consume_peak, s0.max(s1).max(s2));
        assert_eq!(b.consume_extra, b.consume_peak - full);
        assert_eq!(b.extract_extra, 150);
    }

    #[test]
    fn consumed_blocks_shrink_the_bound() {
        let m = sample();
        let fresh = bound(&m, 1000, 0, &no_allowances(1));
        let later = bound(&m, 1000, 2, &no_allowances(1));
        assert_eq!(later.remaining_u, 22);
        assert!(later.archive_len < fresh.archive_len);
        assert_eq!(later.batches, 1);
    }

    /// Millions of blocks, one per batch: the bound is linear in the block count (it used to
    /// rebuild the offset table for every batch).
    #[test]
    fn many_blocks_stay_linear() {
        let mut m = sample();
        let one = m.blocks[0];
        m.blocks = vec![one; 2_000_000];
        let t = std::time::Instant::now();
        let b = bound(&m, 1000, 0, &no_allowances(1));
        assert_eq!(b.batches, 2_000_000);
        assert!(
            t.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn allowances_are_added() {
        let m = sample();
        let p = SpaceParams {
            cluster_size: 4096,
            per_entry_overhead: 100,
            ..no_allowances(1)
        };
        let b = bound(&m, 1000, 0, &p);
        // d/a 100 -> 4096, d/b 50 -> 4096, others 0.
        assert_eq!(b.slack, (4096 - 100) + (4096 - 50) + 4 * 100);
    }
}

//! Space planning for a whole shard set consumed one shard after another.
//!
//! While shard `i` is being consumed the disk holds: the outputs of shards `0..i` (already
//! consumed, their archives gone), shard `i` at its own peak (what trunc's planner says: the
//! archive not yet freed plus what it has written so far), and the untouched archives of shards
//! `i+1..`. The set's peak is the largest of these sums. Everything is measured against the
//! starting point, where all archives are already on disk.

/// What trunc's planner says about one shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSpace {
    pub name: String,
    /// Size of the archive (all parts).
    pub archive_len: u64,
    /// Bytes of file content inside.
    pub content: u64,
    /// Space its outputs take once written (content, cluster rounding, safety margin): what a
    /// plain extract of this shard needs.
    pub extract_extra: u64,
    /// Highest occupancy while consuming this shard alone, archive included.
    pub consume_peak: u64,
}

/// The plan for the whole set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetPlan {
    /// Occupancy (relative to nothing on disk) while each shard is consumed.
    pub peak_during: Vec<u64>,
    /// Largest of `peak_during`, and the shard it happens at.
    pub peak: u64,
    pub peak_shard: usize,
    pub archives: u64,
    pub content: u64,
    /// Free space a plain extract of every shard (archives kept) needs.
    pub extract_extra: u64,
    /// Free space consuming needs: the peak above what the archives already take.
    pub consume_extra: u64,
}

impl SetPlan {
    /// Free space consuming saves compared with a plain extract.
    pub fn saving(&self) -> u64 {
        self.extract_extra.saturating_sub(self.consume_extra)
    }
}

/// Plan a sequential consume of `shards`. `same_volume`: the archives live on the destination
/// volume, so the space they free can be reused for outputs; otherwise the destination needs
/// room for all outputs whatever happens to the archives.
pub fn plan(shards: &[ShardSpace], same_volume: bool) -> SetPlan {
    let archives: u64 = shards.iter().map(|s| s.archive_len).sum();
    let content: u64 = shards.iter().map(|s| s.content).sum();
    let extract_extra: u64 = shards.iter().map(|s| s.extract_extra).sum();
    let mut peak_during = Vec::with_capacity(shards.len());
    let mut outputs_before = 0u64;
    let mut archives_after = archives;
    for s in shards {
        archives_after -= s.archive_len;
        peak_during.push(outputs_before + s.consume_peak.max(s.archive_len) + archives_after);
        outputs_before += s.extract_extra;
    }
    let (peak_shard, peak) = peak_during
        .iter()
        .copied()
        .enumerate()
        .max_by_key(|&(i, p)| (p, std::cmp::Reverse(i)))
        .unwrap_or((0, archives));
    // The outputs of the last shard stay; the end state needs `extract_extra` beyond nothing,
    // which the peak always covers because each shard's peak includes its own outputs.
    let peak = peak.max(outputs_before);
    let consume_extra = if same_volume {
        peak.saturating_sub(archives)
    } else {
        extract_extra
    };
    SetPlan {
        peak_during,
        peak,
        peak_shard,
        archives,
        content,
        extract_extra,
        consume_extra,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(archive_len: u64, extract_extra: u64, consume_peak: u64) -> ShardSpace {
        ShardSpace {
            name: String::new(),
            archive_len,
            content: extract_extra,
            extract_extra,
            consume_peak,
        }
    }

    #[test]
    fn empty_set_needs_nothing() {
        let p = plan(&[], true);
        assert_eq!(p.peak, 0);
        assert_eq!(p.consume_extra, 0);
        assert_eq!(p.saving(), 0);
    }

    #[test]
    fn one_shard_is_trunc_s_own_plan() {
        let p = plan(&[s(100, 120, 130)], true);
        assert_eq!(p.peak, 130);
        assert_eq!(p.consume_extra, 30);
        assert_eq!(p.extract_extra, 120);
        assert_eq!(p.saving(), 90);
    }

    #[test]
    fn peak_is_max_over_shards_of_outputs_shard_peak_and_remaining() {
        // archives 100 + 100 + 100; each expands to 120 and peaks at 130 while consumed.
        let p = plan(
            &[s(100, 120, 130), s(100, 120, 130), s(100, 120, 130)],
            true,
        );
        // shard 0: 0 + 130 + 200; shard 1: 120 + 130 + 100; shard 2: 240 + 130 + 0
        assert_eq!(p.peak_during, vec![330, 350, 370]);
        assert_eq!(p.peak, 370);
        assert_eq!(p.peak_shard, 2);
        assert_eq!(p.archives, 300);
        assert_eq!(p.consume_extra, 70);
        assert_eq!(p.extract_extra, 360);
        assert_eq!(p.saving(), 290);
    }

    #[test]
    fn a_big_shard_early_can_set_the_peak() {
        let p = plan(&[s(1000, 1000, 1500), s(10, 10, 15)], true);
        assert_eq!(p.peak_during, vec![1510, 1015]);
        assert_eq!(p.peak_shard, 0);
        assert_eq!(p.consume_extra, 500);
    }

    #[test]
    fn ties_report_the_first_shard() {
        let p = plan(&[s(10, 10, 20), s(10, 0, 20)], true);
        assert_eq!(p.peak_during, vec![30, 30]);
        assert_eq!(p.peak_shard, 0);
    }

    #[test]
    fn other_volume_needs_every_output() {
        let p = plan(&[s(100, 120, 130), s(100, 120, 130)], false);
        assert_eq!(p.consume_extra, 240);
        assert_eq!(p.saving(), 0);
    }

    #[test]
    fn shrinking_content_needs_no_extra() {
        // Outputs smaller than archives (already-compressed data, sparse wins): peak is the
        // archives themselves.
        let p = plan(&[s(100, 50, 100), s(100, 50, 100)], true);
        assert_eq!(p.peak, 200);
        assert_eq!(p.consume_extra, 0);
    }

    #[test]
    fn three_hundred_gigabytes_on_a_small_disk() {
        // The README example: 100 shards of 3 GB expanding to 3.2 GB, peaking at 3.3 GB.
        const G: u64 = 1_000_000_000;
        let shards: Vec<ShardSpace> = (0..100)
            .map(|_| s(3 * G, 32 * G / 10, 33 * G / 10))
            .collect();
        let p = plan(&shards, true);
        assert_eq!(p.archives, 300 * G);
        assert_eq!(p.extract_extra, 320 * G);
        // last shard: 99 * 3.2 + 3.3 = 320.1 GB on disk, 20.1 GB beyond the archives
        assert_eq!(p.peak, 3201 * G / 10);
        assert_eq!(p.consume_extra, 201 * G / 10);
    }
}

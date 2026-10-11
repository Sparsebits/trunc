//! Randomized checks of the `.trnc` space planner (`trunc_core::space`) against a simulation
//! of the order in which `consume` allocates and releases space.
//!
//! The planner is what stops a consume from filling the disk mid-way, so it must never
//! under-estimate. Each case builds a random manifest (one to two thousand blocks, empty
//! files, files spanning many blocks, blocks holding many tiny files), plans it, then replays
//! the engine's batch loop: every output byte of a batch is written (each write first
//! preallocates up to its end, so a file occupies its written length rounded up to whole
//! clusters), the batch is flushed, and only then is the archive truncated past the batch.
//! Occupancy peaks just before each truncation; the simulated peak must stay within
//! `consume_peak`. `.trnc` releases space by truncation only (blocks are stored back to front),
//! so there is no separate deallocation mode to model.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::ops::Range;

use trunc_core::space::{self, SpaceParams};
use trunc_core::{BlockRecord, CodecId, Entry, EntryKind, FOOTER_LEN, FORMAT_VERSION, Manifest};
use trunc_testkit::Rng;

const F: u64 = FOOTER_LEN as u64;

fn pick<T: Copy>(rng: &mut Rng, xs: &[T]) -> T {
    xs[rng.below(xs.len() as u64) as usize]
}

/// Inclusive range `lo..=hi`.
fn between(rng: &mut Rng, lo: u64, hi: u64) -> u64 {
    lo + rng.below(hi - lo + 1)
}

fn round_up(x: u64, unit: u64) -> u64 {
    x.div_ceil(unit) * unit
}

fn entry(path: String, kind: EntryKind, size: u64, off: u64) -> Entry {
    Entry {
        path,
        kind,
        size,
        mode: 0o644,
        mtime_unix: 1_700_000_000,
        mtime_nanos: 0,
        stream_off: off,
        blake3: [0; 32],
    }
}

/// A random but structurally valid manifest.
fn random_manifest(rng: &mut Rng) -> Manifest {
    let n_blocks = match rng.below(4) {
        0 => between(rng, 1, 4),
        1 => between(rng, 1, 60),
        _ => between(rng, 1, 2000),
    };
    let max_u = pick(rng, &[1u64, 16, 4096, 1 << 20, 4 << 20]);
    let blocks_u: Vec<u64> = (0..n_blocks).map(|_| between(rng, 1, max_u)).collect();
    let total_u: u64 = blocks_u.iter().sum();

    // Cut the stream into files: few big ones, many tiny ones, or anything in between. Equal
    // cut points make empty files.
    let n_files = match rng.below(4) {
        0 => between(rng, 1, 3),
        1 => between(rng, 1, 5000),
        2 => between(rng, 1, 50),
        _ => between(rng, 1, 400),
    };
    let mut cuts: Vec<u64> = (1..n_files).map(|_| rng.below(total_u + 1)).collect();
    if rng.below(3) == 0 {
        // Align some cuts to block boundaries and to 4 KiB, where off-by-one errors hide.
        let mut acc = 0;
        let bounds: Vec<u64> = blocks_u
            .iter()
            .map(|u| {
                acc += u;
                acc
            })
            .collect();
        for c in &mut cuts {
            if rng.below(2) == 0 {
                *c = pick(rng, &bounds);
            } else {
                *c = *c / 4096 * 4096;
            }
        }
    }
    cuts.sort_unstable();
    cuts.push(total_u);

    let mut entries = Vec::new();
    let mut prev = 0u64;
    for (i, &c) in cuts.iter().enumerate() {
        if rng.below(8) == 0 {
            entries.push(entry(format!("d{i}"), EntryKind::Dir, 0, prev));
        }
        if rng.below(16) == 0 {
            let link = EntryKind::Symlink { target: "t".into() };
            entries.push(entry(format!("l{i}"), link, 0, prev));
        }
        entries.push(entry(format!("f{i}"), EntryKind::File, c - prev, prev));
        prev = c;
    }

    let blocks_uc: Vec<(u64, u64)> = blocks_u
        .iter()
        .map(|&u| match rng.below(3) {
            0 => (u, u), // stored
            1 => (u, between(rng, 1, u)),
            _ => (u, between(rng, 1, u + u / 8 + 64)),
        })
        .collect();
    manifest(entries, &blocks_uc)
}

/// A manifest with these entries and blocks of these (decoded, compressed) sizes.
fn manifest(entries: Vec<Entry>, blocks_uc: &[(u64, u64)]) -> Manifest {
    let mut blocks = Vec::with_capacity(blocks_uc.len());
    let mut off = 0u64;
    let mut total_c = 0u64;
    for &(u, c) in blocks_uc {
        blocks.push(BlockRecord {
            stream_off: off,
            u_len: u,
            c_len: c,
            codec: CodecId::Zstd.as_u16(),
            blake3_c: [0; 32],
            blake3_u: [0; 32],
        });
        off += u;
        total_c += c;
    }
    Manifest {
        format_version: FORMAT_VERSION,
        archive_id: [1; 16],
        created_unix: 0,
        producer: "space_plan".into(),
        entries,
        blocks,
        dict: None,
        total_u: off,
        total_c,
        merkle_root: [0; 32],
    }
}

fn random_params(rng: &mut Rng) -> SpaceParams {
    SpaceParams {
        cluster_size: pick(rng, &[1, 512, 4096, 65536]),
        per_entry_overhead: pick(rng, &[0, 0, 1, 256, 4096]),
        margin_fixed: pick(rng, &[0, 0, 0, 4096]),
        margin_ppm: pick(rng, &[0, 0, 5_000]),
        batch_max_u: pick(rng, &[1, 4096, 1 << 20, 64 << 20, 256 << 20, u64::MAX]),
    }
}

/// Archive length after consuming the first `k` blocks, from first principles: the header and
/// manifest, plus every block not yet consumed with its footer.
fn oracle_len(m: &Manifest, fbo: u64, k: usize) -> u64 {
    fbo + m.blocks[k..].iter().map(|b| b.c_len + F).sum::<u64>()
}

/// Check that `groups` cut `from..n` into non-empty consecutive batches, each within
/// `batch_max_u` unless it is a single block, and each as long as the limit allows.
fn check_batches(m: &Manifest, from: usize, batch_max_u: u64, groups: &[Range<usize>]) {
    let n = m.blocks.len();
    let u = |r: &Range<usize>| m.blocks[r.clone()].iter().map(|b| b.u_len).sum::<u64>();
    assert_eq!(groups.is_empty(), from == n, "{groups:?}");
    let mut next = from;
    for (gi, g) in groups.iter().enumerate() {
        assert_eq!(g.start, next, "batches leave a gap or overlap: {groups:?}");
        assert!(g.end > g.start, "empty batch {g:?}");
        assert!(
            g.len() == 1 || u(g) <= batch_max_u,
            "batch {g:?} holds {} > {batch_max_u}",
            u(g)
        );
        if let Some(h) = groups.get(gi + 1) {
            assert!(
                u(g).saturating_add(m.blocks[h.start].u_len) > batch_max_u,
                "batch {g:?} was cut early"
            );
        }
        next = g.end;
    }
    assert_eq!(next, n, "batches do not reach the last block");
}

/// Replay `consume_blocks` for blocks `consumed..` and return the highest occupancy of the
/// archive plus everything this run allocates. Occupancy is counted the way the planner
/// claims to: archive bytes, plus each output's allocation (its preallocated length rounded
/// up to whole clusters), plus per-entry metadata for entries this run creates.
fn simulate(m: &Manifest, fbo: u64, consumed: usize, p: &SpaceParams) -> u64 {
    let cluster = p.cluster_size.max(1);
    let groups = space::batches(m, consumed, p.batch_max_u);
    check_batches(m, consumed, p.batch_max_u, &groups);

    // Content bytes already written by an earlier run (everything before the first block left).
    let done_to = m.blocks.get(consumed).map_or(m.total_u, |b| b.stream_off);
    let mut written: Vec<u64> = m
        .entries
        .iter()
        .map(|e| done_to.saturating_sub(e.stream_off).min(e.size))
        .collect();
    let alloc = |w: &[u64]| w.iter().map(|&x| round_up(x, cluster)).sum::<u64>();
    let base_out = alloc(&written);
    // A fresh consume creates every entry (build_structure) before the first batch.
    let meta = if consumed == 0 {
        m.entries.len() as u64 * p.per_entry_overhead
    } else {
        0
    };

    let mut archive = oracle_len(m, fbo, consumed);
    let mut out = base_out;
    let mut peak = archive + meta;
    // Entries are in stream order; walk them alongside the blocks.
    let mut first = 0usize;
    for g in &groups {
        for b in &m.blocks[g.clone()] {
            let (lo, hi) = (b.stream_off, b.stream_off + b.u_len);
            while first < m.entries.len()
                && m.entries[first].stream_off + m.entries[first].size <= lo
            {
                first += 1;
            }
            let mut i = first;
            while i < m.entries.len() && m.entries[i].stream_off < hi {
                let e = &m.entries[i];
                let end = (hi - e.stream_off).min(e.size);
                if e.size > 0 && end > written[i] {
                    // preallocate(end), then write: the allocation grows to `end`.
                    out = out - round_up(written[i], cluster) + round_up(end, cluster);
                    written[i] = end;
                }
                i += 1;
            }
        }
        // All of the batch's outputs exist (and are flushed) before the truncation.
        peak = peak.max(archive + meta + out - base_out);
        archive = oracle_len(m, fbo, g.end);
    }
    assert_eq!(
        written,
        m.entries.iter().map(|e| e.size).collect::<Vec<_>>()
    );
    peak
}

/// The offset helpers agree with the layout computed from first principles.
fn check_offsets(rng: &mut Rng, m: &Manifest, fbo: u64) {
    let n = m.blocks.len();
    let offs = m.block_offsets(fbo);
    for k in 1..=n {
        assert_eq!(
            offs[k - 1],
            oracle_len(m, fbo, k),
            "block_offsets[{}]",
            k - 1
        );
    }
    assert_eq!(m.archive_len(fbo), oracle_len(m, fbo, 0));
    for _ in 0..4 {
        let k = rng.below(n as u64 + 1) as usize;
        let len = oracle_len(m, fbo, k);
        assert_eq!(m.len_after_consuming(fbo, k), len);
        assert_eq!(m.consumed_blocks(fbo, len), Some(k));
        // Lengths between boundaries (a torn truncation) are not taken for a boundary.
        if k < n && m.blocks[k].c_len + F > 1 {
            assert_eq!(m.consumed_blocks(fbo, len + 1), None);
        }
    }
}

fn run_case(seed: u64) {
    let mut rng = Rng::new(seed);
    let m = random_manifest(&mut rng);
    let n = m.blocks.len();
    let fbo = between(&mut rng, 64, 1 << 20);
    let consumed = match rng.below(4) {
        0 => rng.below(n as u64 + 1) as usize,
        _ => 0,
    };
    let p = random_params(&mut rng);
    check_offsets(&mut rng, &m, fbo);

    let b = space::bound(&m, fbo, consumed, &p);
    assert_eq!(b.archive_len, oracle_len(&m, fbo, consumed));
    assert_eq!(
        b.remaining_u,
        m.blocks[consumed..].iter().map(|b| b.u_len).sum::<u64>()
    );
    assert_eq!(b.batches, space::batches(&m, consumed, p.batch_max_u).len());
    assert_eq!(b.consume_extra, b.consume_peak - b.archive_len);

    let peak = simulate(&m, fbo, consumed, &p);
    assert!(
        peak <= b.consume_peak,
        "seed {seed}: simulated peak {peak} > planned {} ({} blocks, {} entries, consumed \
         {consumed}, {p:?})",
        b.consume_peak,
        n,
        m.entries.len()
    );
}

#[test]
fn trnc_planner_never_underestimates_the_consume_peak() {
    for seed in 0..1000 {
        run_case(seed);
    }
}

/// Lots of single-block batches over tiny files: the case where the per-batch accounting has
/// the most chances to drift.
#[test]
fn trnc_planner_holds_for_one_block_batches() {
    for seed in 10_000..10_500 {
        let mut rng = Rng::new(seed);
        let m = random_manifest(&mut rng);
        let p = SpaceParams {
            batch_max_u: 1,
            ..random_params(&mut rng)
        };
        let b = space::bound(&m, 4096, 0, &p);
        let peak = simulate(&m, 4096, 0, &p);
        assert!(
            peak <= b.consume_peak,
            "seed {seed}: {peak} > {}",
            b.consume_peak
        );
    }
}

/// Regression: a file that straddles a batch boundary is released half written. Its allocation
/// then reaches a whole cluster past its written length, which the rounding allowance for its
/// final size (zero here: the size is a multiple of the cluster) does not cover.
#[test]
fn trnc_bound_covers_a_file_released_half_written() {
    let size = 2 * 4096;
    let m = manifest(
        vec![entry("f".into(), EntryKind::File, size, 0)],
        &[(4097, 4097), (4095, 4095)],
    );
    let p = SpaceParams {
        cluster_size: 4096,
        per_entry_overhead: 0,
        margin_fixed: 0,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    let fbo = 1000;
    // First batch: the whole archive is present and "f" holds 4097 bytes in two clusters.
    let full = oracle_len(&m, fbo, 0);
    assert_eq!(simulate(&m, fbo, 0, &p), full + size);
    let b = space::bound(&m, fbo, 0, &p);
    assert!(
        full + size <= b.consume_peak,
        "planned {} is short by {}",
        b.consume_peak,
        (full + size).saturating_sub(b.consume_peak)
    );
}

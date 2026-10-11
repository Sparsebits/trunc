//! The resumable stream decoders against reference encoders: every sample decodes to the
//! original, corruption is caught, and decoding resumes from every safe point with the input
//! before it zeroed (as punching leaves it) and the window read back through `History`.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::stream::{self, Codec, History, Input, Limits, NoHistory, StreamError};
use trunc_testkit::tarbuild::{self, XzCheck};
use trunc_testkit::{CrashModel, FaultFs, Rng, fixtures};

fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/z"), bytes);
    let h = fs
        .open(Path::new("/z"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    (fs, h)
}

/// A safe point as handed out: cursor, output offset, free-below.
type Point = (Vec<u8>, u64, u64);

fn decode(
    codec: Codec,
    h: &dyn FileHandle,
    start: Option<&[u8]>,
    history: &mut dyn History,
    every: u64,
) -> Result<(Vec<u8>, Vec<Point>, stream::StreamEnd), StreamError> {
    decode_threads(codec, h, start, history, every, 0)
}

fn decode_threads(
    codec: Codec,
    h: &dyn FileHandle,
    start: Option<&[u8]>,
    history: &mut dyn History,
    every: u64,
    threads: usize,
) -> Result<(Vec<u8>, Vec<Point>, stream::StreamEnd), StreamError> {
    let mut out = Vec::new();
    let mut points = Vec::new();
    let len = h.size().unwrap();
    let end = stream::decode(
        codec,
        Input { src: h, len },
        start,
        history,
        Limits {
            threads,
            ..Limits::new(u64::MAX)
        },
        every,
        &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        },
        &mut |p| {
            points.push((p.cursor.to_vec(), p.out, p.free_below));
            Ok(())
        },
    )?;
    Ok((out, points, end))
}

/// Output already produced, as the engine would read it back from disk.
struct VecHistory<'a>(&'a [u8]);

impl History for VecHistory<'_> {
    fn read(&mut self, at: u64, buf: &mut [u8]) -> stream::Result<()> {
        let at = usize::try_from(at).unwrap();
        buf.copy_from_slice(&self.0[at..at + buf.len()]);
        Ok(())
    }
}

fn samples() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(31);
    let mut mixed = fixtures::text_bytes(&mut rng, 300_000);
    mixed.extend(fixtures::noise_bytes(&mut rng, 100_000));
    mixed.extend(vec![0u8; 200_000]);
    mixed.extend(fixtures::text_bytes(&mut rng, 100_000));
    vec![
        Vec::new(),
        b"a".to_vec(),
        b"aaaaa".to_vec(),
        vec![7u8; 1000],
        (0..=255u8).cycle().take(70_000).collect(),
        fixtures::text_bytes(&mut rng, 50_000),
        fixtures::noise_bytes(&mut rng, 40_000),
        mixed,
    ]
}

/// Decode, compare, then resume from every safe point and compare the rest.
fn check(codec: Codec, data: &[u8], bytes: &[u8], every: u64) -> usize {
    let (_fs, h) = host(bytes);
    let (out, points, end) = decode(codec, h.as_ref(), None, &mut NoHistory, every)
        .unwrap_or_else(|e| panic!("{codec:?}, {} bytes: {e}", data.len()));
    assert!(
        out == data,
        "{codec:?}: output differs ({} vs {})",
        out.len(),
        data.len()
    );
    assert_eq!(end.out_len, data.len() as u64);
    // Safe points do not depend on how decoding started: a second pass meets the same ones.
    let (_, again, _) = decode(codec, h.as_ref(), None, &mut NoHistory, every).unwrap();
    assert_eq!(again, points);
    let mut prev = (0u64, 0u64);
    for (cursor, at, free_below) in &points {
        assert!(
            *at > prev.0 && *free_below >= prev.1,
            "{codec:?}: points go forward"
        );
        prev = (*at, *free_below);
        assert!(*free_below <= bytes.len() as u64);
        // The input before free_below is gone after a punch.
        let mut punched = bytes.to_vec();
        punched[..*free_below as usize].fill(0);
        let (_fs, h) = host(&punched);
        let (rest, later, end) = decode(
            codec,
            h.as_ref(),
            Some(cursor),
            &mut VecHistory(&out),
            every,
        )
        .unwrap_or_else(|e| panic!("{codec:?}: resume at {at}: {e}"));
        assert!(
            rest == data[*at as usize..],
            "{codec:?}: resume at {at} differs"
        );
        assert_eq!(end.out_len, data.len() as u64);
        let expect: Vec<_> = points.iter().filter(|p| p.1 > *at).cloned().collect();
        assert_eq!(
            later, expect,
            "{codec:?}: resumed run meets the same points"
        );
    }
    points.len()
}

fn corrupt_is_refused(codec: Codec, bytes: &[u8]) {
    for at in [bytes.len() / 3, bytes.len() / 2, bytes.len() * 4 / 5] {
        let mut bad = bytes.to_vec();
        bad[at] ^= 0x20;
        let (_fs, h) = host(&bad);
        let r = decode(codec, h.as_ref(), None, &mut NoHistory, 0);
        assert!(r.is_err(), "{codec:?}: flipped byte {at} was not noticed");
    }
    let (_fs, h) = host(&bytes[..bytes.len() - 3]);
    assert!(
        decode(codec, h.as_ref(), None, &mut NoHistory, 0).is_err(),
        "{codec:?}: truncated"
    );
}

#[test]
fn gzip_round_trips_and_resumes() {
    for d in samples() {
        check(Codec::Gzip, &d, &tarbuild::gzip(&d, 6), 16 << 10);
        check(
            Codec::Gzip,
            &d,
            &tarbuild::gzip_members(&d, 30_000, 6),
            16 << 10,
        );
        for chunk in [0xff00, 5000] {
            check(Codec::Gzip, &d, &tarbuild::bgzf(&d, chunk, 6), 16 << 10);
        }
        // Safe points more often than members end: still only between BGZF members.
        let bytes = tarbuild::bgzf(&d, 0xff00, 1);
        let (_fs, h) = host(&bytes);
        let (_, points, _) =
            decode(Codec::Gzip, h.as_ref(), None, &mut NoHistory, 1 << 10).unwrap();
        assert!(points.iter().all(|p| gzip_between_members(&p.0)));
        check(Codec::Gzip, &d, &bytes, 1 << 10);
    }
}

/// A gzip cursor at a member boundary: its inflate checkpoint has produced nothing.
fn gzip_between_members(cursor: &[u8]) -> bool {
    cursor[24..32] == [0; 8]
}

/// A BGZF member around one DEFLATE stream of `data`, its header claiming `bsize`.
fn bgzf_member_claiming(data: &[u8], bsize: u16) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data).unwrap();
    let mut b = vec![
        0x1f, 0x8b, 8, 4, 0, 0, 0, 0, 0, 0xff, 6, 0, b'B', b'C', 2, 0,
    ];
    b.extend_from_slice(&bsize.to_le_bytes());
    b.extend(e.finish().unwrap());
    b.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b
}

/// Decode with one thread and with eight: the same output, safe points or error.
fn same_with_threads(bytes: &[u8], every: u64) -> Result<Vec<u8>, String> {
    let (_fs, h) = host(bytes);
    let run = |threads| {
        decode_threads(
            Codec::Gzip,
            h.as_ref(),
            None,
            &mut NoHistory,
            every,
            threads,
        )
        .map(|(out, points, _)| (out, points))
        .map_err(|e| e.to_string())
    };
    let one = run(1);
    assert_eq!(one, run(8));
    one.map(|r| r.0)
}

/// BGZF headers whose sizes are wrong, and damaged or truncated BGZF files: the same result
/// with and without threads (a gzip decoder ignores the sizes, and so does trunc in the end).
#[test]
fn bgzf_with_wrong_sizes_or_damage() {
    let mut rng = Rng::new(37);
    let d = fixtures::text_bytes(&mut rng, 1_500_000);
    let good = tarbuild::bgzf(&d, 20_000, 6);
    // Member starts, from the sizes in the headers.
    let mut starts = Vec::new();
    let mut at = 0;
    while at < good.len() {
        starts.push(at);
        at += usize::from(u16::from_le_bytes([good[at + 16], good[at + 17]])) + 1;
    }
    assert!(starts.len() > 40);
    for k in [1, starts.len() / 2, starts.len() - 2] {
        for delta in [1i32, -1, 3000] {
            let mut bad = good.clone();
            let s = starts[k] + 16;
            let size = i32::from(u16::from_le_bytes([bad[s], bad[s + 1]])) + delta;
            bad[s..s + 2].copy_from_slice(&(size as u16).to_le_bytes());
            assert!(same_with_threads(&bad, 64 << 10).unwrap() == d);
            check(Codec::Gzip, &d, &bad, 64 << 10);
        }
    }
    // A member much larger than its header says: safe points inside it past the claimed size.
    let mut lying = bgzf_member_claiming(&d[..1_000_000], 2000);
    lying.extend(tarbuild::bgzf(&d[1_000_000..], 20_000, 6));
    assert!(same_with_threads(&lying, 64 << 10).unwrap() == d);
    check(Codec::Gzip, &d, &lying, 64 << 10);
    let (_fs, h) = host(&lying);
    let (_, points, _) = decode(Codec::Gzip, h.as_ref(), None, &mut NoHistory, 64 << 10).unwrap();
    let inside = points
        .iter()
        .filter(|p| !gzip_between_members(&p.0))
        .count();
    assert!(inside >= 2, "{inside} safe points inside the first member");
    for at in [good.len() / 3, good.len() / 2, good.len() - 32] {
        let mut bad = good.clone();
        bad[at] ^= 0x20;
        assert!(same_with_threads(&bad, 64 << 10).is_err(), "flipped {at}");
    }
    for cut in [
        starts[5],
        starts[5] + 9,
        starts[5] + 100,
        good.len() - 30,
        good.len() - 3,
    ] {
        let r = same_with_threads(&good[..cut], 64 << 10);
        // Cut exactly between members, it is a shorter valid file.
        assert!(r.is_err() || cut == starts[5], "cut at {cut}");
    }
    // More output than allowed: the same error, after the same output.
    let (_fs, h) = host(&good);
    let limited = |threads| {
        let mut n = 0u64;
        let r = stream::decode(
            Codec::Gzip,
            Input {
                src: h.as_ref(),
                len: good.len() as u64,
            },
            None,
            &mut NoHistory,
            Limits {
                threads,
                ..Limits::new(700_000)
            },
            64 << 10,
            &mut |b| {
                n += b.len() as u64;
                Ok(())
            },
            &mut |_| Ok(()),
        );
        (n, r.map_err(|e| e.to_string()))
    };
    let one = limited(1);
    assert!(one.1.is_err());
    assert_eq!(one, limited(8));
}

#[test]
fn bzip2_round_trips_and_resumes() {
    let mut points = 0;
    for d in samples() {
        for level in [1, 9] {
            points += check(Codec::Bzip2, &d, &tarbuild::bzip2(&d, level), 16 << 10);
        }
        points += check(
            Codec::Bzip2,
            &d,
            &tarbuild::bzip2_streams(&d, 150_000, 1),
            16 << 10,
        );
    }
    assert!(points > 10, "only {points} safe points");
    let mut rng = Rng::new(32);
    let d = fixtures::text_bytes(&mut rng, 400_000);
    corrupt_is_refused(Codec::Bzip2, &tarbuild::bzip2(&d, 1));
}

#[test]
fn bzip2_long_runs_and_large_blocks() {
    // Runs of every length around the four-byte run-length threshold, and output much larger
    // than the block (runs of 259 bytes compress to five).
    let mut d = Vec::new();
    for n in 0..300usize {
        d.extend(std::iter::repeat_n((n % 251) as u8, n));
    }
    d.extend(vec![b'z'; 3 << 20]);
    for level in [1, 5, 9] {
        check(Codec::Bzip2, &d, &tarbuild::bzip2(&d, level), 64 << 10);
    }
}

#[test]
fn xz_round_trips_and_resumes() {
    let mut points = 0;
    for d in samples() {
        for preset in [0, 6] {
            points += check(Codec::Xz, &d, &tarbuild::xz(&d, preset), 16 << 10);
        }
        for check_kind in [XzCheck::None, XzCheck::Crc32, XzCheck::Sha256] {
            let bytes = tarbuild::xz_with(&d, 1, check_kind, Some(100_000));
            points += check(Codec::Xz, &d, &bytes, 16 << 10);
        }
        // Concatenated streams, as `cat a.xz b.xz` gives.
        let half = d.len() / 2;
        let mut two = tarbuild::xz(&d[..half], 3);
        two.extend(tarbuild::xz(&d[half..], 3));
        points += check(Codec::Xz, &d, &two, 16 << 10);
    }
    assert!(points > 20, "only {points} safe points");
    let mut rng = Rng::new(33);
    let d = fixtures::text_bytes(&mut rng, 400_000);
    corrupt_is_refused(Codec::Xz, &tarbuild::xz(&d, 6));
    corrupt_is_refused(
        Codec::Xz,
        &tarbuild::xz_with(&d, 6, XzCheck::Sha256, Some(50_000)),
    );
}

#[test]
fn zstd_round_trips_and_resumes() {
    let mut points = 0;
    for d in samples() {
        for level in [1, 3, 19] {
            points += check(Codec::Zstd, &d, &tarbuild::zstd(&d, level), 16 << 10);
        }
        points += check(
            Codec::Zstd,
            &d,
            &tarbuild::zstd_with(&d, 3, false, None),
            16 << 10,
        );
        points += check(
            Codec::Zstd,
            &d,
            &tarbuild::zstd_with(&d, 9, true, Some(24)),
            16 << 10,
        );
        points += check(
            Codec::Zstd,
            &d,
            &tarbuild::zstd_frames(&d, 60_000, 3),
            16 << 10,
        );
    }
    assert!(points > 30, "only {points} safe points");
    let mut rng = Rng::new(34);
    let d = fixtures::text_bytes(&mut rng, 400_000);
    corrupt_is_refused(Codec::Zstd, &tarbuild::zstd(&d, 3));
}

#[test]
fn zstd_skippable_frames_are_ignored() {
    let d = b"between the skippable frames".repeat(100);
    let mut bytes = vec![0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3];
    bytes.extend(tarbuild::zstd(&d, 3));
    bytes.extend([0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    check(Codec::Zstd, &d, &bytes, 1 << 10);
}

#[test]
fn not_this_format_is_a_format_error() {
    let (_fs, h) = host(b"definitely not compressed data at all");
    for codec in Codec::ALL {
        match decode(codec, h.as_ref(), None, &mut NoHistory, 0) {
            Err(StreamError::Format(_)) => {}
            other => panic!("{codec:?}: {:?}", other.map(|r| r.0.len())),
        }
    }
}

#[test]
fn sniffing_tells_the_codecs_apart() {
    let d = b"some data";
    assert_eq!(Codec::sniff(&tarbuild::gzip(d, 6)), Some(Codec::Gzip));
    assert_eq!(Codec::sniff(&tarbuild::bzip2(d, 9)), Some(Codec::Bzip2));
    assert_eq!(Codec::sniff(&tarbuild::xz(d, 6)), Some(Codec::Xz));
    assert_eq!(Codec::sniff(&tarbuild::zstd(d, 3)), Some(Codec::Zstd));
    assert_eq!(
        Codec::sniff(&tarbuild::xz_with(d, 6, XzCheck::None, None)),
        Some(Codec::Xz)
    );
    assert_eq!(Codec::sniff(b"BZh9junk"), None);
    assert_eq!(Codec::sniff(b"PK\x03\x04"), None);
}

/// Data with structure at many scales: repeats near and far, runs, text and noise.
fn structured(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut d = Vec::with_capacity(len);
    while d.len() < len {
        match rng.below(6) {
            0 => {
                let n = 1 + rng.below(5000) as usize;
                d.extend(fixtures::text_bytes(&mut rng, n));
            }
            1 => {
                let n = 1 + rng.below(3000) as usize;
                d.extend(fixtures::noise_bytes(&mut rng, n));
            }
            2 => {
                let b = rng.below(256) as u8;
                d.extend(std::iter::repeat_n(b, 1 + rng.below(2000) as usize));
            }
            _ if !d.is_empty() => {
                let back = 1 + rng.below(d.len().min(1 << 20) as u64) as usize;
                let n = 1 + rng.below(4000) as usize;
                let from = d.len() - back;
                for i in 0..n {
                    let c = d[from + i % back];
                    d.push(c);
                }
            }
            _ => d.push(0),
        }
    }
    d.truncate(len);
    d
}

#[test]
fn every_codec_on_structured_data() {
    for seed in 0..6u64 {
        let d = structured(seed, 300_000 + seed as usize * 97_000);
        for level in [-5, 1, 2, 5, 12, 19, 22] {
            check(Codec::Zstd, &d, &tarbuild::zstd(&d, level), 64 << 10);
        }
        for preset in [0, 3, 9] {
            check(Codec::Xz, &d, &tarbuild::xz(&d, preset), 64 << 10);
        }
        check(Codec::Bzip2, &d, &tarbuild::bzip2(&d, 9), 64 << 10);
        check(Codec::Gzip, &d, &tarbuild::gzip(&d, 9), 64 << 10);
    }
}

/// Found by fuzzing: a damaged Huffman table without two weight-1 symbols decoded to garbage
/// (the frame has no checksum to catch it). The reference decoder rejects it, and so must this.
#[test]
fn zstd_refuses_huffman_tables_the_reference_refuses() {
    let damaged = [
        0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x68, 0x85, 0x00, 0x00, 0x52, 0x01, 0x03, 0x07, 0xe0, 0xe9,
        0x00, 0xa0, 0x9b, 0xe8, 0x14, 0xff, 0x30, 0xff, 0x0d, 0x00,
    ];
    let (_fs, h) = host(&damaged);
    match decode(Codec::Zstd, h.as_ref(), None, &mut NoHistory, 0) {
        Err(StreamError::Corrupt(_)) => {}
        other => panic!("{:?}", other.map(|r| r.0)),
    }
}

/// Files whose blocks or frames decode on several threads: the output and every safe point are
/// the same as with one thread, and resuming works from each.
#[test]
fn parallel_decoding_matches_sequential() {
    let mut rng = Rng::new(35);
    let mut d = fixtures::noise_bytes(&mut rng, 2 << 20);
    d.extend(fixtures::text_bytes(&mut rng, 3 << 20));
    d.extend(structured(36, 1 << 20));
    // Each case with the output ranges where a safe point may fall inside a unit (a block or
    // frame decoded piece by piece); everywhere else they fall between units.
    let mb = |n: u64| n << 20;
    let last_frame = mb(5) + 1..=mb(6);
    let cases: Vec<(Codec, Vec<u8>, Vec<std::ops::RangeInclusive<u64>>)> = vec![
        (Codec::Bzip2, tarbuild::bzip2(&d, 1), vec![]),
        (
            Codec::Bzip2,
            tarbuild::bzip2_streams(&d, 1 << 20, 3),
            vec![],
        ),
        (
            Codec::Xz,
            tarbuild::xz_with(&d, 1, XzCheck::Crc64, Some(1 << 20)),
            vec![],
        ),
        (
            Codec::Xz,
            tarbuild::xz_with(&d, 6, XzCheck::Sha256, Some(700_000)),
            vec![],
        ),
        // The last frame is followed by nothing, so it is not decoded whole.
        (
            Codec::Zstd,
            tarbuild::zstd_frames(&d, 1 << 20, 3),
            vec![last_frame.clone()],
        ),
        // Nor is a frame that does not declare its size.
        (
            Codec::Zstd,
            {
                let mut b = tarbuild::zstd_frames(&d[..2 << 20], 1 << 20, 3);
                b.extend(tarbuild::zstd(&d[2 << 20..3 << 20], 3));
                b.extend(tarbuild::zstd_frames(&d[3 << 20..], 1 << 20, 3));
                b
            },
            vec![mb(2) + 1..=mb(3), last_frame],
        ),
        (Codec::Gzip, tarbuild::bgzf(&d, 0xff00, 6), vec![]),
        (Codec::Gzip, tarbuild::bgzf(&d, 9000, 1), vec![]),
    ];
    for (codec, bytes, inside) in cases {
        let (_fs, h) = host(&bytes);
        let one = decode_threads(codec, h.as_ref(), None, &mut NoHistory, 256 << 10, 1).unwrap();
        let many = decode_threads(codec, h.as_ref(), None, &mut NoHistory, 256 << 10, 8).unwrap();
        assert!(one.0 == d && many.0 == d, "{codec:?}: output");
        assert_eq!(one.1, many.1, "{codec:?}: safe points");
        assert!(one.1.len() > 5, "{codec:?}: {} safe points", one.1.len());
        // Cursors between units: xz tag 3 (blocks of a multi-block stream), zstd tag 0
        // (frames), gzip at a member start; bzip2 cursors are always between blocks.
        let between = |c: &[u8]| match codec {
            Codec::Xz => c[0] == 3,
            Codec::Zstd => c[0] == 0,
            Codec::Gzip => gzip_between_members(c),
            Codec::Bzip2 => true,
        };
        for p in &one.1 {
            assert!(
                between(&p.0) || inside.iter().any(|r| r.contains(&p.1)),
                "{codec:?}: a safe point inside a unit at {}",
                p.1
            );
        }
        check(codec, &d, &bytes, 256 << 10);
    }
}

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::DeflateEncoder;
use proptest::prelude::*;
use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::inflate::{Checkpoint, InflateError, Inflater};
use trunc_testkit::{CrashModel, FaultFs, Rng, fixtures};

fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Host `bytes` at offset `pad` of a file (so non-zero base offsets are exercised).
fn host(bytes: &[u8], pad: usize) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    let mut v = vec![0xEE; pad];
    v.extend_from_slice(bytes);
    v.extend_from_slice(&[0xEE; 7]);
    fs.put_file(Path::new("/z"), &v);
    let h = fs
        .open(Path::new("/z"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    (fs, h)
}

fn inflate_all(
    h: &dyn FileHandle,
    base: u64,
    len: u64,
    max: u64,
) -> Result<(Vec<u8>, u32), InflateError> {
    let mut out = Vec::new();
    let f = Inflater::new(&Checkpoint::start(), max).run(
        h,
        base,
        len,
        &mut |b| {
            out.extend_from_slice(b);
            Ok(())
        },
        0,
        &mut |_| Ok(()),
    )?;
    assert_eq!(f.out_total, out.len() as u64);
    Ok((out, f.crc))
}

fn samples() -> Vec<Vec<u8>> {
    let mut rng = Rng::new(9);
    vec![
        vec![],
        b"a".to_vec(),
        fixtures::text_bytes(&mut rng, 100),
        fixtures::text_bytes(&mut rng, 3 << 20),
        fixtures::noise_bytes(&mut rng, 200_000),
        vec![0u8; 5 << 20],
        b"abcabcabcabc".repeat(50_000),
        [
            fixtures::noise_bytes(&mut rng, 70_000),
            vec![7u8; 70_000],
            fixtures::text_bytes(&mut rng, 70_000),
        ]
        .concat(),
    ]
}

#[test]
fn matches_flate2_at_every_level() {
    for data in samples() {
        for level in [0, 1, 4, 6, 9] {
            let c = deflate(&data, level);
            let (h_fs, h) = host(&c, 13);
            let (out, crc) = inflate_all(h.as_ref(), 13, c.len() as u64, u64::MAX).unwrap();
            assert!(
                out == data,
                "level {level}, {} bytes: output differs",
                data.len()
            );
            assert_eq!(crc, crc32fast::hash(&data));
            drop(h_fs);
        }
    }
}

#[test]
fn resumes_from_every_checkpoint_even_after_earlier_input_is_gone() {
    let mut rng = Rng::new(3);
    let data = [
        fixtures::text_bytes(&mut rng, 2 << 20),
        fixtures::noise_bytes(&mut rng, 300_000),
    ]
    .concat();
    let c = deflate(&data, 6);
    let base = 5u64;
    let (_fs, h) = host(&c, base as usize);

    let out = std::cell::RefCell::new(Vec::new());
    let mut cks: Vec<Checkpoint> = Vec::new();
    Inflater::new(&Checkpoint::start(), u64::MAX)
        .run(
            h.as_ref(),
            base,
            c.len() as u64,
            &mut |b| {
                out.borrow_mut().extend_from_slice(b);
                Ok(())
            },
            64 * 1024,
            &mut |ck| {
                // Every checkpoint is taken after all prior output reached the sink.
                let out = out.borrow();
                assert_eq!(ck.out_total, out.len() as u64);
                assert_eq!(ck.crc, crc32fast::hash(&out));
                cks.push(ck.clone());
                Ok(())
            },
        )
        .unwrap();
    let out = out.into_inner();
    assert_eq!(out, data);
    assert!(cks.len() >= 5, "{} checkpoints", cks.len());

    for ck in &cks {
        let ck = Checkpoint::from_bytes(&ck.to_bytes()).unwrap();
        // Simulate punch mode: wipe every compressed byte wholly before the checkpoint.
        let wipe = (ck.in_bit / 8) as usize;
        h.write_all_at(&vec![0u8; wipe], base).unwrap();
        let mut rest = Vec::new();
        let f = Inflater::new(&ck, u64::MAX)
            .run(
                h.as_ref(),
                base,
                c.len() as u64,
                &mut |b| {
                    rest.extend_from_slice(b);
                    Ok(())
                },
                0,
                &mut |_| Ok(()),
            )
            .unwrap();
        assert_eq!(&data[ck.out_total as usize..], &rest[..]);
        assert_eq!(f.crc, crc32fast::hash(&data));
    }
}

#[test]
fn output_limit_and_overrun_are_errors() {
    let data = vec![1u8; 100_000];
    let c = deflate(&data, 6);
    let (_fs, h) = host(&c, 0);
    assert!(matches!(
        inflate_all(h.as_ref(), 0, c.len() as u64, 99_999),
        Err(InflateError::TooLong(_))
    ));
    inflate_all(h.as_ref(), 0, c.len() as u64, 100_000).unwrap();
    // Telling the decoder the stream is shorter than it is.
    assert!(inflate_all(h.as_ref(), 0, c.len() as u64 - 2, u64::MAX).is_err());
}

#[test]
fn checkpoint_bytes_reject_garbage() {
    assert!(Checkpoint::from_bytes(&[]).is_none());
    let ck = Checkpoint {
        in_bit: 99,
        out_total: 10,
        crc: 5,
        window: vec![1; 10],
    };
    let b = ck.to_bytes();
    assert_eq!(Checkpoint::from_bytes(&b).unwrap(), ck);
    assert!(Checkpoint::from_bytes(&b[..b.len() - 1]).is_none());
    let bad = Checkpoint {
        window: vec![1; 9],
        ..ck
    };
    assert!(
        Checkpoint::from_bytes(&bad.to_bytes()).is_none(),
        "window must match out_total"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let (_fs, h) = host(&bytes, 0);
        let _ = inflate_all(h.as_ref(), 0, bytes.len() as u64, 1 << 20);
    }

    #[test]
    fn corrupted_streams_never_panic(seed in any::<u64>(), flips in 1usize..8) {
        let mut rng = Rng::new(seed);
        let data = fixtures::text_bytes(&mut rng, 20_000);
        let mut c = deflate(&data, 6);
        for _ in 0..flips {
            let i = rng.below(c.len() as u64) as usize;
            c[i] ^= 1 << rng.below(8);
        }
        let (_fs, h) = host(&c, 0);
        let _ = inflate_all(h.as_ref(), 0, c.len() as u64, 1 << 20);
    }

    #[test]
    fn random_data_round_trips(seed in any::<u64>(), len in 0usize..50_000, level in 0u32..10) {
        let mut rng = Rng::new(seed);
        let data = if seed % 2 == 0 { fixtures::text_bytes(&mut rng, len) } else { fixtures::noise_bytes(&mut rng, len) };
        let c = deflate(&data, level);
        let (_fs, h) = host(&c, 3);
        let (out, crc) = inflate_all(h.as_ref(), 3, c.len() as u64, u64::MAX).unwrap();
        prop_assert!(out == data);
        prop_assert_eq!(crc, crc32fast::hash(&data));
    }
}

/// A bit writer for hand-built DEFLATE streams.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    n: usize,
}

impl Bits {
    /// `n` bits of `v`, least significant first (header fields, extra bits).
    fn put(&mut self, v: u32, n: usize) {
        for k in 0..n {
            if self.n % 8 == 0 {
                self.out.push(0);
            }
            *self.out.last_mut().unwrap() |= (((v >> k) & 1) as u8) << (self.n % 8);
            self.n += 1;
        }
    }

    /// A Huffman code of `len` bits, most significant first.
    fn code(&mut self, c: u32, len: usize) {
        for k in (0..len).rev() {
            self.put((c >> k) & 1, 1);
        }
    }
}

/// A final dynamic block with a literal/length code of 'a' (length 1), 256 (length 2) and 257
/// (length `l257`, 0 for none), one distance code of `dist_len` bits, and a code-length code of
/// 0, 1, 2 and 18 at length 2 (18 at `cl18`). It encodes "aaaa": a literal, a match of 3 at
/// distance 1, the end (just "a" without 257).
fn dynamic_block(l257: u32, dist_len: u32, cl18: u32) -> Vec<u8> {
    let mut b = Bits::default();
    b.put(1, 1); // BFINAL
    b.put(2, 2); // dynamic
    b.put(1, 5); // 258 literal/length codes
    b.put(0, 5); // 1 distance code
    b.put(14, 4); // 18 code-length code lengths, up to the one for 1
    // In the order 16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1.
    for l in [0, 0, cl18, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2] {
        b.put(l, 3);
    }
    // Code-length codes (canonical, all of length 2): 0 -> 00, 1 -> 01, 2 -> 10, 18 -> 11.
    let len = |b: &mut Bits, l: u32| b.code(l, 2);
    let zeros = |b: &mut Bits, n: u32| {
        b.code(3, 2);
        b.put(n - 11, 7);
    };
    zeros(&mut b, 97);
    len(&mut b, 1); // 'a'
    zeros(&mut b, 138);
    zeros(&mut b, 20);
    len(&mut b, 2); // 256
    len(&mut b, l257);
    len(&mut b, dist_len);
    // Literal/length codes: 'a' -> 0, 256 -> 10, 257 -> 11; distance 1 -> all zeros.
    b.code(0, 1);
    if l257 != 0 {
        b.code(3, 2);
        b.code(0, dist_len as usize);
    }
    b.code(2, 2);
    b.out
}

fn inflate_bytes(c: &[u8]) -> Result<Vec<u8>, InflateError> {
    let (_fs, h) = host(c, 0);
    inflate_all(h.as_ref(), 0, c.len() as u64, 1 << 20).map(|(o, _)| o)
}

/// flate2's (miniz_oxide's) verdict: the output of a whole stream, or `None`.
fn flate2_inflate(c: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(c), &mut out)
        .ok()
        .map(|_| out)
}

/// zlib (`inflate_table`) refuses incomplete Huffman codes, except a code with no symbols and a
/// literal/length or distance code with a single symbol of length 1; trunc does the same, and
/// so does flate2 (the fuzz oracle). zlib's verdicts, from Python's
/// `zlib.decompress(bytes.fromhex(...), -15)`, are in the comments.
#[test]
fn incomplete_codes_are_refused_as_zlib_does() {
    let cases: [(_, &str, Option<&[u8]>); 4] = [
        // Complete codes, and a single distance code of length 1: "aaaa".
        ((2, 1, 2), "0dc0010900000080a0adfe3f515a", Some(b"aaaa")),
        // A single distance code of length 2: "invalid distances set".
        ((2, 2, 2), "0dc0010900000080a0adfe3f519900", None),
        // No 257, an incomplete literal/length code: "invalid literal/lengths set".
        ((0, 1, 2), "0dc0010900000080a0adfe3f110a", None),
        // 18 at length 3, an incomplete code-length code: "invalid code lengths set".
        ((2, 1, 3), "0dc0810900000080a0adfe3f515a", None),
    ];
    for ((l257, dist_len, cl18), hex, want) in cases {
        let c = dynamic_block(l257, dist_len, cl18);
        let h: String = c.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, hex);
        assert_eq!(inflate_bytes(&c).ok().as_deref(), want, "{hex}");
        assert_eq!(flate2_inflate(&c).as_deref(), want, "{hex}");
    }
}

/// Found by the `inflate_diff` fuzz target (input `176bff888fd78891`): flate2's stream of
/// "\x8f\xd7" and 146 bytes copied from distance 2 (level 7, partial flush) with bit 3 of byte 3
/// flipped. The code-length code is then incomplete, which zlib refuses ("invalid code lengths
/// set") and so does miniz_oxide; trunc used to decode it.
#[test]
fn fuzz_incomplete_code_length_code_is_refused() {
    let c = [
        0xcc, 0xc1, 0xb1, 0x18, 0x00, 0x00, 0x00, 0x80, 0x40, 0xff, 0x29, 0xbc, 0x74, 0xd2, 0xe8,
        0x1e, 0xd9, 0x49, 0x80, 0x01, 0x00,
    ];
    let e = inflate_bytes(&c).unwrap_err();
    assert!(e.to_string().contains("incomplete"), "{e}");
    // The undamaged stream still decodes.
    let mut good = c;
    good[3] ^= 1 << 3;
    let mut want = vec![0x8f, 0xd7];
    for _ in 0..146 {
        want.push(want[want.len() - 2]);
    }
    assert_eq!(inflate_bytes(&good).unwrap(), want);
    assert_eq!(flate2_inflate(&c), None);
    assert_eq!(flate2_inflate(&good), Some(want));
}

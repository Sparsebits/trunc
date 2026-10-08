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

//! Destructive extraction of compressed tarballs and single compressed files: round trips,
//! space freed while decoding, refusals, pauses, crash sweeps and archives made by system tools.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, ConsumeSummary, RetryPolicy};
use trunc_engine::streamconsume::{self, Mode, StreamOptions};
use trunc_engine::zipconsume::ZipOptions;
use trunc_engine::{Error, PauseReason};
use trunc_fs::{FsBackend, FsError, OpenMode, OsFs, Share};
use trunc_legacy::stream::Codec;
use trunc_testkit::tarbuild::{self, NameVia, Spec};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.tar.gz";
const DEST: &str = "/out";

fn specs(seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    let deep = format!("proj/{}/deep.txt", "nested-directory-name".repeat(6));
    vec![
        Spec::dir("./proj"),
        Spec::file("./proj/readme.md", &fixtures::text_bytes(&mut rng, 60_000)),
        Spec::file("proj/src/main.rs", &fixtures::text_bytes(&mut rng, 25_000)),
        Spec::file("proj/bin/blob", &fixtures::noise_bytes(&mut rng, 40_000)),
        Spec::file("proj/empty", b""),
        Spec::dir("proj/hollow"),
        Spec::file(&deep, &fixtures::text_bytes(&mut rng, 9_000)).via(NameVia::GnuLong),
        Spec::file("proj/pax-named.txt", &fixtures::text_bytes(&mut rng, 7_000)).via(NameVia::Pax),
        Spec::file("ünï.txt", "ünïcödé".as_bytes()),
        Spec {
            mode: 0o755,
            ..Spec::file("run.sh", b"#!/bin/sh\n")
        },
    ]
}

fn norm(name: &str) -> String {
    let mut s = name.trim_end_matches('/');
    while let Some(r) = s.strip_prefix("./") {
        s = r;
    }
    s.to_owned()
}

/// What `/out` must contain afterwards.
fn expected(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    for s in specs {
        let name = norm(&s.name);
        let mut parent = name.as_str();
        while let Some((p, _)) = parent.rsplit_once('/') {
            want.insert(format!("out/{p}"), None);
            parent = p;
        }
        let v = (s.typeflag != b'5').then(|| s.data.clone());
        want.insert(format!("out/{name}"), v);
    }
    want
}

fn opts(every: u64) -> ConsumeOptions {
    ConsumeOptions {
        retry: RetryPolicy {
            attempts: 3,
            initial_delay: std::time::Duration::ZERO,
        },
        zip: ZipOptions {
            checkpoint_every: every,
            ..ZipOptions::default()
        },
        ..ConsumeOptions::default()
    }
}

fn fresh(model: CrashModel, bytes: &[u8]) -> FaultFs {
    fresh_at(model, ARC, bytes)
}

fn fresh_at(model: CrashModel, arc: &str, bytes: &[u8]) -> FaultFs {
    let fs = FaultFs::new(model);
    fs.put_file(Path::new(arc), bytes);
    fs.reset_peak();
    fs
}

fn run(fs: &FaultFs, o: &ConsumeOptions) -> Result<ConsumeSummary, Error> {
    run_at(fs, ARC, o)
}

fn run_at(fs: &FaultFs, arc: &str, o: &ConsumeOptions) -> Result<ConsumeSummary, Error> {
    streamconsume::consume_stream(fs, Path::new(arc), Path::new(DEST), o, &mut |_| {})
}

fn assert_complete(fs: &FaultFs, want: &BTreeMap<String, Option<Vec<u8>>>) {
    let got = fs.snapshot();
    if &got != want {
        let missing: Vec<_> = want.keys().filter(|k| !got.contains_key(*k)).collect();
        let extra: Vec<_> = got.keys().filter(|k| !want.contains_key(*k)).collect();
        let differ: Vec<_> = want
            .keys()
            .filter(|k| got.get(*k).is_some_and(|v| Some(v) != want.get(*k)))
            .collect();
        panic!("final tree differs\nmissing {missing:?}\nextra {extra:?}\ndiffer {differ:?}");
    }
}

/// The planner's occupancy bound, with exact (unrounded) accounting as FaultFs measures it.
fn bound(bytes: &[u8], every: u64) -> u64 {
    bound_at(ARC, bytes, every, &opts(every))
}

fn bound_at(arc: &str, bytes: &[u8], every: u64, o: &ConsumeOptions) -> u64 {
    let fs = fresh_at(CrashModel::WriteThrough, arc, bytes);
    let h = fs
        .open(Path::new(arc), OpenMode::Read, Share::Shared)
        .unwrap();
    let layout = streamconsume::scan(h.as_ref(), Path::new(arc), every, &o.stream).unwrap();
    // The margin covers the journal: header, entry list, checkpoint table and two slots.
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 256 << 10,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    streamconsume::stream_space(&layout, true, 4096, &[], &p).consume_peak
}

#[test]
fn extracts_everything_and_removes_the_archive() {
    let sp = specs(1);
    let tar = tarbuild::tar(&sp);
    for bytes in [
        tarbuild::gzip(&tar, 6),
        tarbuild::gzip_members(&tar, 20_000, 6),
    ] {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        let s = run(&fs, &opts(16 << 10)).unwrap();
        assert!(!s.resumed && s.files == 8, "{s:?}");
        assert_complete(&fs, &expected(&sp));
        assert!(fs.peak() <= bound(&bytes, 16 << 10), "peak {}", fs.peak());
    }
}

#[test]
fn frees_compressed_bytes_while_decoding() {
    let mut rng = Rng::new(4);
    let big = fixtures::text_bytes(&mut rng, 3 << 20);
    let sp = vec![Spec::file("big.txt", &big)];
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    run(&fs, &opts(64 << 10)).unwrap();
    assert_complete(&fs, &expected(&sp));
    assert!(fs.peak() <= bound(&bytes, 64 << 10));
    // Most of the archive was released before the output finished growing.
    let saved = bytes.len() as u64 + big.len() as u64 - fs.peak();
    assert!(
        saved > bytes.len() as u64 / 2,
        "peak {} saved only {saved}",
        fs.peak()
    );
}

#[test]
fn without_hole_punching_it_still_works() {
    let sp = specs(2);
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    fs.set_dealloc_supported(false);
    run(&fs, &opts(16 << 10)).unwrap();
    assert_complete(&fs, &expected(&sp));
}

#[test]
fn hostile_and_unsupported_archives_are_refused_untouched() {
    let cases: Vec<Vec<Spec>> = vec![
        vec![
            Spec::file("ok.txt", b"fine"),
            Spec::file("../escape.txt", b"evil"),
        ],
        vec![Spec::file("/etc/passwd", b"evil")],
        vec![Spec::file("a.txt", b"1"), Spec::file("a.txt", b"2")],
        vec![Spec::file("a", b"file"), Spec::file("a/b", b"under a file")],
        vec![
            Spec::file("t.txt", b"target"),
            Spec {
                typeflag: b'1',
                ..Spec::file("hard", b"t.txt")
            },
        ],
    ];
    for sp in cases {
        let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        assert!(
            run(&fs, &opts(16 << 10)).is_err(),
            "{:?}",
            sp[sp.len() - 1].name
        );
        assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.tar.gz"]);
        assert_eq!(fs.get_file(Path::new(ARC)).unwrap(), bytes);
    }
}

#[test]
fn symlinks_and_specials_are_skipped() {
    let sp = vec![
        Spec::file("dir/a.txt", b"a"),
        Spec::symlink("dir/link", "a.txt"),
        Spec {
            typeflag: b'6',
            ..Spec::file("dir/fifo", b"")
        },
    ];
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    let s = run(&fs, &opts(16 << 10)).unwrap();
    assert_eq!((s.symlinks_skipped, s.specials_skipped), (1, 1));
    assert_complete(&fs, &expected(&sp[..1]));
}

#[test]
fn corruption_is_found_before_anything_is_destroyed() {
    let sp = specs(3);
    let mut bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x5A;
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    assert!(run(&fs, &opts(16 << 10)).is_err());
    assert_eq!(
        fs.get_file(Path::new(ARC)).unwrap(),
        bytes,
        "nothing was punched"
    );
    assert!(fs.get_file(Path::new("/a.tar.gz.trncj")).is_none());

    // A truncated download (no gzip trailer) is refused too.
    let good = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::WriteThrough, &good[..good.len() - 4]);
    assert!(run(&fs, &opts(16 << 10)).is_err());
}

#[test]
fn pauses_for_space_and_resumes() {
    let sp = specs(5);
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let needed = {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        run(&fs, &opts(16 << 10)).unwrap();
        fs.peak()
    };
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    fs.set_capacity(Some(needed - 1));
    let mut o = opts(16 << 10);
    o.skip_space_check = true;
    match run(&fs, &o) {
        Err(Error::Paused(PauseReason::NoSpace { .. })) => {}
        other => panic!("expected pause, got {other:?}"),
    }
    fs.set_capacity(None);
    assert!(run(&fs, &o).unwrap().resumed);
    assert_complete(&fs, &expected(&sp));
}

#[test]
fn refuses_to_resume_into_another_destination() {
    let sp = specs(6);
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    fs.inject(Fault::CrashAt(40));
    assert!(run(&fs, &opts(16 << 10)).is_err());
    fs.recover();
    let e = streamconsume::consume_stream(
        &fs,
        Path::new(ARC),
        Path::new("/elsewhere"),
        &opts(16 << 10),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("resume with that destination"),
        "{e}"
    );
    run(&fs, &opts(16 << 10)).unwrap();
    assert_complete(&fs, &expected(&sp));
}

fn op_total(arc: &str, bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh_at(CrashModel::WriteThrough, arc, bytes);
    run_at(&fs, arc, o).unwrap();
    fs.op_count()
}

fn sweep(
    model: CrashModel,
    bytes: &[u8],
    want: &BTreeMap<String, Option<Vec<u8>>>,
    every: u64,
    torn: bool,
) -> u64 {
    sweep_at(model, ARC, bytes, want, &opts(every), torn)
}

/// Crash at every filesystem operation of a consume, recover, finish, and check the result and
/// the peak occupancy.
fn sweep_at(
    model: CrashModel,
    arc: &str,
    bytes: &[u8],
    want: &BTreeMap<String, Option<Vec<u8>>>,
    o: &ConsumeOptions,
    torn: bool,
) -> u64 {
    let every = o.zip.checkpoint_every;
    let total = op_total(arc, bytes, o);
    let limit = bound_at(arc, bytes, every, o);
    let base = arc.trim_start_matches('/');
    for k in 1..=total {
        let fs = fresh_at(model, arc, bytes);
        fs.inject(if torn {
            Fault::TornWrite { op: k, keep: 5 }
        } else {
            Fault::CrashAt(k)
        });
        match run_at(&fs, arc, o) {
            Err(Error::Fs(FsError::Crashed)) => {}
            Ok(_) if torn => continue, // op k was not a write
            other => panic!("op {k}: expected crash, got {other:?}"),
        }
        fs.recover();
        for key in fs.snapshot().keys() {
            let ok = key == "out" || key.starts_with("out/") || key.starts_with(base);
            assert!(ok, "crash at op {k}: unexpected path {key}");
        }
        match run_at(&fs, arc, o) {
            Ok(_) => {}
            // The crash hit the final cleanup and both removals survived.
            Err(Error::Fs(FsError::NotFound { .. })) if fs.get_file(Path::new(arc)).is_none() => {}
            Err(e) => panic!(
                "crash at op {k}: recovery failed: {e}\nstate: {:?}",
                fs.snapshot().keys().collect::<Vec<_>>()
            ),
        }
        assert_complete(&fs, want);
        assert!(
            fs.peak() <= limit,
            "crash at op {k}: peak {} > bound {limit}",
            fs.peak()
        );
    }
    total
}

#[test]
fn crash_sweep() {
    let mut rng = Rng::new(11);
    let sp = vec![
        Spec::file("a/big.txt", &fixtures::text_bytes(&mut rng, 300_000)),
        Spec::file("a/raw.bin", &fixtures::noise_bytes(&mut rng, 90_000)),
        Spec::file("a/b/c.txt", &fixtures::text_bytes(&mut rng, 20_000)),
        Spec::file("small.txt", b"small"),
        Spec::file("empty.txt", b""),
    ];
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let want = expected(&sp);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, 32 << 10, false);
    assert!(n > 60, "{n} crash points");
    // Write-through keeps every punch that happened before the crash: this is the model that
    // catches freeing bytes before the checkpoint covering them is durable.
    sweep(CrashModel::WriteThrough, &bytes, &want, 32 << 10, false);
    for seed in [3, 4, 5] {
        sweep(
            CrashModel::RandomSubset { seed },
            &bytes,
            &want,
            32 << 10,
            false,
        );
    }
    sweep(CrashModel::LoseUnflushed, &bytes, &want, 32 << 10, true);
}

#[test]
fn crash_sweep_many_members() {
    let mut rng = Rng::new(12);
    let sp = vec![
        Spec::file("x/one.txt", &fixtures::text_bytes(&mut rng, 120_000)),
        Spec::file("x/two.bin", &fixtures::noise_bytes(&mut rng, 30_000)),
        Spec::dir("x/empty-dir"),
    ];
    // Members of 8 KiB: checkpoints fall on member boundaries.
    let bytes = tarbuild::gzip_members(&tarbuild::tar(&sp), 8 << 10, 6);
    let want = expected(&sp);
    sweep(CrashModel::LoseUnflushed, &bytes, &want, 24 << 10, false);
    sweep(CrashModel::WriteThrough, &bytes, &want, 24 << 10, false);
}

#[test]
fn verify_and_extract_without_consuming() {
    let sp = specs(7);
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 9);
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.tar.gz");
    std::fs::write(&arc, &bytes).unwrap();
    let fs = OsFs::new();
    assert_eq!(
        streamconsume::detect(&fs, &arc, false),
        Some((Codec::Gzip, Mode::Tar))
    );
    let layout = streamconsume::verify_stream(&fs, &arc, &StreamOptions::default()).unwrap();
    assert_eq!(layout.entries.len(), sp.len());
    let out = d.path().join("out");
    let s =
        streamconsume::extract_stream(&fs, &arc, &out, false, &StreamOptions::default()).unwrap();
    assert_eq!(s.files, 8);
    for spec in sp.iter().filter(|s| s.typeflag == b'0') {
        assert_eq!(
            std::fs::read(out.join(norm(&spec.name))).unwrap(),
            spec.data,
            "{}",
            spec.name
        );
    }
    assert!(
        streamconsume::extract_stream(&fs, &arc, &out, false, &StreamOptions::default()).is_err(),
        "refuses to overwrite"
    );
    streamconsume::extract_stream(&fs, &arc, &out, true, &StreamOptions::default()).unwrap();
    assert_eq!(
        std::fs::read(&arc).unwrap(),
        bytes,
        "extraction leaves the archive alone"
    );

    // A plain gzip file that is not a tar is a single compressed file.
    let plain = d.path().join("notes.txt.gz");
    std::fs::write(
        &plain,
        tarbuild::gzip(b"just some text, not a tar archive", 6),
    )
    .unwrap();
    assert_eq!(
        streamconsume::detect(&fs, &plain, false),
        Some((Codec::Gzip, Mode::Single))
    );
}

#[test]
fn consumes_on_the_real_filesystem() {
    let sp = specs(8);
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.tar.gz");
    std::fs::write(&arc, tarbuild::gzip(&tarbuild::tar(&sp), 6)).unwrap();
    let out = d.path().join("out");
    let s = streamconsume::consume_stream(&OsFs::new(), &arc, &out, &opts(16 << 10), &mut |_| {})
        .unwrap();
    assert_eq!(s.files, 8);
    assert!(!arc.exists() && !d.path().join("a.tar.gz.trncj").exists());
    for spec in sp.iter().filter(|s| s.typeflag == b'0') {
        assert_eq!(
            std::fs::read(out.join(norm(&spec.name))).unwrap(),
            spec.data,
            "{}",
            spec.name
        );
    }
}

/// Archives written by the platform's own tar (GNU tar on Linux, bsdtar on Windows and macOS).
#[test]
fn consumes_archives_made_by_system_tar() {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("src");
    fixtures::mixed(&src.join("data"), 21);
    let long = src
        .join("data")
        .join("a-rather-long-directory-name-".repeat(5));
    std::fs::create_dir_all(&long).unwrap();
    std::fs::write(long.join("file-with-a-long-name-too.txt"), b"long path").unwrap();
    let arc = d.path().join("sys.tar.gz");
    let ok = std::process::Command::new("tar")
        .arg("-czf")
        .arg(&arc)
        .arg("-C")
        .arg(&src)
        .arg("data")
        .status();
    match ok {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("no usable system tar; skipping");
            return;
        }
    }
    let out = d.path().join("out");
    streamconsume::consume_stream(&OsFs::new(), &arc, &out, &opts(64 << 10), &mut |_| {}).unwrap();
    trunc_testkit::tree::assert_same(&src.join("data"), &out.join("data"));
    assert!(!arc.exists());
}

/// A pause, a resume, and a crash at every step of the resumed run.
#[test]
fn pause_then_resume_survives_a_crash_at_every_step() {
    let mut rng = Rng::new(13);
    let sp = vec![
        Spec::file("a/big.txt", &fixtures::text_bytes(&mut rng, 200_000)),
        Spec::file("a/b/c.txt", &fixtures::text_bytes(&mut rng, 30_000)),
        Spec::file("top.txt", b"top"),
    ];
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let want = expected(&sp);
    let mut o = opts(32 << 10);
    o.skip_space_check = true;
    for extra in [20_000u64, 60_000, 150_000] {
        let paused = |fs: &FaultFs| {
            fs.set_capacity(Some(bytes.len() as u64 + extra));
            let r = run(fs, &o);
            fs.set_capacity(None);
            r.is_err()
        };
        let probe = fresh(CrashModel::LoseUnflushed, &bytes);
        if !paused(&probe) {
            continue;
        }
        let base = probe.op_count();
        run(&probe, &o).unwrap();
        let resumed_ops = probe.op_count() - base;
        for k in 1..=resumed_ops {
            let fs = fresh(CrashModel::LoseUnflushed, &bytes);
            assert!(paused(&fs));
            fs.inject(Fault::CrashAt(fs.op_count() + k));
            if run(&fs, &o).is_ok() {
                continue;
            }
            fs.recover();
            fs.clear_faults();
            match run(&fs, &o) {
                Ok(_) => {}
                Err(Error::Fs(FsError::NotFound { .. }))
                    if fs.get_file(Path::new(ARC)).is_none() => {}
                Err(e) => panic!("extra {extra}, op {k}: {e}"),
            }
            assert_complete(&fs, &want);
        }
    }
}

fn single_tree(name: &str, data: &[u8]) -> BTreeMap<String, Option<Vec<u8>>> {
    BTreeMap::from([
        ("out".to_string(), None),
        (format!("out/{name}"), Some(data.to_vec())),
    ])
}

#[test]
fn single_compressed_files_become_one_output() {
    let mut rng = Rng::new(21);
    let data = fixtures::text_bytes(&mut rng, 400_000);
    let bytes = tarbuild::gzip(&data, 6);
    let arc = "/disk.img.gz";
    let fs = fresh_at(CrashModel::LoseUnflushed, arc, &bytes);
    let s = run_at(&fs, arc, &opts(32 << 10)).unwrap();
    assert_eq!(s.files, 1);
    assert_complete(&fs, &single_tree("disk.img", &data));
    assert!(fs.peak() <= bound_at(arc, &bytes, 32 << 10, &opts(32 << 10)));

    // Names: known suffixes are stripped, tarball shorthands become .tar, others get .out.
    for (arc, out) in [
        ("/notes.GZ", "notes"),
        ("/backup.tgz", "backup.tar"),
        ("/mystery", "mystery.out"),
    ] {
        let small = tarbuild::gzip(b"hello", 6);
        let fs = fresh_at(CrashModel::LoseUnflushed, arc, &small);
        run_at(&fs, arc, &opts(32 << 10)).unwrap();
        assert_complete(&fs, &single_tree(out, b"hello"));
    }

    // An empty stream gives an empty file.
    let fs = fresh_at(
        CrashModel::LoseUnflushed,
        "/empty.gz",
        &tarbuild::gzip(b"", 6),
    );
    run_at(&fs, "/empty.gz", &opts(32 << 10)).unwrap();
    assert_complete(&fs, &single_tree("empty", b""));
}

#[test]
fn raw_mode_keeps_the_tarball_whole() {
    let sp = specs(22);
    let tar = tarbuild::tar(&sp);
    let bytes = tarbuild::gzip(&tar, 6);
    let mut o = opts(16 << 10);
    o.stream.raw = true;
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    run(&fs, &o).unwrap();
    assert_complete(&fs, &single_tree("a.tar", &tar));
}

#[test]
fn crash_sweep_single_file() {
    let mut rng = Rng::new(23);
    let mut data = fixtures::text_bytes(&mut rng, 200_000);
    data.extend(fixtures::noise_bytes(&mut rng, 50_000));
    let bytes = tarbuild::gzip(&data, 6);
    let arc = "/blob.bin.gz";
    let want = single_tree("blob.bin", &data);
    let o = opts(24 << 10);
    let n = sweep_at(CrashModel::LoseUnflushed, arc, &bytes, &want, &o, false);
    assert!(n > 30, "{n} crash points");
    sweep_at(CrashModel::WriteThrough, arc, &bytes, &want, &o, false);
    sweep_at(CrashModel::LoseUnflushed, arc, &bytes, &want, &o, true);
}

/// A fixture encoder.
type Encode = fn(&[u8]) -> Vec<u8>;

/// Every codec, with a fixture encoder and the archive suffix.
fn codecs() -> Vec<(Codec, &'static str, Encode)> {
    vec![
        (Codec::Gzip, "gz", |d| tarbuild::gzip(d, 6)),
        (Codec::Bzip2, "bz2", |d| tarbuild::bzip2(d, 1)),
        (Codec::Xz, "xz", |d| tarbuild::xz(d, 6)),
        (Codec::Zstd, "zst", |d| tarbuild::zstd(d, 3)),
    ]
}

#[test]
fn every_codec_consumes_tarballs_and_single_files() {
    let mut rng = Rng::new(41);
    let sp = vec![
        Spec::file("d/big.txt", &fixtures::text_bytes(&mut rng, 500_000)),
        Spec::file("d/noise.bin", &fixtures::noise_bytes(&mut rng, 120_000)),
        Spec::file("d/e/small.txt", b"small"),
        Spec::dir("d/empty"),
    ];
    let tar = tarbuild::tar(&sp);
    let mut data = fixtures::text_bytes(&mut rng, 300_000);
    data.extend(fixtures::noise_bytes(&mut rng, 400_000));
    for (codec, ext, enc) in codecs() {
        let o = opts(64 << 10);
        let arc = format!("/a.tar.{ext}");
        let bytes = enc(&tar);
        let fs = fresh_at(CrashModel::LoseUnflushed, &arc, &bytes);
        let s = run_at(&fs, &arc, &o).unwrap_or_else(|e| panic!("{codec:?}: {e}"));
        assert!(s.batches > 2, "{codec:?}: {} steps", s.batches);
        assert_complete(&fs, &expected(&sp));
        assert!(
            fs.peak() <= bound_at(&arc, &bytes, 64 << 10, &o),
            "{codec:?}"
        );

        let arc = format!("/data.bin.{ext}");
        let bytes = enc(&data);
        let fs = fresh_at(CrashModel::LoseUnflushed, &arc, &bytes);
        run_at(&fs, &arc, &o).unwrap_or_else(|e| panic!("{codec:?}: {e}"));
        assert_complete(&fs, &single_tree("data.bin", &data));
        let saved = (bytes.len() as u64 + data.len() as u64).saturating_sub(fs.peak());
        assert!(
            saved > bytes.len() as u64 / 3,
            "{codec:?}: saved only {saved}"
        );
    }
}

#[test]
fn crash_sweep_every_codec() {
    let mut rng = Rng::new(42);
    // Noise keeps LZMA2 chunks and zstd blocks small, so there are several checkpoints and
    // resumes need the window back from the staged output and the gap log.
    let sp = vec![
        Spec::file("a/one.txt", &fixtures::text_bytes(&mut rng, 100_000)),
        Spec::file("a/two.bin", &fixtures::noise_bytes(&mut rng, 150_000)),
        Spec::file("a/three.bin", &fixtures::noise_bytes(&mut rng, 3_000)),
        Spec::file("b.txt", b"b"),
        Spec::file("c.bin", &fixtures::noise_bytes(&mut rng, 90_000)),
    ];
    let tar = tarbuild::tar(&sp);
    let mut data = fixtures::text_bytes(&mut rng, 100_000);
    data.extend(fixtures::noise_bytes(&mut rng, 200_000));
    for (codec, ext, enc) in codecs().into_iter().skip(1) {
        let o = opts(48 << 10);
        let arc = format!("/a.tar.{ext}");
        let bytes = enc(&tar);
        assert!(
            checkpoints(&arc, &bytes, &o) >= 2,
            "{codec:?}: too few checkpoints"
        );
        let want = expected(&sp);
        let n = sweep_at(CrashModel::LoseUnflushed, &arc, &bytes, &want, &o, false);
        assert!(n > 40, "{codec:?}: {n} crash points");
        sweep_at(CrashModel::WriteThrough, &arc, &bytes, &want, &o, false);

        let arc = format!("/s.{ext}");
        let bytes = enc(&data);
        assert!(
            checkpoints(&arc, &bytes, &o) >= 2,
            "{codec:?}: too few checkpoints"
        );
        let want = single_tree("s", &data);
        sweep_at(CrashModel::LoseUnflushed, &arc, &bytes, &want, &o, false);
        sweep_at(
            CrashModel::RandomSubset { seed: 9 },
            &arc,
            &bytes,
            &want,
            &o,
            false,
        );
    }
}

/// Multi-block xz, multi-frame zstd and BGZF decode their units on worker threads, with safe
/// points between units only; consuming them survives a crash anywhere.
#[test]
fn crash_sweep_independent_units() {
    let mut rng = Rng::new(43);
    let sp = vec![
        Spec::file("a/one.txt", &fixtures::text_bytes(&mut rng, 120_000)),
        Spec::file("a/two.bin", &fixtures::noise_bytes(&mut rng, 150_000)),
        Spec::file("b.txt", b"b"),
        Spec::file("c.bin", &fixtures::noise_bytes(&mut rng, 90_000)),
    ];
    let tar = tarbuild::tar(&sp);
    let want = expected(&sp);
    let cases = [
        (
            "xz",
            tarbuild::xz_with(&tar, 1, tarbuild::XzCheck::Crc64, Some(64 << 10)),
        ),
        ("zst", tarbuild::zstd_frames(&tar, 64 << 10, 3)),
        ("gz", tarbuild::bgzf(&tar, 16 << 10, 6)),
    ];
    for (ext, bytes) in cases {
        let o = opts(48 << 10);
        let arc = format!("/a.tar.{ext}");
        assert!(
            checkpoints(&arc, &bytes, &o) >= 4,
            "{ext}: too few checkpoints"
        );
        let n = sweep_at(CrashModel::LoseUnflushed, &arc, &bytes, &want, &o, false);
        assert!(n > 40, "{ext}: {n} crash points");
        sweep_at(CrashModel::WriteThrough, &arc, &bytes, &want, &o, false);
        sweep_at(
            CrashModel::RandomSubset { seed: 11 },
            &arc,
            &bytes,
            &want,
            &o,
            false,
        );
    }
}

fn checkpoints(arc: &str, bytes: &[u8], o: &ConsumeOptions) -> usize {
    let fs = fresh_at(CrashModel::WriteThrough, arc, bytes);
    let h = fs
        .open(Path::new(arc), OpenMode::Read, Share::Shared)
        .unwrap();
    streamconsume::scan(
        h.as_ref(),
        Path::new(arc),
        o.zip.checkpoint_every,
        &o.stream,
    )
    .unwrap()
    .ckpts
    .len()
}

/// Names that are ordinary on Linux but illegal on Windows, as real Linux tarballs have them
/// (systemd unit names with backslashes, kernel headers that differ only in case).
#[test]
fn host_names_follow_the_platform() {
    let sp = vec![
        Spec::file("lib/system-systemd\\x2dcryptsetup.slice", b"unit"),
        Spec::file("include/xt_CONNMARK.h", b"upper"),
        Spec::file("include/xt_connmark.h", b"lower"),
        Spec::file("odd:name?", b"odd"),
    ];
    let bytes = tarbuild::gzip(&tarbuild::tar(&sp), 6);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    let r = run(&fs, &opts(16 << 10));
    if cfg!(windows) {
        assert!(r.is_err(), "Windows cannot hold these names");
        assert_eq!(
            fs.get_file(Path::new(ARC)).unwrap(),
            bytes,
            "refused untouched"
        );
    } else {
        r.unwrap();
        assert_complete(&fs, &expected(&sp));
    }
}

/// Put `bytes` on `fs` as parts of `part` bytes named `{base}.001`, `{base}.002`, …
fn put_parts(fs: &FaultFs, base: &str, bytes: &[u8], part: usize) -> Vec<String> {
    tarbuild::split(bytes, part)
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = format!("{base}.{:03}", i + 1);
            fs.put_file(Path::new(&name), p);
            name
        })
        .collect()
}

#[test]
fn split_archives_are_consumed_part_by_part() {
    let mut rng = Rng::new(51);
    let sp = vec![
        Spec::file("v/a.bin", &fixtures::noise_bytes(&mut rng, 300_000)),
        Spec::file("v/b.txt", &fixtures::text_bytes(&mut rng, 200_000)),
        Spec::file("c.bin", &fixtures::noise_bytes(&mut rng, 150_000)),
    ];
    let tar = tarbuild::tar(&sp);
    for (codec, ext, enc) in codecs() {
        let bytes = enc(&tar);
        // Without hole punching, deleting finished parts is what frees space.
        for dealloc in [true, false] {
            let fs = FaultFs::new(CrashModel::LoseUnflushed);
            fs.set_dealloc_supported(dealloc);
            let parts = put_parts(&fs, &format!("/a.tar.{ext}"), &bytes, 60_000);
            assert!(parts.len() > 3);
            fs.reset_peak();
            let first = parts[0].clone();
            let mut o = opts(48 << 10);
            o.allow_unjournaled = true;
            let s = run_at(&fs, &first, &o).unwrap_or_else(|e| panic!("{codec:?}: {e}"));
            assert!(s.files == 3, "{codec:?}: {s:?}");
            assert_complete(&fs, &expected(&sp));
            let total = bytes.len() as u64 + tar.len() as u64;
            assert!(
                fs.peak() + bytes.len() as u64 / 3 < total,
                "{codec:?} dealloc={dealloc}: peak {} of {total}",
                fs.peak()
            );
        }
    }

    // A single compressed file split in parts is named after the joined file.
    let mut rng = Rng::new(52);
    let data = fixtures::noise_bytes(&mut rng, 250_000);
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    let parts = put_parts(&fs, "/disk.img.xz", &tarbuild::xz(&data, 1), 70_000);
    run_at(&fs, &parts[0], &opts(32 << 10)).unwrap();
    assert_complete(&fs, &single_tree("disk.img", &data));
}

#[test]
fn split_archives_refuse_later_parts_and_replaced_parts() {
    let mut rng = Rng::new(53);
    let sp = vec![Spec::file(
        "x.bin",
        &fixtures::noise_bytes(&mut rng, 400_000),
    )];
    let bytes = tarbuild::zstd(&tarbuild::tar(&sp), 3);
    let fs = FaultFs::new(CrashModel::WriteThrough);
    let parts = put_parts(&fs, "/s.tar.zst", &bytes, 100_000);
    let e = run_at(&fs, &parts[2], &opts(32 << 10)).unwrap_err();
    assert!(e.to_string().contains("pass the first part"), "{e}");

    // Crash a third of the way, replace a part that is still needed: resuming refuses.
    let total = {
        let probe = FaultFs::new(CrashModel::WriteThrough);
        let p = put_parts(&probe, "/s.tar.zst", &bytes, 100_000);
        run_at(&probe, &p[0], &opts(32 << 10)).unwrap();
        probe.op_count()
    };
    fs.inject(Fault::CrashAt(total / 3));
    assert!(run_at(&fs, &parts[0], &opts(32 << 10)).is_err());
    fs.recover();
    fs.clear_faults();
    let last = parts.last().unwrap();
    let mut changed = fs.get_file(Path::new(last)).unwrap();
    changed.push(0);
    fs.put_file(Path::new(last), &changed);
    let e = run_at(&fs, &parts[0], &opts(32 << 10)).unwrap_err();
    assert!(e.to_string().contains("not the part"), "{e}");
}

#[test]
fn crash_sweep_split_archive() {
    let mut rng = Rng::new(54);
    let sp = vec![
        Spec::file("p/one.bin", &fixtures::noise_bytes(&mut rng, 160_000)),
        Spec::file("p/two.txt", &fixtures::text_bytes(&mut rng, 60_000)),
    ];
    let tar = tarbuild::tar(&sp);
    let want = expected(&sp);
    for (codec, ext, enc) in [
        (Codec::Zstd, "zst", tarbuild::zstd(&tar, 3)),
        (Codec::Gzip, "gz", tarbuild::gzip(&tar, 6)),
    ] {
        let o = opts(32 << 10);
        let base = format!("/a.tar.{ext}");
        let setup = |model| {
            let fs = FaultFs::new(model);
            let parts = put_parts(&fs, &base, &enc, 50_000);
            fs.reset_peak();
            (fs, parts[0].clone())
        };
        let total = {
            let (fs, first) = setup(CrashModel::WriteThrough);
            run_at(&fs, &first, &o).unwrap();
            fs.op_count()
        };
        for model in [CrashModel::LoseUnflushed, CrashModel::WriteThrough] {
            for k in 1..=total {
                let (fs, first) = setup(model);
                fs.inject(Fault::CrashAt(k));
                match run_at(&fs, &first, &o) {
                    Err(Error::Fs(FsError::Crashed)) => {}
                    other => panic!("{codec:?} op {k}: expected crash, got {other:?}"),
                }
                fs.recover();
                for key in fs.snapshot().keys() {
                    let ok = key == "out" || key.starts_with("out/") || key.starts_with("a.tar.");
                    assert!(ok, "{codec:?} op {k}: unexpected path {key}");
                }
                match run_at(&fs, &first, &o) {
                    Ok(_) => {}
                    // The crash hit the final cleanup and every removal survived.
                    Err(Error::Fs(FsError::NotFound { .. }))
                        if fs.get_file(Path::new(&first)).is_none() => {}
                    Err(e) => panic!(
                        "{codec:?} op {k}: recovery failed: {e}\nstate: {:?}",
                        fs.snapshot().keys().collect::<Vec<_>>()
                    ),
                }
                assert_complete(&fs, &want);
            }
        }
    }
}

/// Archives made by the system's own tools, when they are installed (CI installs them on
/// Linux): tar's compression flags, the parallel compressors that write many members, streams
/// or blocks, long-window zstd, and `split`.
#[test]
fn consumes_archives_made_by_system_tools() {
    use std::process::Command;
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("src");
    fixtures::mixed(&src.join("data"), 61);
    let mut rng = Rng::new(62);
    std::fs::write(
        src.join("data/noise.bin"),
        fixtures::noise_bytes(&mut rng, 3 << 20),
    )
    .unwrap();
    let plain = d.path().join("plain.tar");
    if !Command::new("tar")
        .arg("-cf")
        .arg(&plain)
        .arg("-C")
        .arg(&src)
        .arg("data")
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("no usable system tar; skipping");
        return;
    }
    let sh = |cmd: &str, dir: &Path| {
        let (prog, args) = if cfg!(windows) {
            ("cmd", ["/C", cmd])
        } else {
            ("sh", ["-c", cmd])
        };
        Command::new(prog)
            .args(args)
            .current_dir(dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    // (name, command that writes `name` from `plain.tar` or `src/`, first part if split)
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("t.tar.zst", "tar --zstd -cf t.tar.zst -C src data", None),
        ("t.tar.xz", "tar -cJf t.tar.xz -C src data", None),
        ("t.tar.bz2", "tar -cjf t.tar.bz2 -C src data", None),
        (
            "mt.tar.xz",
            "xz -T0 --block-size=1MiB -c plain.tar > mt.tar.xz",
            None,
        ),
        (
            "long.tar.zst",
            "zstd -q -19 --long=27 -T0 -c plain.tar > long.tar.zst",
            None,
        ),
        ("p.tar.zst", "pzstd -q -p 4 -c plain.tar > p.tar.zst", None),
        ("pi.tar.xz", "pixz -t < plain.tar > pi.tar.xz", None),
        ("pb.tar.bz2", "pbzip2 -c -b5 plain.tar > pb.tar.bz2", None),
        ("lb.tar.bz2", "lbzip2 -c plain.tar > lb.tar.bz2", None),
        ("pg.tar.gz", "pigz -c -i -b 128 plain.tar > pg.tar.gz", None),
        (
            "s.tar.zst",
            "zstd -q -c plain.tar > s.tar.zst && split -b 300k -d -a 3 --numeric-suffixes=1 s.tar.zst s.tar.zst. && rm s.tar.zst",
            Some("s.tar.zst.001"),
        ),
        (
            "a.tar.xz",
            "xz -c plain.tar > a.tar.xz && split -b 250k a.tar.xz a.tar.xz. && rm a.tar.xz",
            Some("a.tar.xz.aa"),
        ),
    ];
    let mut ran = 0;
    for (name, cmd, first) in cases {
        let w = d.path();
        if !sh(cmd, w) {
            eprintln!("{name}: tool not available; skipping");
            continue;
        }
        let arc = w.join(first.unwrap_or(name));
        let out = w.join(format!("out-{name}"));
        streamconsume::consume_stream(&OsFs::new(), &arc, &out, &opts(256 << 10), &mut |_| {})
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        trunc_testkit::tree::assert_same(&src.join("data"), &out.join("data"));
        let stem = first.map_or(*name, |f| &f[..f.len() - 3]);
        let left: Vec<_> = std::fs::read_dir(w)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(stem))
            .collect();
        assert!(left.is_empty(), "{name}: left behind {left:?}");
        ran += 1;
    }
    eprintln!("{ran} of {} system-made archives consumed", cases.len());
}

/// Linux hands a deleted file's inode number to the next new file. Outputs created after a
/// part of a split archive was deleted can get that part's old id, and must not be mistaken for
/// the archive.
#[test]
fn split_part_ids_are_reused_by_later_outputs() {
    let mut rng = Rng::new(55);
    let mut sp = vec![Spec::file(
        "big.bin",
        &fixtures::noise_bytes(&mut rng, 200_000),
    )];
    for i in 0..40 {
        sp.push(Spec::file(
            &format!("many/f{i:02}.txt"),
            &fixtures::text_bytes(&mut rng, 3_000),
        ));
    }
    let bytes = tarbuild::zstd(&tarbuild::tar(&sp), 3);
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.set_reuse_ids(true);
    let parts = put_parts(&fs, "/r.tar.zst", &bytes, 40_000);
    run_at(&fs, &parts[0], &opts(16 << 10)).unwrap();
    assert_complete(&fs, &expected(&sp));
}

/// Names that only clash at the end of a consume (or only on NTFS) are refused before anything
/// is freed: the staging directory's name, a gap-log sidecar next to the archive, and pairs
/// NTFS upper-cases to the same name.
#[test]
fn late_name_clashes_are_refused_untouched() {
    let refused = |arc: &str, dest: &str, sp: &[Spec]| {
        let bytes = tarbuild::gzip(&tarbuild::tar(sp), 6);
        let fs = fresh_at(CrashModel::WriteThrough, arc, &bytes);
        let r = streamconsume::consume_stream(
            &fs,
            Path::new(arc),
            Path::new(dest),
            &opts(16 << 10),
            &mut |_| {},
        );
        let untouched = fs.get_file(Path::new(arc)).as_deref() == Some(&bytes[..]);
        (r.is_err(), untouched)
    };
    let stage = [
        Spec::file("ok.txt", b"fine"),
        Spec::file(".trunc-stage-00112233445566778899aabbccddeeff", b"x"),
    ];
    assert_eq!(refused(ARC, DEST, &stage), (true, true));
    let gap = [
        Spec::file("ok.txt", b"fine"),
        Spec::file("a.tar.gz.TRNCG", b"x"),
    ];
    assert_eq!(refused("/out/a.tar.gz", "/out", &gap), (true, true));
    assert_eq!(refused("/out/a.tar.gz", "/out", &gap[..1]), (false, false));
    for (a, b) in [("file", "f\u{131}le"), ("sea", "\u{17f}ea")] {
        let pair = [Spec::file(a, b"1"), Spec::file(b, b"2")];
        let insensitive = cfg!(any(windows, target_os = "macos"));
        assert_eq!(
            refused(ARC, DEST, &pair),
            (insensitive, insensitive),
            "{a:?} vs {b:?}"
        );
    }
}

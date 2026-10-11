//! Uncompressed tar archives: extraction, verification, and destructive extraction through the
//! ZIP consumer (entry and punch mode, refusals, pauses and crash sweeps).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, ConsumeSummary, RetryPolicy};
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_engine::{Error, PauseReason, isoconsume, streamconsume, tarconsume};
use trunc_fs::{FsBackend, FsError, OpenMode, OsFs, Share};
use trunc_testkit::tarbuild::{self, NameVia, Spec};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.tar";
const DEST: &str = "/out";

fn specs(seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    let long = format!("proj/{}/deep.txt", "long-directory-name".repeat(8));
    let mut run = Spec::file("run.sh", b"#!/bin/sh\n");
    run.mode = 0o755;
    vec![
        Spec::dir("proj"),
        Spec::file("proj/readme.md", &fixtures::text_bytes(&mut rng, 6000)),
        Spec::file("proj/src/main.rs", &fixtures::text_bytes(&mut rng, 2500)),
        Spec::file("proj/bin/blob", &fixtures::noise_bytes(&mut rng, 9000)),
        Spec::file("proj/empty", b""),
        Spec::dir("proj/hollow"),
        Spec::file(&long, b"gnu long name").via(NameVia::GnuLong),
        Spec::file("pax/naïve file.txt", &fixtures::text_bytes(&mut rng, 700)).via(NameVia::Pax),
        Spec::file("top.txt", &fixtures::text_bytes(&mut rng, 900)),
        Spec::file("ünï.txt", "ünïcödé".as_bytes()),
        run,
    ]
}

fn build(specs: &[Spec]) -> Vec<u8> {
    let mut b = tarbuild::tar(specs);
    // Writers pad to a 10 KiB record; the reader accepts trailing zeros.
    b.resize(b.len().next_multiple_of(10240), 0);
    b
}

/// What `/out` must contain afterwards (symlinks are never created).
fn expected(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    for s in specs {
        let path = s.name.trim_end_matches('/');
        let mut parent = path;
        while let Some((p, _)) = parent.rsplit_once('/') {
            want.insert(format!("out/{p}"), None);
            parent = p;
        }
        match s.typeflag {
            b'0' => {
                want.insert(format!("out/{path}"), Some(s.data.clone()));
            }
            b'5' => {
                want.insert(format!("out/{path}"), None);
            }
            _ => {}
        }
    }
    want
}

fn opts() -> ConsumeOptions {
    ConsumeOptions {
        retry: RetryPolicy {
            attempts: 3,
            initial_delay: std::time::Duration::ZERO,
        },
        zip: ZipOptions {
            punch: PunchPolicy::Never,
            ..ZipOptions::default()
        },
        ..ConsumeOptions::default()
    }
}

fn punch_opts(every: u64) -> ConsumeOptions {
    let mut o = opts();
    o.zip = ZipOptions {
        punch: PunchPolicy::Auto,
        punch_min: 1,
        checkpoint_every: every,
        allow_overlap: false,
    };
    o
}

fn fresh(model: CrashModel, bytes: &[u8]) -> FaultFs {
    let fs = FaultFs::new(model);
    fs.put_file(Path::new(ARC), bytes);
    fs.reset_peak();
    fs
}

fn run(fs: &FaultFs, o: &ConsumeOptions) -> Result<ConsumeSummary, Error> {
    tarconsume::consume_tar(fs, Path::new(ARC), Path::new(DEST), o, &mut |_| {})
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

/// The planner's occupancy bound that holds whatever the data looks like.
fn guaranteed_peak(bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh(CrashModel::WriteThrough, bytes);
    let t = tarconsume::open_tar(&fs, Path::new(ARC)).unwrap();
    // FaultFs counts exact bytes; the margin covers the journal (header, layout, two slots).
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 128 << 10,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    zipconsume::zip_space(&t.layout, bytes.len() as u64, o, true, 4096, &p).consume_peak_guaranteed
}

#[test]
fn detected_as_plain_tar_only() {
    let bytes = build(&specs(1));
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    let p = Path::new(ARC);
    assert!(tarconsume::is_tar(&fs, p));
    assert!(streamconsume::detect(&fs, p, false).is_none());
    assert!(!isoconsume::is_iso(&fs, p));
    assert!(!trunc_engine::image::detect(&fs, p));
    // A compressed tarball is not a plain tar.
    fs.put_file(Path::new("/b.tar.gz"), &tarbuild::gzip(&bytes, 6));
    assert!(!tarconsume::is_tar(&fs, Path::new("/b.tar.gz")));
    fs.put_file(
        Path::new("/c.bin"),
        &fixtures::noise_bytes(&mut Rng::new(1), 4096),
    );
    assert!(!tarconsume::is_tar(&fs, Path::new("/c.bin")));
}

#[test]
fn extracts_and_verifies_without_touching_the_archive() {
    let sp = specs(1);
    let bytes = build(&sp);
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    let t = tarconsume::verify_tar(&fs, Path::new(ARC)).unwrap();
    assert_eq!(t.layout.entries.len(), sp.len());
    assert!(t.layout.overlaps.is_empty());
    let s = tarconsume::extract_tar(&fs, Path::new(ARC), Path::new(DEST), false).unwrap();
    assert_eq!(s.files, 9);
    let mut want = expected(&sp);
    want.insert("a.tar".into(), Some(bytes.clone()));
    assert_complete(&fs, &want);
    // Without --overwrite, a second extraction refuses to replace anything.
    let e = tarconsume::extract_tar(&fs, Path::new(ARC), Path::new(DEST), false);
    assert!(matches!(e, Err(Error::Refused(_))), "{e:?}");
    tarconsume::extract_tar(&fs, Path::new(ARC), Path::new(DEST), true).unwrap();
    assert_complete(&fs, &want);
}

#[test]
fn entry_mode_consumes_and_removes_the_archive() {
    let sp = specs(2);
    let bytes = build(&sp);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    let s = run(&fs, &opts()).unwrap();
    assert!(!s.resumed);
    assert_complete(&fs, &expected(&sp));
    assert!(
        fs.peak() <= guaranteed_peak(&bytes, &opts()),
        "peak {}",
        fs.peak()
    );
}

#[test]
fn punch_mode_frees_space_inside_a_big_file() {
    let mut rng = Rng::new(4);
    let big = fixtures::noise_bytes(&mut rng, 3 << 20);
    let sp = vec![Spec::file("big.bin", &big), Spec::file("s.txt", b"small")];
    let bytes = build(&sp);
    let o = punch_opts(64 << 10);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    run(&fs, &o).unwrap();
    assert_complete(&fs, &expected(&sp));
    assert!(fs.peak() <= guaranteed_peak(&bytes, &o));
    let saved = bytes.len() as u64 + big.len() as u64 - fs.peak();
    assert!(
        saved > big.len() as u64 / 2,
        "peak {} saved only {saved}",
        fs.peak()
    );
}

#[test]
fn symlinks_and_devices_are_skipped() {
    let mut fifo = Spec::file("fifo", b"");
    fifo.typeflag = b'6';
    let sp = vec![
        Spec::file("dir/a.txt", b"a"),
        Spec::symlink("dir/link", "a.txt"),
        fifo,
        Spec::symlink("toplink", "dir/a.txt"),
    ];
    let bytes = build(&sp);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    let s = run(&fs, &opts()).unwrap();
    assert_eq!(s.symlinks_skipped, 2);
    assert_eq!(s.specials_skipped, 1);
    assert_complete(&fs, &expected(&sp[..1]));
}

#[test]
fn hostile_archives_are_refused_untouched() {
    let traversal = |name: &str| {
        let mut s = Spec::file("x", b"evil");
        s.name = name.into();
        s
    };
    let mut hard = Spec::file("h", b"");
    hard.typeflag = b'1';
    let cases: Vec<Vec<Spec>> = vec![
        vec![Spec::file("ok.txt", b"ok"), traversal("../escape.txt")],
        vec![traversal("/etc/passwd")],
        vec![traversal("a/../../b")],
        vec![traversal("../../x").via(NameVia::Pax)],
        vec![Spec::file("dup.txt", b"1"), Spec::file("dup.txt", b"2")],
        vec![Spec::file("f", b"file"), Spec::file("f/under", b"nested")],
        vec![Spec::symlink("l", "/etc"), Spec::file("l/passwd", b"x")],
        vec![Spec::file("ok.txt", b"ok"), hard],
    ];
    for (i, sp) in cases.iter().enumerate() {
        let bytes = build(sp);
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        assert!(run(&fs, &opts()).is_err(), "case {i}");
        assert!(
            tarconsume::extract_tar(&fs, Path::new(ARC), Path::new(DEST), false).is_err(),
            "case {i}"
        );
        assert!(
            tarconsume::verify_tar(&fs, Path::new(ARC)).is_err(),
            "case {i}"
        );
        assert_eq!(
            fs.snapshot().keys().collect::<Vec<_>>(),
            vec!["a.tar"],
            "case {i}"
        );
        assert_eq!(fs.get_file(Path::new(ARC)).unwrap(), bytes, "case {i}");
    }
    // Truncated inside a file's content.
    let bytes = tarbuild::tar(&[Spec::file("a.bin", &[7u8; 5000])]);
    let fs = fresh(CrashModel::WriteThrough, &bytes[..3000]);
    assert!(matches!(run(&fs, &opts()), Err(Error::Input(_))));
}

#[test]
fn a_file_changed_before_extraction_is_caught_before_release() {
    let mut rng = Rng::new(6);
    let sp = vec![
        Spec::file("first.bin", &fixtures::noise_bytes(&mut rng, 40_000)),
        Spec::file("second.bin", &fixtures::noise_bytes(&mut rng, 40_000)),
    ];
    let bytes = build(&sp);
    let t = {
        let probe = fresh(CrashModel::WriteThrough, &bytes);
        tarconsume::open_tar(&probe, Path::new(ARC)).unwrap()
    };
    let first = t
        .layout
        .entries
        .iter()
        .find(|e| e.name == "first.bin")
        .unwrap();
    let mut tried = 0;
    for k in 1..op_total(&bytes, &opts()) {
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        fs.inject(Fault::CrashAt(k));
        assert!(run(&fs, &opts()).is_err());
        fs.recover();
        fs.clear_faults();
        let len = fs.get_file(Path::new(ARC)).map_or(0, |b| b.len() as u64);
        if fs.get_file(Path::new("/a.tar.trncj")).is_none() || len < first.region_end {
            continue;
        }
        let h = fs
            .open(Path::new(ARC), OpenMode::ReadWrite, Share::Exclusive)
            .unwrap();
        h.write_all_at(b"tampered", first.data_offset + 100)
            .unwrap();
        drop(h);
        let e = run(&fs, &opts()).unwrap_err();
        assert!(matches!(e, Error::Integrity(_)), "op {k}: {e}");
        assert!(fs.get_file(Path::new(ARC)).unwrap().len() as u64 >= first.region_end);
        tried += 1;
    }
    assert!(tried > 0);
}

#[test]
fn pauses_for_space_and_resumes() {
    let sp = specs(3);
    let bytes = build(&sp);
    let needed = {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        run(&fs, &opts()).unwrap();
        fs.peak()
    };
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    fs.set_capacity(Some(needed - 1));
    let mut o = opts();
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
fn zip_iso_and_tar_journals_are_not_mixed_up() {
    let sp = specs(4);
    let bytes = build(&sp);
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    fs.inject(Fault::CrashAt(30));
    assert!(run(&fs, &opts()).is_err());
    fs.recover();
    fs.clear_faults();
    let p = Path::new(ARC);
    assert!(tarconsume::is_tar(&fs, p));
    assert!(!zipconsume::is_zip(&fs, p));
    assert!(!isoconsume::is_iso(&fs, p));
    assert!(streamconsume::detect(&fs, p, false).is_none());
    assert!(isoconsume::journal_dest(&fs, p).is_none());
    let recorded = tarconsume::journal_dest(&fs, p).unwrap();
    assert_eq!(recorded.file_name().unwrap(), "out");
    let e = zipconsume::consume_zip(&fs, p, Path::new(DEST), &opts(), &mut |_| {}).unwrap_err();
    assert!(e.to_string().contains("another kind of archive"), "{e}");
    let e =
        isoconsume::consume_iso(&fs, p, Path::new(DEST), &opts(), false, &mut |_| {}).unwrap_err();
    assert!(e.to_string().contains("another kind of archive"), "{e}");
    run(&fs, &opts()).unwrap();
    assert_complete(&fs, &expected(&sp));
}

fn op_total(bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh(CrashModel::WriteThrough, bytes);
    run(&fs, o).unwrap();
    fs.op_count()
}

fn sweep(
    model: CrashModel,
    bytes: &[u8],
    want: &BTreeMap<String, Option<Vec<u8>>>,
    o: &ConsumeOptions,
    torn: bool,
) -> u64 {
    let total = op_total(bytes, o);
    let bound = guaranteed_peak(bytes, o);
    for k in 1..=total {
        let fs = fresh(model, bytes);
        fs.inject(if torn {
            Fault::TornWrite { op: k, keep: 5 }
        } else {
            Fault::CrashAt(k)
        });
        match run(&fs, o) {
            Err(Error::Fs(FsError::Crashed)) => {}
            Ok(_) if torn => continue, // op k was not a write
            other => panic!("op {k}: expected crash, got {other:?}"),
        }
        fs.recover();
        for key in fs.snapshot().keys() {
            let ok = key == "out" || key.starts_with("out/") || key.starts_with("a.tar");
            assert!(ok, "crash at op {k}: unexpected path {key}");
        }
        match run(&fs, o) {
            Ok(_) => {}
            // The crash hit the final cleanup and both removals survived.
            Err(Error::Fs(FsError::NotFound { .. })) if fs.get_file(Path::new(ARC)).is_none() => {}
            Err(e) => panic!(
                "crash at op {k}: recovery failed: {e}\nstate: {:?}",
                fs.snapshot().keys().collect::<Vec<_>>()
            ),
        }
        assert_complete(&fs, want);
        assert!(
            fs.peak() <= bound,
            "crash at op {k}: peak {} > bound {bound}",
            fs.peak()
        );
    }
    total
}

#[test]
fn crash_sweep_entry_mode() {
    let sp = specs(10);
    let bytes = build(&sp);
    let want = expected(&sp);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, &opts(), false);
    assert!(n > 40, "{n} crash points");
    sweep(CrashModel::WriteThrough, &bytes, &want, &opts(), false);
    for seed in 0..3 {
        sweep(
            CrashModel::RandomSubset { seed },
            &bytes,
            &want,
            &opts(),
            false,
        );
    }
    sweep(CrashModel::LoseUnflushed, &bytes, &want, &opts(), true);
}

#[test]
fn crash_sweep_punch_mode() {
    let mut rng = Rng::new(11);
    let sp = vec![
        Spec::file("a/big.bin", &fixtures::noise_bytes(&mut rng, 300_000)),
        Spec::file("a/raw.txt", &fixtures::text_bytes(&mut rng, 150_000)),
        Spec::file("small.txt", b"small"),
    ];
    let bytes = build(&sp);
    let want = expected(&sp);
    let o = punch_opts(32 << 10);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, &o, false);
    assert!(n > 40, "{n} crash points");
    sweep(CrashModel::WriteThrough, &bytes, &want, &o, false);
    for seed in [7, 8, 9] {
        sweep(CrashModel::RandomSubset { seed }, &bytes, &want, &o, false);
    }
    sweep(CrashModel::LoseUnflushed, &bytes, &want, &o, true);
}

#[test]
fn consumes_on_the_real_filesystem() {
    let sp = specs(5);
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.tar");
    std::fs::write(&arc, build(&sp)).unwrap();
    assert!(tarconsume::is_tar(&OsFs::new(), &arc));
    let dest = d.path().join("out");
    tarconsume::consume_tar(&OsFs::new(), &arc, &dest, &opts(), &mut |_| {}).unwrap();
    assert!(!arc.exists() && !tarconsume::journal_path(&arc).exists());
    for s in &sp {
        if s.typeflag == b'0' {
            assert_eq!(
                &std::fs::read(dest.join(&s.name)).unwrap(),
                &s.data,
                "{}",
                s.name
            );
        }
    }
}

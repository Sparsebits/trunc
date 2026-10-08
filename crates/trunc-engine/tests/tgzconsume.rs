//! Destructive `.tar.gz` extraction: round trips, space freed while decoding, refusals,
//! pauses, crash sweeps and archives made by the system `tar`.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, ConsumeSummary, RetryPolicy};
use trunc_engine::tgzconsume;
use trunc_engine::zipconsume::ZipOptions;
use trunc_engine::{Error, PauseReason};
use trunc_fs::{FsBackend, FsError, OpenMode, OsFs, Share};
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
    let fs = FaultFs::new(model);
    fs.put_file(Path::new(ARC), bytes);
    fs.reset_peak();
    fs
}

fn run(fs: &FaultFs, o: &ConsumeOptions) -> Result<ConsumeSummary, Error> {
    tgzconsume::consume_tgz(fs, Path::new(ARC), Path::new(DEST), o, &mut |_| {})
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
    let fs = fresh(CrashModel::WriteThrough, bytes);
    let h = fs
        .open(Path::new(ARC), OpenMode::Read, Share::Shared)
        .unwrap();
    let layout = tgzconsume::scan(h.as_ref(), Path::new(ARC), every).unwrap();
    // The margin covers the journal: header, entry list, checkpoint table and two slots.
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 256 << 10,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    tgzconsume::tgz_space(&layout, true, 4096, &p).consume_peak
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
        vec![Spec::file("a.txt", b"1"), Spec::file("A.TXT", b"2")],
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
    let e = tgzconsume::consume_tgz(
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

fn op_total(bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh(CrashModel::WriteThrough, bytes);
    run(&fs, o).unwrap();
    fs.op_count()
}

fn sweep(
    model: CrashModel,
    bytes: &[u8],
    want: &BTreeMap<String, Option<Vec<u8>>>,
    every: u64,
    torn: bool,
) -> u64 {
    let o = opts(every);
    let total = op_total(bytes, &o);
    let limit = bound(bytes, every);
    for k in 1..=total {
        let fs = fresh(model, bytes);
        fs.inject(if torn {
            Fault::TornWrite { op: k, keep: 5 }
        } else {
            Fault::CrashAt(k)
        });
        match run(&fs, &o) {
            Err(Error::Fs(FsError::Crashed)) => {}
            Ok(_) if torn => continue, // op k was not a write
            other => panic!("op {k}: expected crash, got {other:?}"),
        }
        fs.recover();
        for key in fs.snapshot().keys() {
            let ok = key == "out" || key.starts_with("out/") || key.starts_with("a.tar.gz");
            assert!(ok, "crash at op {k}: unexpected path {key}");
        }
        match run(&fs, &o) {
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
    assert!(tgzconsume::is_tgz(&fs, &arc));
    let layout = tgzconsume::verify_tgz(&fs, &arc).unwrap();
    assert_eq!(layout.entries.len(), sp.len());
    let out = d.path().join("out");
    let s = tgzconsume::extract_tgz(&fs, &arc, &out, false).unwrap();
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
        tgzconsume::extract_tgz(&fs, &arc, &out, false).is_err(),
        "refuses to overwrite"
    );
    tgzconsume::extract_tgz(&fs, &arc, &out, true).unwrap();
    assert_eq!(
        std::fs::read(&arc).unwrap(),
        bytes,
        "extraction leaves the archive alone"
    );

    // A plain gzip file that is not a tar is not mistaken for one.
    let plain = d.path().join("notes.txt.gz");
    std::fs::write(
        &plain,
        tarbuild::gzip(b"just some text, not a tar archive", 6),
    )
    .unwrap();
    assert!(!tgzconsume::is_tgz(&fs, &plain));
}

#[test]
fn consumes_on_the_real_filesystem() {
    let sp = specs(8);
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.tar.gz");
    std::fs::write(&arc, tarbuild::gzip(&tarbuild::tar(&sp), 6)).unwrap();
    let out = d.path().join("out");
    let s =
        tgzconsume::consume_tgz(&OsFs::new(), &arc, &out, &opts(16 << 10), &mut |_| {}).unwrap();
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
    tgzconsume::consume_tgz(&OsFs::new(), &arc, &out, &opts(64 << 10), &mut |_| {}).unwrap();
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

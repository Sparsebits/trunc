//! ISO 9660 images: extraction, verification, and destructive extraction through the ZIP
//! consumer (entry and punch mode, refusals, pauses and crash sweeps).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, ConsumeSummary, RetryPolicy};
use trunc_engine::isoconsume;
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_engine::{Error, PauseReason};
use trunc_fs::{FsBackend, FsError, OpenMode, OsFs, Share};
use trunc_testkit::isobuild::{IsoBuilder, Spec, SpecKind, Tree};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.iso";
const DEST: &str = "/out";

fn specs(seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    vec![
        Spec::file("proj/readme.md", &fixtures::text_bytes(&mut rng, 6000)),
        Spec::file("proj/src/main.rs", &fixtures::text_bytes(&mut rng, 2500)),
        Spec::file("proj/bin/blob", &fixtures::noise_bytes(&mut rng, 9000)).sections(4096),
        Spec::file("proj/empty", b""),
        Spec::dir("proj/hollow"),
        Spec::file("top.txt", &fixtures::text_bytes(&mut rng, 900)),
        Spec::file("ünï.txt", "ünïcödé".as_bytes()),
        Spec::file("run.sh", b"#!/bin/sh\n").mode(0o755),
    ]
}

fn build(specs: &[Spec]) -> Vec<u8> {
    let mut b = IsoBuilder::new().rock_ridge(true).joliet(true).pad(4);
    for s in specs {
        b.add(s.clone());
    }
    b.build().bytes
}

/// What `/out` must contain afterwards (symlinks are never created).
fn expected(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    for s in specs {
        let mut parent = s.path.as_str();
        while let Some((p, _)) = parent.rsplit_once('/') {
            want.insert(format!("out/{p}"), None);
            parent = p;
        }
        match &s.kind {
            SpecKind::File(d) => {
                want.insert(format!("out/{}", s.path), Some(d.clone()));
            }
            SpecKind::Dir => {
                want.insert(format!("out/{}", s.path), None);
            }
            SpecKind::Symlink(_) => {}
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
    isoconsume::consume_iso(fs, Path::new(ARC), Path::new(DEST), o, &mut |_| {})
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
    let img = isoconsume::open_image(&fs, Path::new(ARC)).unwrap();
    // FaultFs counts exact bytes; the margin covers the journal (header, layout, two slots).
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 128 << 10,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    zipconsume::zip_space(&img.layout, bytes.len() as u64, o, true, 4096, &p)
        .consume_peak_guaranteed
}

#[test]
fn extracts_and_verifies_without_touching_the_image() {
    let sp = specs(1);
    let bytes = build(&sp);
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    let img = isoconsume::verify_iso(&fs, Path::new(ARC)).unwrap();
    assert_eq!(img.layout.entries.len(), 11);
    let s = isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, false).unwrap();
    assert_eq!(s.files, 7);
    let mut want = expected(&sp);
    want.insert("a.iso".into(), Some(bytes.clone()));
    assert_complete(&fs, &want);
    // Without --overwrite, a second extraction refuses to replace anything.
    let e = isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, false);
    assert!(matches!(e, Err(Error::Refused(_))), "{e:?}");
    isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), true, false).unwrap();
    assert_complete(&fs, &want);
}

#[test]
fn entry_mode_consumes_and_removes_the_image() {
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
    // Most of the file's source was released before its output finished growing.
    let saved = bytes.len() as u64 + big.len() as u64 - fs.peak();
    assert!(
        saved > big.len() as u64 / 2,
        "peak {} saved only {saved}",
        fs.peak()
    );
}

#[test]
fn symlinks_and_devices_are_skipped() {
    let sp = vec![
        Spec::file("dir/a.txt", b"a"),
        Spec::symlink("dir/link", "a.txt"),
        Spec::symlink("toplink", "dir/a.txt"),
        Spec::file("dev", b"").mode(0o020_644),
    ];
    let bytes = build(&sp);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    let s = run(&fs, &opts()).unwrap();
    assert_eq!(s.symlinks_skipped, 2);
    assert_complete(&fs, &expected(&sp[..1]));
}

#[test]
fn shared_extents_need_opt_in_to_consume_but_not_to_extract() {
    let sp = vec![
        Spec::file("a.txt", b"shared data"),
        Spec::file("b.txt", b"second"),
        Spec::file("c.txt", b"third file"),
    ];
    let mut b = IsoBuilder::new().rock_ridge(true);
    for s in &sp {
        b.add(s.clone());
    }
    let mut built = b.build();
    let (lba, size) = built.extent(Tree::Primary, "a.txt");
    built.set_extent(Tree::Primary, "b.txt", lba);
    built.set_size(Tree::Primary, "b.txt", size);
    let bytes = built.bytes;
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    want.insert("out/a.txt".into(), Some(b"shared data".to_vec()));
    want.insert("out/b.txt".into(), Some(b"shared data".to_vec()));
    want.insert("out/c.txt".into(), Some(b"third file".to_vec()));

    let fs = fresh(CrashModel::WriteThrough, &bytes);
    isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, false).unwrap();
    let mut with_arc = want.clone();
    with_arc.insert("a.iso".into(), Some(bytes.clone()));
    assert_complete(&fs, &with_arc);

    let fs = fresh(CrashModel::WriteThrough, &bytes);
    let e = run(&fs, &opts()).unwrap_err();
    assert!(e.to_string().contains("--allow-overlap"), "{e}");
    assert_eq!(
        fs.get_file(Path::new(ARC)).unwrap(),
        bytes,
        "refusal touches nothing"
    );
    assert!(fs.get_file(Path::new("/a.iso.trncj")).is_none());
    for base in [opts(), punch_opts(4096)] {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        let mut o = base;
        o.zip.allow_overlap = true;
        run(&fs, &o).unwrap();
        assert_complete(&fs, &want);
    }
}

#[test]
fn partial_overlaps_are_refused_for_extraction_too() {
    let mut rng = Rng::new(5);
    let sp = vec![
        Spec::file("a.bin", &fixtures::noise_bytes(&mut rng, 3 * 2048)),
        Spec::file("b.bin", b"tiny"),
    ];
    let mut b = IsoBuilder::new().joliet(true);
    for s in &sp {
        b.add(s.clone());
    }
    let mut built = b.build();
    let (lba, _) = built.extent(Tree::Joliet, "a.bin");
    built.set_extent(Tree::Joliet, "b.bin", lba + 1);
    let fs = fresh(CrashModel::WriteThrough, &built.bytes);
    assert!(isoconsume::verify_iso(&fs, Path::new(ARC)).is_err());
    let e = isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, false);
    assert!(matches!(e, Err(Error::Refused(_))), "{e:?}");
    assert!(matches!(run(&fs, &opts()), Err(Error::Refused(_))));
    isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, true).unwrap();
}

#[test]
fn hostile_images_are_refused_untouched() {
    let sp = vec![
        Spec::file("a/b/c.txt", b"deep"),
        Spec::file("top.txt", b"top"),
    ];
    let mut b = IsoBuilder::new().joliet(true);
    for s in &sp {
        b.add(s.clone());
    }
    let mut built = b.build();
    built.set_extent(Tree::Joliet, "a/b", built.root(Tree::Joliet));
    let fs = fresh(CrashModel::WriteThrough, &built.bytes);
    assert!(matches!(run(&fs, &opts()), Err(Error::Input(_))));
    assert!(isoconsume::extract_iso(&fs, Path::new(ARC), Path::new(DEST), false, false).is_err());
    assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.iso"]);
}

#[test]
fn a_file_changed_before_extraction_is_caught_before_release() {
    // Interrupt a consumption after its journal exists, then change a file still in the image
    // (in place, so it is the same file): the CRC taken when the consumption started catches it
    // on resume, before the file's bytes are released.
    let mut rng = Rng::new(6);
    let sp = vec![
        Spec::file("first.bin", &fixtures::noise_bytes(&mut rng, 40_000)),
        Spec::file("second.bin", &fixtures::noise_bytes(&mut rng, 40_000)),
    ];
    let bytes = build(&sp);
    let img = {
        let probe = fresh(CrashModel::WriteThrough, &bytes);
        isoconsume::open_image(&probe, Path::new(ARC)).unwrap()
    };
    let first = img
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
        if fs.get_file(Path::new("/a.iso.trncj")).is_none() || len < first.region_end {
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
fn zip_and_iso_journals_are_not_mixed_up() {
    let sp = specs(4);
    let bytes = build(&sp);
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    fs.inject(Fault::CrashAt(30));
    assert!(run(&fs, &opts()).is_err());
    fs.recover();
    fs.clear_faults();
    assert!(isoconsume::is_iso(&fs, Path::new(ARC)));
    assert!(!zipconsume::is_zip(&fs, Path::new(ARC)));
    let recorded = isoconsume::journal_dest(&fs, Path::new(ARC)).unwrap();
    assert_eq!(recorded.file_name().unwrap(), "out");
    let e = zipconsume::consume_zip(&fs, Path::new(ARC), Path::new(DEST), &opts(), &mut |_| {})
        .unwrap_err();
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
            let ok = key == "out" || key.starts_with("out/") || key.starts_with("a.iso");
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
        Spec::file("a/big.bin", &fixtures::noise_bytes(&mut rng, 300_000)).sections(64 << 10),
        Spec::file("a/raw.txt", &fixtures::text_bytes(&mut rng, 150_000)),
        Spec::file("small.txt", b"small"),
    ];
    let bytes = build(&sp);
    let want = expected(&sp);
    let o = punch_opts(32 << 10);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, &o, false);
    assert!(n > 40, "{n} crash points");
    // Write-through keeps every punch made before the crash.
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
    let arc = d.path().join("a.iso");
    std::fs::write(&arc, build(&sp)).unwrap();
    assert!(isoconsume::is_iso(&OsFs::new(), &arc));
    let dest = d.path().join("out");
    isoconsume::consume_iso(&OsFs::new(), &arc, &dest, &opts(), &mut |_| {}).unwrap();
    assert!(!arc.exists() && !isoconsume::journal_path(&arc).exists());
    for s in &sp {
        if let SpecKind::File(data) = &s.kind {
            assert_eq!(
                &std::fs::read(dest.join(&s.path)).unwrap(),
                data,
                "{}",
                s.path
            );
        }
    }
}

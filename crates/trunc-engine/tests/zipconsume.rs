//! Destructive ZIP extraction: entry mode, punch mode, refusals, pauses and crash sweeps.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, ConsumeSummary, RetryPolicy};
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_engine::{Error, PauseReason};
use trunc_fs::{FsBackend, FsError, OpenMode, OsFs, Share};
use trunc_legacy::zip;
use trunc_testkit::zipbuild::{Spec, ZipBuilder};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.zip";
const DEST: &str = "/out";

fn specs(seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    vec![
        Spec::dir("proj"),
        Spec::file("proj/readme.md", &fixtures::text_bytes(&mut rng, 6000)),
        Spec::file("proj/src/main.rs", &fixtures::text_bytes(&mut rng, 2500)).descriptor(true),
        Spec::file("proj/bin/blob", &fixtures::noise_bytes(&mut rng, 4000)).stored(),
        Spec::file("proj/empty", b""),
        Spec::dir("proj/hollow"),
        Spec::file("top.txt", &fixtures::text_bytes(&mut rng, 900)).zip64(),
        Spec::file("ünï.txt", "ünïcödé".as_bytes()).descriptor(false),
        Spec::file("run.sh", b"#!/bin/sh\n").mode(0o100_755),
    ]
}

fn build(specs: &[Spec], prefix: &[u8]) -> Vec<u8> {
    let mut b = ZipBuilder::new().prefix(prefix).comment(b"zip comment");
    for s in specs {
        b.add(s.clone());
    }
    b.build()
}

/// What `/out` must contain afterwards.
fn expected(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    for s in specs {
        let name = String::from_utf8(s.name.clone()).unwrap();
        let name = name.trim_end_matches('/');
        let mut parent = name;
        while let Some((p, _)) = parent.rsplit_once('/') {
            want.insert(format!("out/{p}"), None);
            parent = p;
        }
        let v = if s.name.ends_with(b"/") {
            None
        } else {
            Some(s.data.clone())
        };
        want.insert(format!("out/{name}"), v);
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
    zipconsume::consume_zip(fs, Path::new(ARC), Path::new(DEST), o, &mut |_| {})
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

/// The occupancy bound that holds whatever the data looks like.
fn guaranteed_peak(bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh(CrashModel::WriteThrough, bytes);
    let h = fs
        .open(Path::new(ARC), OpenMode::Read, Share::Shared)
        .unwrap();
    let layout = zip::parse(h.as_ref()).unwrap();
    // FaultFs counts exact bytes; the margin covers the journal (header, layout, two slots).
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 128 << 10,
        margin_ppm: 0,
        batch_max_u: 1,
    };
    zipconsume::zip_space(&layout, bytes.len() as u64, o, true, 4096, &p).consume_peak_guaranteed
}

#[test]
fn entry_mode_extracts_everything_and_removes_the_archive() {
    let sp = specs(1);
    for prefix in [&b""[..], b"#!self-extractor stub\n"] {
        let bytes = build(&sp, prefix);
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        let s = run(&fs, &opts()).unwrap();
        assert!(!s.resumed && s.files >= 6);
        assert_complete(&fs, &expected(&sp));
        assert!(
            fs.peak() <= guaranteed_peak(&bytes, &opts()),
            "peak {}",
            fs.peak()
        );
    }
}

#[test]
fn punch_mode_frees_space_inside_a_big_entry() {
    let mut rng = Rng::new(4);
    let big = fixtures::text_bytes(&mut rng, 3 << 20);
    for spec in [
        Spec::file("big.txt", &big),
        Spec::file("big.raw", &big).stored(),
    ] {
        let sp = vec![spec];
        let bytes = build(&sp, b"");
        let o = punch_opts(64 << 10);
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        run(&fs, &o).unwrap();
        assert_complete(&fs, &expected(&sp));
        let whole = guaranteed_peak(&bytes, &o);
        assert!(fs.peak() <= whole);
        // Most of the compressed entry was released before the output finished growing.
        let saved = bytes.len() as u64 + big.len() as u64 - fs.peak();
        assert!(
            saved > bytes.len() as u64 / 2,
            "peak {} saved only {saved}",
            fs.peak()
        );
    }
}

#[test]
fn overlapping_entries_need_opt_in_and_then_extract_correctly() {
    let inner = Spec::file("inner.txt", b"inside another entry").stored();
    let record = ZipBuilder::local_record(&inner);
    let mut b = ZipBuilder::new();
    b.add(Spec::file("outer.bin", &record).stored());
    b.add(Spec::file("after.txt", b"tail entry"));
    let outer_data_lho = 30 + "outer.bin".len() as u64;
    b.alias(inner.clone(), outer_data_lho);
    let bytes = b.build();

    let fs = fresh(CrashModel::WriteThrough, &bytes);
    assert!(matches!(run(&fs, &opts()), Err(Error::Refused(_))));
    assert_eq!(
        fs.get_file(Path::new(ARC)).unwrap(),
        bytes,
        "refusal touches nothing"
    );
    assert!(fs.get_file(Path::new("/a.zip.trncj")).is_none());

    let mut o = opts();
    o.zip.allow_overlap = true;
    run(&fs, &o).unwrap();
    assert_eq!(
        fs.get_file(Path::new("/out/inner.txt")).unwrap(),
        inner.data
    );
    assert_eq!(fs.get_file(Path::new("/out/outer.bin")).unwrap(), record);
    assert_eq!(
        fs.get_file(Path::new("/out/after.txt")).unwrap(),
        b"tail entry"
    );
}

#[test]
fn hostile_archives_are_refused_untouched() {
    let bytes = build(
        &[
            Spec::file("ok.txt", b"fine"),
            Spec::file("../escape.txt", b"evil"),
        ],
        b"",
    );
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    assert!(run(&fs, &opts()).is_err());
    assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.zip"]);
}

/// Names that differ only in case are refused before anything is freed when the destination
/// folds case (a `casefold` or NTFS folder on Linux), and extracted where it does not (on Linux;
/// Windows and macOS always compare case-insensitively).
#[test]
fn case_insensitive_destinations_are_found_up_front() {
    let pairs: [&[Spec]; 2] = [
        &[Spec::file("A.txt", b"upper"), Spec::file("a.txt", b"lower")],
        &[Spec::file("x", b"file"), Spec::file("X/y", b"under")],
    ];
    for sp in pairs {
        let bytes = build(sp, b"");
        for folds in [true, false] {
            let refused = folds || cfg!(any(windows, target_os = "macos"));
            let fs = fresh(CrashModel::WriteThrough, &bytes);
            fs.set_case_insensitive(folds);
            let r = run(&fs, &opts());
            assert_eq!(r.is_err(), refused, "folds={folds}: {r:?}");
            if refused {
                assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.zip"]);
                assert_eq!(fs.get_file(Path::new(ARC)).unwrap(), bytes, "untouched");
            } else {
                assert_complete(&fs, &expected(sp));
            }

            let fs = fresh(CrashModel::WriteThrough, &bytes);
            fs.set_case_insensitive(folds);
            let r = zipconsume::extract_zip(&fs, Path::new(ARC), Path::new(DEST), false);
            assert_eq!(r.is_err(), refused, "extract, folds={folds}");
            assert_eq!(fs.metadata(Path::new(DEST)).unwrap().is_some(), !refused);
        }
    }
}

#[test]
fn corrupt_entry_stops_before_it_is_destroyed() {
    let sp = specs(2);
    let mut bytes = build(&sp, b"");
    let layout = {
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        let h = fs
            .open(Path::new(ARC), OpenMode::Read, Share::Shared)
            .unwrap();
        zip::parse(h.as_ref()).unwrap()
    };
    let victim = layout
        .entries
        .iter()
        .find(|e| e.name == "proj/readme.md")
        .unwrap()
        .clone();
    bytes[(victim.data_offset + victim.compressed_size / 2) as usize] ^= 0x5A;
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    assert!(matches!(run(&fs, &opts()), Err(Error::Integrity(_))));
    let len = fs.get_file(Path::new(ARC)).unwrap().len() as u64;
    assert!(
        len >= victim.region_end,
        "the corrupt entry's bytes are still there"
    );
    assert!(len < bytes.len() as u64, "entries after it were consumed");
}

#[test]
fn pauses_for_space_and_resumes() {
    let sp = specs(3);
    let bytes = build(&sp, b"");
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
fn refuses_to_resume_into_another_destination() {
    let sp = specs(4);
    let bytes = build(&sp, b"");
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    fs.inject(Fault::CrashAt(30));
    assert!(run(&fs, &opts()).is_err());
    fs.recover();
    let e = zipconsume::consume_zip(
        &fs,
        Path::new(ARC),
        Path::new("/elsewhere"),
        &opts(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("resume with that destination"),
        "{e}"
    );
    run(&fs, &opts()).unwrap();
    assert_complete(&fs, &expected(&sp));
}

fn op_total(bytes: &[u8], o: &ConsumeOptions) -> u64 {
    let fs = fresh(CrashModel::WriteThrough, bytes);
    run(&fs, o).unwrap();
    fs.op_count()
}

fn check_crash_state(fs: &FaultFs, k: u64) {
    for key in fs.snapshot().keys() {
        let ok = key == "out" || key.starts_with("out/") || key.starts_with("a.zip");
        assert!(ok, "crash at op {k}: unexpected path {key}");
    }
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
        check_crash_state(&fs, k);
        match run(&fs, o) {
            Ok(_) => {}
            // The crash hit the final cleanup and both removals survived: the job is complete
            // and nothing of the archive remains, so "not found" is the correct answer.
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
    let bytes = build(&sp, b"stub");
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
        Spec::file("a/big.txt", &fixtures::text_bytes(&mut rng, 400_000)),
        Spec::file("a/raw.bin", &fixtures::noise_bytes(&mut rng, 150_000)).stored(),
        Spec::file("small.txt", b"small"),
    ];
    let bytes = build(&sp, b"");
    let want = expected(&sp);
    let o = punch_opts(32 << 10);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, &o, false);
    assert!(n > 40, "{n} crash points");
    // Write-through keeps every punch that happened before the crash: this is the model that
    // catches deallocating before the checkpoint covering it is durable.
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
    let arc = d.path().join("a.zip");
    std::fs::write(&arc, build(&sp, b"")).unwrap();
    let dest = d.path().join("out");
    zipconsume::consume_zip(&OsFs::new(), &arc, &dest, &opts(), &mut |_| {}).unwrap();
    assert!(!arc.exists() && !zipconsume::journal_path(&arc).exists());
    for s in sp.iter().filter(|s| !s.name.ends_with(b"/")) {
        let name = String::from_utf8(s.name.clone()).unwrap();
        assert_eq!(std::fs::read(dest.join(&name)).unwrap(), s.data, "{name}");
    }
}

/// Punch mode on NTFS: real sparse deallocation inside the archive while it decompresses.
#[cfg(windows)]
#[test]
fn punch_mode_on_ntfs() {
    let mut rng = Rng::new(6);
    let big = fixtures::text_bytes(&mut rng, 8 << 20);
    let sp = vec![Spec::file("big.txt", &big)];
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.zip");
    std::fs::write(&arc, build(&sp, b"")).unwrap();
    let dest = d.path().join("out");
    let mut o = punch_opts(256 << 10);
    o.retry = RetryPolicy::default();
    zipconsume::consume_zip(&OsFs::new(), &arc, &dest, &o, &mut |_| {}).unwrap();
    assert_eq!(std::fs::read(dest.join("big.txt")).unwrap(), big);
    assert!(!arc.exists());
}

/// A ZIP written by Windows' own tooling, consumed destructively.
#[cfg(windows)]
#[test]
fn consumes_archives_made_by_windows() {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("src");
    fixtures::mixed(&src, 8);
    let arc = d.path().join("w.zip");
    let ps = format!(
        "$ErrorActionPreference='Stop'; Compress-Archive -Path '{}' -DestinationPath '{}'",
        src.display(),
        arc.display()
    );
    assert!(
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &ps])
            .status()
            .unwrap()
            .success()
    );
    let dest = d.path().join("out");
    zipconsume::consume_zip(&OsFs::new(), &arc, &dest, &opts(), &mut |_| {}).unwrap();
    trunc_testkit::tree::assert_same(&src, &dest.join("src"));
    assert!(!arc.exists());
}

#[test]
fn verify_media_catches_a_lying_drive_in_both_zip_modes() {
    let mut rng = Rng::new(31);
    let sp = vec![
        Spec::file("big.txt", &fixtures::text_bytes(&mut rng, 400_000)),
        Spec::file("s.txt", b"small"),
    ];
    let bytes = build(&sp, b"");
    for mut o in [opts(), punch_opts(32 << 10)] {
        o.verify_media = true;
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        run(&fs, &o).unwrap();
        assert_complete(&fs, &expected(&sp));

        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        fs.set_flush_lies(true);
        let e = run(&fs, &o).unwrap_err();
        assert!(e.to_string().contains("media verification failed"), "{e}");
        // The entry whose output failed verification still has all its source bytes.
        let h = fs
            .open(Path::new(ARC), OpenMode::Read, Share::Shared)
            .unwrap();
        let mut zeros = 0usize;
        let len = h.size().unwrap() as usize;
        let mut buf = vec![0u8; len];
        h.read_exact_at(&mut buf, 0).unwrap();
        zeros += buf.iter().filter(|&&b| b == 0).count();
        assert!(
            zeros < len / 4,
            "source was not punched away: {zeros} zero bytes of {len}"
        );
    }
}

#[test]
fn refuses_staged_files_that_are_the_zip() {
    let sp = specs(32);
    let bytes = build(&sp, b"");
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.zip");
    std::fs::write(&arc, &bytes).unwrap();
    let dest = d.path().join("out");
    let layout = {
        let h = OsFs::new()
            .open(&arc, OpenMode::Read, Share::Shared)
            .unwrap();
        zip::parse(h.as_ref()).unwrap()
    };
    let id: [u8; 16] = trunc_hash::blake3(&layout.to_bytes())[..16]
        .try_into()
        .unwrap();
    let staged = trunc_engine::consume::stage_dir(&dest, &id)
        .join("proj")
        .join("readme.md");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::hard_link(&arc, &staged).unwrap();
    let e = zipconsume::consume_zip(&OsFs::new(), &arc, &dest, &opts(), &mut |_| {}).unwrap_err();
    let refused =
        e.to_string().contains("is the archive") || matches!(e, Error::Fs(FsError::Busy { .. }));
    assert!(refused, "{e}");
    // Entries after it (consumed first, from the end) were extracted safely; the victim's own
    // bytes are still in the archive.
    let victim = layout
        .entries
        .iter()
        .find(|e| e.name == "proj/readme.md")
        .unwrap();
    let h = OsFs::new()
        .open(&arc, OpenMode::Read, Share::Shared)
        .unwrap();
    assert!(h.size().unwrap() >= victim.region_end);
}

/// A pause, a resume, and a crash at every step of the resumed run (entry and punch mode).
#[test]
fn pause_then_resume_survives_a_crash_at_every_step() {
    let mut rng = Rng::new(13);
    let sp = vec![
        Spec::file("a/big.txt", &fixtures::text_bytes(&mut rng, 200_000)),
        Spec::file("a/b/c.txt", &fixtures::text_bytes(&mut rng, 30_000)),
        Spec::file("top.txt", b"top"),
    ];
    let bytes = build(&sp, b"");
    let want = expected(&sp);
    for base_opts in [opts(), punch_opts(32 << 10)] {
        let mut o = base_opts;
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
}

/// A top-level symlink entry is never created; a crash after the rename phase must still let
/// the cleanup finish.
#[test]
fn top_level_symlink_does_not_wedge_recovery() {
    let sp = vec![
        Spec::file("dir/a.txt", b"a"),
        Spec::file("link", b"dir/a.txt").mode(0o120_777),
    ];
    let bytes = build(&sp, b"");
    let want = expected(&sp[..1]);
    let total = op_total(&bytes, &opts());
    for k in 1..=total {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        fs.inject(Fault::CrashAt(k));
        if run(&fs, &opts()).is_ok() {
            continue;
        }
        fs.recover();
        fs.clear_faults();
        match run(&fs, &opts()) {
            Ok(_) => {}
            Err(Error::Fs(FsError::NotFound { .. })) if fs.get_file(Path::new(ARC)).is_none() => {}
            Err(e) => panic!("op {k}: {e}"),
        }
        assert_complete(&fs, &want);
    }
}

// ---------------------------------------------------------------------------------------------
// bzip2 (12), zstd (93) and xz (95) entries.

/// ZIP method numbers decoded by the stream decoders.
const STREAM_METHODS: [u16; 3] = [12, 93, 95];

fn mixed_specs(seed: u64) -> Vec<Spec> {
    let mut rng = Rng::new(seed);
    vec![
        Spec::dir("m"),
        Spec::file("m/deflate.txt", &fixtures::text_bytes(&mut rng, 30_000)),
        Spec::file("m/stored.bin", &fixtures::noise_bytes(&mut rng, 5_000)).stored(),
        Spec::file("m/bzip2.txt", &fixtures::text_bytes(&mut rng, 40_000)).method(12),
        Spec::file("m/zstd.txt", &fixtures::text_bytes(&mut rng, 60_000)).method(93),
        Spec::file("m/xz.txt", &fixtures::text_bytes(&mut rng, 50_000))
            .method(95)
            .descriptor(true),
        Spec::file("m/zstd.noise", &fixtures::noise_bytes(&mut rng, 20_000))
            .method(93)
            .zip64(),
        Spec::file("m/empty.bz2", b"").method(12),
        Spec::file("m/empty.xz", b"").method(95).descriptor(false),
    ]
}

fn extract(fs: &FaultFs) -> Result<ConsumeSummary, Error> {
    zipconsume::extract_zip(fs, Path::new(ARC), Path::new(DEST), false)
}

/// Contents of `/out` plus the untouched archive.
fn expected_with_archive(sp: &[Spec], bytes: &[u8]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = expected(sp);
    want.insert("a.zip".into(), Some(bytes.to_vec()));
    want
}

#[test]
fn bzip2_zstd_and_xz_entries_extract_and_consume() {
    let sp = mixed_specs(20);
    let bytes = build(&sp, b"sfx");
    {
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        let h = fs
            .open(Path::new(ARC), OpenMode::Read, Share::Shared)
            .unwrap();
        let layout = zip::parse(h.as_ref()).unwrap();
        let methods: Vec<zip::Method> = layout.entries.iter().map(|e| e.method).collect();
        for m in [zip::Method::Bzip2, zip::Method::Zstd, zip::Method::Xz] {
            assert!(methods.contains(&m), "{m:?} missing");
        }
        assert_eq!(zip::Layout::from_bytes(&layout.to_bytes()).unwrap(), layout);
    }
    // Plain extraction.
    let fs = fresh(CrashModel::WriteThrough, &bytes);
    let s = extract(&fs).unwrap();
    assert_eq!(s.files, 8);
    assert_complete(&fs, &expected_with_archive(&sp, &bytes));
    // Consume, in entry mode and in punch mode (where only deflate and stored are punched).
    for o in [opts(), punch_opts(8 << 10)] {
        let fs = fresh(CrashModel::LoseUnflushed, &bytes);
        run(&fs, &o).unwrap();
        assert_complete(&fs, &expected(&sp));
        assert!(
            fs.peak() <= guaranteed_peak(&bytes, &o),
            "peak {}",
            fs.peak()
        );
    }
}

#[test]
fn big_stream_method_entries_are_not_punched() {
    // In punch mode a large zstd entry is still extracted whole: its compressed bytes stay
    // until the entry is complete, so the peak holds both.
    let mut rng = Rng::new(21);
    let big = fixtures::text_bytes(&mut rng, 2 << 20);
    let sp = vec![Spec::file("big.zst.txt", &big).method(93)];
    let bytes = build(&sp, b"");
    let o = punch_opts(64 << 10);
    let fs = fresh(CrashModel::LoseUnflushed, &bytes);
    run(&fs, &o).unwrap();
    assert_complete(&fs, &expected(&sp));
    assert!(fs.peak() >= big.len() as u64 + bytes.len() as u64 / 2);
    assert!(fs.peak() <= guaranteed_peak(&bytes, &o));
}

/// Offsets of the central-directory records.
fn cd_records(bytes: &[u8]) -> Vec<usize> {
    bytes
        .windows(4)
        .enumerate()
        .filter(|(_, w)| *w == [0x50, 0x4b, 0x01, 0x02])
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn crc_or_payload_damage_in_stream_entries_is_refused() {
    let mut rng = Rng::new(22);
    let data = fixtures::text_bytes(&mut rng, 30_000);
    for m in STREAM_METHODS {
        let sp = vec![
            Spec::file("first.txt", b"first entry, consumed before the damaged one"),
            Spec::file("bad.txt", &data).method(m),
        ];
        let good = build(&sp, b"");
        let cds = cd_records(&good);
        assert_eq!(cds.len(), 2);
        // The second entry's local header follows the first entry's record.
        let second = ZipBuilder::local_record(&sp[0]).len();
        assert_eq!(&good[second..second + 4], b"PK\x03\x04");

        // Wrong CRC in both headers: the data decodes but does not match.
        let mut crc = good.clone();
        for at in [second + 14, cds[1] + 16] {
            crc[at] ^= 0x01;
        }
        // Damaged payload: the decoder itself (or the CRC) catches it.
        let mut payload = good.clone();
        let data_at = second + 30 + "bad.txt".len();
        payload[data_at + (cds[0] - data_at) / 3] ^= 0x5A;

        for (what, bytes) in [("crc", &crc), ("payload", &payload)] {
            let fs = fresh(CrashModel::WriteThrough, bytes);
            match extract(&fs) {
                Err(Error::Integrity(msg)) => assert!(msg.contains("bad.txt"), "{msg}"),
                other => panic!("method {m} {what}: extract gave {other:?}"),
            }
            let fs = fresh(CrashModel::WriteThrough, bytes);
            match run(&fs, &opts()) {
                Err(Error::Integrity(msg)) => assert!(msg.contains("bad.txt"), "{msg}"),
                other => panic!("method {m} {what}: consume gave {other:?}"),
            }
            let len = fs.get_file(Path::new(ARC)).unwrap().len();
            assert!(
                len >= cds[0],
                "method {m} {what}: the damaged entry was released"
            );
        }
    }
}

#[test]
fn lzma_and_unknown_methods_are_refused_untouched() {
    for (m, word) in [(14u16, "LZMA"), (98, "PPMd"), (200, "200")] {
        let bytes = build(
            &[
                Spec::file("ok.txt", b"fine"),
                Spec::file("odd.bin", b"not really compressed").method(m),
            ],
            b"",
        );
        let fs = fresh(CrashModel::WriteThrough, &bytes);
        match run(&fs, &opts()) {
            Err(Error::Input(msg)) => {
                assert!(msg.contains(word) && msg.contains("supported"), "{msg}");
            }
            other => panic!("method {m}: {other:?}"),
        }
        assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.zip"]);
        assert!(matches!(extract(&fs), Err(Error::Input(_))));
    }
}

#[test]
fn crash_sweep_mixed_methods() {
    let mut rng = Rng::new(23);
    let sp = vec![
        Spec::file("d.txt", &fixtures::text_bytes(&mut rng, 24_000)),
        Spec::file("b.txt", &fixtures::text_bytes(&mut rng, 6_000)).method(12),
        Spec::file("z.txt", &fixtures::text_bytes(&mut rng, 20_000)).method(93),
        Spec::file("x.txt", &fixtures::text_bytes(&mut rng, 6_000))
            .method(95)
            .descriptor(true),
        Spec::file("s.bin", &fixtures::noise_bytes(&mut rng, 8_000)).stored(),
    ];
    let bytes = build(&sp, b"");
    let want = expected(&sp);
    let n = sweep(CrashModel::LoseUnflushed, &bytes, &want, &opts(), false);
    assert!(n > 20, "{n} crash points");
    sweep(CrashModel::WriteThrough, &bytes, &want, &opts(), false);
    // Punch mode: deflate and stored entries punch, the others go whole.
    let o = punch_opts(4 << 10);
    sweep(CrashModel::WriteThrough, &bytes, &want, &o, false);
}

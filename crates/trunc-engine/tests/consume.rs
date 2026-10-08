//! Destructive extraction: round trips, refusals, pauses, and the crash sweep that checks the
//! invariants in docs/spec/invariants.md at every operation index.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use trunc_core::space::{self, SpaceParams};
use trunc_engine::consume::{self, ConsumeOptions, RetryPolicy};
use trunc_engine::producer::{self, CreateOptions};
use trunc_engine::{Archive, Error, PauseReason};
use trunc_fs::{FsError, OpenMode, OsFs, Share};
use trunc_testkit::tree::{self, Node};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.trnc";
const DEST: &str = "/out";

/// A small but structurally rich tree: nesting, empty files, an empty directory, files that
/// span many blocks and blocks that span many files.
fn sample_tree(root: &Path, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut put = |rel: &str, len: usize| {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, fixtures::text_bytes(&mut rng, len)).unwrap();
    };
    put("a/one.txt", 700);
    put("a/b/two.txt", 3);
    put("a/b/c/big.bin", 9000);
    put("a/empty.txt", 0);
    put("z.txt", 1500);
    put("m/x", 1);
    put("m/y", 2500);
    fs::create_dir_all(root.join("a/hollow")).unwrap();
}

struct Fixture {
    _dir: tempfile::TempDir,
    src: PathBuf,
    bytes: Vec<u8>,
}

fn build(block: u64, f: impl FnOnce(&Path)) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(&src).unwrap();
    f(&src);
    let arc = dir.path().join("a.trnc");
    let o = CreateOptions {
        block_size: block,
        ..CreateOptions::default()
    };
    producer::create(&arc, std::slice::from_ref(&src), &o).unwrap();
    let bytes = fs::read(&arc).unwrap();
    Fixture {
        _dir: dir,
        src,
        bytes,
    }
}

fn opts(batch: u64) -> ConsumeOptions {
    ConsumeOptions {
        space: SpaceParams {
            batch_max_u: batch,
            ..SpaceParams::default()
        },
        retry: RetryPolicy {
            attempts: 3,
            initial_delay: std::time::Duration::ZERO,
        },
        threads: 2,
        ..ConsumeOptions::default()
    }
}

fn fresh_fs(model: CrashModel, fx: &Fixture) -> FaultFs {
    let fs = FaultFs::new(model);
    fs.put_file(Path::new(ARC), &fx.bytes);
    fs.reset_peak();
    fs
}

fn run(fs: &FaultFs, o: &ConsumeOptions) -> Result<consume::ConsumeSummary, Error> {
    consume::consume(fs, Path::new(ARC), Path::new(DEST), o, &mut |_| {})
}

/// The final FaultFs state must hold exactly the source tree under /out/src, plus the receipt.
fn assert_complete(fs: &FaultFs, fx: &Fixture) {
    let snap = fs.snapshot();
    let mut want: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    want.insert("out".into(), None);
    want.insert("out/src".into(), None);
    for (k, v) in tree::snapshot(&fx.src) {
        let v = match v {
            Node::Dir => None,
            Node::File(d) => Some(d),
            Node::Symlink(_) => continue,
        };
        want.insert(format!("out/src/{k}"), v);
    }
    let receipt = snap.get("a.trnc.receipt").cloned();
    let got: BTreeMap<_, _> = snap
        .into_iter()
        .filter(|(k, _)| k != "a.trnc.receipt")
        .collect();
    if got != want {
        let missing: Vec<_> = want.keys().filter(|k| !got.contains_key(*k)).collect();
        let extra: Vec<_> = got.keys().filter(|k| !want.contains_key(*k)).collect();
        let differ: Vec<_> = want
            .keys()
            .filter(|k| got.get(*k).is_some_and(|v| Some(v) != want.get(*k)))
            .collect();
        panic!(
            "final tree differs\nmissing {missing:?}\nextra {extra:?}\ncontent differs {differ:?}"
        );
    }
    let receipt = receipt.flatten().expect("receipt kept");
    let fbo = trunc_core::Header::decode(&fx.bytes[..trunc_core::HEADER_LEN])
        .unwrap()
        .first_block_off();
    assert_eq!(
        receipt.as_slice(),
        &fx.bytes[..fbo as usize],
        "receipt is header + manifest"
    );
}

/// Peak occupancy allowed by the space model with no cluster/metadata allowances (FaultFs
/// counts exact bytes) and a small margin for the resume note.
fn peak_bound(fx: &Fixture, batch: u64) -> u64 {
    let a = {
        let fs = FaultFs::new(CrashModel::WriteThrough);
        fs.put_file(Path::new(ARC), &fx.bytes);
        Archive::open_with(&fs, Path::new(ARC), OpenMode::Read, Share::Shared).unwrap()
    };
    let p = SpaceParams {
        cluster_size: 1,
        per_entry_overhead: 0,
        margin_fixed: 1024,
        margin_ppm: 0,
        batch_max_u: batch,
    };
    space::bound(a.manifest(), a.header().first_block_off(), 0, &p).consume_peak
}

#[test]
fn consumes_on_faultfs_for_various_batch_sizes() {
    let fx = build(1024, |r| sample_tree(r, 1));
    for batch in [1, 4096, 1 << 30] {
        let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
        let s = run(&fs, &opts(batch)).unwrap();
        assert!(!s.resumed);
        assert_complete(&fs, &fx);
        assert!(
            fs.peak() <= peak_bound(&fx, batch),
            "peak {} > bound {}",
            fs.peak(),
            peak_bound(&fx, batch)
        );
        assert!(
            fs.peak() < fx.bytes.len() as u64 + 16_000 + 1024,
            "never holds archive + all output"
        );
    }
}

#[test]
fn consumes_trees_with_no_data_blocks() {
    let fx = build(1024, |r| {
        fs::create_dir_all(r.join("d/e")).unwrap();
        fs::write(r.join("d/empty"), b"").unwrap();
    });
    let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
    run(&fs, &opts(4096)).unwrap();
    assert_complete(&fs, &fx);
}

#[test]
fn consumes_on_the_real_filesystem() {
    let fx = build(64 << 10, |r| fixtures::mixed(r, 5));
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.trnc");
    fs::write(&arc, &fx.bytes).unwrap();
    let dest = d.path().join("out");
    let mut batches = 0;
    let s = consume::consume(&OsFs::new(), &arc, &dest, &opts(256 << 10), &mut |p| {
        if matches!(p, consume::Progress::Batch { .. }) {
            batches += 1;
        }
    })
    .unwrap();
    assert!(batches > 3 && s.batches == batches);
    tree::assert_same(&fx.src, &dest.join("src"));
    assert!(!arc.exists(), "archive consumed");
    assert!(consume::receipt_path(&arc).exists());
    assert!(!consume::resume_note_path(&arc).exists());
    let staged: Vec<_> = fs::read_dir(&dest)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        staged,
        vec![std::ffi::OsString::from("src")],
        "staging directory removed"
    );
}

#[test]
fn refuses_existing_targets_and_wrong_destinations() {
    let fx = build(1024, |r| sample_tree(r, 2));
    let fs = fresh_fs(CrashModel::WriteThrough, &fx);
    fs.put_file(Path::new("/out/src/keep.txt"), b"mine");
    assert!(matches!(run(&fs, &opts(4096)), Err(Error::Refused(_))));
    assert_eq!(
        fs.get_file(Path::new("/out/src/keep.txt")).unwrap(),
        b"mine"
    );
    assert_eq!(
        fs.get_file(Path::new(ARC)).unwrap(),
        fx.bytes,
        "archive untouched"
    );

    // Partially consume into /out, then try to resume into /elsewhere.
    let fs = fresh_fs(CrashModel::WriteThrough, &fx);
    fs.inject(Fault::CrashAt(40));
    assert!(run(&fs, &opts(1024)).is_err());
    fs.recover();
    let a = Archive::open_with(&fs, Path::new(ARC), OpenMode::Read, Share::Shared).unwrap();
    assert!(
        a.consumed() > 0,
        "crash point should be after the first truncation"
    );
    drop(a);
    let e = consume::consume(
        &fs,
        Path::new(ARC),
        Path::new("/elsewhere"),
        &opts(1024),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(e.to_string().contains("being extracted into"), "{e}");
    run(&fs, &opts(1024)).unwrap();
    assert_complete(&fs, &fx);
}

#[test]
fn pauses_when_space_runs_out_and_resumes() {
    let fx = build(1024, |r| sample_tree(r, 3));
    let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
    let mut o = opts(2048);
    o.skip_space_check = true;
    fs.set_capacity(Some(fx.bytes.len() as u64 + 3000));
    match run(&fs, &o) {
        Err(Error::Paused(PauseReason::NoSpace { needed })) => assert!(needed > 0),
        other => panic!("expected a pause, got {other:?}"),
    }
    assert!(!fs.is_crashed(), "a pause is not a crash");
    // Archive is still a valid, partially consumed .trnc.
    Archive::open_with(&fs, Path::new(ARC), OpenMode::Read, Share::Shared).unwrap();
    fs.set_capacity(None);
    let s = run(&fs, &o).unwrap();
    assert!(s.resumed);
    assert_complete(&fs, &fx);
}

#[test]
fn refuses_up_front_when_space_is_clearly_short() {
    let fx = build(1024, |r| sample_tree(r, 3));
    let fs = fresh_fs(CrashModel::WriteThrough, &fx);
    fs.set_capacity(Some(fx.bytes.len() as u64 + 10));
    assert!(matches!(run(&fs, &opts(2048)), Err(Error::Refused(_))));
    assert_eq!(fs.get_file(Path::new(ARC)).unwrap(), fx.bytes);
}

#[test]
fn retries_and_then_pauses_on_mapped_archives() {
    let fx = build(1024, |r| sample_tree(r, 4));
    // Two transient failures: retried within the policy.
    let fs = fresh_fs(CrashModel::WriteThrough, &fx);
    for op in 1..=2000 {
        fs.inject(Fault::MappedAt(op));
    }
    // Every set_len fails: the first truncation pauses after its retries.
    match run(&fs, &opts(4096)) {
        Err(Error::Paused(PauseReason::Mapped)) => {}
        other => panic!("expected a mapped pause, got {other:?}"),
    }
    fs.clear_faults();
    run(&fs, &opts(4096)).unwrap();
    assert_complete(&fs, &fx);
}

#[test]
fn tampered_block_stops_before_destroying_it() {
    let mut fx = build(1024, |r| sample_tree(r, 5));
    let a = {
        let fs = FaultFs::new(CrashModel::WriteThrough);
        fs.put_file(Path::new(ARC), &fx.bytes);
        Archive::open_with(&fs, Path::new(ARC), OpenMode::Read, Share::Shared).unwrap()
    };
    let target = a.block_offset(4) + 3;
    drop(a);
    fx.bytes[target as usize] ^= 0x55;
    let fs = fresh_fs(CrashModel::WriteThrough, &fx);
    assert!(matches!(run(&fs, &opts(1024)), Err(Error::Integrity(_))));
    let a = Archive::open_with(&fs, Path::new(ARC), OpenMode::Read, Share::Shared).unwrap();
    assert_eq!(
        a.consumed(),
        4,
        "blocks before the corrupt one consumed, the corrupt one kept"
    );
}

/// Number of mutating operations in an uninterrupted consume.
fn op_total(fx: &Fixture, o: &ConsumeOptions) -> u64 {
    let fs = fresh_fs(CrashModel::WriteThrough, fx);
    run(&fs, o).unwrap();
    fs.op_count()
}

/// After a crash and reboot, before resuming: the archive must open cleanly (its length on a
/// block boundary) and nothing may exist outside the archive's files and the destination (I5).
fn check_crash_state(fs: &FaultFs, k: u64) {
    for key in fs.snapshot().keys() {
        let allowed = key == "out" || key.starts_with("out/") || key.starts_with("a.trnc");
        assert!(allowed, "crash at op {k}: unexpected path {key}");
    }
    if fs.get_file(Path::new(ARC)).is_some() {
        if let Err(e) = Archive::open_with(fs, Path::new(ARC), OpenMode::Read, Share::Shared) {
            panic!("crash at op {k}: archive no longer opens: {e}");
        }
    }
}

fn sweep(model: CrashModel, fx: &Fixture, batch: u64, double: bool) -> u64 {
    let o = opts(batch);
    let total = op_total(fx, &o);
    let bound = peak_bound(fx, batch);
    for k in 1..=total {
        let fs = fresh_fs(model, fx);
        fs.inject(Fault::CrashAt(k));
        match run(&fs, &o) {
            Err(Error::Fs(FsError::Crashed)) => {}
            other => panic!("crash at op {k}: expected crash, got {other:?}"),
        }
        fs.recover();
        check_crash_state(&fs, k);
        if double {
            // Crash again partway through the recovery run (I3: recovery is idempotent).
            let at = fs.op_count() + 1 + (k % 23);
            fs.inject(Fault::CrashAt(at));
            if run(&fs, &o).is_ok() {
                // The second crash point lay past the end; recovery already finished.
                assert_complete(&fs, fx);
                continue;
            }
            fs.recover();
            check_crash_state(&fs, k);
        }
        match run(&fs, &o) {
            Ok(_) => {}
            Err(e) => {
                let note = fs
                    .get_file(Path::new("/a.trnc.trncr"))
                    .map(|b| String::from_utf8_lossy(&b).into_owned());
                panic!(
                    "crash at op {k}: recovery failed: {e}
state: {:?}
note: {note:?}",
                    fs.snapshot().keys().collect::<Vec<_>>()
                )
            }
        }
        assert_complete(&fs, fx);
        assert!(
            fs.peak() <= bound,
            "crash at op {k}: peak {} > bound {bound}",
            fs.peak()
        );
    }
    total
}

#[test]
fn crash_sweep_lose_unflushed() {
    let fx = build(1024, |r| sample_tree(r, 10));
    let n = sweep(CrashModel::LoseUnflushed, &fx, 2048, false);
    assert!(n > 50, "sweep covered {n} crash points");
}

#[test]
fn crash_sweep_random_subset() {
    let fx = build(1024, |r| sample_tree(r, 11));
    for seed in 0..4 {
        sweep(CrashModel::RandomSubset { seed }, &fx, 2048, false);
    }
}

#[test]
fn crash_sweep_write_through_with_double_crashes() {
    let fx = build(1024, |r| sample_tree(r, 12));
    sweep(CrashModel::WriteThrough, &fx, 4096, true);
    sweep(CrashModel::LoseUnflushed, &fx, 1, true);
}

#[test]
fn crash_sweep_torn_writes() {
    let fx = build(1024, |r| sample_tree(r, 13));
    let o = opts(2048);
    let total = op_total(&fx, &o);
    for k in 1..=total {
        let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
        fs.inject(Fault::TornWrite { op: k, keep: 7 });
        if run(&fs, &o).is_ok() {
            continue; // op k was not a write
        }
        fs.recover();
        check_crash_state(&fs, k);
        run(&fs, &o).unwrap();
        assert_complete(&fs, &fx);
    }
}

#[test]
fn verify_media_catches_a_lying_drive_before_destroying_anything() {
    let fx = build(1024, |r| sample_tree(r, 21));
    let mut o = opts(4096);
    o.verify_media = true;

    let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
    run(&fs, &o).unwrap();
    assert_complete(&fs, &fx); // no false alarms on an honest drive

    let fs = fresh_fs(CrashModel::LoseUnflushed, &fx);
    fs.set_flush_lies(true);
    let e = run(&fs, &o).unwrap_err();
    assert!(e.to_string().contains("media verification failed"), "{e}");
    assert_eq!(
        fs.get_file(Path::new(ARC)).unwrap(),
        fx.bytes,
        "nothing was truncated"
    );
}

#[test]
fn verify_media_on_the_real_filesystem() {
    let fx = build(64 << 10, |r| fixtures::mixed(r, 22));
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.trnc");
    fs::write(&arc, &fx.bytes).unwrap();
    let mut o = opts(256 << 10);
    o.verify_media = true;
    consume::consume(&OsFs::new(), &arc, &d.path().join("out"), &o, &mut |_| {}).unwrap();
    tree::assert_same(&fx.src, &d.path().join("out/src"));
}

/// A staged output that is really the archive (a planted hard link) must never be written.
#[test]
fn refuses_staged_files_that_are_the_archive() {
    let fx = build(1024, |r| sample_tree(r, 23));
    let d = tempfile::tempdir().unwrap();
    let arc = d.path().join("a.trnc");
    fs::write(&arc, &fx.bytes).unwrap();
    let dest = d.path().join("out");
    let a = Archive::open(&arc).unwrap();
    let id = a.manifest().archive_id;
    let victim = a
        .manifest()
        .entries
        .iter()
        .find(|e| e.size > 0)
        .unwrap()
        .path
        .clone();
    drop(a);
    let staged =
        consume::stage_dir(&dest, &id).join(victim.replace('/', std::path::MAIN_SEPARATOR_STR));
    fs::create_dir_all(staged.parent().unwrap()).unwrap();
    fs::hard_link(&arc, &staged).unwrap();
    let e = consume::consume(&OsFs::new(), &arc, &dest, &opts(4096), &mut |_| {}).unwrap_err();
    // Windows sharing rules stop it first (we hold the archive open against writers); where
    // locks are advisory, the file-identity check does.
    let refused =
        e.to_string().contains("is the archive") || matches!(e, Error::Fs(FsError::Busy { .. }));
    assert!(refused, "{e}");
    assert_eq!(fs::read(&arc).unwrap(), fx.bytes, "archive untouched");
}

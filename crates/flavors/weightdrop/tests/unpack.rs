//! End-to-end: shard sets of `.tar.zst` built with trunc-testkit, unpacked for real.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use trunc_testkit::tarbuild::{self, Spec};
use trunc_testkit::{Rng, fixtures};
use weightdrop::state::{self, Layout};
use weightdrop::{Event, UnpackOptions, plan_set, unpack};

/// One WebDataset-style shard: samples `NNNNNN.bin` + `NNNNNN.cls`, plus whatever `extra` adds.
fn shard_files(shard: u64, extra: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    let mut rng = Rng::new(shard + 1);
    let mut v = Vec::new();
    for k in 0..4 {
        let id = shard * 100 + k;
        v.push((
            format!("{id:06}.bin"),
            fixtures::noise_bytes(&mut rng, 30_000),
        ));
        v.push((
            format!("{id:06}.cls"),
            fixtures::text_bytes(&mut rng, 2_000),
        ));
    }
    for (n, d) in extra {
        v.push(((*n).to_owned(), d.to_vec()));
    }
    v
}

fn write_shard(dir: &Path, name: &str, files: &[(String, Vec<u8>)]) -> PathBuf {
    let specs: Vec<Spec> = files.iter().map(|(n, d)| Spec::file(n, d)).collect();
    let tar = tarbuild::tar(&specs);
    let path = dir.join(name);
    std::fs::write(&path, tarbuild::zstd_frames(&tar, 64 * 1024, 3)).unwrap();
    path
}

struct Set {
    _tmp: tempfile::TempDir,
    src: PathBuf,
    dest: PathBuf,
    shards: Vec<PathBuf>,
    /// Expected output (relative path -> bytes) for each shard.
    files: Vec<Vec<(String, Vec<u8>)>>,
}

fn make_set(extras: &[&[(&str, &[u8])]]) -> Set {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("shards");
    let dest = tmp.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    let mut shards = Vec::new();
    let mut files = Vec::new();
    for (i, extra) in extras.iter().enumerate() {
        let f = shard_files(i as u64, extra);
        shards.push(write_shard(&src, &format!("train-{i:06}.tar.zst"), &f));
        files.push(f);
    }
    // Not an archive: ignored.
    std::fs::write(src.join("README.md"), b"dataset card").unwrap();
    Set {
        _tmp: tmp,
        src,
        dest,
        shards,
        files,
    }
}

fn snapshot(paths: &[PathBuf]) -> BTreeMap<PathBuf, Vec<u8>> {
    paths
        .iter()
        .map(|p| (p.clone(), std::fs::read(p).unwrap()))
        .collect()
}

fn check_outputs(root: &Path, files: &[(String, Vec<u8>)]) {
    for (n, d) in files {
        let got = std::fs::read(root.join(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert!(got == *d, "{n} differs");
    }
}

fn dir_input(set: &Set) -> Vec<String> {
    vec![set.src.to_string_lossy().into_owned()]
}

#[test]
fn three_shards_consumed_then_resumed_after_interruption() {
    let set = make_set(&[&[], &[], &[]]);
    let mut opts = UnpackOptions::new(dir_input(&set), &set.dest);
    opts.stop_after = Some(1);
    let mut events = Vec::new();
    let s = unpack(&opts, &mut |e| events.push(e)).unwrap();
    assert!(s.stopped);
    assert_eq!(s.unpacked, 1);
    assert_eq!(s.layout, Layout::Flat);
    assert!(events.iter().any(|e| matches!(
        e,
        Event::ShardDone {
            number: 1,
            count: 3,
            ..
        }
    )));
    // Shard 1 is consumed and its files are in place; shards 2 and 3 are untouched.
    assert!(!set.shards[0].exists());
    assert!(set.shards[1].exists() && set.shards[2].exists());
    check_outputs(&set.dest, &set.files[0]);
    assert!(!set.dest.join(&set.files[1][0].0).exists());
    let st = state::State::load(&set.dest).unwrap().unwrap();
    assert_eq!(st.shards[0].status, state::Status::Done);
    assert_eq!(st.shards[1].status, state::Status::Pending);

    // Re-run the same command: the gap left by the consumed shard is fine, the rest follows.
    let mut events = Vec::new();
    let s = unpack(&UnpackOptions::new(dir_input(&set), &set.dest), &mut |e| {
        events.push(e)
    })
    .unwrap();
    assert!(!s.stopped);
    assert_eq!(s.unpacked, 2);
    assert_eq!(s.shards, 3);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Note(n) if n.contains("resuming: 1 of 3")))
    );
    for (p, f) in set.shards.iter().zip(&set.files) {
        assert!(!p.exists(), "{} should be consumed", p.display());
        check_outputs(&set.dest, f);
    }
    assert!(
        !state::path_in(&set.dest).exists(),
        "state file removed at the end"
    );
    // No trunc leftovers next to the shards.
    let left: Vec<String> = std::fs::read_dir(&set.src)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["README.md".to_string()]);
}

#[test]
fn a_shard_already_finished_but_not_recorded_counts_as_done() {
    // Crash window: trunc finished shard 1 (archive gone) but the state still says "started".
    let set = make_set(&[&[], &[]]);
    let mut opts = UnpackOptions::new(dir_input(&set), &set.dest);
    opts.stop_after = Some(1);
    unpack(&opts, &mut |_| {}).unwrap();
    let mut st = state::State::load(&set.dest).unwrap().unwrap();
    st.shards[0].status = state::Status::Started;
    st.save(&set.dest).unwrap();
    let s = unpack(&UnpackOptions::new(dir_input(&set), &set.dest), &mut |_| {}).unwrap();
    assert_eq!(s.unpacked, 1);
    check_outputs(&set.dest, &set.files[0]);
    check_outputs(&set.dest, &set.files[1]);
}

#[test]
fn flatten_refuses_colliding_names_and_touches_nothing() {
    let set = make_set(&[
        &[("config.json", b"{\"a\":1}")],
        &[],
        &[("config.json", b"{\"a\":2}")],
    ]);
    let before = snapshot(&set.shards);
    let mut opts = UnpackOptions::new(dir_input(&set), &set.dest);
    opts.flatten = true;
    let e = unpack(&opts, &mut |_| {}).unwrap_err().to_string();
    assert!(
        e.contains("config.json") && e.contains("nothing was changed"),
        "{e}"
    );
    assert!(
        e.contains("train-000000.tar.zst") && e.contains("train-000002.tar.zst"),
        "{e}"
    );
    assert_eq!(snapshot(&set.shards), before, "shards must be untouched");
    assert!(!set.dest.exists(), "destination must not be created");
    for s in &set.shards {
        let mut j = s.as_os_str().to_owned();
        j.push(".trncj");
        assert!(!PathBuf::from(j).exists());
    }
}

#[test]
fn colliding_names_get_per_shard_folders_by_default() {
    let set = make_set(&[&[("meta/info.txt", b"one")], &[("meta/info.txt", b"two")]]);
    let mut events = Vec::new();
    let s = unpack(&UnpackOptions::new(dir_input(&set), &set.dest), &mut |e| {
        events.push(e)
    })
    .unwrap();
    assert_eq!(s.layout, Layout::PerShard);
    check_outputs(&set.dest.join("train-000000"), &set.files[0]);
    check_outputs(&set.dest.join("train-000001"), &set.files[1]);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Note(n) if n.contains("own folder")))
    );
}

#[test]
fn existing_output_is_refused_up_front() {
    let set = make_set(&[&[], &[]]);
    std::fs::create_dir_all(&set.dest).unwrap();
    // A file shard 2 would create.
    std::fs::write(set.dest.join(&set.files[1][0].0), b"mine").unwrap();
    let before = snapshot(&set.shards);
    let e = unpack(&UnpackOptions::new(dir_input(&set), &set.dest), &mut |_| {})
        .unwrap_err()
        .to_string();
    assert!(e.contains("already exists"), "{e}");
    assert_eq!(snapshot(&set.shards), before);
    assert!(!set.dest.join(&set.files[0][0].0).exists());
}

#[test]
fn gap_in_numbering_is_refused() {
    let set = make_set(&[&[], &[], &[]]);
    std::fs::remove_file(&set.shards[1]).unwrap();
    let e = unpack(&UnpackOptions::new(dir_input(&set), &set.dest), &mut |_| {})
        .unwrap_err()
        .to_string();
    assert!(e.contains("incomplete") && e.contains("numbers 1"), "{e}");
    assert!(set.shards[0].exists() && set.shards[2].exists());
}

#[test]
fn keep_extracts_and_leaves_archives() {
    let set = make_set(&[&[], &[]]);
    let before = snapshot(&set.shards);
    let mut opts = UnpackOptions::new(
        vec![
            set.src
                .join("train-*.tar.zst")
                .to_string_lossy()
                .into_owned(),
        ],
        &set.dest,
    );
    opts.keep = true;
    let s = unpack(&opts, &mut |_| {}).unwrap();
    assert_eq!(s.unpacked, 2);
    assert_eq!(snapshot(&set.shards), before);
    check_outputs(&set.dest, &set.files[0]);
    check_outputs(&set.dest, &set.files[1]);
}

#[test]
fn plan_reports_every_shard_and_changes_nothing() {
    let set = make_set(&[&[], &[], &[]]);
    let before = snapshot(&set.shards);
    let r = plan_set(&dir_input(&set), &set.dest).unwrap();
    assert_eq!(r.shards.len(), 3);
    assert_eq!(r.plan.peak_during.len(), 3);
    let content: u64 = set
        .files
        .iter()
        .flatten()
        .map(|(_, d)| d.len() as u64)
        .sum();
    assert_eq!(r.plan.content, content);
    assert!(r.plan.extract_extra >= content);
    assert!(r.plan.consume_extra <= r.plan.extract_extra);
    assert!(r.notes.iter().any(|n| n.contains("README.md")));
    assert_eq!(snapshot(&set.shards), before);
    assert!(!set.dest.exists());
}

#[test]
fn plain_tar_shards_are_refused_before_anything_happens() {
    let tmp = tempfile::tempdir().unwrap();
    let specs = [Spec::file("a.txt", b"hello")];
    for i in 0..2 {
        std::fs::write(
            tmp.path().join(format!("train-{i:05}-of-00002.tar")),
            tarbuild::tar(&specs),
        )
        .unwrap();
    }
    let e = unpack(
        &UnpackOptions::new(
            vec![tmp.path().to_string_lossy().into_owned()],
            tmp.path().join("out"),
        ),
        &mut |_| {},
    )
    .unwrap_err()
    .to_string();
    assert!(e.contains("uncompressed .tar"), "{e}");
}

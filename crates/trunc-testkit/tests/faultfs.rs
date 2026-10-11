#![allow(clippy::unwrap_used)]

use std::path::Path;

use trunc_fs::{Dealloc, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_testkit::{CrashModel, Fault, FaultFs};

fn p(s: &str) -> &Path {
    Path::new(s)
}

/// Create `/d/f` with `data` through the API (not durable unless flushed below).
fn create(fs: &FaultFs, path: &str, data: &[u8]) -> Box<dyn trunc_fs::FileHandle> {
    let h = fs
        .open(p(path), OpenMode::CreateNew, Share::Shared)
        .unwrap();
    h.write_all_at(data, 0).unwrap();
    h
}

#[test]
fn flushed_data_survives_unflushed_is_lost() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.put_file(p("/a"), b"old");
    let h = fs
        .open(p("/a"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    h.write_all_at(b"new", 0).unwrap();
    h.flush_data().unwrap();
    h.write_all_at(b"XXXXXX", 0).unwrap();
    fs.recover();
    assert_eq!(fs.get_file(p("/a")).unwrap(), b"new");
}

#[test]
fn new_entries_need_a_directory_flush() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.put_file(p("/d/keep"), b"k");
    let h = create(&fs, "/d/f", b"data");
    h.flush_data().unwrap();
    fs.recover();
    assert!(
        fs.get_file(p("/d/f")).is_none(),
        "entry was never made durable"
    );

    let h = create(&fs, "/d/g", b"data");
    h.flush_data().unwrap();
    fs.flush_dir(p("/d")).unwrap();
    fs.recover();
    assert_eq!(fs.get_file(p("/d/g")).unwrap(), b"data");
}

#[test]
fn entries_without_their_data_flush_come_back_empty() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.create_dir(p("/d")).unwrap();
    fs.flush_dir(p("/")).unwrap();
    let _h = create(&fs, "/d/f", b"data");
    fs.flush_dir(p("/d")).unwrap();
    fs.recover();
    assert_eq!(
        fs.get_file(p("/d/f")).unwrap(),
        b"",
        "name durable, contents not"
    );
}

#[test]
fn rename_needs_both_parents_flushed() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.put_file(p("/a/x"), b"x");
    fs.put_file(p("/b/keep"), b"");
    fs.rename(p("/a/x"), p("/b/x")).unwrap();
    fs.flush_dir(p("/b")).unwrap();
    fs.recover();
    assert!(fs.get_file(p("/a/x")).is_some() && fs.get_file(p("/b/x")).is_none());

    fs.rename(p("/a/x"), p("/b/x")).unwrap();
    fs.flush_dir(p("/a")).unwrap();
    fs.flush_dir(p("/b")).unwrap();
    fs.recover();
    assert!(fs.get_file(p("/a/x")).is_none());
    assert_eq!(fs.get_file(p("/b/x")).unwrap(), b"x");
}

#[test]
fn directory_rename_moves_children_and_never_replaces() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(p("/stage/a/f"), b"1");
    fs.put_file(p("/stage/b"), b"2");
    fs.create_dir(p("/out")).unwrap();
    fs.rename(p("/stage/a"), p("/out/a")).unwrap();
    assert_eq!(fs.get_file(p("/out/a/f")).unwrap(), b"1");
    assert!(matches!(
        fs.rename(p("/stage/b"), p("/out/a")),
        Err(FsError::AlreadyExists { .. })
    ));
    assert_eq!(fs.read_dir(p("/out")).unwrap(), vec!["a"]);
}

#[test]
fn crash_at_stops_everything_until_recover() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(p("/f"), b"");
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    let start = fs.op_count();
    fs.inject(Fault::CrashAt(start + 2));
    h.write_all_at(b"one", 0).unwrap(); // op start+1
    assert!(matches!(h.write_all_at(b"two", 3), Err(FsError::Crashed))); // op start+2
    assert!(fs.is_crashed());
    assert!(matches!(fs.metadata(p("/f")), Err(FsError::Crashed)));
    assert!(matches!(h.size(), Err(FsError::Crashed)));
    fs.recover();
    assert_eq!(fs.get_file(p("/f")).unwrap(), b"one");
    assert!(
        matches!(h.size(), Err(FsError::Crashed)),
        "pre-crash handles are dead"
    );
    let h2 = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    h2.write_all_at(b"two", 3).unwrap();
}

#[test]
fn torn_write_keeps_a_prefix_then_crashes() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(p("/f"), b"");
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    fs.inject(Fault::TornWrite {
        op: fs.op_count() + 1,
        keep: 4,
    });
    assert!(matches!(
        h.write_all_at(b"abcdefgh", 0),
        Err(FsError::Crashed)
    ));
    fs.recover();
    assert_eq!(fs.get_file(p("/f")).unwrap(), b"abcd");
}

#[test]
fn no_space_and_mapped_faults_have_no_effect() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(p("/f"), b"0123456789");
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    let n = fs.op_count();
    fs.inject(Fault::NoSpaceAt(n + 1));
    fs.inject(Fault::MappedAt(n + 2));
    assert!(matches!(
        h.write_all_at(b"zz", 0),
        Err(FsError::NoSpace { .. })
    ));
    let e = h.set_len(3).unwrap_err();
    assert!(matches!(e, FsError::Mapped { .. }) && e.is_retryable());
    assert_eq!(fs.get_file(p("/f")).unwrap(), b"0123456789");
    h.set_len(3).unwrap(); // the retry is a new operation and succeeds
    assert_eq!(fs.get_file(p("/f")).unwrap(), b"012");
    assert!(!fs.is_crashed());
}

#[test]
fn capacity_occupancy_and_peak() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.set_capacity(Some(10_000));
    fs.put_file(p("/a"), &[1u8; 6000]);
    assert_eq!(fs.used(), 6000);
    let b = create(&fs, "/b", &[2u8; 3000]);
    assert_eq!((fs.used(), fs.peak()), (9000, 9000));
    assert!(matches!(
        b.write_all_at(&[3u8; 2000], 3000),
        Err(FsError::NoSpace { .. })
    ));
    assert!(matches!(b.preallocate(5000), Err(FsError::NoSpace { .. })));
    let a = fs
        .open(p("/a"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    a.set_len(1000).unwrap();
    assert_eq!(fs.used(), 4000);
    b.write_all_at(&[3u8; 2000], 3000).unwrap();
    assert_eq!((fs.used(), fs.peak()), (6000, 9000));
    fs.reset_peak();
    assert_eq!(fs.peak(), 6000);
    drop(b);
    fs.remove_file(p("/b")).unwrap();
    assert_eq!(fs.used(), 1000);
}

#[test]
fn deallocation_frees_aligned_units_and_zeroes() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.set_granularity(1000);
    fs.put_file(p("/f"), &[9u8; 5000]);
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    assert_eq!(
        h.deallocate(1500, 4200).unwrap(),
        Dealloc::Freed { freed: 2000..4000 }
    );
    assert_eq!(fs.used(), 3000);
    assert_eq!(h.allocated_ranges().unwrap(), vec![0..2000, 4000..5000]);
    let data = fs.get_file(p("/f")).unwrap();
    assert!(data[1500..4200].iter().all(|&b| b == 0) && data[1499] == 9 && data[4200] == 9);
    h.write_all_at(&[1u8; 10], 2500).unwrap();
    // Writing into a hole allocates just what was written (the hole splits around it).
    assert_eq!(
        h.allocated_ranges().unwrap(),
        vec![0..2000, 2500..2510, 4000..5000]
    );

    fs.set_dealloc_supported(false);
    assert_eq!(h.deallocate(0, 5000).unwrap(), Dealloc::Unsupported);
}

#[test]
fn exclusive_handles_and_create_semantics() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(p("/f"), b"abc");
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    // Exclusive admits readers but no writers.
    drop(fs.open(p("/f"), OpenMode::Read, Share::Shared).unwrap());
    assert!(matches!(
        fs.open(p("/f"), OpenMode::ReadWrite, Share::Shared),
        Err(FsError::Busy { .. })
    ));
    assert!(matches!(
        fs.open(p("/f"), OpenMode::CreateOrTruncate, Share::Shared),
        Err(FsError::Busy { .. })
    ));
    assert_eq!(
        fs.get_file(p("/f")).unwrap(),
        b"abc",
        "busy open must not truncate"
    );
    drop(h);
    let _s1 = fs.open(p("/f"), OpenMode::Read, Share::Shared).unwrap();
    let w = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
        .unwrap();
    assert!(
        matches!(
            fs.open(p("/f"), OpenMode::Read, Share::Exclusive),
            Err(FsError::Busy { .. })
        ),
        "a writer is open"
    );
    drop(w);
    drop(fs.open(p("/f"), OpenMode::Read, Share::Exclusive).unwrap());
    assert!(matches!(
        fs.open(p("/f"), OpenMode::CreateNew, Share::Shared),
        Err(FsError::AlreadyExists { .. })
    ));
    assert!(matches!(
        fs.open(p("/nope/f"), OpenMode::CreateNew, Share::Shared),
        Err(FsError::NotFound { .. })
    ));
    let ro = fs.open(p("/f"), OpenMode::Read, Share::Shared).unwrap();
    assert!(ro.write_all_at(b"x", 0).is_err(), "read-only handle");
    assert_eq!(fs.metadata(p("/f")).unwrap().unwrap().kind, NodeKind::File);
}

/// Random-subset crashes keep flushed state and some subset of unflushed operations; across
/// seeds every combination of two independent unflushed writes appears.
#[test]
fn random_subset_explores_partial_persistence() {
    let mut seen = std::collections::BTreeSet::new();
    for seed in 0..64 {
        let fs = FaultFs::new(CrashModel::RandomSubset { seed });
        fs.put_file(p("/f"), b"....");
        let h = fs
            .open(p("/f"), OpenMode::ReadWrite, Share::Shared)
            .unwrap();
        h.write_all_at(b"A", 0).unwrap();
        h.flush_data().unwrap();
        h.write_all_at(b"B", 1).unwrap();
        h.write_all_at(b"C", 2).unwrap();
        fs.recover();
        let got = fs.get_file(p("/f")).unwrap();
        assert_eq!(got[0], b'A', "flushed write always survives");
        assert_eq!(got[3], b'.');
        seen.insert((got[1], got[2]));
    }
    assert_eq!(seen.len(), 4, "{seen:?}");
}

#[test]
fn orphans_are_pruned_after_crash() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.create_dir(p("/d")).unwrap(); // root never flushed
    let h = create(&fs, "/d/f", b"x");
    h.flush_data().unwrap();
    fs.flush_dir(p("/d")).unwrap();
    fs.recover();
    assert!(fs.metadata(p("/d")).unwrap().is_none());
    assert!(fs.get_file(p("/d/f")).is_none());
    assert!(fs.snapshot().is_empty());
}

#[test]
fn unflushed_removal_is_undone_with_its_data() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.put_file(p("/d/f"), b"precious");
    fs.remove_file(p("/d/f")).unwrap();
    assert!(fs.get_file(p("/d/f")).is_none());
    assert_eq!(fs.used(), 0);
    fs.recover();
    assert_eq!(fs.get_file(p("/d/f")).unwrap(), b"precious");
    assert_eq!(fs.used(), 8);

    fs.remove_file(p("/d/f")).unwrap();
    fs.flush_dir(p("/d")).unwrap();
    fs.recover();
    assert!(fs.get_file(p("/d/f")).is_none());
}

#[test]
fn read_back_returns_only_durable_bytes() {
    let fs = FaultFs::new(CrashModel::LoseUnflushed);
    fs.put_file(p("/f"), b"aaaa");
    let h = fs
        .open(p("/f"), OpenMode::ReadWrite, Share::Exclusive)
        .unwrap();
    h.write_all_at(b"bb", 0).unwrap();
    let mut buf = [0u8; 4];
    h.read_back(&mut buf, 0).unwrap();
    assert_eq!(&buf, b"aaaa", "not flushed yet");
    h.flush_data().unwrap();
    h.read_back(&mut buf, 0).unwrap();
    assert_eq!(&buf, b"bbaa");
}

#[test]
fn case_insensitive_mode_folds_names_and_keeps_their_case() {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.set_case_insensitive(true);
    fs.create_dir(p("/Dir")).unwrap();
    drop(create(&fs, "/dir/A.txt", b"upper"));
    assert_eq!(fs.read_dir(p("/DIR")).unwrap(), vec!["A.txt".to_owned()]);
    assert!(matches!(
        fs.open(p("/DIR/a.TXT"), OpenMode::CreateNew, Share::Shared),
        Err(FsError::AlreadyExists { .. })
    ));
    assert_eq!(fs.metadata(p("/dir/a.txt")).unwrap().unwrap().len, 5);
    assert!(fs.folds_case(p("/dir")).unwrap());
    assert!(trunc_fs::probe_case_folding(&fs, p("/dir")).unwrap());
    assert_eq!(fs.read_dir(p("/dir")).unwrap(), vec!["A.txt".to_owned()]);

    let exact = FaultFs::new(CrashModel::WriteThrough);
    exact.create_dir(p("/dir")).unwrap();
    drop(create(&exact, "/dir/A.txt", b"upper"));
    assert!(exact.metadata(p("/dir/a.txt")).unwrap().is_none());
    assert!(!exact.folds_case(p("/dir")).unwrap());
    assert!(!trunc_fs::probe_case_folding(&exact, p("/dir")).unwrap());
    // A probe file left behind by a crash is judged, then removed.
    drop(create(
        &exact,
        &format!("/dir/{}", trunc_fs::CASE_PROBE_NAME),
        b"",
    ));
    assert!(!trunc_fs::probe_case_folding(&exact, p("/dir")).unwrap());
    assert_eq!(exact.read_dir(p("/dir")).unwrap(), vec!["A.txt".to_owned()]);
}

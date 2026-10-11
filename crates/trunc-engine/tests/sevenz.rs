//! 7z extraction and verification: staging, refusals, CRC failures and failure injection.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_engine::Error;
use trunc_engine::sevenz;
use trunc_testkit::sevenzbuild::{Codec7, Item7, Opts7, build};
use trunc_testkit::{CrashModel, Fault, FaultFs, Rng, fixtures};

const ARC: &str = "/a.7z";
const DEST: &str = "/out";
const WINDOW: u64 = 256 << 20;

fn items(seed: u64) -> Vec<Item7> {
    let mut rng = Rng::new(seed);
    vec![
        Item7::dir("proj"),
        Item7::file("proj/readme.md", &fixtures::text_bytes(&mut rng, 6000)),
        Item7::file("proj/src/main.rs", &fixtures::text_bytes(&mut rng, 2500)),
        Item7::file("proj/bin/blob", &fixtures::noise_bytes(&mut rng, 4000)),
        Item7::file("proj/empty", b""),
        Item7::dir("proj/hollow"),
        Item7::file("top.txt", &fixtures::text_bytes(&mut rng, 900)),
        Item7::file("ünï.txt", "ünïcödé".as_bytes()),
        Item7::file("run.sh", b"#!/bin/sh\n").attrib(0x8000 | (0o100_755 << 16)),
        Item7::file("link", b"top.txt").attrib(0x8000 | (0o120_777 << 16)),
    ]
}

/// What `/out` must contain afterwards (symlinks are skipped).
fn expected(items: &[Item7]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut want = BTreeMap::new();
    want.insert("out".to_string(), None);
    for i in items.iter().filter(|i| i.name != "link") {
        let mut parent = i.name.as_str();
        while let Some((p, _)) = parent.rsplit_once('/') {
            want.insert(format!("out/{p}"), None);
            parent = p;
        }
        want.insert(format!("out/{}", i.name), i.data.clone());
    }
    want
}

fn out_tree(fs: &FaultFs) -> BTreeMap<String, Option<Vec<u8>>> {
    fs.snapshot()
        .into_iter()
        .filter(|(k, _)| k == "out" || k.starts_with("out/"))
        .collect()
}

fn setup(bytes: &[u8]) -> FaultFs {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new(ARC), bytes);
    fs
}

fn extract(fs: &FaultFs, overwrite: bool) -> Result<trunc_engine::consume::ConsumeSummary, Error> {
    sevenz::extract_7z(fs, Path::new(ARC), Path::new(DEST), overwrite, WINDOW)
}

#[test]
fn extracts_every_layout() {
    let items = items(1);
    for codec in [Codec7::Copy, Codec7::Lzma, Codec7::Lzma2, Codec7::BcjLzma2] {
        for solid in [true, false] {
            let o = Opts7 {
                codec,
                solid,
                ..Opts7::default()
            };
            let fs = setup(&build(&items, &o));
            let s = extract(&fs, false).unwrap_or_else(|e| panic!("{o:?}: {e}"));
            assert_eq!(out_tree(&fs), expected(&items), "{o:?}");
            assert_eq!(s.files, 7);
            assert_eq!(s.symlinks_skipped, 1);
            assert_eq!(s.dirs, 4);
            let (n, bytes) = sevenz::verify_7z(&fs, Path::new(ARC), WINDOW, 1).unwrap();
            assert_eq!(n, items.len());
            assert_eq!(bytes, s.bytes_written);
        }
    }
}

#[test]
fn crc_failure_leaves_the_destination_untouched() {
    let items = items(2);
    let mut a = build(
        &items,
        &Opts7 {
            codec: Codec7::Copy,
            solid: false,
            encode_header: false,
            ..Opts7::default()
        },
    );
    // The last file's packed bytes sit just before the header; damage a byte of the blob,
    // which the first files precede, so some files decode fine before the failure.
    let at = 32 + 6000 + 2500 + 100;
    a[at] ^= 0xFF;
    let fs = setup(&a);
    let e = extract(&fs, false).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e}");
    // Only the (empty) destination directory remains: nothing staged is left behind.
    let tree = out_tree(&fs);
    assert_eq!(tree.keys().collect::<Vec<_>>(), ["out"], "{tree:?}");
    let e = sevenz::verify_7z(&fs, Path::new(ARC), WINDOW, 1).unwrap_err();
    assert!(matches!(e, Error::Integrity(_)), "{e}");
}

#[test]
fn existing_files_need_overwrite() {
    let items = items(3);
    let fs = setup(&build(&items, &Opts7::default()));
    fs.put_file(Path::new("/out/top.txt"), b"old");
    let e = extract(&fs, false).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");
    // Refused before writing: the old file is intact and nothing else appeared.
    let tree = out_tree(&fs);
    assert_eq!(tree.len(), 2, "{tree:?}");
    assert_eq!(fs.get_file(Path::new("/out/top.txt")).unwrap(), b"old");
    extract(&fs, true).unwrap();
    assert_eq!(out_tree(&fs), expected(&items));
}

#[test]
fn a_file_where_a_directory_goes_is_refused() {
    let items = items(4);
    let fs = setup(&build(&items, &Opts7::default()));
    fs.put_file(Path::new("/out/proj"), b"not a dir");
    let e = extract(&fs, true).unwrap_err();
    assert!(matches!(e, Error::Refused(_)), "{e}");
}

/// Names that differ only in case are refused before anything is written when the destination
/// folds case (a `casefold` or NTFS folder on Linux), and extracted where it does not (on Linux;
/// Windows and macOS always compare case-insensitively).
#[test]
fn case_insensitive_destinations_are_found_up_front() {
    let items = vec![
        Item7::file("A.txt", b"upper"),
        Item7::file("a.txt", b"lower"),
    ];
    let bytes = build(&items, &Opts7::default());
    for folds in [true, false] {
        let refused = folds || cfg!(any(windows, target_os = "macos"));
        let fs = setup(&bytes);
        fs.set_case_insensitive(folds);
        let r = extract(&fs, false);
        assert_eq!(r.is_err(), refused, "folds={folds}: {r:?}");
        if refused {
            assert!(matches!(r, Err(Error::Input(_))), "{r:?}");
            assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), vec!["a.7z"]);
        } else {
            assert_eq!(out_tree(&fs), expected(&items));
        }
    }
}

#[test]
fn hostile_names_are_refused_before_writing() {
    let items = vec![Item7::file("ok", b"fine"), Item7::file("../evil", b"x")];
    let fs = setup(&build(&items, &Opts7::default()));
    let e = extract(&fs, false).unwrap_err();
    assert!(matches!(e, Error::Input(_)), "{e}");
    assert!(fs.get_file(Path::new("/out/ok")).is_none());
}

#[test]
fn leftover_staging_is_replaced() {
    let items = items(5);
    let a = build(&items, &Opts7::default());
    let fs = setup(&a);
    // Fail part-way through (an injected out-of-space on some write), then run again.
    let base = fs.op_count();
    fs.inject(Fault::NoSpaceAt(base + 12));
    assert!(extract(&fs, false).is_err());
    fs.clear_faults();
    extract(&fs, false).unwrap();
    assert_eq!(out_tree(&fs), expected(&items));
}

#[test]
fn any_failure_point_leaves_no_partial_staging() {
    // Inject an I/O failure at every operation in turn: the run fails cleanly (or succeeds when
    // the failed operation was optional), and a second run always produces the full tree.
    let items = items(6);
    let a = build(
        &items,
        &Opts7 {
            solid: false,
            ..Opts7::default()
        },
    );
    let probe = setup(&a);
    let start = probe.op_count();
    extract(&probe, false).unwrap();
    let total = probe.op_count() - start;
    for k in 0..total {
        let fs = setup(&a);
        let base = fs.op_count();
        fs.inject(Fault::NoSpaceAt(base + k));
        let first = extract(&fs, false);
        fs.clear_faults();
        if first.is_ok() {
            assert_eq!(out_tree(&fs), expected(&items), "op {k}");
            continue;
        }
        // Whatever was moved before the failure is complete; a rerun with --overwrite finishes.
        extract(&fs, true).unwrap_or_else(|e| panic!("op {k}: {e}"));
        assert_eq!(out_tree(&fs), expected(&items), "op {k}");
    }
}

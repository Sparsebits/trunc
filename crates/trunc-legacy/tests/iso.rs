//! ISO 9660 parsing: name sources, multi-extent files, Rock Ridge details and hostile images.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::iso::{self, Image, IsoError, Names};
use trunc_legacy::zip::Kind;
use trunc_testkit::isobuild::{self, Built, IsoBuilder, Spec, Tree};
use trunc_testkit::{CrashModel, FaultFs, Rng, fixtures};

fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/i.iso"), bytes);
    let h = fs
        .open(Path::new("/i.iso"), OpenMode::Read, Share::Shared)
        .unwrap();
    (fs, h)
}

fn parse(bytes: &[u8]) -> Result<Image, IsoError> {
    let (_fs, h) = host(bytes);
    iso::parse(h.as_ref())
}

fn build(b: IsoBuilder, specs: &[Spec]) -> Built {
    let mut b = b;
    for s in specs {
        b.add(s.clone());
    }
    b.build()
}

/// name -> Some(content) for files, None for directories.
fn contents(bytes: &[u8], img: &Image) -> BTreeMap<String, Option<Vec<u8>>> {
    img.layout
        .entries
        .iter()
        .filter(|e| e.kind != Kind::Symlink)
        .map(|e| {
            let v = (e.kind == Kind::File)
                .then(|| bytes[e.data_offset as usize..(e.data_offset + e.size) as usize].to_vec());
            (e.name.clone(), v)
        })
        .collect()
}

fn mixed_case_specs() -> Vec<Spec> {
    let mut rng = Rng::new(1);
    vec![
        Spec::file("Docs/Read Me.txt", &fixtures::text_bytes(&mut rng, 5000)),
        Spec::file(
            "Docs/deep/er/blob.bin",
            &fixtures::noise_bytes(&mut rng, 9000),
        ),
        Spec::file("ünïcödé.txt", "ünïcödé".as_bytes()),
        Spec::file("empty", b""),
        Spec::dir("hollow"),
    ]
}

fn want(specs: &[Spec]) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut m = BTreeMap::new();
    for s in specs {
        let mut p = s.path.as_str();
        while let Some((parent, _)) = p.rsplit_once('/') {
            m.insert(parent.to_owned(), None);
            p = parent;
        }
        let v = match &s.kind {
            isobuild::SpecKind::File(d) => Some(d.clone()),
            _ => None,
        };
        m.insert(s.path.clone(), v);
    }
    m
}

#[test]
fn joliet_and_rock_ridge_names_round_trip() {
    let specs = mixed_case_specs();
    for (b, names) in [
        (IsoBuilder::new().joliet(true), Names::Joliet),
        (IsoBuilder::new().rock_ridge(true), Names::RockRidge),
        (
            IsoBuilder::new().rock_ridge(true).joliet(true),
            Names::RockRidge,
        ),
        (
            IsoBuilder::new().rock_ridge(true).ce_names(true).pad(150),
            Names::RockRidge,
        ),
    ] {
        let built = build(b, &specs);
        let img = parse(&built.bytes).unwrap();
        assert_eq!(img.names, names);
        assert_eq!(img.volume_id, "TESTDISC");
        assert_eq!(contents(&built.bytes, &img), want(&specs), "{names}");
        assert!(img.layout.overlaps.is_empty());
        let f = img
            .layout
            .entries
            .iter()
            .find(|e| e.name == "empty")
            .unwrap();
        assert_eq!((f.kind, f.size, f.region_end), (Kind::File, 0, 0));
        assert!(
            img.layout
                .entries
                .iter()
                .all(|e| e.mtime_unix == isobuild::DATE_UNIX)
        );
    }
}

#[test]
fn plain_names_lose_their_version_and_dot() {
    let specs = vec![
        Spec::file("README.TXT", b"readme"),
        Spec::file("NOEXT", b"no extension"),
        Spec::file("DIR1/DIR2/DATA.BIN", b"nested"),
    ];
    let built = build(IsoBuilder::new(), &specs);
    let img = parse(&built.bytes).unwrap();
    assert_eq!(img.names, Names::Iso9660);
    assert_eq!(contents(&built.bytes, &img), want(&specs));
}

#[test]
fn multi_extent_files_are_joined() {
    let mut rng = Rng::new(2);
    let data = fixtures::noise_bytes(&mut rng, 5 * 2048 + 77);
    let exact = fixtures::noise_bytes(&mut rng, 4 * 2048);
    let specs = vec![
        Spec::file("big.bin", &data).sections(2048),
        Spec::file("exact.bin", &exact).sections(2 * 2048),
        Spec::file("after.txt", b"after"),
    ];
    for b in [
        IsoBuilder::new().joliet(true),
        IsoBuilder::new().rock_ridge(true),
    ] {
        let built = build(b, &specs);
        assert_eq!(built.records[&(Tree::Primary, "big.bin".into())].len(), 6);
        let img = parse(&built.bytes).unwrap();
        assert_eq!(contents(&built.bytes, &img), want(&specs));
    }
}

#[test]
fn rock_ridge_modes_symlinks_hidden_and_associated() {
    let specs = vec![
        Spec::file("bin/run.sh", b"#!/bin/sh\n").mode(0o755),
        Spec::symlink("bin/link", "run.sh"),
        Spec::file("secret.txt", b"hidden but extracted").hidden(),
        Spec::file("fork", b"resource fork").associated(),
    ];
    let built = build(IsoBuilder::new().rock_ridge(true), &specs);
    let img = parse(&built.bytes).unwrap();
    let by: BTreeMap<_, _> = img
        .layout
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e))
        .collect();
    assert_eq!(by["bin/run.sh"].mode, Some(0o755));
    assert_eq!(by["secret.txt"].mode, Some(0o644));
    assert_eq!(by["bin/link"].kind, Kind::Symlink);
    assert!(!by.contains_key("fork"));
    assert_eq!((img.hidden, img.associated_skipped), (1, 1));
}

#[test]
fn shared_extents_are_counted_not_refused() {
    let specs = vec![
        Spec::file("a.txt", b"same data"),
        Spec::file("b.txt", b"other"),
    ];
    let mut built = build(IsoBuilder::new().joliet(true), &specs);
    let (lba, size) = built.extent(Tree::Joliet, "a.txt");
    built.set_extent(Tree::Joliet, "b.txt", lba);
    built.set_size(Tree::Joliet, "b.txt", size);
    let img = parse(&built.bytes).unwrap();
    assert_eq!((img.shared, img.partial_overlaps), (1, 0));
    assert_eq!(img.layout.overlaps.len(), 1);
}

#[test]
fn partial_overlaps_are_counted() {
    let mut rng = Rng::new(3);
    let specs = vec![
        Spec::file("a.bin", &fixtures::noise_bytes(&mut rng, 3 * 2048)),
        Spec::file("b.bin", b"tiny"),
    ];
    let mut built = build(IsoBuilder::new().joliet(true), &specs);
    let (lba, _) = built.extent(Tree::Joliet, "a.bin");
    built.set_extent(Tree::Joliet, "b.bin", lba + 1);
    let img = parse(&built.bytes).unwrap();
    assert_eq!((img.shared, img.partial_overlaps), (0, 1));
}

fn refused(bytes: &[u8], what: &str) {
    match parse(bytes) {
        Ok(_) => panic!("{what}: accepted"),
        Err(IsoError::Fs(e)) => panic!("{what}: I/O error {e}"),
        Err(_) => {}
    }
}

#[test]
fn hostile_images_are_refused() {
    let specs = vec![
        Spec::file("a/b/c.txt", b"deep file"),
        Spec::file("top.txt", b"top"),
    ];
    for tree in [Tree::Primary, Tree::Joliet] {
        let base = build(IsoBuilder::new().joliet(tree == Tree::Joliet), &specs);
        // A directory pointing at an ancestor's records.
        let mut b = base.clone();
        b.set_extent(tree, "a/b", base.root(tree));
        refused(&b.bytes, "loop to root");
        let mut b = base.clone();
        let (lba_a, size_a) = b.extent(tree, "a");
        b.set_extent(tree, "a/b", lba_a);
        b.set_size(tree, "a/b", size_a);
        refused(&b.bytes, "loop to parent");

        // Extents beyond the end of the file.
        let mut b = base.clone();
        b.set_extent(tree, "top.txt", 1 << 30);
        refused(&b.bytes, "file outside");
        let mut b = base.clone();
        b.set_size(tree, "top.txt", u32::MAX);
        refused(&b.bytes, "file size outside");
        let mut b = base.clone();
        b.set_extent(tree, "a", 1 << 30);
        refused(&b.bytes, "directory outside");

        // File data over directory records.
        let mut b = base.clone();
        b.set_extent(tree, "top.txt", lba_a);
        refused(&b.bytes, "file over directory");

        // Truncated image.
        refused(&base.bytes[..base.bytes.len() - 2048], "truncated");
        refused(&base.bytes[..16 * 2048 + 100], "no descriptors");
    }
}

#[test]
fn invalid_names_are_refused() {
    for bad in ["..", "x\u{1}y"] {
        let built = build(
            IsoBuilder::new().rock_ridge(true),
            &[Spec::file(bad, b"evil"), Spec::file("ok", b"fine")],
        );
        refused(&built.bytes, bad);
    }
    // A Rock Ridge name with a slash, and a Joliet name that is "..".
    let built = build(
        IsoBuilder::new().rock_ridge(true),
        &[Spec::file("a\\b", b"x")],
    );
    let mut bytes = built.bytes.clone();
    let at = bytes.windows(3).position(|w| w == b"a\\b").unwrap();
    bytes[at + 1] = b'/';
    refused(&bytes, "slash in NM");
    let mut built = build(IsoBuilder::new().joliet(true), &[Spec::file("xy", b"x")]);
    // "xy;1" in UCS-2: rename to "..;1".
    built.set_name(Tree::Joliet, "xy", &[0, b'.', 0, b'.', 0, b';', 0, b'1']);
    refused(&built.bytes, "dotdot in Joliet");
    // Duplicates after stripping versions.
    let mut built = build(
        IsoBuilder::new(),
        &[Spec::file("A.TXT", b"1"), Spec::file("B.TXT", b"2")],
    );
    built.set_name(Tree::Primary, "B.TXT", b"A.TXT;2");
    refused(&built.bytes, "duplicate");
}

#[test]
fn absurd_depth_is_refused() {
    let deep: Vec<String> = (0..300).map(|i| format!("d{i}")).collect();
    let built = build(
        IsoBuilder::new().rock_ridge(true),
        &[Spec::file(&format!("{}/f", deep.join("/")), b"x")],
    );
    refused(&built.bytes, "300 levels");
}

#[test]
fn udf_only_images_get_a_clear_refusal() {
    let built = IsoBuilder::new().udf_only().build();
    let (_fs, h) = host(&built.bytes);
    assert!(iso::looks_like_image(h.as_ref()));
    let e = iso::parse(h.as_ref()).unwrap_err();
    assert!(e.to_string().contains("UDF"), "{e}");
    let (_fs, h) = host(&vec![0u8; 40_000]);
    assert!(!iso::looks_like_image(h.as_ref()));
    assert!(matches!(iso::parse(h.as_ref()), Err(IsoError::NotIso(_))));
}

#[test]
fn non_contiguous_multi_extent_is_refused() {
    let mut rng = Rng::new(4);
    let built = build(
        IsoBuilder::new(),
        &[Spec::file("BIG.BIN", &fixtures::noise_bytes(&mut rng, 3 * 2048)).sections(2048)],
    );
    let mut bytes = built.bytes.clone();
    let second = built.records[&(Tree::Primary, "BIG.BIN".into())][1];
    let lba = u32::from_le_bytes(bytes[second + 2..second + 6].try_into().unwrap()) + 1;
    bytes[second + 2..second + 6].copy_from_slice(&lba.to_le_bytes());
    refused(&bytes, "gap between sections");
}

/// Random corruption of the descriptors and directory records never panics or hangs.
#[test]
fn corrupt_images_never_panic() {
    let specs = mixed_case_specs();
    let bases = [
        build(IsoBuilder::new().rock_ridge(true).ce_names(true), &specs).bytes,
        build(IsoBuilder::new().joliet(true), &specs).bytes,
    ];
    let mut rng = Rng::new(9);
    for base in &bases {
        // Descriptors, directories and continuation areas sit before the file data.
        let meta_end = 40 * 2048;
        for _ in 0..1500 {
            let mut b = base.clone();
            for _ in 0..1 + rng.below(6) {
                let at = 16 * 2048 + rng.below(meta_end - 16 * 2048) as usize;
                if at < b.len() {
                    b[at] = rng.next_u64() as u8;
                }
            }
            let _ = parse(&b);
        }
    }
}

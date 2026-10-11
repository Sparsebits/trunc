//! The tar reader against archives from the test builder, plus regressions found by fuzzing.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use trunc_legacy::tar::{Kind, Reader, TarError};
use trunc_testkit::tarbuild::{self, NameVia, SparseFormat, Spec};

fn parse(bytes: &[u8], chunk: usize) -> Result<Vec<trunc_legacy::tar::Entry>, TarError> {
    let mut r = Reader::new();
    for piece in bytes.chunks(chunk) {
        r.feed(piece)?;
    }
    r.finish()
}

#[test]
fn reads_every_header_style_at_any_chunking() {
    let long = format!("dir/{}/file.txt", "x".repeat(150));
    let pax = format!("dir/{}/pax.txt", "y".repeat(200));
    let specs = vec![
        Spec::dir("./dir"),
        Spec::file("./dir/a.txt", b"hello"),
        Spec::file(
            &format!("dir/{}/split.txt", "p".repeat(90)),
            b"ustar prefix",
        ),
        Spec::file(&long, b"gnu long name").via(NameVia::GnuLong),
        Spec::file(&pax, b"pax name").via(NameVia::Pax),
        Spec::symlink("dir/link", "a.txt"),
        Spec::file("dir/empty", b""),
    ];
    let tar = tarbuild::tar(&specs);
    for chunk in [1, 7, 511, 512, 513, 4096, tar.len()] {
        let e = parse(&tar, chunk).unwrap();
        let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names[0], "dir");
        assert_eq!(names[3], long);
        assert_eq!(names[4], pax);
        let a = &e[1];
        assert_eq!((a.kind, a.size), (Kind::File, 5));
        assert_eq!(
            &tar[a.data_offset as usize..a.data_offset as usize + 5],
            b"hello"
        );
        assert_eq!(e[5].kind, Kind::Symlink);
    }
}

#[test]
fn files_over_8_gib_use_base_256_sizes() {
    // A header claiming 20 GiB with no data: the size parses, and the stream is reported as
    // ending inside the entry (not a panic, not an overflow).
    let spec = Spec::file("huge.bin", b"");
    let mut tar = tarbuild::tar(&[spec]);
    tar[124] = 0x80;
    tar[124 + 1..124 + 4].fill(0);
    tar[128..136].copy_from_slice(&(20u64 << 30).to_be_bytes());
    tar[148..156].fill(b' ');
    let sum: u64 = tar[..512].iter().map(|&c| u64::from(c)).sum();
    tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert!(matches!(parse(&tar, 512), Err(TarError::Corrupt(..))));
}

#[test]
fn hostile_sizes_and_roots_are_errors_not_panics() {
    // A size near 2^64 (found by fuzzing: rounding up to a block overflowed).
    let mut tar = tarbuild::tar(&[Spec::file("x", b"")]);
    tar[124] = 0x80;
    tar[125..136].fill(0xFF);
    tar[148..156].fill(b' ');
    let sum: u64 = tar[..512].iter().map(|&c| u64::from(c)).sum();
    tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    assert!(parse(&tar, 512).is_err());
    // A regular file named "." would carry content that belongs to no output.
    let tar = tarbuild::tar(&[Spec::file(".", b"stray content")]);
    assert!(matches!(parse(&tar, 512), Err(TarError::Name { .. })));
    // The root as a directory is fine and creates nothing.
    let tar = tarbuild::tar(&[Spec::dir("."), Spec::file("./a", b"a")]);
    assert_eq!(parse(&tar, 512).unwrap().len(), 1);
}

#[test]
fn concatenated_archives_and_garbage_are_refused() {
    let one = tarbuild::tar(&[Spec::file("a", b"1")]);
    let two = tarbuild::tar(&[Spec::file("b", b"2")]);
    assert!(parse(&[one.clone(), two].concat(), 512).is_err());
    assert!(matches!(parse(&[0x41u8; 512], 512), Err(TarError::NotTar)));
    assert!(
        parse(&one[..700], 512).is_err(),
        "truncated inside an entry"
    );
}

#[test]
fn hard_links_lead_to_earlier_files() {
    let long = format!("dir/{}/target.txt", "t".repeat(120));
    let specs = vec![
        Spec::file("dir/a.txt", b"content"),
        Spec::hardlink("dir/b.txt", "dir/a.txt"),
        // A link to a link leads to the file.
        Spec::hardlink("./c.txt", "./dir/b.txt"),
        Spec::file(&long, b"long").via(NameVia::Pax),
        Spec::hardlink("gnu-long-link", &long).via(NameVia::GnuLong),
        Spec::hardlink("pax-long-link", &long).via(NameVia::Pax),
        Spec::file("after", b"x"),
    ];
    let tar = tarbuild::tar(&specs);
    for chunk in [1, 7, 512, 513, tar.len()] {
        let e = parse(&tar, chunk).unwrap();
        let kinds: Vec<Kind> = e.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::File,
                Kind::HardLink(0),
                Kind::HardLink(0),
                Kind::File,
                Kind::HardLink(3),
                Kind::HardLink(3),
                Kind::File
            ]
        );
        assert_eq!(e[2].name, "c.txt");
        assert!(e.iter().all(|e| e.kind == Kind::File || e.size == 0));
    }
}

#[test]
fn hard_links_are_validated_like_names() {
    let file = || Spec::file("a.txt", b"a");
    let cases: Vec<(Vec<Spec>, &str)> = vec![
        (vec![file(), Spec::hardlink("l", "../a.txt")], "escapes"),
        (vec![file(), Spec::hardlink("l", "/etc/passwd")], "absolute"),
        (
            vec![file(), Spec::hardlink("l", "dir/../../a.txt")],
            "climbs",
        ),
        (vec![file(), Spec::hardlink("l", ".")], "the root"),
        (vec![file(), Spec::hardlink("l", "missing")], "missing"),
        (
            vec![Spec::hardlink("l", "later"), Spec::file("later", b"x")],
            "later entry",
        ),
        (vec![Spec::dir("d"), Spec::hardlink("l", "d")], "directory"),
        (
            vec![Spec::symlink("s", "a.txt"), Spec::hardlink("l", "s")],
            "symlink",
        ),
        (vec![file(), Spec::hardlink("a.txt", "a.txt")], "itself"),
        (vec![file(), Spec::hardlink("../l", "a.txt")], "link name"),
        (
            vec![file(), Spec::hardlink("l", "a.txt"), Spec::file("l/x", b"")],
            "nested under a link",
        ),
    ];
    for (specs, what) in cases {
        let tar = tarbuild::tar(&specs);
        assert!(
            matches!(parse(&tar, 512), Err(TarError::Name { .. })),
            "{what}: {:?}",
            parse(&tar, 512)
        );
    }
}

/// Data segments with distinct bytes, `n` of them, `gap` bytes apart.
fn segments(n: u64, len: usize, gap: u64) -> Vec<(u64, Vec<u8>)> {
    (0..n)
        .map(|i| (i * gap + 100, vec![b'a' + (i % 26) as u8; len]))
        .collect()
}

fn sparse_spec(name: &str, real: u64, segs: &[(u64, Vec<u8>)], f: SparseFormat) -> Spec {
    let refs: Vec<(u64, &[u8])> = segs.iter().map(|(o, d)| (*o, &d[..])).collect();
    Spec::sparse(name, real, &refs, f)
}

const FORMATS: [SparseFormat; 4] = [
    SparseFormat::OldGnu,
    SparseFormat::Pax00,
    SparseFormat::Pax01,
    SparseFormat::Pax10,
];

#[test]
fn sparse_files_in_every_format() {
    for f in FORMATS {
        // 30 segments: the old GNU format needs two extension headers, the PAX 1.0 map more
        // than one block.
        let many = segments(30, 700, 5000);
        let specs = vec![
            Spec::file("before", b"b"),
            sparse_spec("dir/sparse.img", 200_000, &many, f),
            sparse_spec("hollow", 1 << 40, &[], f),
            sparse_spec("tail", 9000, &segments(1, 10, 1), f),
            Spec::hardlink("link", "dir/sparse.img"),
            Spec::file("after", b"a"),
        ];
        let tar = tarbuild::tar(&specs);
        for chunk in [1, 7, 512, 513, tar.len()] {
            let e = parse(&tar, chunk).unwrap_or_else(|x| panic!("{f:?}: {x}"));
            let names: Vec<&str> = e.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(
                names,
                [
                    "before",
                    "dir/sparse.img",
                    "hollow",
                    "tail",
                    "link",
                    "after"
                ],
                "{f:?}"
            );
            let s = &e[1];
            let map = s.sparse.as_ref().unwrap();
            assert_eq!((s.size, s.file_size()), (30 * 700, 200_000), "{f:?}");
            assert_eq!(map.segments().len(), 30);
            assert_eq!(map.segments()[29], (29 * 5000 + 100, 700));
            let at = s.data_offset as usize;
            assert_eq!(&tar[at..at + 700], &many[0].1[..], "{f:?}: data offset");
            let h = &e[2];
            assert_eq!((h.size, h.file_size()), (0, 1 << 40), "{f:?}");
            assert_eq!(e[3].file_size(), 9000);
            assert_eq!(e[4].kind, Kind::HardLink(1));
            assert_eq!(e[5].data_offset as usize % 512, 0);
            assert_eq!(&tar[e[5].data_offset as usize], &b'a');
        }
    }
}

#[test]
fn bad_sparse_maps_are_refused() {
    let segs = segments(3, 100, 1000);
    for f in FORMATS {
        let good = sparse_spec("s", 10_000, &segs, f);
        let mut cases: Vec<(Spec, &str)> = Vec::new();
        let mut with_map = |map: Vec<(u64, u64)>, real: u64, what| {
            let mut s = good.clone();
            let sp = s.sparse.as_mut().unwrap();
            sp.map = map;
            sp.real_size = real;
            cases.push((s, what));
        };
        with_map(
            vec![(100, 100), (150, 100), (2100, 100)],
            10_000,
            "overlapping",
        );
        with_map(
            vec![(2100, 100), (100, 100), (1100, 100)],
            10_000,
            "unsorted",
        );
        with_map(
            vec![(100, 100), (1100, 100), (9950, 100)],
            10_000,
            "past the end",
        );
        with_map(vec![(100, 100), (1100, 100)], 10_000, "short of the data");
        with_map(
            vec![(100, 100), (1100, 100), (2100, 101)],
            10_000,
            "more than the data",
        );
        with_map(
            vec![(100, 100), (1100, 100), (u64::MAX - 10, 100)],
            u64::MAX,
            "overflowing",
        );
        for (spec, what) in cases {
            let tar = tarbuild::tar(&[spec]);
            assert!(parse(&tar, 512).is_err(), "{f:?} {what}");
        }
    }

    // Format-specific damage.
    let pax = |records: &[(&str, &str)]| {
        let mut s = Spec::file("s", &[1u8; 100]);
        s.pax = records
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        tarbuild::tar(&[s])
    };
    for (records, what) in [
        (
            vec![
                ("GNU.sparse.size", "1000"),
                ("GNU.sparse.numblocks", "2"),
                ("GNU.sparse.map", "0,100"),
            ],
            "numblocks",
        ),
        (
            vec![("GNU.sparse.size", "1000"), ("GNU.sparse.map", "0,100,5")],
            "odd map",
        ),
        (
            vec![("GNU.sparse.size", "1000"), ("GNU.sparse.offset", "0")],
            "offset alone",
        ),
        (
            vec![("GNU.sparse.size", "1000"), ("GNU.sparse.numbytes", "100")],
            "length alone",
        ),
        (vec![("GNU.sparse.map", "0,100")], "no real size"),
        (
            vec![
                ("GNU.sparse.major", "2"),
                ("GNU.sparse.minor", "0"),
                ("GNU.sparse.realsize", "1000"),
            ],
            "unknown format",
        ),
        (
            vec![
                ("GNU.sparse.major", "1"),
                ("GNU.sparse.minor", "0"),
                ("GNU.sparse.realsize", "1000"),
            ],
            "1.0 without room for its map",
        ),
        (
            vec![("GNU.sparse.size", "1000"), ("GNU.sparse.frobnicate", "1")],
            "unknown record",
        ),
    ] {
        assert!(parse(&pax(&records), 512).is_err(), "{what}");
    }

    // A PAX 1.0 map that runs past its entry, or holds garbage.
    let damaged = |text: &[u8]| {
        let mut tar = tarbuild::tar(&[sparse_spec(
            "s",
            10_000,
            &segments(1, 100, 1),
            SparseFormat::Pax10,
        )]);
        let at = tar.windows(8).position(|w| w == b"1\n100\n10").unwrap();
        tar[at..at + 512].fill(0);
        tar[at..at + text.len()].copy_from_slice(text);
        tar
    };
    let mut endless = b"9999\n".to_vec();
    endless.resize(512, b'1');
    for i in (6..512).step_by(2) {
        endless[i] = b'\n';
    }
    let e = parse(&damaged(&endless), 512).unwrap_err();
    assert!(e.to_string().contains("past the end of its entry"), "{e}");
    assert!(parse(&damaged(b"1\nx\n100\n"), 512).is_err(), "garbage");
    assert!(parse(&damaged(b"1\n100\n\n"), 512).is_err(), "empty line");
    // An absurd segment count is refused when read, before any memory goes to it.
    let e = parse(&damaged(format!("{}\n", u64::MAX / 4).as_bytes()), 512).unwrap_err();
    assert!(e.to_string().contains("segments"), "{e}");

    // Sparse records on something that is not a file.
    let mut d = Spec::dir("d");
    d.pax = vec![("GNU.sparse.size".into(), "10".into())];
    assert!(parse(&tarbuild::tar(&[d]), 512).is_err());
}

#[test]
fn names_ntfs_upper_cases_together_collide_up_front() {
    // `to_lowercase` keeps these apart; NTFS's upcase table (and macOS case folding) do not.
    for (a, b) in [
        ("file", "f\u{131}le"),
        ("sea.txt", "\u{17f}ea.txt"),
        ("\u{3b1}\u{3c3}", "\u{3b1}\u{3c2}"),
        // The Kelvin sign is not NFC: it is normalized to "K" first.
        ("kelvin", "\u{212a}elvin"),
    ] {
        let tar = tarbuild::tar(&[Spec::file(a, b"1"), Spec::file(b, b"2").via(NameVia::Pax)]);
        assert_eq!(
            matches!(parse(&tar, 512), Err(TarError::Name { .. })),
            cfg!(any(windows, target_os = "macos")),
            "{a:?} vs {b:?}"
        );
    }
}

#[test]
fn staging_directory_names_are_refused_at_the_top() {
    for bad in [".trunc-stage-0011", "./.trunc-stage-x/inner.txt"] {
        let tar = tarbuild::tar(&[Spec::file(bad, b"x")]);
        assert!(
            matches!(parse(&tar, 512), Err(TarError::Name { .. })),
            "{bad:?}"
        );
    }
    let tar = tarbuild::tar(&[Spec::file("dir/.trunc-stage-0011", b"x")]);
    assert!(parse(&tar, 512).is_ok());
}

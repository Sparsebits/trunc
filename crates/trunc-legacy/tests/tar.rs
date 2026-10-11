//! The tar reader against archives from the test builder, plus regressions found by fuzzing.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use trunc_legacy::tar::{Kind, Reader, TarError};
use trunc_testkit::tarbuild::{self, NameVia, Spec};

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

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::path::Path;

use proptest::prelude::*;
use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::inflate::{Checkpoint, Inflater};
use trunc_legacy::zip::{self, Entry, Kind, Layout, Method, ZipError};
use trunc_testkit::zipbuild::{Spec, ZipBuilder};
use trunc_testkit::{CrashModel, FaultFs, Rng, fixtures};

fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/z.zip"), bytes);
    let h = fs
        .open(Path::new("/z.zip"), OpenMode::Read, Share::Shared)
        .unwrap();
    (fs, h)
}

fn parse(bytes: &[u8]) -> Result<Layout, ZipError> {
    let (_fs, h) = host(bytes);
    zip::parse(h.as_ref())
}

fn content(h: &dyn FileHandle, e: &Entry) -> Vec<u8> {
    match e.method {
        Method::Stored => {
            let mut v = vec![0u8; e.size as usize];
            h.read_exact_at(&mut v, e.data_offset).unwrap();
            v
        }
        Method::Deflate => {
            let mut out = Vec::new();
            let f = Inflater::new(&Checkpoint::start(), e.size)
                .run(
                    h,
                    e.data_offset,
                    e.compressed_size,
                    &mut |b| {
                        out.extend_from_slice(b);
                        Ok(())
                    },
                    0,
                    &mut |_| Ok(()),
                )
                .unwrap();
            assert_eq!(f.crc, e.crc32);
            out
        }
    }
}

fn sample_specs() -> Vec<Spec> {
    let mut rng = Rng::new(1);
    vec![
        Spec::dir("docs"),
        Spec::file("docs/readme.txt", &fixtures::text_bytes(&mut rng, 5000)),
        Spec::file("docs/raw.bin", &fixtures::noise_bytes(&mut rng, 3000)).stored(),
        Spec::file("empty.txt", b""),
        Spec::file("ünï/ファイル.txt", "héllo".as_bytes()),
        Spec::file("tool.sh", b"#!/bin/sh\necho hi\n").mode(0o100_755),
        Spec::file("dd/with_sig.txt", &fixtures::text_bytes(&mut rng, 2000)).descriptor(true),
        Spec::file("dd/no_sig.txt", &fixtures::text_bytes(&mut rng, 2000)).descriptor(false),
        Spec::file("big64/z.txt", &fixtures::text_bytes(&mut rng, 4000)).zip64(),
        Spec::file("big64/zd.txt", &fixtures::text_bytes(&mut rng, 4000))
            .zip64()
            .descriptor(true),
    ]
}

fn build(specs: &[Spec]) -> Vec<u8> {
    let mut b = ZipBuilder::new();
    for s in specs {
        b.add(s.clone());
    }
    b.build()
}

#[test]
fn parses_and_extracts_every_feature() {
    let specs = sample_specs();
    for (prefix, comment, z64) in [
        (&b""[..], &b""[..], false),
        (b"MZ fake sfx stub", b"a comment", false),
        (b"", b"", true),
    ] {
        let mut b = ZipBuilder::new().prefix(prefix).comment(comment);
        if z64 {
            b = b.zip64_eocd();
        }
        for s in &specs {
            b.add(s.clone());
        }
        let bytes = b.build();
        let (_fs, h) = host(&bytes);
        let layout = zip::parse(h.as_ref()).unwrap();
        assert!(layout.overlaps.is_empty());
        assert_eq!(layout.entries.len(), specs.len());
        for (e, s) in layout.entries.iter().zip(&specs) {
            let want = String::from_utf8(s.name.clone()).unwrap();
            assert_eq!(e.name, want.trim_end_matches('/'));
            if e.kind == Kind::Dir {
                assert!(s.name.ends_with(b"/"));
                continue;
            }
            assert_eq!(content(h.as_ref(), e), s.data, "{}", e.name);
            assert!(
                e.region_start < e.data_offset && e.data_offset + e.compressed_size <= e.region_end
            );
        }
        let tool = layout.entries.iter().find(|e| e.name == "tool.sh").unwrap();
        assert_eq!(tool.mode, Some(0o755));
        assert_eq!(layout.entries[1].mtime_unix, 1_715_949_000); // 2024-05-17 12:30:00
        assert_eq!(Layout::from_bytes(&layout.to_bytes()).unwrap(), layout);
    }
}

#[test]
fn cp437_and_backslash_names() {
    let mut s = Spec::file("x", b"1");
    s.name = vec![b'd', b'\\', 0x81, b'.', b't', b'x', b't'];
    s.utf8 = false;
    let l = parse(&build(&[s])).unwrap();
    assert_eq!(l.entries[0].name, "d/ü.txt");
}

#[test]
fn symlinks_are_recognised() {
    let l = parse(&build(&[Spec::file("link", b"target")
        .stored()
        .mode(0o120_777)]))
    .unwrap();
    assert_eq!(l.entries[0].kind, Kind::Symlink);
}

#[test]
fn rejects_hostile_names() {
    for bad in [
        "../evil.txt",
        "/etc/passwd",
        "C:/Windows/x",
        "a/../../b",
        "a/b\0c",
    ] {
        let e = parse(&build(&[Spec::file(bad, b"x")])).unwrap_err();
        assert!(matches!(e, ZipError::Name { .. }), "{bad:?}: {e}");
    }
    let dup = [Spec::file("same.txt", b"1"), Spec::file("same.txt", b"2")];
    assert!(matches!(parse(&build(&dup)), Err(ZipError::Name { .. })));
    // Names that differ only in case are one file on Windows and macOS, two on Linux.
    let case = [Spec::file("Same.txt", b"1"), Spec::file("same.TXT", b"2")];
    assert_eq!(
        matches!(parse(&build(&case)), Err(ZipError::Name { .. })),
        cfg!(any(windows, target_os = "macos"))
    );
    let nested = [Spec::file("a", b"file"), Spec::file("a/b", b"under a file")];
    assert!(matches!(parse(&build(&nested)), Err(ZipError::Name { .. })));
}

#[test]
fn names_ntfs_upper_cases_together_collide_up_front() {
    // `to_lowercase` keeps these apart; NTFS's upcase table (and macOS case folding) do not.
    for (a, b) in [
        ("file", "f\u{131}le"),
        ("sea.txt", "\u{17f}ea.txt"),
        ("\u{3b1}\u{3c3}", "\u{3b1}\u{3c2}"),
        ("kelvin", "\u{212a}elvin"),
    ] {
        let pair = [Spec::file(a, b"1"), Spec::file(b, b"2")];
        assert_eq!(
            matches!(parse(&build(&pair)), Err(ZipError::Name { .. })),
            cfg!(any(windows, target_os = "macos")),
            "{a:?} vs {b:?}"
        );
    }
    // A file and a directory named like it, too.
    let nested = [Spec::file("f\u{131}le", b"x"), Spec::file("FILE/b", b"y")];
    assert_eq!(
        matches!(parse(&build(&nested)), Err(ZipError::Name { .. })),
        cfg!(any(windows, target_os = "macos"))
    );
}

#[test]
fn staging_directory_names_are_refused_at_the_top() {
    for bad in [".trunc-stage-0011", ".TRUNC-STAGE-x/inner.txt"] {
        let e = parse(&build(&[Spec::file(bad, b"x")])).unwrap_err();
        assert!(matches!(e, ZipError::Name { .. }), "{bad:?}: {e}");
    }
    assert!(parse(&build(&[Spec::file("dir/.trunc-stage-0011", b"x")])).is_ok());
}

/// Offset of the first central-directory record in a built ZIP.
fn cd_start(bytes: &[u8]) -> usize {
    bytes
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap()
}

#[test]
fn rejects_unsupported_and_inconsistent_archives() {
    let base = build(&[Spec::file("a.txt", &[7u8; 1000])]);
    let cd = cd_start(&base);

    let mut enc = base.clone();
    enc[cd + 8] |= 1; // encrypted flag in the central directory
    enc[6] |= 1; // and local header
    assert!(matches!(parse(&enc), Err(ZipError::Unsupported(_))));

    let mut method = base.clone();
    method[cd + 10] = 12; // bzip2
    assert!(matches!(parse(&method), Err(ZipError::Unsupported(_))));

    let mut name = base.clone();
    name[30] = b'b'; // local header name differs from the directory
    assert!(matches!(parse(&name), Err(ZipError::Corrupt(_))));

    let mut crc = base.clone();
    crc[14] ^= 0xFF; // local header CRC
    assert!(matches!(parse(&crc), Err(ZipError::Corrupt(_))));

    let mut size = base.clone();
    size[cd + 20..cd + 24].copy_from_slice(&u32::MAX.to_le_bytes().map(|_| 0x7F)); // huge csize
    assert!(parse(&size).is_err());

    assert!(matches!(
        parse(&base[..base.len() - 3]),
        Err(ZipError::NotZip(_))
    ));
    assert!(matches!(
        parse(b"PK\x03\x04 not really"),
        Err(ZipError::NotZip(_))
    ));
    assert!(matches!(parse(&[]), Err(ZipError::NotZip(_))));
}

#[test]
fn detects_overlapping_entries() {
    // Entry "outer" (stored) contains a complete local record for "inner"; a second directory
    // record points at it, so the two regions overlap.
    let inner = Spec::file("inner.txt", b"inside another entry's data").stored();
    let record = ZipBuilder::local_record(&inner);
    let mut b = ZipBuilder::new();
    let outer = b.add(Spec::file("outer.bin", &record).stored());
    b.alias(inner.clone(), outer.data);
    let bytes = b.build();
    let (_fs, h) = host(&bytes);
    let l = zip::parse(h.as_ref()).unwrap();
    assert_eq!(l.overlaps.len(), 1);
    assert_eq!(content(h.as_ref(), &l.entries[1]), inner.data);
}

/// A ZIP made by Windows' own System.IO.Compression (via PowerShell).
#[cfg(windows)]
#[test]
fn reads_archives_made_by_windows() {
    let d = tempfile::tempdir().unwrap();
    let src = d.path().join("src");
    fixtures::small_files(&src, 40, 5);
    fixtures::edge_cases(&src);
    let out = d.path().join("w.zip");
    let ps = format!(
        "$ErrorActionPreference='Stop'; Compress-Archive -Path '{}\\*' -DestinationPath '{}'",
        src.display(),
        out.display()
    );
    let ok = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .status()
        .unwrap();
    assert!(ok.success());
    let bytes = std::fs::read(&out).unwrap();
    let (_fs, h) = host(&bytes);
    let l = zip::parse(h.as_ref()).unwrap();
    let mut files = 0;
    for e in l.entries.iter().filter(|e| e.kind == Kind::File) {
        let on_disk = std::fs::read(src.join(&e.name)).unwrap();
        assert_eq!(content(h.as_ref(), e), on_disk, "{}", e.name);
        files += 1;
    }
    assert!(files >= 40, "{files} files");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    #[test]
    fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = parse(&bytes);
    }

    #[test]
    fn tampered_archives_never_panic(seed in any::<u64>(), flips in 1usize..12) {
        let mut bytes = build(&sample_specs());
        let mut rng = Rng::new(seed);
        for _ in 0..flips {
            let i = rng.below(bytes.len() as u64) as usize;
            bytes[i] = rng.next_u64() as u8;
        }
        if let Ok(l) = parse(&bytes) {
            // Anything accepted must be internally consistent.
            for e in &l.entries {
                prop_assert!(e.region_start < e.data_offset);
                prop_assert!(e.data_offset + e.compressed_size <= e.region_end);
                prop_assert!(e.region_end <= l.cd_start);
            }
            let _ = Layout::from_bytes(&l.to_bytes()).unwrap();
        }
    }
}

/// Regression (found by cargo-fuzz): a Zip64 locator pointing near u64::MAX overflowed.
#[test]
fn zip64_locator_offset_near_max_is_an_error() {
    let mut bytes = ZipBuilder::new().zip64_eocd().build();
    let loc = bytes
        .windows(4)
        .rposition(|w| w == [0x50, 0x4b, 0x06, 0x07])
        .unwrap();
    bytes[loc + 8..loc + 16].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
    assert!(matches!(parse(&bytes), Err(ZipError::Corrupt(_))));
}

/// Huge Zip64 local-header offsets must not overflow either.
#[test]
fn zip64_header_offset_near_max_is_an_error() {
    let mut bytes = build(&[Spec::file("a.txt", b"hello").zip64()]);
    let cd = bytes
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    let lho = cd + 46 + "a.txt".len() + 4 + 16; // zip64 extra: usize, csize, then offset
    bytes[lho..lho + 8].copy_from_slice(&(u64::MAX - 5).to_le_bytes());
    assert!(parse(&bytes).is_err());
}

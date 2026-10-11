#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::HashMap;
use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_legacy::sevenz::{self, Kind, Layout, SevenZError};
use trunc_testkit::sevenzbuild::{Codec7, Item7, Opts7, assemble, build, coders, compress, number};
use trunc_testkit::{CrashModel, FaultFs, Rng};

const WINDOW: u64 = 256 << 20;

fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new("/a.7z"), bytes);
    let h = fs
        .open(Path::new("/a.7z"), OpenMode::Read, Share::Shared)
        .unwrap();
    (fs, h)
}

fn parse(bytes: &[u8]) -> Result<Layout, SevenZError> {
    let (_fs, h) = host(bytes);
    sevenz::parse(h.as_ref(), WINDOW)
}

/// Parse and decode everything: name -> content.
fn unpack(bytes: &[u8]) -> Result<HashMap<String, Vec<u8>>, SevenZError> {
    let (_fs, h) = host(bytes);
    let l = sevenz::parse(h.as_ref(), WINDOW)?;
    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    for e in &l.entries {
        if e.kind != Kind::Dir {
            out.insert(e.name.clone(), Vec::new());
        }
    }
    for i in 0..l.folders.len() {
        sevenz::decode_folder(
            h.as_ref(),
            &l,
            i,
            &mut |_| Ok(()),
            &mut |e, b| {
                out.get_mut(&l.entries[e].name)
                    .unwrap()
                    .extend_from_slice(b);
                Ok(())
            },
            &mut |_| Ok(()),
        )?;
    }
    Ok(out)
}

/// Text with x86-like call instructions, so the BCJ filter has work to do.
fn sample(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        match rng.below(6) {
            0 => {
                v.push(0xE8);
                v.extend_from_slice(&(rng.below(1 << 20) as u32).to_le_bytes());
            }
            1 => v.extend_from_slice(b"the quick brown fox jumps over the lazy dog "),
            _ => {
                let mut b = [0u8; 7];
                rng.fill(&mut b);
                v.extend_from_slice(&b[..(rng.below(7) as usize)]);
            }
        }
    }
    v.truncate(len);
    v
}

fn items() -> Vec<Item7> {
    vec![
        Item7::file("a.txt", b"hello 7z\n"),
        Item7::file("dir/b.bin", &sample(1, 200_000)),
        Item7::file("dir/sub/c.bin", &sample(2, 70_000)),
        Item7::file("dir/empty.txt", b""),
        Item7::dir("dir/emptydir"),
        Item7::file("ünïcödé/файл.txt", "текст".as_bytes()),
    ]
}

fn check(items: &[Item7], got: &HashMap<String, Vec<u8>>) {
    for i in items.iter().filter(|i| !i.anti) {
        if let Some(d) = &i.data {
            assert_eq!(got.get(&i.name), Some(d), "{}", i.name);
        }
    }
}

#[test]
fn every_codec_solid_and_not_with_and_without_encoded_header() {
    let items = items();
    for codec in [
        Codec7::Copy,
        Codec7::Lzma,
        Codec7::Lzma2,
        Codec7::BcjLzma2,
        Codec7::BcjLzma,
        Codec7::DeltaLzma2(4),
    ] {
        for solid in [true, false] {
            for encode_header in [true, false] {
                for folder_crc in [true, false] {
                    let o = Opts7 {
                        codec,
                        solid,
                        encode_header,
                        folder_crc,
                        ..Opts7::default()
                    };
                    let a = build(&items, &o);
                    let l = parse(&a).unwrap_or_else(|e| panic!("{o:?}: {e}"));
                    assert_eq!(l.encoded_header, encode_header);
                    assert_eq!(l.solid(), solid, "{o:?}");
                    assert_eq!(l.entries.len(), items.len());
                    let got = unpack(&a).unwrap_or_else(|e| panic!("{o:?}: {e}"));
                    check(&items, &got);
                }
            }
        }
    }
}

#[test]
fn kinds_attributes_times_and_anti_items() {
    let items = vec![
        Item7::file("x", b"data").attrib(0x8000 | (0o100_640 << 16)),
        Item7::file("link", b"x").attrib(0x8000 | (0o120_777 << 16)),
        Item7::dir("d").attrib(0x10),
        Item7::file("gone", b"").anti(),
        Item7::file("e", b""),
    ];
    let a = build(&items, &Opts7::default());
    let l = parse(&a).unwrap();
    assert_eq!(l.anti_items, 1);
    let by: HashMap<&str, &sevenz::Entry> =
        l.entries.iter().map(|e| (e.name.as_str(), e)).collect();
    assert_eq!(by.len(), 4);
    assert_eq!(by["x"].kind, Kind::File);
    assert_eq!(by["x"].mode, Some(0o640));
    assert_eq!(by["link"].kind, Kind::Symlink);
    assert_eq!(by["d"].kind, Kind::Dir);
    assert_eq!(by["e"].kind, Kind::File);
    assert_eq!(by["e"].size, 0);
    // FILETIME 133_000_000_000_000_000 is 13_300_000_000 s after 1601.
    assert_eq!(by["x"].mtime_unix, 13_300_000_000 - 11_644_473_600);
}

#[test]
fn large_data_crosses_chunks_and_windows() {
    // Larger than an LZMA2 chunk (2 MiB) and the dictionary, so window trimming and chunk
    // boundaries are exercised, for LZMA1 as well.
    let big = sample(9, 5 << 20);
    let items = vec![Item7::file("big", &big), Item7::file("small", b"tail")];
    for codec in [Codec7::Lzma, Codec7::Lzma2, Codec7::BcjLzma2] {
        let a = build(
            &items,
            &Opts7 {
                codec,
                ..Opts7::default()
            },
        );
        check(&items, &unpack(&a).unwrap());
    }
}

#[test]
fn empty_archive_and_only_directories() {
    let a = build(&[], &Opts7::default());
    assert!(parse(&a).unwrap().entries.is_empty());
    let items = vec![Item7::dir("a"), Item7::dir("a/b"), Item7::file("a/c", b"")];
    let l = parse(&build(&items, &Opts7::default())).unwrap();
    assert_eq!(l.entries.len(), 3);
    assert!(l.folders.is_empty());
}

fn err(bytes: &[u8]) -> String {
    match unpack(bytes) {
        Ok(_) => panic!("accepted"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn crc_mismatch_is_caught() {
    let items = vec![Item7::file("a", &sample(3, 5000))];
    for codec in [Codec7::Copy, Codec7::Lzma2] {
        let mut a = build(
            &items,
            &Opts7 {
                codec,
                encode_header: false,
                ..Opts7::default()
            },
        );
        // Flip a byte inside the packed stream (it starts right after the 32-byte header).
        a[32 + 100] ^= 0x55;
        let e = err(&a);
        assert!(e.contains("CRC") || e.contains("corrupt"), "{e}");
    }
}

#[test]
fn truncated_archives_are_refused() {
    let a = build(&items(), &Opts7::default());
    for cut in [10, 31, 32, 100, a.len() / 2, a.len() - 1] {
        assert!(parse(&a[..cut]).is_err(), "cut at {cut}");
    }
    // Header CRC protects the header itself.
    let mut b = a.clone();
    let n = b.len();
    b[n - 3] ^= 1;
    assert!(parse(&b).unwrap_err().to_string().contains("CRC"));
}

#[test]
fn traversal_and_duplicate_names_are_refused() {
    for names in [
        vec!["../evil"],
        vec!["/abs"],
        vec!["a/../../b"],
        vec!["C:\\windows"],
        vec!["dup", "dup"],
        vec!["f", "f/g"],
    ] {
        let items: Vec<Item7> = names.iter().map(|n| Item7::file(n, b"x")).collect();
        let a = build(&items, &Opts7::default());
        assert!(
            matches!(parse(&a), Err(SevenZError::Name { .. })),
            "{names:?}: {:?}",
            parse(&a)
        );
    }
}

/// A hand-made header: one Copy folder of `size` over `packed`, then `files`.
fn copy_archive(packed: &[u8], size: u64, files_info: &[u8]) -> Vec<u8> {
    let mut h = vec![0x01, 0x04, 0x06];
    number(&mut h, 0);
    number(&mut h, 1);
    h.push(0x09);
    number(&mut h, packed.len() as u64);
    h.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&coders(Codec7::Copy, 0, size).0);
    h.push(0x0C);
    number(&mut h, size);
    h.extend_from_slice(&[0x00, 0x00]);
    h.extend_from_slice(files_info);
    h.push(0x00);
    assemble(packed, &h)
}

fn one_name(name: &str) -> Vec<u8> {
    let mut f = vec![0x05, 0x01, 0x11];
    let mut names = vec![0u8];
    for u in name.encode_utf16() {
        names.extend_from_slice(&u.to_le_bytes());
    }
    names.extend_from_slice(&[0, 0]);
    number(&mut f, names.len() as u64);
    f.extend_from_slice(&names);
    f.push(0x00);
    f
}

#[test]
fn hostile_headers_are_refused() {
    // The baseline is valid.
    let ok = copy_archive(b"abcd", 4, &one_name("f"));
    assert_eq!(unpack(&ok).unwrap()["f"], b"abcd");

    // Declared output larger or smaller than the packed Copy stream.
    assert!(err(&copy_archive(b"abcd", 5, &one_name("f"))).contains("shorter"));
    assert!(err(&copy_archive(b"abcd", 3, &one_name("f"))).contains("longer"));

    // Huge file count.
    let mut f = vec![0x05];
    number(&mut f, u64::MAX >> 1);
    f.push(0x00);
    assert!(err(&copy_archive(b"abcd", 4, &f)).contains("count"));

    // Huge folder count.
    let mut h = vec![0x01, 0x04, 0x07, 0x0B];
    number(&mut h, 1 << 40);
    assert!(err(&assemble(b"", &h)).contains("count"));

    // Packed stream past the header.
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    number(&mut h, 1 << 30);
    h.push(0x00);
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&coders(Codec7::Copy, 0, 4).0);
    h.extend_from_slice(&[0x0C, 0x04, 0x00, 0x00, 0x00]);
    assert!(err(&assemble(b"abcd", &h)).contains("past the header"));

    // Substream sizes larger than their folder.
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x04, 0x00];
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&coders(Codec7::Copy, 0, 4).0);
    h.extend_from_slice(&[0x0C, 0x04, 0x00]);
    h.extend_from_slice(&[0x08, 0x0D, 0x02, 0x09, 0x09, 0x00, 0x00]);
    assert!(err(&assemble(b"abcd", &h)).contains("more than"));

    // Bind pairs forming a cycle: of three Copy coders, two feed each other and only the
    // third reaches the packed stream.
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x04, 0x00];
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&[0x03, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00]);
    h.extend_from_slice(&[0x00, 0x01, 0x01, 0x00]);
    h.extend_from_slice(&[0x0C, 0x04, 0x04, 0x04, 0x00, 0x00]);
    let e = err(&assemble(b"abcd", &h));
    assert!(e.contains("chain"), "{e}");

    // An unsupported method is named; AES says the archive is encrypted.
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x04, 0x00];
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&[0x01, 0x24, 0x06, 0xF1, 0x07, 0x01, 0x00]);
    h.extend_from_slice(&[0x0C, 0x04, 0x00, 0x00]);
    let e = err(&assemble(b"abcd", &h));
    assert!(e.contains("encrypted"), "{e}");
    let mut h = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x04, 0x00];
    h.extend_from_slice(&[0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&[0x01, 0x03, 0x03, 0x04, 0x01]);
    h.extend_from_slice(&[0x0C, 0x04, 0x00, 0x00]);
    let e = err(&assemble(b"abcd", &h));
    assert!(e.contains("PPMd"), "{e}");
}

#[test]
fn dictionary_limit_is_enforced() {
    let items = vec![Item7::file("a", b"some data")];
    let a = build(
        &items,
        &Opts7 {
            dict: 64 << 20,
            ..Opts7::default()
        },
    );
    let (_fs, h) = host(&a);
    let e = sevenz::parse(h.as_ref(), 16 << 20).unwrap_err().to_string();
    assert!(e.contains("--max-window"), "{e}");
    assert!(sevenz::parse(h.as_ref(), 64 << 20).is_ok());
}

#[test]
fn garbage_never_panics() {
    let a = build(&items(), &Opts7::default());
    let b = build(
        &items(),
        &Opts7 {
            codec: Codec7::Lzma,
            encode_header: false,
            solid: false,
            ..Opts7::default()
        },
    );
    let mut rng = Rng::new(7);
    for base in [a, b] {
        for _ in 0..300 {
            let mut x = base.clone();
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(x.len() as u64) as usize;
                x[i] = rng.next_u64() as u8;
            }
            let _ = unpack(&x);
        }
    }
    // Raw LZMA streams cut short or followed by junk.
    let p = compress(Codec7::Lzma, 1 << 16, &sample(5, 10_000));
    for cut in [5, 6, 100, p.len() - 1] {
        let _ = unpack(&copy_like(&p[..cut]));
    }
}

/// An LZMA folder over `packed` declaring 10 000 bytes of output.
fn copy_like(packed: &[u8]) -> Vec<u8> {
    let mut h = vec![0x01, 0x04, 0x06];
    number(&mut h, 0);
    number(&mut h, 1);
    h.push(0x09);
    number(&mut h, packed.len() as u64);
    h.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00]);
    h.extend_from_slice(&coders(Codec7::Lzma, 1 << 16, 10_000).0);
    h.push(0x0C);
    number(&mut h, 10_000);
    h.extend_from_slice(&[0x00, 0x00]);
    h.extend_from_slice(&one_name("f"));
    h.push(0x00);
    assemble(packed, &h)
}

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use trunc_codec::CodecChoice;
use trunc_core::{FOOTER_LEN, Footer};
use trunc_engine::extract::{self, ExtractOptions, TrustPolicy};
use trunc_engine::producer::{self, CreateOptions, DictMode};
use trunc_engine::{Archive, Error, keys};
use trunc_testkit::{fixtures, tree};

fn opts(codec: CodecChoice, block: u64) -> CreateOptions {
    CreateOptions {
        block_size: block,
        codec,
        ..CreateOptions::default()
    }
}

/// An opened archive plus the temp directory holding it. Fields drop in order, so the archive's
/// file handle closes before the directory is removed.
struct RoundTrip {
    archive: Archive,
    _work: tempfile::TempDir,
}

impl std::ops::Deref for RoundTrip {
    type Target = Archive;
    fn deref(&self) -> &Archive {
        &self.archive
    }
}

/// Create an archive of `src` (as one directory input), verify it, extract it and compare.
fn round_trip(src: &Path, o: &CreateOptions) -> RoundTrip {
    let work = tempfile::tempdir().unwrap();
    let arc = work.path().join("a.trnc");
    let s = producer::create(&arc, &[src.to_path_buf()], o).unwrap();
    assert_eq!(fs::metadata(&arc).unwrap().len(), s.archive_len);

    let archive = Archive::open(&arc).unwrap();
    assert!(archive.is_complete());
    extract::verify(&archive, &TrustPolicy::default(), 0).unwrap();

    let dest = work.path().join("out");
    extract::extract(&archive, &dest, &ExtractOptions::default()).unwrap();
    tree::assert_same(src, &dest.join(src.file_name().unwrap()));

    // Layout invariant: the last FOOTER_LEN bytes are block 0's footer.
    if !archive.manifest().blocks.is_empty() {
        let mut f = fs::File::open(&arc).unwrap();
        f.seek(SeekFrom::End(-(FOOTER_LEN as i64))).unwrap();
        let mut fb = [0u8; FOOTER_LEN];
        f.read_exact(&mut fb).unwrap();
        assert_eq!(Footer::decode(&fb).unwrap().block_index, 0);
    }
    RoundTrip {
        archive,
        _work: work,
    }
}

fn fixture(f: impl FnOnce(&Path)) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("src");
    fs::create_dir_all(&root).unwrap();
    f(&root);
    (d, root)
}

#[test]
fn mixed_tree_all_codecs_and_block_sizes() {
    let (_d, src) = fixture(|r| fixtures::mixed(r, 1));
    for codec in [
        CodecChoice::Store,
        CodecChoice::Lz4,
        CodecChoice::Zstd { level: 3 },
    ] {
        for block in [64 << 10, 1 << 20, 8 << 20] {
            let a = round_trip(&src, &opts(codec, block));
            assert!(!a.manifest().blocks.is_empty());
        }
    }
}

#[test]
fn tiny_blocks_split_files_everywhere() {
    let (_d, src) = fixture(|r| {
        fixtures::small_files(r, 40, 7);
        fixtures::edge_cases(r);
    });
    for block in [1, 7, 4096] {
        round_trip(&src, &opts(CodecChoice::Zstd { level: 1 }, block));
    }
}

#[test]
fn edge_cases_and_empty_dir_input() {
    let (_d, src) = fixture(fixtures::edge_cases);
    round_trip(&src, &CreateOptions::default());

    let (_d2, empty) = fixture(|_| {});
    let a = round_trip(&empty, &CreateOptions::default());
    assert!(a.manifest().blocks.is_empty());
    assert_eq!(a.manifest().total_u, 0);
}

#[test]
fn incompressible_blocks_are_stored() {
    let (_d, src) = fixture(|r| fixtures::extremes(r, 2 << 20, 3));
    let a = round_trip(&src, &opts(CodecChoice::Zstd { level: 3 }, 256 << 10));
    let codecs: Vec<u16> = a.manifest().blocks.iter().map(|b| b.codec).collect();
    assert!(
        codecs.contains(&0),
        "noise blocks should fall back to store"
    );
    assert!(codecs.contains(&2), "zero blocks should stay zstd");
}

#[test]
fn trained_dictionary() {
    let (_d, src) = fixture(|r| fixtures::small_files(r, 400, 11));
    let o = CreateOptions {
        dict: DictMode::Train,
        block_size: 64 << 10,
        ..CreateOptions::default()
    };
    let a = round_trip(&src, &o);
    assert!(a.dict().is_some());
}

#[test]
fn multiple_inputs_files_and_dirs() {
    let (d, src) = fixture(|r| fixtures::small_files(r, 10, 5));
    let single = d.path().join("single.txt");
    fs::write(&single, b"single file input").unwrap();
    let work = tempfile::tempdir().unwrap();
    let arc = work.path().join("m.trnc");
    producer::create(
        &arc,
        &[src.clone(), single.clone()],
        &CreateOptions::default(),
    )
    .unwrap();
    let a = Archive::open(&arc).unwrap();
    let out = work.path().join("out");
    extract::extract(&a, &out, &ExtractOptions::default()).unwrap();
    tree::assert_same(&src, &out.join("src"));
    assert_eq!(
        fs::read(out.join("single.txt")).unwrap(),
        b"single file input"
    );
}

#[test]
fn duplicate_input_names_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    let (a, b) = (d.path().join("x/same"), d.path().join("y/same"));
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let err = producer::create(&d.path().join("o.trnc"), &[a, b], &CreateOptions::default());
    assert!(err.is_err());
}

fn make_archive(src: &Path, o: &CreateOptions) -> (tempfile::TempDir, PathBuf) {
    let work = tempfile::tempdir().unwrap();
    let arc = work.path().join("a.trnc");
    producer::create(&arc, &[src.to_path_buf()], o).unwrap();
    (work, arc)
}

fn flip_byte(path: &Path, off: u64) {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    let mut b = [0u8; 1];
    f.read_exact(&mut b).unwrap();
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&[b[0] ^ 0x5A]).unwrap();
}

#[test]
fn tampered_payload_is_detected() {
    let (_d, src) = fixture(|r| fixtures::large_file(r, 1 << 20, 2));
    let (_w, arc) = make_archive(&src, &opts(CodecChoice::Zstd { level: 3 }, 128 << 10));
    let a = Archive::open(&arc).unwrap();
    let target = a.block_offset(3) + 5;
    drop(a);
    flip_byte(&arc, target);
    let a = Archive::open(&arc).unwrap(); // manifest and header are intact
    let err = extract::verify(&a, &TrustPolicy::default(), 0).unwrap_err();
    assert!(matches!(err, Error::Integrity(_)), "{err}");
    let out = tempfile::tempdir().unwrap();
    assert!(extract::extract(&a, out.path(), &ExtractOptions::default()).is_err());
}

#[test]
fn tampered_footer_and_manifest_are_detected() {
    let (_d, src) = fixture(|r| fixtures::small_files(r, 20, 4));
    let (_w, arc) = make_archive(&src, &opts(CodecChoice::Lz4, 16 << 10));
    let a = Archive::open(&arc).unwrap();
    let footer_off = a.block_offset(1) + a.manifest().blocks[1].c_len + 20;
    drop(a);
    flip_byte(&arc, footer_off);
    let a = Archive::open(&arc).unwrap();
    assert!(matches!(
        extract::verify(&a, &TrustPolicy::default(), 0),
        Err(Error::Format(_))
    ));
    drop(a);

    // Any corrupted byte in the header or manifest region must be caught at open.
    let (w2, arc2) = make_archive(&src, &opts(CodecChoice::Lz4, 16 << 10));
    let pristine = fs::read(&arc2).unwrap();
    let fbo = Archive::open(&arc2).unwrap().header().first_block_off();
    let probe = w2.path().join("probe.trnc");
    for off in (0..fbo as usize).step_by(5) {
        let mut bytes = pristine.clone();
        bytes[off] ^= 0x20;
        fs::write(&probe, &bytes).unwrap();
        assert!(
            Archive::open(&probe).is_err(),
            "flip at byte {off} went undetected"
        );
    }
}

#[test]
fn partially_consumed_archive_is_recognised_and_refused() {
    let (_d, src) = fixture(|r| fixtures::small_files(r, 50, 9));
    let (_w, arc) = make_archive(&src, &opts(CodecChoice::Zstd { level: 1 }, 32 << 10));
    let a = Archive::open(&arc).unwrap();
    let m = a.manifest().clone();
    let fbo = a.header().first_block_off();
    drop(a);
    assert!(m.blocks.len() > 3);

    // Simulate a consumer that truncated away blocks 0..3.
    let len3 = m.len_after_consuming(fbo, 3);
    OpenOptions::new()
        .write(true)
        .open(&arc)
        .unwrap()
        .set_len(len3)
        .unwrap();
    let a = Archive::open(&arc).unwrap();
    assert_eq!(a.consumed(), 3);
    assert!(a.decode_block(2).is_err());
    a.decode_block(3).unwrap();
    assert!(matches!(
        extract::verify(&a, &TrustPolicy::default(), 0),
        Err(Error::Refused(_))
    ));
    let out = tempfile::tempdir().unwrap();
    assert!(matches!(
        extract::extract(&a, out.path(), &ExtractOptions::default()),
        Err(Error::Refused(_))
    ));
    drop(a);

    // A length that is not on a block boundary is a torn or corrupt file.
    OpenOptions::new()
        .write(true)
        .open(&arc)
        .unwrap()
        .set_len(len3 - 1)
        .unwrap();
    assert!(matches!(Archive::open(&arc), Err(Error::Integrity(_))));

    // Fully consumed: only header + manifest remain.
    OpenOptions::new()
        .write(true)
        .open(&arc)
        .unwrap()
        .set_len(fbo)
        .unwrap();
    assert_eq!(Archive::open(&arc).unwrap().consumed(), m.blocks.len());
}

#[test]
fn signatures_and_trust_policy() {
    let (_d, src) = fixture(|r| fixtures::small_files(r, 5, 1));
    let key = keys::generate().unwrap();
    let pk = key.verifying_key().to_bytes();
    let o = CreateOptions {
        signing_key: Some(key),
        ..CreateOptions::default()
    };
    let (_w, signed) = make_archive(&src, &o);
    let (_w2, unsigned) = make_archive(&src, &CreateOptions::default());

    let s = Archive::open(&signed).unwrap();
    let u = Archive::open(&unsigned).unwrap();
    assert_eq!(s.signer(), Some(pk));
    assert_eq!(u.signer(), None);

    let require = TrustPolicy {
        require_signed: true,
        trusted_keys: vec![],
    };
    let pinned = TrustPolicy {
        require_signed: false,
        trusted_keys: vec![pk],
    };
    let other = TrustPolicy {
        require_signed: false,
        trusted_keys: vec![[1; 32]],
    };
    extract::verify(&s, &require, 0).unwrap();
    extract::verify(&s, &pinned, 0).unwrap();
    assert!(matches!(
        extract::verify(&s, &other, 0),
        Err(Error::Refused(_))
    ));
    assert!(matches!(
        extract::verify(&u, &require, 0),
        Err(Error::Refused(_))
    ));
    assert!(matches!(
        extract::verify(&u, &pinned, 0),
        Err(Error::Refused(_))
    ));
}

#[test]
fn existing_outputs_need_overwrite() {
    let (_d, src) = fixture(|r| fixtures::small_files(r, 5, 2));
    let (w, arc) = make_archive(&src, &CreateOptions::default());
    let a = Archive::open(&arc).unwrap();
    let out = w.path().join("out");
    extract::extract(&a, &out, &ExtractOptions::default()).unwrap();
    assert!(matches!(
        extract::extract(&a, &out, &ExtractOptions::default()),
        Err(Error::Refused(_))
    ));
    extract::extract(
        &a,
        &out,
        &ExtractOptions {
            overwrite: true,
            ..Default::default()
        },
    )
    .unwrap();
    tree::assert_same(&src, &out.join("src"));

    // The producer also refuses to clobber its output unless asked.
    assert!(matches!(
        producer::create(&arc, std::slice::from_ref(&src), &CreateOptions::default()),
        Err(Error::Refused(_))
    ));
    drop(a);
    producer::create(
        &arc,
        &[src],
        &CreateOptions {
            overwrite: true,
            ..Default::default()
        },
    )
    .unwrap();
}

/// `--overwrite` makes read-only outputs writable without going through a path that could be a
/// link, and refuses (never truncates through) an output that was replaced by a symlink.
#[test]
fn overwrite_handles_read_only_outputs_and_links() {
    fn first_file(dir: &Path) -> Option<PathBuf> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        entries
            .into_iter()
            .find_map(|p| if p.is_dir() { first_file(&p) } else { Some(p) })
    }
    let (_d, src) = fixture(|r| fixtures::small_files(r, 5, 2));
    let (w, arc) = make_archive(&src, &CreateOptions::default());
    let a = Archive::open(&arc).unwrap();
    let out = w.path().join("out");
    extract::extract(&a, &out, &ExtractOptions::default()).unwrap();
    let over = ExtractOptions {
        overwrite: true,
        ..Default::default()
    };
    let victim = first_file(&out).unwrap();
    let mut perms = std::fs::metadata(&victim).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&victim, perms).unwrap();
    extract::extract(&a, &out, &over).unwrap();
    tree::assert_same(&src, &out.join("src"));

    #[cfg(unix)]
    {
        let outside = w.path().join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::fs::remove_file(&victim).unwrap();
        std::os::unix::fs::symlink(&outside, &victim).unwrap();
        assert!(matches!(
            extract::extract(&a, &out, &over),
            Err(Error::Refused(_))
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
    }
}

/// Hand-build an archive whose manifest names a path outside the destination.
#[test]
fn hostile_manifest_is_rejected_at_open() {
    use trunc_core::{Entry, EntryKind, FORMAT_VERSION, Header, Manifest, SignedManifest};
    let m = Manifest {
        format_version: FORMAT_VERSION,
        archive_id: [0; 16],
        created_unix: 0,
        producer: "evil".into(),
        entries: vec![Entry {
            path: "../escape.txt".into(),
            kind: EntryKind::File,
            size: 0,
            mode: 0o644,
            mtime_unix: 0,
            mtime_nanos: 0,
            stream_off: 0,
            blake3: trunc_hash::blake3(b""),
        }],
        blocks: vec![],
        dict: None,
        total_u: 0,
        total_c: 0,
        merkle_root: trunc_hash::merkle::root(&[]),
    };
    let region = SignedManifest::new(m.encode_body(), None).encode();
    let h = Header::for_manifest(&region, 0);
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("evil.trnc");
    let mut bytes = h.encode().to_vec();
    bytes.extend_from_slice(&region);
    fs::write(&p, bytes).unwrap();
    let err = Archive::open(&p).unwrap_err();
    assert!(
        matches!(err, Error::Format(trunc_core::FormatError::Path { .. })),
        "{err}"
    );
}

#[test]
fn garbage_files_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    for (name, data) in [
        ("empty", vec![]),
        ("short", b"TRNC".to_vec()),
        (
            "zip",
            b"PK\x03\x04 not a trnc file at all, just bytes........................".to_vec(),
        ),
    ] {
        let p = d.path().join(name);
        fs::write(&p, data).unwrap();
        assert!(Archive::open(&p).is_err(), "{name} accepted");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(24)
    ))]
    #[test]
    fn random_trees_round_trip(
        files in proptest::collection::vec((0u8..4, 0usize..3000, any::<u64>()), 0..25),
        block in 1u64..5000,
        codec in 0u8..3,
    ) {
        let (_d, src) = fixture(|root| {
            for (i, (dir, len, seed)) in files.iter().enumerate() {
                let mut rng = trunc_testkit::Rng::new(*seed);
                let data = if seed % 2 == 0 {
                    fixtures::text_bytes(&mut rng, *len)
                } else {
                    fixtures::noise_bytes(&mut rng, *len)
                };
                let p = root.join(format!("d{dir}")).join(format!("f{i}"));
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(p, data).unwrap();
            }
        });
        let codec = match codec { 0 => CodecChoice::Store, 1 => CodecChoice::Lz4, _ => CodecChoice::Zstd { level: 1 } };
        round_trip(&src, &opts(codec, block));
    }
}

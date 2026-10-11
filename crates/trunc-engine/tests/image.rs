//! Container image tarballs: merged root filesystems from `docker save` and OCI layouts,
//! platform selection, digest checks and refusals of broken or hostile images.

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use trunc_engine::Error;
use trunc_engine::image::{self, ImageFormat, ImageOptions};
use trunc_fs::OsFs;
use trunc_legacy::stream::Codec;
use trunc_testkit::imagebuild::{
    self as ib, Compression, INDEX, Layer, MANIFEST, Outer, descriptor, platform,
};
use trunc_testkit::tarbuild::{self, Spec};
use trunc_testkit::tree::{Node, snapshot};
use trunc_testkit::{CrashModel, FaultFs};

fn opts() -> ImageOptions {
    ImageOptions::default()
}

/// Three layers exercising whiteouts, opaque directories and file/directory replacement.
fn layers() -> Vec<Layer> {
    vec![
        ib::layer(
            &[
                Spec::dir("etc"),
                Spec::file("etc/os-release", b"base"),
                Spec::file("etc/passwd", b"root"),
                Spec::dir("var/cache"),
                Spec::file("var/cache/a", b"cache a"),
                Spec::file("var/cache/b", b"cache b"),
                Spec::dir("opt/tool"),
                Spec::file("opt/tool/bin", b"tool"),
                Spec::file("data", b"a file that becomes a directory"),
                Spec::file("usr/lib/big", &vec![7u8; 300_000]),
                Spec::file("empty", b""),
            ],
            Compression::None,
        ),
        ib::layer(
            &[
                Spec::file("etc/.wh.passwd", b""),
                Spec::file("var/cache/.wh..wh..opq", b""),
                Spec::file("var/cache/c", b"cache c"),
                Spec::file("opt/tool", b"a directory that becomes a file"),
                Spec::file("data/inside", b"now a directory"),
                Spec::file("usr/lib/new", b"added"),
            ],
            Compression::Gzip,
        ),
        ib::layer(
            &[
                Spec::file("etc/os-release", b"final"),
                Spec::file("etc/passwd", b"recreated"),
                Spec::file(".wh.empty", b""),
                Spec::symlink("usr/lib/big", "new"),
                Spec::file("usr/lib/.wh.gone", b""),
            ],
            Compression::Zstd,
        ),
    ]
}

fn expected() -> BTreeMap<String, Node> {
    let f = |s: &[u8]| Node::File(s.to_vec());
    BTreeMap::from([
        ("etc".into(), Node::Dir),
        ("etc/os-release".into(), f(b"final")),
        ("etc/passwd".into(), f(b"recreated")),
        ("var".into(), Node::Dir),
        ("var/cache".into(), Node::Dir),
        ("var/cache/c".into(), f(b"cache c")),
        ("opt".into(), Node::Dir),
        ("opt/tool".into(), f(b"a directory that becomes a file")),
        ("data".into(), Node::Dir),
        ("data/inside".into(), f(b"now a directory")),
        ("usr".into(), Node::Dir),
        ("usr/lib".into(), Node::Dir),
        ("usr/lib/new".into(), f(b"added")),
    ])
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

fn extract(
    archive: &Path,
    dest: &Path,
    o: &ImageOptions,
) -> trunc_engine::Result<image::ImageSummary> {
    image::extract_image(&OsFs::new(), archive, dest, o, &mut |_| Ok(()))
}

/// Nothing but the destination itself (no staging leftovers, no temporary files).
fn assert_empty(dest: &Path) {
    let left: Vec<_> = std::fs::read_dir(dest)
        .map(|r| r.map(|e| e.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(left.is_empty(), "left behind: {left:?}");
}

#[test]
fn oci_layers_merge_into_one_root() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "img.tar",
        &ib::oci_archive(&[("linux/amd64", layers())]),
    );
    let fs = OsFs::new();
    assert!(image::detect(&fs, &arc));
    let info = image::inspect_image(&fs, &arc, t.path(), &opts()).unwrap();
    assert_eq!(info.format, ImageFormat::Oci);
    assert_eq!(info.platform, "linux/amd64");
    let codecs: Vec<_> = info.layers.iter().map(|l| l.codec).collect();
    assert_eq!(codecs, [None, Some(Codec::Gzip), Some(Codec::Zstd)]);

    let scan = image::verify_image(&fs, &arc, t.path(), &opts()).unwrap();
    assert_eq!(scan.stats.whiteouts, 3);
    assert_eq!(scan.stats.opaques, 1);

    let dest = t.path().join("root");
    let s = extract(&arc, &dest, &opts()).unwrap();
    assert_eq!(snapshot(&dest), expected());
    assert_eq!(s.symlinks_skipped, 1);
    assert_eq!(s.files, 6);
    // The 300 KB file is replaced by a symlink in the last layer: never written.
    assert!(s.bytes_written < 1000, "{}", s.bytes_written);
}

#[test]
fn docker_save_gives_the_same_root() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "img.tar",
        &ib::docker_archive(&[(&["example/app:1.0"], "linux/amd64", layers())]),
    );
    let fs = OsFs::new();
    assert!(image::detect(&fs, &arc));
    let info = image::inspect_image(&fs, &arc, t.path(), &opts()).unwrap();
    assert_eq!(info.format, ImageFormat::Docker);
    assert_eq!(info.names, ["example/app:1.0"]);
    let dest = t.path().join("root");
    extract(&arc, &dest, &opts()).unwrap();
    assert_eq!(snapshot(&dest), expected());
}

#[test]
fn compressed_outer_tar() {
    let t = tempfile::tempdir().unwrap();
    let raw = ib::oci_archive(&[("linux/amd64", layers())]);
    for (name, data) in [
        ("img.tar.gz", tarbuild::gzip(&raw, 6)),
        ("img.tar.zst", tarbuild::zstd(&raw, 3)),
    ] {
        let arc = write(t.path(), name, &data);
        let fs = OsFs::new();
        assert!(image::detect(&fs, &arc), "{name}");
        let dest = t.path().join(format!("root-{name}"));
        extract(&arc, &dest, &opts()).unwrap();
        assert_eq!(snapshot(&dest), expected(), "{name}");
        let tmp = tempfile::tempdir().unwrap();
        let info = image::inspect_image(&fs, &arc, tmp.path(), &opts()).unwrap();
        assert!(info.outer_codec.is_some());
        assert_empty(tmp.path());
    }
}

#[test]
fn plain_tarballs_are_not_images() {
    let t = tempfile::tempdir().unwrap();
    let plain = tarbuild::tar(&[Spec::file("a.txt", b"x"), Spec::file("config.json", b"{}")]);
    let fs = OsFs::new();
    assert!(!image::detect(&fs, &write(t.path(), "a.tar", &plain)));
    assert!(!image::detect(
        &fs,
        &write(t.path(), "a.tar.gz", &tarbuild::gzip(&plain, 6))
    ));
    assert!(!image::detect(
        &fs,
        &write(t.path(), "x.bin", b"not a tar at all")
    ));
}

fn one_file_layer(content: &[u8]) -> Vec<Layer> {
    vec![ib::layer(
        &[Spec::file("which", content)],
        Compression::Gzip,
    )]
}

#[test]
fn platform_selection() {
    let t = tempfile::tempdir().unwrap();
    let (_, arch) = image::host_platform();
    let other = if arch == "arm64" { "amd64" } else { "arm64" };
    let arc = write(
        t.path(),
        "multi.tar",
        &ib::oci_archive(&[
            (&format!("linux/{other}"), one_file_layer(b"other")),
            (&format!("linux/{arch}"), one_file_layer(b"host")),
            ("linux/s390x", one_file_layer(b"s390x")),
        ]),
    );
    let fs = OsFs::new();
    let info = image::inspect_image(&fs, &arc, t.path(), &opts()).unwrap();
    assert_eq!(info.platform, format!("linux/{arch}"));
    assert_eq!(info.others.len(), 2);

    let dest = t.path().join("s390x");
    let o = ImageOptions {
        platform: Some("linux/s390x".into()),
        ..opts()
    };
    extract(&arc, &dest, &o).unwrap();
    assert_eq!(std::fs::read(dest.join("which")).unwrap(), b"s390x");

    let o = ImageOptions {
        platform: Some("windows/amd64".into()),
        ..opts()
    };
    let e = image::inspect_image(&fs, &arc, t.path(), &o).unwrap_err();
    assert!(e.to_string().contains("no image for platform"), "{e}");

    // Several platforms, none of them this computer's: the choice is the user's.
    let arc = write(
        t.path(),
        "foreign.tar",
        &ib::oci_archive(&[
            ("linux/s390x", one_file_layer(b"a")),
            ("linux/riscv64", one_file_layer(b"b")),
        ]),
    );
    let e = image::inspect_image(&fs, &arc, t.path(), &opts()).unwrap_err();
    assert!(e.to_string().contains("--platform"), "{e}");
}

#[test]
fn nested_index_and_missing_platform_blobs() {
    let t = tempfile::tempdir().unwrap();
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let m = o.image("linux/arm64/v8", &one_file_layer(b"arm"));
    // A second platform listed in the index whose blobs were not saved.
    let absent = ib::manifest(b"{}", &one_file_layer(b"absent"));
    let inner = ib::index(&[
        descriptor(MANIFEST, &m, &platform("linux/arm64/v8")),
        descriptor(MANIFEST, &absent, &platform("linux/ppc64le")),
    ]);
    o.blob(&inner);
    o.add(
        "index.json",
        &ib::index(&[descriptor(
            INDEX,
            &inner,
            r#","annotations":{"io.containerd.image.name":"docker.io/library/x:latest"}"#,
        )]),
    );
    let arc = write(t.path(), "nested.tar", &o.tar());
    let info = image::inspect_image(&OsFs::new(), &arc, t.path(), &opts()).unwrap();
    assert_eq!(info.platform, "linux/arm64/v8");
    assert_eq!(info.names, ["docker.io/library/x:latest"]);
    let dest = t.path().join("root");
    let o = ImageOptions {
        image: Some("docker.io/library/x:latest".into()),
        platform: Some("linux/arm64".into()),
        ..opts()
    };
    extract(&arc, &dest, &o).unwrap();
    assert_eq!(std::fs::read(dest.join("which")).unwrap(), b"arm");
}

#[test]
fn several_docker_images_need_a_choice() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "two.tar",
        &ib::docker_archive(&[
            (&["a:1"], "linux/amd64", one_file_layer(b"a")),
            (&["b:1", "b:latest"], "linux/amd64", one_file_layer(b"b")),
        ]),
    );
    let fs = OsFs::new();
    let e = image::inspect_image(&fs, &arc, t.path(), &opts()).unwrap_err();
    assert!(e.to_string().contains("--image"), "{e}");
    let o = ImageOptions {
        image: Some("b:latest".into()),
        ..opts()
    };
    let dest = t.path().join("root");
    extract(&arc, &dest, &o).unwrap();
    assert_eq!(std::fs::read(dest.join("which")).unwrap(), b"b");
}

/// Extraction fails with `want` in the message and leaves `dest` empty; verify fails too.
fn refused(data: &[u8], want: &str) -> Error {
    let t = tempfile::tempdir().unwrap();
    let arc = write(t.path(), "bad.tar", data);
    let dest = t.path().join("root");
    let e = extract(&arc, &dest, &opts()).unwrap_err();
    assert!(e.to_string().contains(want), "wanted {want:?} in: {e}");
    assert_empty(&dest);
    assert!(image::verify_image(&OsFs::new(), &arc, t.path(), &opts()).is_err());
    e
}

#[test]
fn layer_digest_mismatch_is_refused() {
    let mut ls = one_file_layer(b"original");
    // Same size, different bytes: the blob no longer matches its digest.
    let mut tampered = ib::layer(&[Spec::file("which", b"tampered")], Compression::Gzip);
    tampered.digest.clone_from(&ls[0].digest);
    tampered.diff_id.clone_from(&ls[0].diff_id);
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let m = o.image("linux/amd64", &ls);
    let path = format!("blobs/sha256/{}", &ls[0].digest[7..]);
    let slot = o.files.iter_mut().find(|(n, _)| *n == path).unwrap();
    slot.1 = tampered.blob.clone();
    o.add(
        "index.json",
        &ib::index(&[descriptor(MANIFEST, &m, &platform("linux/amd64"))]),
    );
    let e = refused(&o.tar(), "sha256");
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");

    // Uncompressed layer whose diff_id in the config is wrong (docker save has no blob digest).
    ls = vec![ib::layer(&[Spec::file("x", b"x")], Compression::None)];
    ls[0].diff_id = ib::digest(b"something else");
    let e = refused(
        &ib::docker_archive(&[(&["t:1"], "linux/amd64", ls)]),
        "uncompressed",
    );
    assert!(matches!(e, Error::Integrity(_)), "{e:?}");
}

#[test]
fn hostile_names_in_layers_are_refused() {
    for name in ["../escape", "/abs/path", "a/../../b"] {
        let ls = vec![ib::layer(&[Spec::file(name, b"x")], Compression::Gzip)];
        refused(
            &ib::oci_archive(&[("linux/amd64", ls)]),
            "unsafe or invalid entry name",
        );
    }
}

#[test]
fn whiteouts_cannot_escape() {
    for name in ["etc/.wh...", "etc/.wh..", ".wh.", "etc/.wh.x/inside"] {
        let ls = vec![
            ib::layer(&[Spec::file("etc/a", b"x")], Compression::None),
            ib::layer(&[Spec::file(name, b"")], Compression::None),
        ];
        refused(&ib::oci_archive(&[("linux/amd64", ls)]), "");
    }
}

#[test]
fn missing_blobs_and_paths_outside_blobs_are_refused() {
    // The manifest names a layer whose blob is not in the archive.
    let ls = one_file_layer(b"x");
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let m = o.image("linux/amd64", &ls);
    o.files.retain(|(n, _)| !n.ends_with(&ls[0].digest[7..]));
    o.add(
        "index.json",
        &ib::index(&[descriptor(MANIFEST, &m, &platform("linux/amd64"))]),
    );
    refused(&o.tar(), "not in the archive");

    // A layer digest that would be a path outside blobs/.
    let mut bad = one_file_layer(b"x");
    bad[0].digest = "sha256:../../../etc/passwd".into();
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let m = o.image("linux/amd64", &bad);
    o.add(
        "index.json",
        &ib::index(&[descriptor(MANIFEST, &m, &platform("linux/amd64"))]),
    );
    refused(&o.tar(), "invalid digest");

    // docker save manifest naming a layer outside the archive.
    let l = &one_file_layer(b"x")[0];
    let mut o = Outer::default();
    let cfg = ib::config("linux/amd64", &[&l.diff_id]);
    o.add("cfg.json", &cfg);
    o.add("x/layer.tar", &l.blob);
    o.add(
        "manifest.json",
        br#"[{"Config":"cfg.json","RepoTags":["t:1"],"Layers":["../x/layer.tar"]}]"#,
    );
    refused(&o.tar(), "not in the archive");
}

#[test]
fn hard_links_are_refused_clearly() {
    let ls = vec![ib::layer(
        &[
            Spec::file("a", b"x"),
            Spec {
                typeflag: b'1',
                ..Spec::file("b", b"a")
            },
        ],
        Compression::None,
    )];
    refused(&ib::oci_archive(&[("linux/amd64", ls)]), "hard link");
}

#[test]
fn existing_top_level_names_are_refused() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "img.tar",
        &ib::oci_archive(&[("linux/amd64", layers())]),
    );
    let dest = t.path().join("root");
    std::fs::create_dir_all(dest.join("etc")).unwrap();
    let e = extract(&arc, &dest, &opts()).unwrap_err();
    assert!(e.to_string().contains("already exists"), "{e}");
    let left: Vec<_> = std::fs::read_dir(&dest)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["etc"]);
}

#[test]
fn media_type_must_match_the_blob() {
    let mut ls = one_file_layer(b"x");
    ls[0].media_type = "application/vnd.oci.image.layer.v1.tar+zstd".into();
    refused(&ib::oci_archive(&[("linux/amd64", ls)]), "media type");
    let mut ls = one_file_layer(b"x");
    ls[0].media_type = "application/vnd.oci.image.layer.v1.tar+gzip+encrypted".into();
    refused(&ib::oci_archive(&[("linux/amd64", ls)]), "not supported");
}

/// Layers with names Windows forbids and case-only twins, as real Debian images have.
fn unfriendly_layers() -> Vec<Layer> {
    vec![
        ib::layer(
            &[
                Spec::file("etc/hostname", b"h"),
                Spec::file("usr/share/man/man3/IO::File.3pm", b"perl"),
                Spec::file("usr/share/terminfo/E/foo", b"E foo"),
                Spec::file("usr/share/terminfo/e/bar", b"e bar"),
                Spec::file("usr/include/aux.h", b"aux"),
                Spec::file("usr/share/doc/pkg./README", b"trailing dot"),
                Spec::file("lib/system-systemd\\x2dcryptsetup.slice", b"unit"),
                Spec::file("usr/lib/old:file", b"deleted by the next layer"),
            ],
            Compression::Gzip,
        ),
        ib::layer(
            &[
                Spec::file("usr/lib/.wh.old:file", b""),
                Spec::file("etc/motd", b"m"),
            ],
            Compression::Zstd,
        ),
    ]
}

#[test]
fn names_this_computer_cannot_create_are_skipped_and_reported() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "img.tar",
        &ib::oci_archive(&[("linux/amd64", unfriendly_layers())]),
    );
    let dest = t.path().join("root");
    let s = extract(&arc, &dest, &opts()).unwrap();
    let scan = image::verify_image(&OsFs::new(), &arc, t.path(), &opts()).unwrap();
    assert_eq!(scan.skipped, s.skipped);

    let f = |b: &[u8]| Node::File(b.to_vec());
    let mut want = BTreeMap::from([
        ("etc".to_owned(), Node::Dir),
        ("etc/hostname".into(), f(b"h")),
        ("etc/motd".into(), f(b"m")),
        ("lib".into(), Node::Dir),
        ("usr".into(), Node::Dir),
        ("usr/include".into(), Node::Dir),
        ("usr/lib".into(), Node::Dir),
        ("usr/share".into(), Node::Dir),
        ("usr/share/doc".into(), Node::Dir),
        ("usr/share/man".into(), Node::Dir),
        ("usr/share/man/man3".into(), Node::Dir),
        ("usr/share/terminfo".into(), Node::Dir),
    ]);
    let skipped: Vec<(&str, bool, usize)> = s
        .skipped
        .iter()
        .map(|k| (k.path.as_str(), k.dir, k.entries))
        .collect();
    // The twins: the directory node both share is counted with the name it was first given.
    let twins = [
        ("usr/share/terminfo/E", true, 2),
        ("usr/share/terminfo/e", true, 1),
    ];
    if cfg!(windows) {
        assert_eq!(
            skipped,
            [
                ("lib/system-systemd\\x2dcryptsetup.slice", false, 1),
                ("usr/include/aux.h", false, 1),
                ("usr/share/doc/pkg.", true, 2),
                ("usr/share/man/man3/IO::File.3pm", false, 1),
                twins[0],
                twins[1],
            ]
        );
        let reasons: Vec<&str> = s.skipped.iter().map(|k| k.reason.as_str()).collect();
        assert_eq!(
            reasons,
            [
                "character not allowed on Windows",
                "reserved Windows device name",
                "trailing '.' or space (stripped by Windows)",
                "character not allowed on Windows",
                "differs only in case from \"usr/share/terminfo/e\"",
                "differs only in case from \"usr/share/terminfo/E\"",
            ]
        );
        assert_eq!(s.stats.skipped, 8);
    } else {
        want.extend([
            (
                "lib/system-systemd\\x2dcryptsetup.slice".to_owned(),
                f(b"unit"),
            ),
            ("usr/include/aux.h".into(), f(b"aux")),
            ("usr/share/doc/pkg.".into(), Node::Dir),
            ("usr/share/doc/pkg./README".into(), f(b"trailing dot")),
            ("usr/share/man/man3/IO::File.3pm".into(), f(b"perl")),
        ]);
        if cfg!(target_os = "macos") {
            assert_eq!(skipped, twins);
        } else {
            assert_eq!(skipped, []);
            want.extend([
                ("usr/share/terminfo/E".to_owned(), Node::Dir),
                ("usr/share/terminfo/E/foo".into(), f(b"E foo")),
                ("usr/share/terminfo/e".into(), Node::Dir),
                ("usr/share/terminfo/e/bar".into(), f(b"e bar")),
            ]);
        }
    }
    assert_eq!(snapshot(&dest), want);
    // The whiteout of a skipped name applied: the deleted file is neither written nor reported.
    assert!(!s.skipped.iter().any(|k| k.path.contains("old")));
}

#[test]
fn hostile_names_are_refused_even_beside_skipped_ones() {
    for hostile in ["../escape", "/abs/path", "a/../../b", "C:/x"] {
        let mut ls = unfriendly_layers();
        ls.push(ib::layer(&[Spec::file(hostile, b"x")], Compression::None));
        refused(
            &ib::oci_archive(&[("linux/amd64", ls)]),
            "unsafe or invalid entry name",
        );
    }
    for whiteout in ["usr/.wh..", "usr/.wh.a\\b", "usr/.wh.x/inside"] {
        let mut ls = unfriendly_layers();
        ls.push(ib::layer(&[Spec::file(whiteout, b"")], Compression::None));
        refused(&ib::oci_archive(&[("linux/amd64", ls)]), "whiteout");
    }
}

#[test]
fn web_bundles_with_root_metadata_are_not_images() {
    let t = tempfile::tempdir().unwrap();
    let fs = OsFs::new();
    let bundle = tarbuild::tar(&[
        Spec::file("index.json", br#"{"name":"site","pages":["a.html"]}"#),
        Spec::file("manifest.json", br#"{"name":"app","icons":[]}"#),
        Spec::file("repositories", b"x"),
        Spec::file("a.html", b"<p>"),
    ]);
    assert!(!image::detect(&fs, &write(t.path(), "b.tar", &bundle)));
    assert!(!image::detect(
        &fs,
        &write(t.path(), "b.tar.gz", &tarbuild::gzip(&bundle, 6))
    ));
    // Image-like blob names but no image structure: detected, then found not to be one, and
    // the temporary copy is removed.
    let fake = tarbuild::tar(&[Spec::file(
        &format!("blobs/sha256/{}", "a".repeat(64)),
        b"x",
    )]);
    let arc = write(t.path(), "fake.tar.gz", &tarbuild::gzip(&fake, 6));
    assert!(image::detect(&fs, &arc));
    let tmp = tempfile::tempdir().unwrap();
    let e = image::inspect_image(&fs, &arc, tmp.path(), &opts()).unwrap_err();
    assert!(image::is_not_an_image(&e), "{e}");
    assert_empty(tmp.path());
}

#[test]
fn repeated_descriptors_are_one_candidate_and_capped() {
    let t = tempfile::tempdir().unwrap();
    let mut o = Outer::default();
    o.add("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
    let m = o.image("linux/amd64", &one_file_layer(b"x"));
    let d = descriptor(MANIFEST, &m, &platform("linux/amd64"));
    let mut o2 = o.clone();
    o.add("index.json", &ib::index(&[d.clone(), d.clone()]));
    let arc = write(t.path(), "dup.tar", &o.tar());
    image::inspect_image(&OsFs::new(), &arc, t.path(), &opts()).unwrap();
    o2.add("index.json", &ib::index(&vec![d; 5000]));
    let arc = write(t.path(), "many.tar", &o2.tar());
    let e = image::inspect_image(&OsFs::new(), &arc, t.path(), &opts()).unwrap_err();
    assert!(e.to_string().contains("4096"), "{e}");
}

#[test]
fn docker_platforms_come_from_configs() {
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "two.tar",
        &ib::docker_archive(&[
            (&["a:1"], "linux/riscv64", one_file_layer(b"riscv")),
            (&["a:1"], "linux/s390x", one_file_layer(b"s390x")),
        ]),
    );
    let o = ImageOptions {
        platform: Some("linux/s390x".into()),
        ..opts()
    };
    let dest = t.path().join("root");
    extract(&arc, &dest, &o).unwrap();
    assert_eq!(std::fs::read(dest.join("which")).unwrap(), b"s390x");
}

#[test]
fn aufs_and_merged_usr_layers() {
    let aufs = vec![ib::layer(
        &[
            Spec::dir(".wh..wh.plnk"),
            Spec::file(".wh..wh.plnk/1.2", b"x"),
            Spec::dir(".wh..wh.orph"),
            Spec::file(".wh..wh.aufs", b""),
            Spec::file("etc/hostname", b"h"),
        ],
        Compression::Gzip,
    )];
    let t = tempfile::tempdir().unwrap();
    let arc = write(
        t.path(),
        "aufs.tar",
        &ib::oci_archive(&[("linux/amd64", aufs)]),
    );
    let dest = t.path().join("root");
    extract(&arc, &dest, &opts()).unwrap();
    assert_eq!(std::fs::read(dest.join("etc/hostname")).unwrap(), b"h");
    assert!(!dest.join(".wh..wh.plnk").exists());

    let usr = vec![
        ib::layer(
            &[
                Spec::file("usr/lib/libc.so", b"c"),
                Spec::symlink("lib", "usr/lib"),
            ],
            Compression::None,
        ),
        ib::layer(&[Spec::file("lib/extra.so", b"e")], Compression::Gzip),
    ];
    refused(&ib::oci_archive(&[("linux/amd64", usr)]), "symlink");
}

#[test]
fn stale_temp_copies_are_removed_unless_in_use() {
    let t = tempfile::tempdir().unwrap();
    let stale = t.path().join(".trunc-image-0123456789abcdef.tar");
    std::fs::write(&stale, b"left").unwrap();
    let fs = OsFs::new();
    let found = image::stale_temp_files(&fs, t.path());
    assert_eq!(found.len(), 1);
    if cfg!(any(windows, target_os = "linux")) {
        assert!(found[0].1);
        assert!(!stale.exists());
        let busy = t.path().join(".trunc-image-fedcba9876543210.tar");
        let h = trunc_fs::FsBackend::open(
            &fs,
            &busy,
            trunc_fs::OpenMode::CreateNew,
            trunc_fs::Share::Exclusive,
        )
        .unwrap();
        let found = image::stale_temp_files(&fs, t.path());
        assert_eq!(found, vec![(busy.clone(), false)]);
        drop(h);
    }
}

/// Paths that differ only in case, in one layer or across layers, are left out and reported
/// when the destination folds case (a `casefold` or NTFS folder on Linux, found by probing),
/// and extracted where it does not (on Linux; Windows and macOS always compare
/// case-insensitively). A whiteout that names a path only up to case is refused there.
#[test]
fn case_insensitive_destinations_are_found_up_front() {
    let one = vec![ib::layer(
        &[
            Spec::file("etc/A.txt", b"upper"),
            Spec::file("etc/a.txt", b"lower"),
            Spec::file("etc/keep", b"k"),
        ],
        Compression::None,
    )];
    let two = vec![
        ib::layer(
            &[
                Spec::file("etc/A.txt", b"upper"),
                Spec::file("etc/keep", b"k"),
            ],
            Compression::None,
        ),
        ib::layer(&[Spec::file("etc/a.txt", b"lower")], Compression::Gzip),
    ];
    for ls in [one, two] {
        let bytes = ib::oci_archive(&[("linux/amd64", ls)]);
        for folds in [true, false] {
            let skips = folds || cfg!(any(windows, target_os = "macos"));
            let fs = FaultFs::new(CrashModel::WriteThrough);
            fs.set_case_insensitive(folds);
            fs.put_file(Path::new("/img.tar"), &bytes);
            let s = image::extract_image(
                &fs,
                Path::new("/img.tar"),
                Path::new("/root"),
                &opts(),
                &mut |_| Ok(()),
            )
            .unwrap();
            let skipped: Vec<&str> = s.skipped.iter().map(|k| k.path.as_str()).collect();
            let mut want = vec!["img.tar", "root", "root/etc", "root/etc/keep"];
            if skips {
                assert_eq!(skipped, ["etc/A.txt", "etc/a.txt"], "folds={folds}");
            } else {
                assert!(skipped.is_empty(), "folds={folds}: {skipped:?}");
                want.extend(["root/etc/A.txt", "root/etc/a.txt"]);
                want.sort_unstable();
            }
            assert_eq!(fs.snapshot().keys().collect::<Vec<_>>(), want);
        }
    }

    // `.wh.foo` does not delete `Foo` where names fold case: refused before anything is written.
    let wh = vec![
        ib::layer(&[Spec::file("etc/Foo", b"f")], Compression::None),
        ib::layer(&[Spec::file("etc/.wh.foo", b"")], Compression::None),
    ];
    let bytes = ib::oci_archive(&[("linux/amd64", wh)]);
    for folds in [true, false] {
        let refuses = folds || cfg!(any(windows, target_os = "macos"));
        let fs = FaultFs::new(CrashModel::WriteThrough);
        fs.set_case_insensitive(folds);
        fs.put_file(Path::new("/img.tar"), &bytes);
        let r = image::extract_image(
            &fs,
            Path::new("/img.tar"),
            Path::new("/root"),
            &opts(),
            &mut |_| Ok(()),
        );
        assert_eq!(r.is_err(), refuses, "folds={folds}: {r:?}");
        if refuses {
            assert!(format!("{:?}", r.unwrap_err()).contains("differ only in case"));
            assert_eq!(
                fs.snapshot().keys().collect::<Vec<_>>(),
                ["img.tar", "root"]
            );
        }
    }
}

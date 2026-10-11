//! 7z archives through the command line.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use trunc_testkit::sevenzbuild::{Codec7, Item7, Opts7, build};
use trunc_testkit::{Rng, fixtures};

fn trunc(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_trunc"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn ok(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "command failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

fn fails(out: &Output) -> String {
    assert!(!out.status.success(), "command succeeded unexpectedly");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn items(seed: u64) -> Vec<Item7> {
    let mut rng = Rng::new(seed);
    vec![
        Item7::file("docs/readme.md", &fixtures::text_bytes(&mut rng, 20_000)),
        Item7::file("docs/notes/n.txt", &fixtures::text_bytes(&mut rng, 3000)),
        Item7::file("bin/blob", &fixtures::noise_bytes(&mut rng, 50_000)),
        Item7::file("empty", b""),
        Item7::dir("hollow"),
    ]
}

fn assert_files(root: &Path, items: &[Item7]) {
    for i in items {
        let p = root.join(&i.name);
        match &i.data {
            Some(d) => assert_eq!(&std::fs::read(&p).unwrap(), d, "{}", i.name),
            None => assert!(p.is_dir(), "{}", i.name),
        }
    }
}

#[test]
fn sevenz_inspect_verify_plan_extract() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let items = items(1);
    let bytes = build(
        &items,
        &Opts7 {
            codec: Codec7::Lzma2,
            ..Opts7::default()
        },
    );
    std::fs::write(w.join("a.7z"), &bytes).unwrap();

    let s = ok(&trunc(&["inspect", "a.7z", "--entries"], w));
    assert!(s.contains("(7z)"), "{s}");
    assert!(s.contains("4 files, 1 directories"), "{s}");
    assert!(s.contains("LZMA2"), "{s}");
    assert!(s.contains("header     compressed"), "{s}");
    assert!(s.contains("docs/notes/n.txt"), "{s}");

    let s = ok(&trunc(&["verify", "a.7z"], w));
    assert!(s.starts_with("ok: 5 entries"), "{s}");

    let s = ok(&trunc(&["plan", "a.7z", "-C", "out"], w));
    assert!(s.contains("not supported for 7z"), "{s}");

    let s = ok(&trunc(&["x", "a.7z", "-C", "out"], w));
    assert!(s.contains("extracted 4 files"), "{s}");
    assert_files(&w.join("out"), &items);

    // Again: refused without --overwrite, fine with it.
    let e = fails(&trunc(&["x", "a.7z", "-C", "out"], w));
    assert!(e.contains("already exists"), "{e}");
    ok(&trunc(&["x", "a.7z", "-C", "out", "--overwrite"], w));
    assert_files(&w.join("out"), &items);

    // --consume is refused with a clear message, leaving the archive alone.
    let e = fails(&trunc(
        &["x", "a.7z", "-C", "out2", "--consume", "--yes"],
        w,
    ));
    assert!(e.contains("not supported for 7z"), "{e}");
    assert_eq!(std::fs::read(w.join("a.7z")).unwrap(), bytes);
    assert!(!w.join("out2").exists());
}

#[test]
fn damaged_and_split_sevenz() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let items = items(2);
    let bytes = build(
        &items,
        &Opts7 {
            codec: Codec7::Copy,
            solid: false,
            encode_header: false,
            ..Opts7::default()
        },
    );
    // Split into two parts: read as one file.
    let (a, b) = bytes.split_at(bytes.len() / 2);
    std::fs::write(w.join("s.7z.001"), a).unwrap();
    std::fs::write(w.join("s.7z.002"), b).unwrap();
    ok(&trunc(&["verify", "s.7z.001"], w));
    ok(&trunc(&["x", "s.7z.001", "-C", "split"], w));
    assert_files(&w.join("split"), &items);

    // A damaged byte in a file's data fails verification and extraction, writing nothing.
    let mut bad = bytes.clone();
    bad[32 + 500] ^= 0x20;
    std::fs::write(w.join("bad.7z"), &bad).unwrap();
    let e = fails(&trunc(&["verify", "bad.7z"], w));
    assert!(e.contains("CRC mismatch"), "{e}");
    let e = fails(&trunc(&["x", "bad.7z", "-C", "bad"], w));
    assert!(e.contains("integrity check failed"), "{e}");
    assert_eq!(std::fs::read_dir(w.join("bad")).unwrap().count(), 0);

    // A dictionary over --max-window is refused before decoding.
    let big = build(
        &items,
        &Opts7 {
            dict: 64 << 20,
            ..Opts7::default()
        },
    );
    std::fs::write(w.join("big.7z"), &big).unwrap();
    let e = fails(&trunc(&["verify", "big.7z", "--max-window", "16M"], w));
    assert!(e.contains("--max-window"), "{e}");
}

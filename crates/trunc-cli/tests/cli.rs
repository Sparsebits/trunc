#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

use trunc_testkit::{fixtures, tree};

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

#[test]
fn create_inspect_verify_plan_extract() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    fixtures::mixed(&w.join("data"), 42);

    let s = ok(&trunc(
        &["create", "data.trnc", "data", "--block-size", "256K"],
        w,
    ));
    assert!(s.contains("created"), "{s}");

    let s = ok(&trunc(
        &["inspect", "data.trnc", "--entries", "--blocks"],
        w,
    ));
    assert!(s.contains("state      complete"), "{s}");
    assert!(s.contains("data/large/big.bin"), "{s}");

    let s = ok(&trunc(&["verify", "data.trnc"], w));
    assert!(s.starts_with("ok:"), "{s}");

    let s = ok(&trunc(&["plan", "data.trnc", "-C", "out"], w));
    assert!(s.contains("consume (--consume)"), "{s}");
    assert!(s.contains("archive       same volume"), "{s}");

    ok(&trunc(&["x", "data.trnc", "-C", "out"], w));
    tree::assert_same(&w.join("data"), &w.join("out/data"));

    // Second extraction into the same place refuses without --overwrite.
    let again = trunc(&["x", "data.trnc", "-C", "out"], w);
    assert!(!again.status.success());
    ok(&trunc(&["x", "data.trnc", "-C", "out", "--overwrite"], w));

    // Destructive mode refuses to run non-interactively without --yes, touching nothing.
    let consume = trunc(&["x", "data.trnc", "-C", "out2", "--consume"], w);
    assert!(!consume.status.success());
    assert!(String::from_utf8_lossy(&consume.stderr).contains("--yes"));
    assert!(w.join("data.trnc").exists() && !w.join("out2").exists());

    let s = ok(&trunc(
        &["x", "data.trnc", "-C", "out2", "--consume", "--yes"],
        w,
    ));
    assert!(s.contains("receipt kept"), "{s}");
    tree::assert_same(&w.join("data"), &w.join("out2/data"));
    assert!(!w.join("data.trnc").exists());
    assert!(w.join("data.trnc.receipt").exists());
    // The receipt is a valid, fully consumed archive.
    let s = ok(&trunc(&["inspect", "data.trnc.receipt"], w));
    assert!(s.contains("partially consumed"), "{s}");
}

#[test]
fn signing_flow() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    fixtures::small_files(&w.join("src"), 20, 3);

    let s = ok(&trunc(&["key", "gen", "k.key"], w));
    let pk = s
        .lines()
        .find_map(|l| l.strip_prefix("public key "))
        .unwrap()
        .to_owned();
    assert_eq!(ok(&trunc(&["key", "show", "k.key"], w)).trim(), pk);

    ok(&trunc(&["create", "s.trnc", "src", "--sign", "k.key"], w));
    ok(&trunc(&["create", "u.trnc", "src"], w));

    ok(&trunc(&["verify", "s.trnc", "--trust-key", &pk], w));
    assert!(
        !trunc(&["verify", "u.trnc", "--require-signed"], w)
            .status
            .success()
    );
    let other = "00".repeat(32);
    assert!(
        !trunc(&["verify", "s.trnc", "--trust-key", &other], w)
            .status
            .success()
    );
}

#[test]
fn bad_arguments_fail_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    std::fs::write(w.join("f"), b"x").unwrap();
    assert!(
        !trunc(&["create", "a.trnc", "f", "--codec", "gzip"], w)
            .status
            .success()
    );
    assert!(
        !trunc(&["create", "a.trnc", "f", "--block-size", "1K"], w)
            .status
            .success()
    );
    assert!(!trunc(&["inspect", "missing.trnc"], w).status.success());
    assert!(!trunc(&["inspect", "f"], w).status.success());
}

/// Kill the process at arbitrary points of a consume; `trunc resume` must always finish the job
/// with a byte-identical tree. (Process death, not power loss: the in-memory FaultFs sweep in
/// trunc-engine covers lost unflushed writes.)
#[test]
fn killed_consume_resumes() {
    for (round, delay_ms) in [5u64, 40, 120, 400].into_iter().enumerate() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        fixtures::mixed(&w.join("data"), 100 + round as u64);
        fixtures::large_file(&w.join("data/more"), 6 << 20, 7);
        ok(&trunc(
            &[
                "create",
                "a.trnc",
                "data",
                "--block-size",
                "64K",
                "--codec",
                "lz4",
            ],
            w,
        ));

        let mut child = Command::new(env!("CARGO_BIN_EXE_trunc"))
            .args([
                "x",
                "a.trnc",
                "-C",
                "out",
                "--consume",
                "--yes",
                "--batch",
                "64K",
            ])
            .current_dir(w)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = child.kill();
        let _ = child.wait();

        if w.join("a.trnc.trncr").exists() {
            ok(&trunc(&["resume", "a.trnc", "-C", "out", "--yes"], w));
        } else {
            // Killed before anything was recorded: `resume` refuses (nothing to resume), so
            // start again.
            let r = trunc(&["resume", "a.trnc", "-C", "out", "--yes"], w);
            assert!(!r.status.success(), "resume must not start a fresh consume");
            ok(&trunc(
                &["x", "a.trnc", "-C", "out", "--consume", "--yes"],
                w,
            ));
        }
        tree::assert_same(&w.join("data"), &w.join("out/data"));
        assert!(
            !w.join("a.trnc").exists(),
            "round {round}: archive left behind"
        );
        assert!(
            !w.join("a.trnc.trncr").exists(),
            "round {round}: resume note left behind"
        );
    }
}

fn write_zip(path: &Path, seed: u64) -> Vec<(String, Vec<u8>)> {
    use trunc_testkit::zipbuild::{Spec, ZipBuilder};
    let mut rng = trunc_testkit::Rng::new(seed);
    let files = vec![
        (
            "pkg/readme.txt".to_string(),
            fixtures::text_bytes(&mut rng, 20_000),
        ),
        (
            "pkg/data/big.txt".to_string(),
            fixtures::text_bytes(&mut rng, 3 << 20),
        ),
        (
            "pkg/data/noise.bin".to_string(),
            fixtures::noise_bytes(&mut rng, 500_000),
        ),
        ("top.txt".to_string(), b"top level".to_vec()),
    ];
    let mut b = ZipBuilder::new();
    for (n, d) in &files {
        b.add(Spec::file(n, d));
    }
    std::fs::write(path, b.build()).unwrap();
    files
}

fn assert_files(root: &Path, files: &[(String, Vec<u8>)]) {
    for (n, d) in files {
        assert_eq!(&std::fs::read(root.join(n)).unwrap(), d, "{n}");
    }
}

#[test]
fn zip_inspect_verify_plan_extract_consume() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let files = write_zip(&w.join("a.zip"), 1);

    let s = ok(&trunc(&["inspect", "a.zip", "--entries"], w));
    assert!(s.contains("(ZIP)") && s.contains("pkg/data/big.txt"), "{s}");
    assert!(ok(&trunc(&["verify", "a.zip"], w)).starts_with("ok:"));
    let s = ok(&trunc(&["plan", "a.zip", "-C", "out"], w));
    assert!(s.contains("consume (--consume)"), "{s}");

    ok(&trunc(&["x", "a.zip", "-C", "copy"], w));
    assert_files(&w.join("copy"), &files);
    assert!(w.join("a.zip").exists());

    let s = ok(&trunc(
        &["x", "a.zip", "-C", "out", "--consume", "--yes"],
        w,
    ));
    assert!(s.contains("consumed and removed"), "{s}");
    assert_files(&w.join("out"), &files);
    assert!(!w.join("a.zip").exists() && !w.join("a.zip.trncj").exists());
}

/// Kill a punch-mode ZIP consume at arbitrary points; `trunc resume` (finding the destination
/// in the journal) must finish with identical files.
#[test]
fn killed_zip_consume_resumes() {
    for (round, delay_ms) in [10u64, 60, 150, 400].into_iter().enumerate() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        let files = write_zip(&w.join("a.zip"), 10 + round as u64);
        let mut child = Command::new(env!("CARGO_BIN_EXE_trunc"))
            .args([
                "x",
                "a.zip",
                "-C",
                "out",
                "--consume",
                "--yes",
                "--punch-min",
                "1",
                "--checkpoint-every",
                "64K",
            ])
            .current_dir(w)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = child.kill();
        let _ = child.wait();
        let punch = ["--yes", "--punch-min", "1", "--checkpoint-every", "64K"];
        if w.join("a.zip.trncj").exists() {
            // Resume without -C: the destination comes from the journal.
            ok(&trunc(&[&["resume", "a.zip"][..], &punch].concat(), w));
        } else if w.join("a.zip").exists() {
            // Killed before anything was recorded or destroyed: just run the command again.
            ok(&trunc(
                &[&["x", "a.zip", "-C", "out", "--consume"][..], &punch].concat(),
                w,
            ));
        }
        assert_files(&w.join("out"), &files);
        assert!(
            !w.join("a.zip").exists(),
            "round {round}: archive left behind"
        );
        assert!(
            !w.join("a.zip.trncj").exists(),
            "round {round}: journal left behind"
        );
    }
}

fn write_iso(path: &Path, seed: u64) -> Vec<(String, Vec<u8>)> {
    use trunc_testkit::isobuild::{IsoBuilder, Spec};
    let mut rng = trunc_testkit::Rng::new(seed);
    let files = vec![
        (
            "disc/readme.txt".to_string(),
            fixtures::text_bytes(&mut rng, 20_000),
        ),
        (
            "disc/data/big.bin".to_string(),
            fixtures::noise_bytes(&mut rng, 3 << 20),
        ),
        ("Top Level.txt".to_string(), b"top level".to_vec()),
    ];
    let mut b = IsoBuilder::new().rock_ridge(true).joliet(true).pad(150);
    for (n, d) in &files {
        b.add(Spec::file(n, d));
    }
    b.add(Spec::symlink("disc/link", "readme.txt"));
    std::fs::write(path, b.build().bytes).unwrap();
    files
}

#[test]
fn iso_inspect_verify_plan_extract_consume() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let files = write_iso(&w.join("a.iso"), 1);

    let s = ok(&trunc(&["inspect", "a.iso", "--entries"], w));
    assert!(
        s.contains("(ISO 9660)") && s.contains("disc/data/big.bin"),
        "{s}"
    );
    assert!(s.contains("Rock Ridge"), "{s}");
    assert!(ok(&trunc(&["verify", "a.iso"], w)).starts_with("ok:"));
    let s = ok(&trunc(&["plan", "a.iso", "-C", "out"], w));
    assert!(s.contains("consume (--consume)"), "{s}");

    let s = ok(&trunc(&["x", "a.iso", "-C", "copy"], w));
    assert!(s.contains("symlinks  1 skipped"), "{s}");
    assert_files(&w.join("copy"), &files);
    assert!(w.join("a.iso").exists());

    let s = ok(&trunc(
        &["x", "a.iso", "-C", "out", "--consume", "--yes"],
        w,
    ));
    assert!(s.contains("consumed and removed"), "{s}");
    assert_files(&w.join("out"), &files);
    assert!(!w.join("a.iso").exists() && !w.join("a.iso.trncj").exists());

    // A UDF-only image gets a clear refusal.
    std::fs::write(
        w.join("u.iso"),
        trunc_testkit::isobuild::IsoBuilder::new()
            .udf_only()
            .build()
            .bytes,
    )
    .unwrap();
    let out = trunc(&["x", "u.iso", "-C", "u"], w);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("UDF-only"), "{err}");
}

/// Kill a punch-mode ISO consume at arbitrary points; `trunc resume` must finish it.
#[test]
fn killed_iso_consume_resumes() {
    for (round, delay_ms) in [10u64, 60, 150, 400].into_iter().enumerate() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        let files = write_iso(&w.join("a.iso"), 20 + round as u64);
        let flags = ["--yes", "--punch-min", "1", "--checkpoint-every", "64K"];
        let mut child = Command::new(env!("CARGO_BIN_EXE_trunc"))
            .args([&["x", "a.iso", "-C", "out", "--consume"][..], &flags].concat())
            .current_dir(w)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = child.kill();
        let _ = child.wait();
        if w.join("a.iso.trncj").exists() {
            ok(&trunc(&[&["resume", "a.iso"][..], &flags].concat(), w));
        } else if w.join("a.iso").exists() {
            ok(&trunc(
                &[&["x", "a.iso", "-C", "out", "--consume"][..], &flags].concat(),
                w,
            ));
        }
        assert_files(&w.join("out"), &files);
        assert!(
            !w.join("a.iso").exists(),
            "round {round}: image left behind"
        );
        assert!(
            !w.join("a.iso.trncj").exists(),
            "round {round}: journal left behind"
        );
    }
}

/// A tiny ZIP whose directory claims 1 TiB of output is refused before anything is written.
#[test]
fn zip_bomb_is_refused_by_the_space_check() {
    use trunc_testkit::zipbuild::{Spec, ZipBuilder};
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let mut b = ZipBuilder::new();
    b.add(Spec::file("bomb.bin", &vec![0u8; 100_000]).zip64());
    let mut bytes = b.build();
    // Patch the central directory's Zip64 uncompressed size (first field of the extra block).
    let cd = bytes
        .windows(4)
        .position(|x| x == [0x50, 0x4b, 0x01, 0x02])
        .unwrap();
    let extra = cd + 46 + "bomb.bin".len() + 4;
    bytes[extra..extra + 8].copy_from_slice(&(1u64 << 40).to_le_bytes());
    std::fs::write(w.join("bomb.zip"), &bytes).unwrap();
    let out = trunc(&["x", "bomb.zip", "-C", "out"], w);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not enough free space"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!w.join("out").exists(), "nothing written");
}

/// FAT32 and exFAT have no metadata journal and no sparse files. `TRUNC_TEST_UNJOURNALED_DIRS`
/// (`:`-separated, e.g. loop-mounted images in CI) names writable directories on such volumes.
/// Destructive mode must refuse there by default, leaving the archive whole, and work with
/// `--allow-unjournaled`, ZIP punch mode falling back to whole entries.
#[test]
fn unjournaled_volumes_need_consent() {
    let Ok(dirs) = std::env::var("TRUNC_TEST_UNJOURNALED_DIRS") else {
        eprintln!("TRUNC_TEST_UNJOURNALED_DIRS not set; skipping");
        return;
    };
    for dir in dirs.split(':').filter(|d| !d.is_empty()) {
        let d = tempfile::tempdir_in(dir).unwrap();
        let w = d.path();
        fixtures::mixed(&w.join("data"), 7);
        ok(&trunc(
            &["create", "data.trnc", "data", "--block-size", "256K"],
            w,
        ));
        let size = std::fs::metadata(w.join("data.trnc")).unwrap().len();

        let s = ok(&trunc(&["plan", "data.trnc", "-C", "out"], w));
        assert!(s.contains("NOT journaled"), "{dir}: {s}");
        let refused = trunc(&["x", "data.trnc", "-C", "out", "--consume", "--yes"], w);
        assert!(!refused.status.success(), "{dir}: consumed without consent");
        assert_eq!(std::fs::metadata(w.join("data.trnc")).unwrap().len(), size);

        let yes = ["--consume", "--yes", "--allow-unjournaled"];
        ok(&trunc(
            &[&["x", "data.trnc", "-C", "out"][..], &yes].concat(),
            w,
        ));
        tree::assert_same(&w.join("data"), &w.join("out/data"));
        assert!(!w.join("data.trnc").exists());

        let files = write_zip(&w.join("a.zip"), 3);
        let punch = ["--punch-min", "1", "--checkpoint-every", "64K"];
        ok(&trunc(
            &[&["x", "a.zip", "-C", "zout"][..], &yes, &punch].concat(),
            w,
        ));
        assert_files(&w.join("zout"), &files);
        assert!(!w.join("a.zip").exists() && !w.join("a.zip.trncj").exists());
    }
}

fn write_tgz(path: &Path, seed: u64) -> Vec<(String, Vec<u8>)> {
    write_tarball(path, seed, |t| trunc_testkit::tarbuild::gzip(t, 6))
}

/// A fixture encoder.
type Encode = fn(&[u8]) -> Vec<u8>;

/// The fixture tarball's files, written compressed with `enc`.
fn write_tarball(path: &Path, seed: u64, enc: fn(&[u8]) -> Vec<u8>) -> Vec<(String, Vec<u8>)> {
    use trunc_testkit::tarbuild::{self, Spec};
    let mut rng = trunc_testkit::Rng::new(seed);
    let files = vec![
        (
            "pkg/readme.txt".to_string(),
            fixtures::text_bytes(&mut rng, 20_000),
        ),
        (
            "pkg/data/big.txt".to_string(),
            fixtures::text_bytes(&mut rng, 3 << 20),
        ),
        (
            "pkg/data/noise.bin".to_string(),
            fixtures::noise_bytes(&mut rng, 500_000),
        ),
        ("top.txt".to_string(), b"top level".to_vec()),
    ];
    let specs: Vec<Spec> = files.iter().map(|(n, d)| Spec::file(n, d)).collect();
    std::fs::write(path, enc(&tarbuild::tar(&specs))).unwrap();
    files
}

/// The compressed formats besides gzip: suffix, label `inspect` prints, encoder.
fn stream_formats() -> Vec<(&'static str, &'static str, Encode)> {
    use trunc_testkit::tarbuild;
    vec![
        ("bz2", "bzip2", |d| tarbuild::bzip2(d, 1)),
        ("xz", "xz", |d| tarbuild::xz(d, 6)),
        ("zst", "zstd", |d| tarbuild::zstd(d, 3)),
    ]
}

#[test]
fn every_compressed_format_through_the_cli() {
    for (ext, codec, enc) in stream_formats() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        let arc = format!("a.tar.{ext}");
        let files = write_tarball(&w.join(&arc), 3, enc);
        let s = ok(&trunc(&["inspect", &arc, "--entries"], w));
        assert!(s.contains(&format!("(tar.{ext})")), "{s}");
        let s = ok(&trunc(&["verify", &arc], w));
        assert!(s.starts_with("ok:") && s.contains(codec), "{s}");
        let s = ok(&trunc(&["plan", &arc, "-C", "out"], w));
        assert!(s.contains("consume (--consume)"), "{s}");
        ok(&trunc(&["x", &arc, "-C", "copy"], w));
        assert_files(&w.join("copy"), &files);
        let s = ok(&trunc(&["x", &arc, "-C", "out", "--consume", "--yes"], w));
        assert!(s.contains("consumed and removed"), "{s}");
        assert_files(&w.join("out"), &files);
        assert!(!w.join(&arc).exists() && !w.join(format!("{arc}.trncj")).exists());
        assert!(
            !w.join(format!("{arc}.trncg")).exists(),
            "gap log left behind"
        );

        // A single compressed file becomes one file named without the suffix.
        let data = files[1].1.clone();
        let single = format!("big.log.{ext}");
        std::fs::write(w.join(&single), enc(&data)).unwrap();
        let s = ok(&trunc(&["inspect", &single], w));
        assert!(
            s.contains(&format!("{codec} file")) && s.contains("big.log"),
            "{s}"
        );
        ok(&trunc(
            &["x", &single, "-C", "one", "--consume", "--yes"],
            w,
        ));
        assert_eq!(std::fs::read(w.join("one/big.log")).unwrap(), data);
        assert!(!w.join(&single).exists());

        // --raw keeps a tarball whole.
        let raw = format!("r.tar.{ext}");
        write_tarball(&w.join(&raw), 3, enc);
        let tar = {
            use trunc_testkit::tarbuild::{self, Spec};
            let specs: Vec<Spec> = files.iter().map(|(n, d)| Spec::file(n, d)).collect();
            tarbuild::tar(&specs)
        };
        ok(&trunc(&["x", &raw, "-C", "raw", "--raw"], w));
        assert_eq!(std::fs::read(w.join("raw/r.tar")).unwrap(), tar);
    }
}

#[test]
fn tgz_inspect_verify_plan_extract_consume() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let files = write_tgz(&w.join("a.tar.gz"), 1);

    let s = ok(&trunc(&["inspect", "a.tar.gz", "--entries"], w));
    assert!(
        s.contains("(tar.gz)") && s.contains("pkg/data/big.txt"),
        "{s}"
    );
    assert!(ok(&trunc(&["verify", "a.tar.gz"], w)).starts_with("ok:"));
    let s = ok(&trunc(&["plan", "a.tar.gz", "-C", "out"], w));
    assert!(s.contains("consume (--consume)"), "{s}");

    ok(&trunc(&["x", "a.tar.gz", "-C", "copy"], w));
    assert_files(&w.join("copy"), &files);
    assert!(w.join("a.tar.gz").exists());

    let s = ok(&trunc(
        &["x", "a.tar.gz", "-C", "out", "--consume", "--yes"],
        w,
    ));
    assert!(s.contains("consumed and removed"), "{s}");
    assert_files(&w.join("out"), &files);
    assert!(!w.join("a.tar.gz").exists() && !w.join("a.tar.gz.trncj").exists());
}

/// Kill a tar.gz consume at arbitrary points; `trunc resume` must finish with identical files.
#[test]
fn killed_tgz_consume_resumes() {
    killed_stream_consume_resumes("gz", |t| trunc_testkit::tarbuild::gzip(t, 6));
}

/// The same for the formats whose window is read back from the output on resume.
#[test]
fn killed_xz_and_zstd_consumes_resume() {
    killed_stream_consume_resumes("xz", |t| trunc_testkit::tarbuild::xz(t, 6));
    killed_stream_consume_resumes("zst", |t| trunc_testkit::tarbuild::zstd(t, 3));
}

fn killed_stream_consume_resumes(ext: &str, enc: Encode) {
    let arc = format!("a.tar.{ext}");
    let arc = arc.as_str();
    let journal = format!("{arc}.trncj");
    for (round, delay_ms) in [10u64, 60, 150, 400].into_iter().enumerate() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        let files = write_tarball(&w.join(arc), 20 + round as u64, enc);
        let flags = ["--yes", "--checkpoint-every", "64K"];
        let mut child = Command::new(env!("CARGO_BIN_EXE_trunc"))
            .args([&["x", arc, "-C", "out", "--consume"][..], &flags].concat())
            .current_dir(w)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        let _ = child.kill();
        let _ = child.wait();
        if w.join(&journal).exists() {
            ok(&trunc(&[&["resume", arc][..], &flags].concat(), w));
        } else if w.join(arc).exists() {
            ok(&trunc(
                &[&["x", arc, "-C", "out", "--consume"][..], &flags].concat(),
                w,
            ));
        }
        assert_files(&w.join("out"), &files);
        assert!(
            !w.join(arc).exists(),
            "{arc} round {round}: archive left behind"
        );
        assert!(
            !w.join(&journal).exists(),
            "{arc} round {round}: journal left behind"
        );
        assert!(
            !w.join(format!("{arc}.trncg")).exists(),
            "{arc} round {round}: gap log left behind"
        );
    }
}

/// ZIP and tar.gz cannot be signed: asking for a signature must fail, not be ignored (a file
/// named `.trnc` could really be a ZIP).
#[test]
fn signature_flags_are_refused_for_unsigned_formats() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    write_zip(&w.join("release.trnc"), 1);
    write_tgz(&w.join("other.trnc"), 2);
    for arc in ["release.trnc", "other.trnc"] {
        for args in [
            &["verify", arc, "--require-signed"][..],
            &["x", arc, "-C", "o1", "--require-signed"],
            &[
                "x",
                arc,
                "-C",
                "o2",
                "--consume",
                "--yes",
                "--trust-key",
                &"ab".repeat(32),
            ],
        ] {
            let out = trunc(args, w);
            assert!(!out.status.success(), "{args:?} succeeded");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("cannot be signed"),
                "{args:?}"
            );
        }
        assert!(w.join(arc).exists(), "{arc} was not touched");
    }
}

/// Split `path` into `{path}.001`, `{path}.002`, … (or `.aa`, `.ab`, … with `letters`) and
/// remove the original. Returns the first part's file name.
fn split_file(path: &Path, part: usize, letters: bool) -> String {
    let bytes = std::fs::read(path).unwrap();
    let name = path.file_name().unwrap().to_str().unwrap().to_string();
    let mut first = String::new();
    for (i, p) in trunc_testkit::tarbuild::split(&bytes, part)
        .iter()
        .enumerate()
    {
        let suffix = if letters {
            let i = u8::try_from(i).unwrap();
            format!("{}{}", char::from(b'a' + i / 26), char::from(b'a' + i % 26))
        } else {
            format!("{:03}", i + 1)
        };
        let n = format!("{name}.{suffix}");
        std::fs::write(path.with_file_name(&n), p).unwrap();
        if i == 0 {
            first = n;
        }
    }
    std::fs::remove_file(path).unwrap();
    first
}

#[test]
fn split_tarballs_through_the_cli() {
    for (letters, ext, enc) in [
        (
            false,
            "zst",
            (|t| trunc_testkit::tarbuild::zstd(t, 3)) as Encode,
        ),
        (true, "gz", |t| trunc_testkit::tarbuild::gzip(t, 6)),
    ] {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        let files = write_tarball(&w.join(format!("a.tar.{ext}")), 5, enc);
        let first = split_file(&w.join(format!("a.tar.{ext}")), 400_000, letters);
        let s = ok(&trunc(&["inspect", &first], w));
        assert!(s.contains(&format!("(tar.{ext})")), "{s}");
        ok(&trunc(&["verify", &first], w));
        ok(&trunc(&["x", &first, "-C", "copy"], w));
        assert_files(&w.join("copy"), &files);
        // Naming a later part points at the first.
        let second = if letters {
            "a.tar.gz.ab".to_string()
        } else {
            "a.tar.zst.002".into()
        };
        let out = trunc(&["x", &second, "-C", "never"], w);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("pass the first part"));

        let s = ok(&trunc(&["x", &first, "-C", "out", "--consume", "--yes"], w));
        assert!(s.contains("consumed and removed"), "{s}");
        assert_files(&w.join("out"), &files);
        let left: Vec<_> = std::fs::read_dir(w)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("a.tar."))
            .collect();
        assert!(left.is_empty(), "left behind: {left:?}");
    }
}

#[test]
fn split_zip_and_trnc_are_readable_but_not_consumed() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    let files = write_zip(&w.join("a.zip"), 6);
    let first = split_file(&w.join("a.zip"), 700_000, false);
    assert!(ok(&trunc(&["verify", &first], w)).starts_with("ok:"));
    ok(&trunc(&["x", &first, "-C", "zcopy"], w));
    assert_files(&w.join("zcopy"), &files);
    let out = trunc(&["x", &first, "-C", "zout", "--consume", "--yes"], w);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("split ZIP"));
    assert!(w.join(&first).exists());

    fixtures::mixed(&w.join("data"), 7);
    ok(&trunc(
        &["create", "d.trnc", "data", "--block-size", "64K"],
        w,
    ));
    let first = split_file(&w.join("d.trnc"), 150_000, false);
    assert!(ok(&trunc(&["verify", &first], w)).starts_with("ok:"));
    ok(&trunc(&["x", &first, "-C", "tcopy"], w));
    trunc_testkit::tree::assert_same(&w.join("data"), &w.join("tcopy").join("data"));
    let out = trunc(&["x", &first, "-C", "tout", "--consume", "--yes"], w);
    assert!(!out.status.success());
}

/// `--profile` prints where the time went and writes a Chrome trace; `TRUNC_PROFILE=-` prints
/// the summary only.
#[test]
fn profile_writes_a_trace_and_a_summary() {
    let d = tempfile::tempdir().unwrap();
    let w = d.path();
    write_tgz(&w.join("a.tar.gz"), 9);
    let out = trunc(&["--profile", "p.json", "verify", "a.tar.gz"], w);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains("profile:") && err.contains("decode.gzip"),
        "{err}"
    );
    assert!(
        err.contains("fs.read") && err.contains("trace written"),
        "{err}"
    );
    let json = std::fs::read_to_string(w.join("p.json")).unwrap();
    assert!(json.starts_with("{\"displayTimeUnit\"") && json.contains("\"traceEvents\""));
    assert!(json.contains("\"name\":\"cli.verify\"") && json.contains("\"ph\":\"X\""));
    let opens = json.matches('{').count();
    assert_eq!(opens, json.matches('}').count(), "balanced JSON objects");

    let out = Command::new(env!("CARGO_BIN_EXE_trunc"))
        .args(["verify", "a.tar.gz"])
        .env("TRUNC_PROFILE", "-")
        .current_dir(w)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && err.contains("profile:"), "{err}");
    assert!(!err.contains("trace written"), "{err}");

    // Without profiling, nothing extra is printed.
    let out = trunc(&["verify", "a.tar.gz"], w);
    assert!(!String::from_utf8_lossy(&out.stderr).contains("profile:"));
}

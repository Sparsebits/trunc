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

        ok(&trunc(&["resume", "a.trnc", "-C", "out", "--yes"], w));
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

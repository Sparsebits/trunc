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

    let s = ok(&trunc(&["plan", "data.trnc"], w));
    assert!(s.contains("consume (--consume)"), "{s}");

    ok(&trunc(&["x", "data.trnc", "-C", "out"], w));
    tree::assert_same(&w.join("data"), &w.join("out/data"));

    // Second extraction into the same place refuses without --overwrite.
    let again = trunc(&["x", "data.trnc", "-C", "out"], w);
    assert!(!again.status.success());
    ok(&trunc(&["x", "data.trnc", "-C", "out", "--overwrite"], w));

    // Destructive mode is not available yet and must say so rather than do anything.
    let consume = trunc(&["x", "data.trnc", "-C", "out2", "--consume"], w);
    assert!(!consume.status.success());
    assert!(String::from_utf8_lossy(&consume.stderr).contains("phase 3"));
    assert!(w.join("data.trnc").exists());
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

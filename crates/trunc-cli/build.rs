//! Stamp the git commit into `trunc --version`, e.g. `trunc 0.1.0 (172e338)`.
//!
//! Release builds get the commit from `TRUNC_BUILD_COMMIT` (set by the release workflow). Local
//! builds ask git, and builds without either (a source tarball) say `unknown`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TRUNC_BUILD_COMMIT");
    // Rebuild when HEAD moves: a checkout changes HEAD, a commit changes the ref it points to.
    // Only existing paths are watched; a missing one would rerun this script on every build.
    for p in [
        "../../.git/HEAD",
        "../../.git/refs/heads",
        "../../.git/packed-refs",
    ] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    let commit = std::env::var("TRUNC_BUILD_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(git_commit)
        .map_or_else(|| "unknown".to_owned(), |c| c.chars().take(7).collect());
    println!("cargo:rustc-env=TRUNC_COMMIT={commit}");
}

fn git_commit() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

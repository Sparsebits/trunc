//! Uncompressed tar support for `x`, `inspect`, `verify` and `plan`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use trunc_core::space::SpaceParams;
use trunc_engine::consume::ConsumeOptions;
use trunc_engine::preflight;
use trunc_engine::tarconsume;
use trunc_engine::zipconsume;
use trunc_fs::{FsBackend, OsFs};
use trunc_legacy::zip::Kind;

use crate::fmt::bytes;

pub fn extract(
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    ignore_space: bool,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    if !ignore_space {
        // Declared sizes are checked against free space before anything is written.
        let t = tarconsume::open_tar(&fs, archive)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = zipconsume::zip_space(
            &t.layout,
            t.layout.file_len,
            &ConsumeOptions::default(),
            false,
            1,
            &params,
        );
        if let Some(free) = vc.destination.free_bytes.filter(|f| *f < sp.extract_extra) {
            anyhow::bail!(
                "not enough free space at {}: extracting needs about {}, {} are free (--ignore-space to try anyway)",
                dest.display(),
                bytes(sp.extract_extra),
                bytes(free)
            );
        }
    }
    let t = Instant::now();
    let s = tarconsume::extract_tar(&fs, archive, dest, overwrite)?;
    println!(
        "extracted {} files, {} directories, {} into {}",
        s.files,
        s.dirs,
        bytes(s.bytes_written),
        dest.display()
    );
    if s.symlinks_skipped > 0 {
        println!("symlinks  {} skipped", s.symlinks_skipped);
    }
    if s.specials_skipped > 0 {
        println!(
            "devices   {} device or FIFO entries skipped",
            s.specials_skipped
        );
    }
    println!("time      {:.2}s", t.elapsed().as_secs_f64());
    Ok(ExitCode::SUCCESS)
}

pub fn verify(archive: &Path) -> Result<ExitCode> {
    let t = Instant::now();
    let tf = tarconsume::verify_tar(&OsFs::new(), archive)?;
    println!(
        "ok: {} entries, {} in bounds, headers and names valid in {:.2}s",
        tf.layout.entries.len(),
        bytes(tarconsume::content_bytes(&tf)),
        t.elapsed().as_secs_f64()
    );
    println!("note: tar has no content checksums; file contents cannot be verified");
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool) -> Result<ExitCode> {
    let fs = OsFs::new();
    if let Some(dest) = tarconsume::journal_dest(&fs, archive) {
        println!(
            "archive    {} (tar, being consumed into {})",
            archive.display(),
            dest.display()
        );
        println!(
            "state      partially consumed; run `trunc resume {}`",
            archive.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let tf = tarconsume::open_tar(&fs, archive)?;
    let l = &tf.layout;
    let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
    println!("archive    {} (tar, uncompressed)", archive.display());
    println!(
        "entries    {files} files, {} directories/links",
        l.entries.len() - files
    );
    println!("content    {}", bytes(tarconsume::content_bytes(&tf)));
    println!("file size  {}", bytes(l.file_len));
    if tf.specials_skipped > 0 {
        println!(
            "skipped    {} devices, FIFOs or sockets",
            tf.specials_skipped
        );
    }
    if list {
        println!();
        for e in &l.entries {
            let size = match e.kind {
                Kind::File => format!("{:>12}", e.size),
                Kind::Dir => format!("{:>12}", "<dir>"),
                Kind::Symlink => format!("{:>12}", "<link>"),
            };
            println!("{size}  {}", e.name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn plan(archive: &Path, dest: &Path) -> Result<ExitCode> {
    let tf = tarconsume::open_tar(&OsFs::new(), archive)?;
    crate::zip_cmd::plan_layout(archive, dest, true, &tf.layout, "tar", None)
}

pub fn is_tar(path: &Path) -> bool {
    tarconsume::is_tar(&OsFs::new() as &dyn FsBackend, path)
}

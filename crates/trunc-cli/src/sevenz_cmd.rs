//! 7z support for `x`, `inspect`, `verify` and `plan`. `--consume` is refused (ADR-0017).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use trunc_core::space::SpaceParams;
use trunc_engine::preflight::{self, Severity};
use trunc_engine::sevenz;
use trunc_fs::{FsBackend, OsFs};
use trunc_legacy::sevenz::Kind;

use crate::fmt::bytes;

/// Why `--consume` is refused, shown by `x --consume` and `plan`.
pub const NO_CONSUME: &str = "--consume is not supported for 7z archives yet (their packed \
     streams cannot be freed safely while decoding); extract without --consume, then delete the \
     archive";

pub fn extract(
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    ignore_space: bool,
    max_window: u64,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    if !ignore_space {
        // Declared sizes are checked against free space before anything is written.
        let layout = sevenz::open_layout(&fs, archive, max_window)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = sevenz::sevenz_space(&layout, &params);
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
    let s = sevenz::extract_7z(&fs, archive, dest, overwrite, max_window)?;
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
    println!("time      {:.2}s", t.elapsed().as_secs_f64());
    Ok(ExitCode::SUCCESS)
}

pub fn verify(archive: &Path, max_window: u64, threads: usize) -> Result<ExitCode> {
    let t = Instant::now();
    let (entries, total) = sevenz::verify_7z(&OsFs::new(), archive, max_window, threads)?;
    println!(
        "ok: {entries} entries, {} decoded and CRC-checked in {:.2}s",
        bytes(total),
        t.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool, max_window: u64) -> Result<ExitCode> {
    let l = sevenz::open_layout(&OsFs::new(), archive, max_window)?;
    let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
    let mut methods: BTreeMap<String, usize> = BTreeMap::new();
    for f in &l.folders {
        *methods.entry(f.methods()).or_default() += 1;
    }
    let methods: Vec<String> = methods.iter().map(|(m, n)| format!("{n} {m}")).collect();
    println!("archive    {} (7z)", archive.display());
    println!(
        "entries    {files} files, {} directories/links",
        l.entries.len() - files
    );
    println!("content    {}", bytes(l.content_bytes()));
    println!(
        "packed     {} in {} folder{}{}",
        bytes(l.packed_bytes()),
        l.folders.len(),
        if l.folders.len() == 1 { "" } else { "s" },
        if l.solid() { ", solid" } else { "" }
    );
    if !methods.is_empty() {
        println!("methods    {}", methods.join(", "));
    }
    println!(
        "header     {}",
        if l.encoded_header {
            "compressed"
        } else {
            "plain"
        }
    );
    if l.anti_items > 0 {
        println!("note       {} anti-items (deletions) skipped", l.anti_items);
    }
    println!("file size  {}", bytes(l.file_len));
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

pub fn plan(archive: &Path, dest: &Path, max_window: u64) -> Result<ExitCode> {
    let fs = OsFs::new();
    let layout = sevenz::open_layout(&fs, archive, max_window)?;
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.name.as_str(), e.size));
    let vc = preflight::check_volumes(&fs, archive, dest, largest)?;
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..SpaceParams::default()
    };
    let sp = sevenz::sevenz_space(&layout, &params);
    let fits = |need: u64| match vc.destination.free_bytes {
        Some(f) if f >= need => "fits",
        Some(_) => "DOES NOT FIT",
        None => "unknown",
    };
    println!(
        "archive       {} (7z, {})",
        archive.display(),
        bytes(layout.file_len)
    );
    println!("content       {} to write", bytes(sp.content));
    if let Some(free) = vc.destination.free_bytes {
        println!(
            "destination   {} ({}), {} free",
            dest.display(),
            vc.destination.fs_name,
            bytes(free)
        );
    }
    println!();
    println!("free space needed at the destination:");
    println!(
        "  extract (keeps archive)   {:>12}   {}",
        bytes(sp.extract_extra),
        fits(sp.extract_extra)
    );
    println!("  consume (--consume)       not supported for 7z");
    for f in &vc.findings {
        let tag = match f.severity() {
            Severity::Blocker => "blocks --consume",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        println!("[{tag}] {f}");
    }
    let fit = vc.destination.free_bytes.map(|f| f >= sp.extract_extra);
    Ok(if fit == Some(false) {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}

pub fn is_7z(path: &Path) -> bool {
    sevenz::is_7z(&OsFs::new() as &dyn FsBackend, path)
}

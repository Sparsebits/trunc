//! `.tar.gz` support for `x`, `inspect`, `verify` and `plan`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use trunc_core::space::SpaceParams;
use trunc_engine::preflight::{self, Severity};
use trunc_engine::tgzconsume;
use trunc_engine::zipconsume::ZipOptions;
use trunc_fs::{FsBackend, OsFs};
use trunc_legacy::tar::Kind;

use crate::fmt::bytes;

pub fn is_tgz(path: &Path) -> bool {
    tgzconsume::is_tgz(&OsFs::new() as &dyn FsBackend, path)
}

pub fn extract(
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    ignore_space: bool,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    let t = Instant::now();
    if !ignore_space {
        // gzip records no sizes, so the archive is scanned first to learn what it will write.
        let layout = tgzconsume::open_layout(&fs, archive, 0)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = tgzconsume::tgz_space(&layout, false, 1, &params);
        if let Some(free) = vc.destination.free_bytes.filter(|f| *f < sp.extract_extra) {
            anyhow::bail!(
                "not enough free space at {}: extracting needs about {}, {} are free (--ignore-space to try anyway)",
                dest.display(),
                bytes(sp.extract_extra),
                bytes(free)
            );
        }
    }
    let s = tgzconsume::extract_tgz(&fs, archive, dest, overwrite)?;
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
    let l = tgzconsume::verify_tgz(&OsFs::new(), archive)?;
    println!(
        "ok: {} entries, {} decoded, gzip CRC and tar headers checked in {:.2}s",
        l.entries.len(),
        bytes(l.content_bytes()),
        t.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool) -> Result<ExitCode> {
    let fs = OsFs::new();
    if let Some(dest) = tgzconsume::journal_dest(&fs, archive) {
        println!(
            "archive    {} (tar.gz, being consumed into {})",
            archive.display(),
            dest.display()
        );
        println!(
            "state      partially consumed; run `trunc resume {}`",
            archive.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let l = tgzconsume::open_layout(&fs, archive, 0)?;
    let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
    println!("archive    {} (tar.gz)", archive.display());
    println!(
        "entries    {files} files, {} directories/links",
        l.entries.len() - files
    );
    println!("content    {}", bytes(l.content_bytes()));
    println!(
        "file size  {} ({} gzip member{})",
        bytes(l.file_len),
        l.members,
        if l.members == 1 { "" } else { "s" }
    );
    if list {
        println!();
        for e in &l.entries {
            let size = match e.kind {
                Kind::File => format!("{:>12}", e.size),
                Kind::Dir => format!("{:>12}", "<dir>"),
                Kind::Symlink => format!("{:>12}", "<link>"),
                Kind::Special => format!("{:>12}", "<device>"),
            };
            println!("{size}  {}", e.name);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn plan(archive: &Path, dest: &Path) -> Result<ExitCode> {
    let fs = OsFs::new();
    let layout = tgzconsume::open_layout(&fs, archive, ZipOptions::default().checkpoint_every)?;
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.name.as_str(), e.size));
    let vc = preflight::check_volumes(&fs, archive, dest, largest)?;
    let can_dealloc = vc.archive_volume.supports_sparse && vc.archive_volume.sparse_granularity > 0;
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..SpaceParams::default()
    };
    let sp = tgzconsume::tgz_space(
        &layout,
        can_dealloc,
        u64::from(vc.archive_volume.sparse_granularity.max(1)),
        &params,
    );
    let consume_needs = if vc.same_volume {
        sp.consume_extra
    } else {
        sp.extract_extra
    };
    let fits = |need: u64| match vc.destination.free_bytes {
        Some(f) if f >= need => "fits",
        Some(_) => "DOES NOT FIT",
        None => "unknown",
    };
    println!(
        "archive       {} (tar.gz, {})",
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
    println!(
        "  consume (--consume)       {:>12}   {}",
        bytes(consume_needs),
        fits(consume_needs)
    );
    if !can_dealloc {
        println!(
            "  ({} cannot free space inside a file, so consuming saves nothing here)",
            vc.archive_volume.fs_name
        );
    }
    for f in &vc.findings {
        let tag = match f.severity() {
            Severity::Blocker => "blocks --consume",
            Severity::Warning => "warning",
            Severity::Note => "note",
        };
        println!("[{tag}] {f}");
    }
    let fit = |need: u64| vc.destination.free_bytes.map(|f| f >= need);
    Ok(match (fit(sp.extract_extra), fit(consume_needs)) {
        (Some(false), Some(true)) => ExitCode::from(2),
        (Some(false), Some(false)) => ExitCode::from(3),
        _ => ExitCode::SUCCESS,
    })
}

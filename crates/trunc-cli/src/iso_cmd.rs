//! ISO 9660 image support for `x`, `inspect`, `verify` and `plan`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use trunc_core::space::SpaceParams;
use trunc_engine::consume::ConsumeOptions;
use trunc_engine::isoconsume;
use trunc_engine::preflight;
use trunc_engine::zipconsume;
use trunc_fs::{FsBackend, OsFs};
use trunc_legacy::iso::Image;
use trunc_legacy::zip::Kind;

use crate::fmt::bytes;

pub fn extract(
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    ignore_space: bool,
    allow_overlap: bool,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    if !ignore_space {
        // Declared sizes are checked against free space before anything is written.
        let img = isoconsume::open_image(&fs, archive)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = zipconsume::zip_space(
            &img.layout,
            img.layout.file_len,
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
    let s = isoconsume::extract_iso(&fs, archive, dest, overwrite, allow_overlap)?;
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
    let img = isoconsume::verify_iso(&OsFs::new(), archive)?;
    println!(
        "ok: {} entries, {} in bounds, no loops or overlaps ({} names) in {:.2}s",
        img.layout.entries.len(),
        bytes(isoconsume::content_bytes(&img)),
        img.names,
        t.elapsed().as_secs_f64()
    );
    if img.shared > 0 {
        println!(
            "note: {} files share their data with another file (hard links)",
            img.shared
        );
    }
    println!("note: ISO 9660 has no checksums; file contents cannot be verified");
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool) -> Result<ExitCode> {
    let fs = OsFs::new();
    if let Some(dest) = isoconsume::journal_dest(&fs, archive) {
        println!(
            "archive    {} (ISO image, being consumed into {})",
            archive.display(),
            dest.display()
        );
        println!(
            "state      partially consumed; run `trunc resume {}`",
            archive.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let img = isoconsume::open_image(&fs, archive)?;
    let l = &img.layout;
    let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
    println!("archive    {} (ISO 9660)", archive.display());
    println!("volume     {}", img.volume_id);
    println!("names      {}", img.names);
    println!(
        "entries    {files} files, {} directories/links",
        l.entries.len() - files
    );
    println!("content    {}", bytes(isoconsume::content_bytes(&img)));
    println!("file size  {}", bytes(l.file_len));
    skipped_lines(&img);
    if img.shared > 0 {
        println!(
            "note       {} files share their data with another file (hard links); --consume needs --allow-overlap",
            img.shared
        );
    }
    if img.partial_overlaps > 0 {
        println!(
            "WARNING    {} files partly overlap another file's data (crafted image)",
            img.partial_overlaps
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

fn skipped_lines(img: &Image) {
    if img.hidden > 0 {
        println!("hidden     {} (extracted like other entries)", img.hidden);
    }
    if img.associated_skipped > 0 {
        println!(
            "skipped    {} associated files (resource forks)",
            img.associated_skipped
        );
    }
    if img.specials_skipped > 0 {
        println!(
            "skipped    {} devices, FIFOs or sockets",
            img.specials_skipped
        );
    }
}

pub fn plan(archive: &Path, dest: &Path) -> Result<ExitCode> {
    let img = isoconsume::open_image(&OsFs::new(), archive)?;
    let overlap = (!img.layout.overlaps.is_empty()).then(|| {
        format!(
            "files share or overlap their data ({} shared, {} partly overlapping); pass --allow-overlap to process them",
            img.shared, img.partial_overlaps
        )
    });
    crate::zip_cmd::plan_layout(
        archive,
        dest,
        true,
        &img.layout,
        "ISO 9660",
        overlap.as_deref(),
    )
}

pub fn is_iso(path: &Path) -> bool {
    isoconsume::is_iso(&OsFs::new() as &dyn FsBackend, path)
}

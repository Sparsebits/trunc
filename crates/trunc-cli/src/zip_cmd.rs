//! ZIP support for `x`, `inspect`, `verify` and `plan`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use trunc_core::space::SpaceParams;
use trunc_engine::consume::ConsumeOptions;
use trunc_engine::preflight::{self, Severity};
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_fs::{FsBackend, OsFs};
use trunc_legacy::zip::{Kind, Layout, Method};

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
        let layout = zipconsume::open_layout(&fs, archive)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = zipconsume::zip_space(
            &layout,
            layout.file_len,
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
    let s = zipconsume::extract_zip(&fs, archive, dest, overwrite)?;
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

pub fn verify(archive: &Path) -> Result<ExitCode> {
    let t = Instant::now();
    let (entries, total) = zipconsume::verify_zip(&OsFs::new(), archive)?;
    println!(
        "ok: {entries} entries, {} CRC-checked in {:.2}s",
        bytes(total),
        t.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool) -> Result<ExitCode> {
    let fs = OsFs::new();
    if let Some(dest) = zipconsume::journal_dest(&fs, archive) {
        println!(
            "archive    {} (ZIP, being consumed into {})",
            archive.display(),
            dest.display()
        );
        println!(
            "state      partially consumed; run `trunc resume {}`",
            archive.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let l = zipconsume::open_layout(&fs, archive)?;
    let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
    let total: u64 = l.entries.iter().map(|e| e.size).sum();
    let stored: u64 = l.entries.iter().map(|e| e.compressed_size).sum();
    let count = |m: Method| l.entries.iter().filter(|e| e.method == m).count();
    let deflated = count(Method::Deflate);
    let mut methods = format!("{deflated} deflated, {} stored", count(Method::Stored));
    for m in [Method::Bzip2, Method::Zstd, Method::Xz] {
        let n = count(m);
        if n > 0 {
            let _ = std::fmt::Write::write_fmt(&mut methods, format_args!(", {n} {}", m.name()));
        }
    }
    println!("archive    {} (ZIP)", archive.display());
    println!(
        "entries    {files} files, {} directories/links",
        l.entries.len() - files
    );
    println!("content    {}", bytes(total));
    println!("stored     {} ({methods})", bytes(stored));
    println!("file size  {}", bytes(l.file_len));
    if !l.overlaps.is_empty() {
        println!(
            "WARNING    {} overlapping entries (zip-bomb technique)",
            l.overlaps.len()
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

pub fn plan(archive: &Path, dest: &Path, punch: bool) -> Result<ExitCode> {
    let layout = zipconsume::open_layout(&OsFs::new(), archive)?;
    let overlap = (!layout.overlaps.is_empty()).then(|| {
        format!(
            "{} entries overlap; pass --allow-overlap to process them",
            layout.overlaps.len()
        )
    });
    plan_layout(archive, dest, punch, &layout, "ZIP", overlap.as_deref())
}

/// `plan` for any archive described by a ZIP layout (ZIP, ISO images). `overlap` is the
/// blocker to report when entries overlap.
pub fn plan_layout(
    archive: &Path,
    dest: &Path,
    punch: bool,
    layout: &Layout,
    label: &str,
    overlap: Option<&str>,
) -> Result<ExitCode> {
    let LayoutFigures {
        vc,
        sp,
        len,
        can_dealloc,
        consume_needs,
    } = layout_figures(archive, dest, punch, layout)?;
    let fits = |need: u64| match vc.destination.free_bytes {
        Some(f) if f >= need => "fits",
        Some(_) => "DOES NOT FIT",
        None => "unknown",
    };
    println!(
        "archive       {} ({label}, {})",
        archive.display(),
        bytes(len)
    );
    println!("content       {} to write", bytes(sp.remaining_u));
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
    if punch && can_dealloc && sp.consume_peak < sp.consume_peak_guaranteed {
        println!(
            "  (punch mode frees space inside large entries; without it consuming needs up to {})",
            bytes(sp.consume_peak_guaranteed.saturating_sub(len))
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
    if let Some(o) = overlap {
        println!("[blocks --consume] {o}");
    }
    let fit = |need: u64| vc.destination.free_bytes.map(|f| f >= need);
    Ok(match (fit(sp.extract_extra), fit(consume_needs)) {
        (Some(false), Some(true)) => ExitCode::from(2),
        (Some(false), Some(false)) => ExitCode::from(3),
        _ => ExitCode::SUCCESS,
    })
}

/// What `plan` computes for an archive described by a ZIP layout.
pub struct LayoutFigures {
    pub vc: preflight::VolumeCheck,
    pub sp: zipconsume::ZipSpace,
    pub len: u64,
    pub can_dealloc: bool,
    /// Free space a consume needs at the destination.
    pub consume_needs: u64,
}

pub fn layout_figures(
    archive: &Path,
    dest: &Path,
    punch: bool,
    layout: &Layout,
) -> Result<LayoutFigures> {
    let fs = OsFs::new();
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.name.as_str(), e.size));
    let vc = preflight::check_volumes(&fs, archive, dest, largest)?;
    let opts = ConsumeOptions {
        zip: ZipOptions {
            punch: if punch {
                PunchPolicy::Auto
            } else {
                PunchPolicy::Never
            },
            ..ZipOptions::default()
        },
        ..ConsumeOptions::default()
    };
    let can_dealloc = vc.archive_volume.supports_sparse && vc.archive_volume.sparse_granularity > 0;
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..SpaceParams::default()
    };
    let len = fs
        .open(archive, trunc_fs::OpenMode::Read, trunc_fs::Share::Shared)?
        .size()?;
    let sp = zipconsume::zip_space(
        layout,
        len,
        &opts,
        can_dealloc,
        u64::from(vc.archive_volume.sparse_granularity.max(1)),
        &params,
    );
    let consume_needs = if vc.same_volume {
        sp.consume_extra
    } else {
        sp.extract_extra
    };
    Ok(LayoutFigures {
        vc,
        sp,
        len,
        can_dealloc,
        consume_needs,
    })
}

pub fn is_zip(path: &Path) -> bool {
    zipconsume::is_zip(&OsFs::new() as &dyn FsBackend, path)
}

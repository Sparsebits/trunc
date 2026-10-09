//! Compressed tarballs and single compressed files (gzip, bzip2, xz, zstd) for `x`, `inspect`,
//! `verify` and `plan`.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use trunc_core::space::SpaceParams;
use trunc_engine::preflight::{self, Severity};
use trunc_engine::streamconsume::{self, Mode, StreamLayout, StreamOptions};
use trunc_engine::zipconsume::ZipOptions;
use trunc_fs::OsFs;
use trunc_legacy::stream::{Codec, Limits};
use trunc_legacy::tar::Kind;

use crate::fmt::{bytes, parse_size};

#[derive(Debug, Args)]
pub struct StreamArgs {
    /// Compressed tarballs: decompress into one `.tar` file instead of unpacking it.
    #[arg(long)]
    pub raw: bool,
    /// zstd and xz: refuse streams whose decoder window (memory) is larger than this.
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub max_window: u64,
}

impl StreamArgs {
    pub fn options(&self) -> StreamOptions {
        StreamOptions {
            raw: self.raw,
            max_window: self.max_window.max(1),
        }
    }
}

impl Default for StreamArgs {
    fn default() -> Self {
        Self {
            raw: false,
            max_window: Limits::DEFAULT_MAX_WINDOW,
        }
    }
}

/// `tar.gz`, `tar.zst`, ... for tarballs; `gzip file`, `zstd file`, ... for single files.
pub fn label(codec: Codec, mode: Mode) -> String {
    match mode {
        Mode::Tar => format!(
            "tar.{}",
            match codec {
                Codec::Gzip => "gz",
                Codec::Bzip2 => "bz2",
                Codec::Xz => "xz",
                Codec::Zstd => "zst",
            }
        ),
        Mode::Single => format!("{} file", codec.name()),
    }
}

fn units(l: &StreamLayout) -> String {
    let unit = l.codec.unit();
    if l.units == 1 {
        format!("1 {}", unit.trim_end_matches('s'))
    } else {
        format!("{} {unit}", l.units)
    }
}

pub fn extract(
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    ignore_space: bool,
    opts: &StreamOptions,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    let t = Instant::now();
    if !ignore_space {
        // Compressed streams record no reliable sizes, so the archive is scanned first to learn
        // what it will write.
        let layout = streamconsume::open_layout(&fs, archive, 0, opts)?;
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        let params = SpaceParams {
            cluster_size: u64::from(vc.destination.cluster_size.max(1)),
            ..SpaceParams::default()
        };
        let sp = streamconsume::stream_space(&layout, false, 1, &[], &params);
        if let Some(free) = vc.destination.free_bytes.filter(|f| *f < sp.extract_extra) {
            anyhow::bail!(
                "not enough free space at {}: extracting needs about {}, {} are free (--ignore-space to try anyway)",
                dest.display(),
                bytes(sp.extract_extra),
                bytes(free)
            );
        }
    }
    let s = streamconsume::extract_stream(&fs, archive, dest, overwrite, opts)?;
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

pub fn verify(archive: &Path, opts: &StreamOptions) -> Result<ExitCode> {
    let t = Instant::now();
    let l = streamconsume::verify_stream(&OsFs::new(), archive, opts)?;
    let (what, checked) = match l.mode {
        Mode::Tar => (
            format!("{} entries", l.entries.len()),
            format!("{} checksums and tar headers", l.codec.name()),
        ),
        Mode::Single => ("1 file".into(), format!("{} checksums", l.codec.name())),
    };
    println!(
        "ok: {what}, {} decoded, {checked} checked in {:.2}s",
        bytes(l.content_bytes()),
        t.elapsed().as_secs_f64()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(archive: &Path, list: bool, opts: &StreamOptions) -> Result<ExitCode> {
    let fs = OsFs::new();
    if let Some(dest) = streamconsume::journal_dest(&fs, archive) {
        let kind = streamconsume::detect(&fs, archive, opts.raw)
            .map_or_else(|| "compressed".into(), |(c, m)| label(c, m));
        println!(
            "archive    {} ({kind}, being consumed into {})",
            archive.display(),
            dest.display()
        );
        println!(
            "state      partially consumed; run `trunc resume {}`",
            archive.display()
        );
        return Ok(ExitCode::SUCCESS);
    }
    let l = streamconsume::open_layout(&fs, archive, 0, opts)?;
    println!(
        "archive    {} ({})",
        archive.display(),
        label(l.codec, l.mode)
    );
    match l.mode {
        Mode::Tar => {
            let files = l.entries.iter().filter(|e| e.kind == Kind::File).count();
            println!(
                "entries    {files} files, {} directories/links",
                l.entries.len() - files
            );
            println!("content    {}", bytes(l.content_bytes()));
        }
        Mode::Single => {
            println!("output     {} ({})", l.entries[0].name, bytes(l.out_len));
        }
    }
    println!("file size  {} ({})", bytes(l.file_len), units(&l));
    if list && l.mode == Mode::Tar {
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

pub fn plan(archive: &Path, dest: &Path, opts: &StreamOptions) -> Result<ExitCode> {
    let fs = OsFs::new();
    let layout =
        streamconsume::open_layout(&fs, archive, ZipOptions::default().checkpoint_every, opts)?;
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
    let sp = streamconsume::stream_space(
        &layout,
        can_dealloc,
        u64::from(vc.archive_volume.sparse_granularity.max(1)),
        &trunc_engine::source::part_sizes(&fs, archive)?,
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
        "archive       {} ({}, {})",
        archive.display(),
        label(layout.codec, layout.mode),
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

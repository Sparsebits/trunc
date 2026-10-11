//! Container image tarballs (`docker save`, OCI archives) for `x`, `inspect` and `verify`:
//! extracted to the image's merged root filesystem.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use clap::Args;
use trunc_engine::extract::TrustPolicy;
use trunc_engine::image::{self, ImageFormat, ImageInfo, ImageOptions, ImageScan, Skipped};
use trunc_engine::preflight;
use trunc_fs::OsFs;
use trunc_legacy::tar::Kind;

use crate::fmt::bytes;
use crate::stream_cmd::StreamArgs;

#[derive(Debug, Args, Default)]
pub struct ImageArgs {
    /// Container images: the platform to use from a multi-platform image, as OS/ARCH or
    /// OS/ARCH/VARIANT (default: this computer's architecture, or the only one).
    #[arg(long, value_name = "OS/ARCH")]
    pub platform: Option<String>,
    /// Container images: the image to use when the archive holds several, by tag
    /// (`name:tag`) or OCI reference name.
    #[arg(long, value_name = "NAME")]
    pub image: Option<String>,
}

impl ImageArgs {
    fn options(&self, stream: &StreamArgs, threads: usize, ignore_space: bool) -> ImageOptions {
        ImageOptions {
            platform: self.platform.clone(),
            image: self.image.clone(),
            max_window: stream.max_window.max(1),
            threads,
            ignore_space,
        }
    }
}

/// Whether `archive` is a container image tarball (never with `--raw`, which asks for the
/// decompressed outer tar itself).
pub fn detect(archive: &Path, stream: &StreamArgs) -> bool {
    !stream.raw && image::detect(&OsFs::new(), archive)
}

/// Whether an image command failed only because the archive, once decompressed, turned out
/// not to be a container image: the caller then handles it as an ordinary tarball.
pub fn not_an_image(e: &anyhow::Error, archive: &Path) -> bool {
    let yes = e
        .downcast_ref::<trunc_engine::Error>()
        .is_some_and(image::is_not_an_image);
    if yes {
        eprintln!(
            "note: {} looked like a container image but is not one; reading it as a tarball",
            archive.display()
        );
    }
    yes
}

/// Remove (or point out) temporary copies a crashed run left in `dir`.
fn clean_stale_temps(dir: &Path) {
    for (p, removed) in image::stale_temp_files(&OsFs::new(), dir) {
        if removed {
            eprintln!(
                "note: removed {}, left behind by an interrupted run",
                p.display()
            );
        } else {
            eprintln!(
                "note: {} looks left behind by an interrupted run; delete it if no trunc is \
                 running",
                p.display()
            );
        }
    }
}

/// Flags that do not apply to container images must not be silently ignored.
pub fn refuse_flags(trust: &TrustPolicy, allow_symlinks: bool) -> Result<()> {
    if trust.require_signed || !trust.trusted_keys.is_empty() {
        anyhow::bail!(
            "this is a container image, which cannot be signed; --require-signed and \
             --trust-key apply only to .trnc archives"
        );
    }
    if allow_symlinks {
        anyhow::bail!("--allow-symlinks is not supported for container images");
    }
    Ok(())
}

/// Where a compressed outer tar is decompressed while it is inspected or verified: next to the
/// archive, or in the system's temporary directory when the archive's folder is not writable.
fn temp_dir(archive: &Path) -> PathBuf {
    let next_to = match archive.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = if !compressed(archive) || writable(&next_to) {
        next_to
    } else {
        std::env::temp_dir()
    };
    clean_stale_temps(&dir);
    dir
}

fn compressed(archive: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 16];
    let n = std::fs::File::open(archive)
        .and_then(|mut f| f.read(&mut head))
        .unwrap_or(0);
    trunc_legacy::stream::Codec::sniff(&head[..n]).is_some()
}

fn writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".trunc-probe-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(f) => {
            drop(f);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn kind_label(info: &ImageInfo) -> String {
    let format = match info.format {
        ImageFormat::Docker => "docker save image",
        ImageFormat::Oci => "OCI image",
    };
    match info.outer_codec {
        None => format.to_owned(),
        Some(c) => format!("{format}, {}-compressed", c.name()),
    }
}

fn name_line(info: &ImageInfo) -> String {
    if info.names.is_empty() {
        "<unnamed>".into()
    } else {
        info.names.join(", ")
    }
}

/// Skipped paths `trunc x` lists before "and N more".
const SKIPPED_SHOWN: usize = 10;

/// One skipped path: a directory with a trailing `/` and the entries left out with it.
fn skipped_line(s: &Skipped) -> String {
    if s.dir {
        format!("{}/ ({} entries; {})", s.path, s.entries, s.reason)
    } else {
        format!("{} ({})", s.path, s.reason)
    }
}

/// "N paths (M entries)" for the skipped list.
fn skipped_count(skipped: &[Skipped]) -> String {
    let entries: usize = skipped.iter().map(|s| s.entries).sum();
    let paths = if skipped.len() == 1 { "path" } else { "paths" };
    format!("{} {paths} ({entries} entries)", skipped.len())
}

/// Short form of a digest for tables.
fn short(d: &str) -> String {
    let hex = d.strip_prefix("sha256:").unwrap_or(d);
    format!("sha256:{}", &hex[..hex.len().min(12)])
}

#[allow(clippy::too_many_arguments)]
pub fn extract(
    archive: &Path,
    dest: &Path,
    consume: bool,
    overwrite: bool,
    ignore_space: bool,
    args: &ImageArgs,
    stream: &StreamArgs,
    threads: usize,
) -> Result<ExitCode> {
    if consume {
        anyhow::bail!(
            "--consume is not supported for container images: a layer can be freed only once \
             every later layer is applied, so consuming would save no space. Extract without \
             --consume, then delete the archive"
        );
    }
    if overwrite {
        anyhow::bail!(
            "--overwrite is not supported for container images; extract into an empty directory"
        );
    }
    let fs = OsFs::new();
    let t = Instant::now();
    let opts = args.options(stream, threads, ignore_space);
    if dest.is_dir() {
        clean_stale_temps(dest);
    }
    let mut check_space = |scan: &ImageScan| -> trunc_engine::Result<()> {
        if ignore_space {
            return Ok(());
        }
        let need = scan.content_bytes();
        let vc = preflight::check_volumes(&fs, archive, dest, None)?;
        match vc.destination.free_bytes {
            Some(free) if free < need => Err(trunc_engine::Error::Refused(format!(
                "not enough free space at {}: the image's root filesystem needs about {}, {} are \
                 free (--ignore-space to try anyway)",
                dest.display(),
                bytes(need),
                bytes(free)
            ))),
            _ => Ok(()),
        }
    };
    let s = image::extract_image(&fs, archive, dest, &opts, &mut check_space)?;
    println!(
        "extracted {} files, {} directories, {} into {}",
        s.files,
        s.dirs,
        bytes(s.bytes_written),
        dest.display()
    );
    if s.stats.shadowed > 0 {
        println!(
            "layers    {} entries ({}) deleted or replaced by later layers were not written",
            s.stats.shadowed,
            bytes(s.stats.shadowed_bytes)
        );
    }
    if s.symlinks_skipped > 0 {
        println!(
            "symlinks  {} skipped (symlinks in the root filesystem are not created)",
            s.symlinks_skipped
        );
    }
    if s.specials_skipped > 0 {
        println!(
            "devices   {} device or FIFO entries skipped",
            s.specials_skipped
        );
    }
    if !s.skipped.is_empty() {
        println!(
            "skipped   {} whose names this computer cannot create:",
            skipped_count(&s.skipped)
        );
        for k in s.skipped.iter().take(SKIPPED_SHOWN) {
            println!("            {}", skipped_line(k));
        }
        if s.skipped.len() > SKIPPED_SHOWN {
            println!(
                "            ... and {} more (`trunc inspect --entries` lists them all)",
                s.skipped.len() - SKIPPED_SHOWN
            );
        }
    }
    println!("time      {:.2}s", t.elapsed().as_secs_f64());
    Ok(ExitCode::SUCCESS)
}

pub fn verify(
    archive: &Path,
    args: &ImageArgs,
    stream: &StreamArgs,
    threads: usize,
) -> Result<ExitCode> {
    let t = Instant::now();
    let opts = args.options(stream, threads, false);
    let scan = image::verify_image(&OsFs::new(), archive, &temp_dir(archive), &opts)?;
    let files = scan
        .tree
        .iter()
        .filter(|w| w.entry.kind == Kind::File)
        .count();
    println!(
        "ok: {} ({}), {} layers, {} decoded; every digest, diff_id and tar header checked in \
         {:.2}s",
        name_line(&scan.info),
        scan.info.platform,
        scan.info.layers.len(),
        bytes(scan.layer_tar_len.iter().sum()),
        t.elapsed().as_secs_f64()
    );
    println!(
        "root filesystem: {files} files, {} other entries, {}",
        scan.tree.len() - files,
        bytes(scan.content_bytes())
    );
    if !scan.skipped.is_empty() {
        println!(
            "skipped: {} whose names this computer cannot create would not be written by \
             `trunc x`; their digests and tar headers were checked like the rest (`trunc \
             inspect --entries` lists them)",
            skipped_count(&scan.skipped)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn inspect(
    archive: &Path,
    list: bool,
    args: &ImageArgs,
    stream: &StreamArgs,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    let opts = args.options(stream, 0, false);
    let (info, scan) = if list {
        let s = image::verify_image(&fs, archive, &temp_dir(archive), &opts)?;
        (s.info.clone(), Some(s))
    } else {
        (
            image::inspect_image(&fs, archive, &temp_dir(archive), &opts)?,
            None,
        )
    };
    println!("archive    {} ({})", archive.display(), kind_label(&info));
    println!("image      {}", name_line(&info));
    println!("platform   {}", info.platform);
    if let Some(c) = &info.config_digest {
        println!("config     {c}");
    }
    println!(
        "layers     {} ({} stored)",
        info.layers.len(),
        bytes(info.blob_bytes())
    );
    for (i, l) in info.layers.iter().enumerate() {
        let codec = l.codec.map_or("tar", |c| c.name());
        let digest = l.digest.as_deref().unwrap_or(&l.diff_id);
        println!(
            "  {:>3}  {}  {:>12}  {codec:<5}  {}",
            i + 1,
            short(digest),
            bytes(l.size),
            l.path
        );
        if l.digest.is_some() {
            println!("       diff_id {}", l.diff_id);
        }
    }
    if !info.others.is_empty() {
        println!("others     {}", info.others.join("; "));
    }
    println!("file size  {}", bytes(info.file_len));
    if let Some(s) = scan {
        println!(
            "root fs    {} entries, {} ({} entries hidden by later layers)",
            s.tree.len(),
            bytes(s.content_bytes()),
            s.stats.shadowed
        );
        println!();
        for w in &s.tree {
            let e = &w.entry;
            let size = match e.kind {
                Kind::File => format!("{:>12}", e.size),
                Kind::Dir => format!("{:>12}", "<dir>"),
                Kind::Symlink => format!("{:>12}", "<link>"),
                _ => format!("{:>12}", "<device>"),
            };
            println!("{size}  L{:<3} {}", w.layer + 1, e.name);
        }
        if !s.skipped.is_empty() {
            println!();
            println!(
                "skipped    {} whose names this computer cannot create (checked, not written):",
                skipped_count(&s.skipped)
            );
            for k in &s.skipped {
                println!("  {}", skipped_line(k));
            }
        }
    } else {
        println!("digests    not checked; `trunc verify` checks every blob and layer");
    }
    Ok(ExitCode::SUCCESS)
}

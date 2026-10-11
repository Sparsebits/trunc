//! The `layerless` command.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use layerless::Resolved;
use layerless::reference::Reference;
use layerless::registry::Client;
use trunc_engine::image::{self, ImageOptions, ImageSummary};
use trunc_fs::OsFs;

/// Pull a container image straight to a root filesystem: no tarball, no daemon, no double disk.
#[derive(Debug, Parser)]
#[command(name = "layerless", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Pull an image from a registry and write its merged root filesystem to a directory.
    Pull {
        /// Image reference: `alpine:3`, `ghcr.io/owner/name:tag`, `name@sha256:...`.
        reference: String,
        /// Directory to write the root filesystem into (created if missing).
        #[arg(short = 'C', long = "directory", value_name = "DIR")]
        dir: PathBuf,
        /// Platform to pull, as OS/ARCH or OS/ARCH/VARIANT (default: linux/<this machine>).
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
    /// Extract an image tarball (`docker save`, OCI archive) to its merged root filesystem.
    Unpack {
        archive: PathBuf,
        #[arg(short = 'C', long = "directory", value_name = "DIR")]
        dir: PathBuf,
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
    /// Show an image's platforms, manifest and layers without downloading any layer.
    Inspect {
        reference: String,
        #[arg(long, value_name = "OS/ARCH")]
        platform: Option<String>,
    },
}

fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn short(d: &str) -> &str {
    let h = d.strip_prefix("sha256:").unwrap_or(d);
    &h[..h.len().min(12)]
}

fn print_summary(s: &ImageSummary, dest: &std::path::Path, started: Instant) {
    let mut skipped = Vec::new();
    if s.symlinks_skipped > 0 {
        skipped.push(format!("{} symlinks", s.symlinks_skipped));
    }
    if s.specials_skipped > 0 {
        skipped.push(format!("{} devices/FIFOs", s.specials_skipped));
    }
    println!(
        "{} files, {} directories, {} written to {} in {:.1}s",
        s.files,
        s.dirs,
        bytes(s.bytes_written),
        dest.display(),
        started.elapsed().as_secs_f64()
    );
    println!(
        "  merged: {} entries, {} whiteouts, {} opaque dirs, {} shadowed ({})",
        s.stats.entries,
        s.stats.whiteouts,
        s.stats.opaques,
        s.stats.shadowed,
        bytes(s.stats.shadowed_bytes)
    );
    if !skipped.is_empty() {
        println!(
            "  skipped (not created on this system): {}",
            skipped.join(", ")
        );
    }
}

fn describe(r: &Resolved) {
    println!("image     {}", r.reference);
    if let Some((d, entries)) = &r.index {
        println!("index     {d}");
        for e in entries.iter().filter(|e| !e.attestation) {
            let mark = if e.descriptor.digest == r.manifest_digest {
                "*"
            } else {
                " "
            };
            println!("  {mark} {:<18} {}", e.platform, e.descriptor.digest);
        }
    }
    println!(
        "manifest  {} ({})",
        r.manifest_digest, r.manifest.media_type
    );
    println!("platform  {}", r.config.platform);
    println!("config    {}", r.manifest.config.digest);
    println!(
        "layers    {} ({} to download)",
        r.manifest.layers.len(),
        bytes(r.download_bytes())
    );
    for (i, l) in r.manifest.layers.iter().enumerate() {
        let kind = l
            .media_type
            .rsplit(['.', '+'])
            .next()
            .unwrap_or(&l.media_type);
        println!(
            "  {:>3}  {:>10}  {:<5} {}",
            i + 1,
            bytes(l.size),
            kind,
            l.digest
        );
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Pull {
            reference,
            dir,
            platform,
        } => {
            let started = Instant::now();
            let total = std::cell::Cell::new(0usize);
            let s = layerless::pull(
                &reference,
                &dir,
                platform.as_deref(),
                &mut |r| {
                    total.set(r.manifest.layers.len());
                    eprintln!(
                        "pulling {} ({}, {} layers, {})",
                        r.reference,
                        r.config.platform,
                        total.get(),
                        bytes(r.download_bytes())
                    );
                },
                &mut |i, l| {
                    eprintln!(
                        "  layer {}/{} {} {:>10}  verified",
                        i + 1,
                        total.get(),
                        short(&l.digest),
                        bytes(l.size)
                    );
                },
            )?;
            print_summary(&s, &dir, started);
        }
        Cmd::Unpack {
            archive,
            dir,
            platform,
        } => {
            let started = Instant::now();
            let opts = ImageOptions {
                platform,
                ..ImageOptions::default()
            };
            let s = image::extract_image(&OsFs::new(), &archive, &dir, &opts, &mut |_| Ok(()))?;
            print_summary(&s, &dir, started);
        }
        Cmd::Inspect {
            reference,
            platform,
        } => {
            let mut client = Client::new(Reference::parse(&reference)?);
            let r = layerless::resolve(&mut client, platform.as_deref())?;
            describe(&r);
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("layerless: {e:#}");
            ExitCode::FAILURE
        }
    }
}

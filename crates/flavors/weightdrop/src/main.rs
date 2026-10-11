//! The `weightdrop` command.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::Result;
use clap::{Parser, Subcommand};
use weightdrop::state::Layout;
use weightdrop::{Event, UnpackOptions, fmt_bytes};

#[derive(Debug, Parser)]
#[command(
    name = "weightdrop",
    version,
    about = "Unpack model weights and datasets on GPU boxes with small disks (built on trunc)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Unpack a shard set, freeing each archive's space as it is decoded.
    Unpack {
        /// Shard files, a directory of shards, or a glob such as 'data/train-*.tar.zst'.
        #[arg(required = true)]
        inputs: Vec<String>,
        /// Destination directory.
        #[arg(short = 'C', long = "dest", default_value = ".")]
        dest: PathBuf,
        /// Keep the archives (plain extract; needs room for everything).
        #[arg(long)]
        keep: bool,
        /// Put every shard's files straight into the destination; refuse if names collide.
        #[arg(long)]
        flatten: bool,
        /// Start even if the plan says the set will not fit.
        #[arg(long)]
        ignore_space: bool,
    },
    /// Show the space each shard and the whole set needs, without changing anything.
    Plan {
        /// Shard files, a directory of shards, or a glob.
        #[arg(required = true)]
        inputs: Vec<String>,
        /// Destination directory (for the free-space check).
        #[arg(short = 'C', long = "dest", default_value = ".")]
        dest: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Unpack {
            inputs,
            dest,
            keep,
            flatten,
            ignore_space,
        } => {
            let mut o = UnpackOptions::new(inputs, dest);
            o.keep = keep;
            o.flatten = flatten;
            o.ignore_space = ignore_space;
            unpack(&o)
        }
        Cmd::Plan { inputs, dest } => plan(&inputs, &dest),
    };
    match r {
        Ok(c) => c,
        Err(e) => {
            eprintln!("weightdrop: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn eta(done: u64, total: u64, secs: f64) -> String {
    if done == 0 || total <= done || secs < 1.0 {
        return "--".into();
    }
    #[allow(clippy::cast_precision_loss)]
    let left = (total - done) as f64 * secs / done as f64;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let s = left.round() as u64;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, s % 3600 / 60)
    } else {
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

fn unpack(o: &UnpackOptions) -> Result<ExitCode> {
    let tty = std::io::stdout().is_terminal();
    let t = Instant::now();
    let mut shard = (0usize, 0usize);
    let mut line_open = false;
    let mut out = std::io::stdout();
    let mut on_event = |e: Event| {
        match e {
            Event::Note(n) => {
                if line_open {
                    let _ = writeln!(out);
                    line_open = false;
                }
                let _ = writeln!(out, "{n}");
            }
            Event::ShardStart {
                number,
                count,
                name,
                resumed,
            } => {
                shard = (number, count);
                if !tty {
                    let r = if resumed { " (resuming)" } else { "" };
                    let _ = writeln!(out, "shard {number}/{count} {name}{r}");
                }
            }
            Event::Bytes { done, total } => {
                if tty {
                    let _ = write!(
                        out,
                        "\r[{}/{}] {} / {}  ETA {}   ",
                        shard.0,
                        shard.1,
                        fmt_bytes(done),
                        fmt_bytes(total),
                        eta(done, total, t.elapsed().as_secs_f64())
                    );
                    line_open = true;
                }
            }
            Event::ShardDone {
                number,
                count,
                name,
                bytes,
            } => {
                if !tty {
                    let _ = writeln!(
                        out,
                        "shard {number}/{count} {name} done, {}",
                        fmt_bytes(bytes)
                    );
                }
            }
        }
        let _ = out.flush();
    };
    let s = weightdrop::unpack(o, &mut on_event)?;
    if tty {
        println!();
    }
    println!(
        "done: {} shard(s), {} this run, {} files, {} into {}{}",
        s.shards,
        s.unpacked,
        s.files,
        fmt_bytes(s.bytes),
        o.dest.display(),
        match s.layout {
            Layout::Flat => "",
            Layout::PerShard => " (one folder per shard)",
        }
    );
    if !o.keep {
        println!("archives  consumed and removed");
    }
    println!("time      {:.1}s", t.elapsed().as_secs_f64());
    Ok(ExitCode::SUCCESS)
}

fn plan(inputs: &[String], dest: &std::path::Path) -> Result<ExitCode> {
    let r = weightdrop::plan_set(inputs, dest)?;
    for n in &r.notes {
        println!("{n}");
    }
    if r.already_done > 0 {
        println!(
            "{} shard(s) already unpacked by an earlier run; planning the rest",
            r.already_done
        );
    }
    let w = r
        .shards
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(5)
        .max(5);
    println!(
        "{:<w$}  {:>11}  {:>11}  {:>11}  {:>11}",
        "shard", "archive", "content", "own peak+", "set peak"
    );
    for (s, peak) in r.shards.iter().zip(&r.plan.peak_during) {
        println!(
            "{:<w$}  {:>11}  {:>11}  {:>11}  {:>11}",
            s.name,
            fmt_bytes(s.archive_len),
            fmt_bytes(s.content),
            fmt_bytes(s.consume_peak.saturating_sub(s.archive_len)),
            fmt_bytes(*peak)
        );
    }
    let p = &r.plan;
    println!();
    println!(
        "total         {} shard(s), {} of archives, {} of content",
        r.shards.len(),
        fmt_bytes(p.archives),
        fmt_bytes(p.content)
    );
    if !r.shards.is_empty() {
        println!(
            "peak on disk  {} (while unpacking {})",
            fmt_bytes(p.peak),
            r.shards[p.peak_shard].name
        );
    }
    let fits = |need: u64| match r.dest_free {
        Some(f) if f >= need => "fits",
        Some(_) => "DOES NOT FIT",
        None => "free space unknown",
    };
    println!("free space needed at {}:", dest.display());
    println!(
        "  plain extract (--keep)    {:>11}   {}",
        fmt_bytes(p.extract_extra),
        fits(p.extract_extra)
    );
    println!(
        "  weightdrop unpack         {:>11}   {}",
        fmt_bytes(p.consume_extra),
        fits(p.consume_extra)
    );
    println!("  saving                    {:>11}", fmt_bytes(p.saving()));
    if let Some(f) = r.dest_free {
        println!(
            "  free now                  {:>11}   ({})",
            fmt_bytes(f),
            r.dest_fs
        );
    }
    if !r.same_volume {
        println!("  (the archives are on another volume, so consuming them frees no room here)");
    } else if !r.can_dealloc {
        println!(
            "  (this filesystem cannot free space inside a file; only whole shards are freed)"
        );
    }
    let fit = |need: u64| r.dest_free.map(|f| f >= need);
    Ok(match (fit(p.extract_extra), fit(p.consume_extra)) {
        (Some(false), Some(true)) => ExitCode::from(2),
        (Some(false), Some(false)) => ExitCode::from(3),
        _ => ExitCode::SUCCESS,
    })
}

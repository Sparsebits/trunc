//! `trunc x --consume` and `trunc resume`, for `.trnc` and ZIP archives.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Result, bail};
use clap::Args;
use trunc_core::space::SpaceParams;
use trunc_engine::consume::{self, ConsumeOptions, Progress, RetryPolicy};
use trunc_engine::extract::TrustPolicy;
use trunc_engine::preflight::{Finding, Severity};
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_engine::{Error, PauseReason};
use trunc_fs::OsFs;

use crate::fmt::{bytes, parse_size};

/// Exit code for a safe pause (EX_TEMPFAIL): resume later, nothing was lost.
pub const EXIT_PAUSED: u8 = 75;

#[derive(Debug, Args)]
pub struct ConsumeFlags {
    /// Don't ask for confirmation before destroying the archive.
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// Allow destructive mode on filesystems without metadata journaling (FAT32, exFAT).
    #[arg(long)]
    pub allow_unjournaled: bool,
    /// Allow destructive mode on an archive inside a cloud-synced folder.
    #[arg(long)]
    pub allow_sync: bool,
    /// .trnc: delete the archive at the end instead of keeping header + manifest as
    /// `<archive>.receipt`.
    #[arg(long)]
    pub no_receipt: bool,
    /// Start even if the free-space check says it will not fit.
    #[arg(long)]
    pub ignore_space: bool,
    /// .trnc: decoded bytes per batch (smaller means less extra space, more flushes).
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub batch: u64,
    /// ZIP: process archives whose entries overlap (a zip-bomb technique).
    #[arg(long)]
    pub allow_overlap: bool,
    /// ZIP: never free space inside an entry while it decompresses.
    #[arg(long)]
    pub no_punch: bool,
    /// ZIP: compressed size from which entries are punched while decompressing.
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub punch_min: u64,
    /// ZIP: output bytes between punch-mode checkpoints.
    #[arg(long, default_value = "64M", value_parser = parse_size)]
    pub checkpoint_every: u64,
}

impl ConsumeFlags {
    fn options(&self, trust: TrustPolicy, threads: usize) -> ConsumeOptions {
        ConsumeOptions {
            trust,
            threads,
            space: SpaceParams {
                batch_max_u: self.batch,
                ..SpaceParams::default()
            },
            allow_unjournaled: self.allow_unjournaled,
            allow_sync: self.allow_sync,
            skip_space_check: self.ignore_space,
            keep_receipt: !self.no_receipt,
            retry: RetryPolicy::default(),
            zip: ZipOptions {
                allow_overlap: self.allow_overlap,
                punch: if self.no_punch {
                    PunchPolicy::Never
                } else {
                    PunchPolicy::Auto
                },
                punch_min: self.punch_min,
                checkpoint_every: self.checkpoint_every,
            },
        }
    }
}

fn confirm(archive: &Path, dest: &Path, zip: bool) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--consume destroys the archive; pass --yes to confirm when not running interactively"
        );
    }
    let zip_note = if zip {
        "Other ZIP tools cannot open the file once the first step has run.\n"
    } else {
        ""
    };
    eprint!(
        "--consume destroys {} while extracting into {}.\n\
         If interrupted, nothing is lost: run the same command again to continue.\n\
         {zip_note}Continue? [y/N] ",
        archive.display(),
        dest.display(),
    );
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

pub fn run(
    archive: &Path,
    dest: &Path,
    flags: &ConsumeFlags,
    trust: TrustPolicy,
    threads: usize,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    let zip = zipconsume::is_zip(&fs, archive);
    if !flags.yes && !confirm(archive, dest, zip)? {
        eprintln!("cancelled; nothing was changed");
        return Ok(ExitCode::FAILURE);
    }
    let opts = flags.options(trust, threads);
    let unit = if zip { "entries" } else { "blocks" };
    let tty = std::io::stderr().is_terminal();
    let t = Instant::now();
    let mut progress = |p: Progress| match p {
        Progress::Started {
            resumed: true,
            blocks_done,
            blocks_total,
        } => {
            eprintln!("resuming: {blocks_done} of {blocks_total} {unit} already consumed");
        }
        Progress::Started { .. } => {}
        Progress::Batch {
            blocks_done,
            blocks_total,
            bytes_written,
            archive_len,
        } => {
            if tty {
                eprint!(
                    "\r{blocks_done}/{blocks_total} {unit}  {} written  archive now {}   ",
                    bytes(bytes_written),
                    bytes(archive_len)
                );
            }
        }
        Progress::Renaming => {
            if tty {
                eprintln!();
            }
            eprintln!("all {unit} consumed; moving files into place");
        }
    };
    let result = if zip {
        zipconsume::consume_zip(&fs, archive, dest, &opts, &mut progress)
    } else {
        consume::consume(&fs, archive, dest, &opts, &mut progress)
    };
    match result {
        Ok(s) => {
            for f in s
                .findings
                .iter()
                .filter(|f| !matches!(f, Finding::PartiallyConsumed { .. }))
            {
                let tag = if f.severity() == Severity::Warning {
                    "warning"
                } else {
                    "note"
                };
                eprintln!("[{tag}] {f}");
            }
            println!(
                "extracted {} files, {} directories, {} into {}{}",
                s.files,
                s.dirs,
                bytes(s.bytes_written),
                dest.display(),
                if s.resumed { " (resumed)" } else { "" }
            );
            if s.symlinks_skipped > 0 {
                println!(
                    "symlinks  {} skipped (not created in --consume mode)",
                    s.symlinks_skipped
                );
            }
            match &s.receipt {
                Some(r) => println!("archive   consumed; receipt kept at {}", r.display()),
                None => println!("archive   consumed and removed"),
            }
            let steps = if zip { "steps" } else { "batches" };
            println!(
                "time      {:.2}s ({} {steps})",
                t.elapsed().as_secs_f64(),
                s.batches
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(Error::Paused(reason)) => {
            if tty {
                eprintln!();
            }
            let what = match reason {
                PauseReason::NoSpace { needed } => {
                    format!(
                        "out of space. Free at least {} at the destination",
                        bytes(needed)
                    )
                }
                PauseReason::Mapped => {
                    "another program (often antivirus or a search indexer) keeps the archive open"
                        .to_string()
                }
            };
            eprintln!(
                "paused safely: {what}, then run the same command again (or `trunc resume`)."
            );
            eprintln!("nothing has been lost: the remaining data is still in the archive.");
            Ok(ExitCode::from(EXIT_PAUSED))
        }
        Err(e) => Err(e.into()),
    }
}

/// Destination for `trunc resume`: the explicit one, else the one recorded when consumption
/// started (ZIP journal or `.trnc` resume note).
pub fn resume_dest(archive: &Path, dest: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = dest {
        return Ok(d);
    }
    let fs = OsFs::new();
    if let Some(d) = zipconsume::journal_dest(&fs, archive) {
        return Ok(d);
    }
    match consume::read_resume_note(&fs, archive) {
        Some(n) => Ok(n.dest),
        None => bail!(
            "no resume note or journal found next to {}; pass the destination with -C",
            archive.display()
        ),
    }
}

//! `trunc x --consume` and `trunc resume`.

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
    /// Delete the archive at the end instead of keeping header + manifest as `<archive>.receipt`.
    #[arg(long)]
    pub no_receipt: bool,
    /// Start even if the free-space check says it will not fit.
    #[arg(long)]
    pub ignore_space: bool,
    /// Decoded bytes per batch: smaller means less extra space, more flushes.
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub batch: u64,
}

fn confirm(archive: &Path, dest: &Path) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--consume destroys the archive; pass --yes to confirm when not running interactively"
        );
    }
    eprint!(
        "--consume destroys {} while extracting into {}.\n\
         If interrupted, nothing is lost: run the same command again to continue.\n\
         Continue? [y/N] ",
        archive.display(),
        dest.display()
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
    if !flags.yes && !confirm(archive, dest)? {
        eprintln!("cancelled; nothing was changed");
        return Ok(ExitCode::FAILURE);
    }
    let opts = ConsumeOptions {
        trust,
        threads,
        space: SpaceParams {
            batch_max_u: flags.batch,
            ..SpaceParams::default()
        },
        allow_unjournaled: flags.allow_unjournaled,
        allow_sync: flags.allow_sync,
        skip_space_check: flags.ignore_space,
        keep_receipt: !flags.no_receipt,
        retry: RetryPolicy::default(),
    };
    let tty = std::io::stderr().is_terminal();
    let t = Instant::now();
    let mut progress = |p: Progress| match p {
        Progress::Started {
            resumed: true,
            blocks_done,
            blocks_total,
        } => {
            eprintln!("resuming: {blocks_done} of {blocks_total} blocks already consumed");
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
                    "\r{blocks_done}/{blocks_total} blocks  {} written  archive now {}   ",
                    bytes(bytes_written),
                    bytes(archive_len)
                );
            }
        }
        Progress::Renaming => {
            if tty {
                eprintln!();
            }
            eprintln!("all blocks consumed; moving files into place");
        }
    };
    let result = consume::consume(&OsFs::new(), archive, dest, &opts, &mut progress);
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
            let plural = if s.batches == 1 { "" } else { "es" };
            println!(
                "time      {:.2}s in {} batch{plural}",
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
                PauseReason::Mapped => "another program (often antivirus or a search indexer) \
                     keeps the archive open"
                    .to_string(),
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

/// Destination for `trunc resume`: the explicit one, else the resume note's.
pub fn resume_dest(archive: &Path, dest: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(d) = dest {
        return Ok(d);
    }
    match consume::read_resume_note(&OsFs::new(), archive) {
        Some(n) => Ok(n.dest),
        None => bail!(
            "no resume note found next to {} ({}); pass the destination with -C",
            archive.display(),
            consume::resume_note_path(archive).display()
        ),
    }
}

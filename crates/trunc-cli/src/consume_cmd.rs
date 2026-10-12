//! `trunc x --consume` and `trunc resume`, for `.trnc`, ZIP, compressed tarballs and compressed
//! files.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Result, bail};
use clap::Args;
use trunc_core::space::SpaceParams;
use trunc_engine::consume::{self, ConsumeOptions, Progress, RetryPolicy};
use trunc_engine::extract::TrustPolicy;
use trunc_engine::isoconsume;
use trunc_engine::preflight::{Finding, Severity};
use trunc_engine::streamconsume::{self, StreamOptions};
use trunc_engine::tarconsume;
use trunc_engine::zipconsume::{self, PunchPolicy, ZipOptions};
use trunc_engine::{Error, PauseReason};
use trunc_fs::OsFs;

use crate::Kind;
use crate::fmt::{bytes, parse_size, size_flag};

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
    /// Before releasing any source bytes, read the extracted data back from disk (bypassing the
    /// OS cache) and check it. Costs one extra read of everything extracted.
    #[arg(long)]
    pub verify_media: bool,
    /// .trnc: decoded bytes per batch (smaller means less extra space, more flushes).
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub batch: u64,
    /// ZIP and ISO: process archives whose entries overlap (a zip-bomb technique) or share
    /// data (ISO hard links).
    #[arg(long)]
    pub allow_overlap: bool,
    /// ISO: consume images holding entries that are never extracted (associated files such as
    /// resource forks, devices, FIFOs), which are destroyed with the image.
    #[arg(long)]
    pub allow_skipped: bool,
    /// ZIP and ISO: never free space inside an entry while it is extracted.
    #[arg(long)]
    pub no_punch: bool,
    /// ZIP and ISO: stored size from which entries are punched while extracted.
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    pub punch_min: u64,
    /// ZIP and compressed tarballs and files: output bytes between checkpoints that free
    /// compressed data.
    #[arg(long, default_value = "64M", value_parser = parse_size)]
    pub checkpoint_every: u64,
    /// Valued flags given on the command line (ids), as opposed to defaults.
    #[arg(skip)]
    pub explicit: Vec<&'static str>,
}

/// The safety-relevant flags a consume started with, remembered next to its journal so that a
/// resume applies them again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SavedFlags {
    verify_media: bool,
    allow_unjournaled: bool,
    allow_sync: bool,
    allow_overlap: bool,
    allow_skipped: bool,
    no_punch: bool,
    no_receipt: bool,
    batch: u64,
    punch_min: u64,
    checkpoint_every: u64,
}

const OPTS_MAGIC: &str = "trunc-consume-options-v1";

impl SavedFlags {
    fn of(f: &ConsumeFlags) -> Self {
        Self {
            verify_media: f.verify_media,
            allow_unjournaled: f.allow_unjournaled,
            allow_sync: f.allow_sync,
            allow_overlap: f.allow_overlap,
            allow_skipped: f.allow_skipped,
            no_punch: f.no_punch,
            no_receipt: f.no_receipt,
            batch: f.batch,
            punch_min: f.punch_min,
            checkpoint_every: f.checkpoint_every,
        }
    }

    fn encode(&self) -> String {
        let b = |v: bool| u8::from(v);
        format!(
            "{OPTS_MAGIC}\nverify_media={}\nallow_unjournaled={}\nallow_sync={}\n\
             allow_overlap={}\nallow_skipped={}\nno_punch={}\nno_receipt={}\nbatch={}\n\
             punch_min={}\ncheckpoint_every={}\n",
            b(self.verify_media),
            b(self.allow_unjournaled),
            b(self.allow_sync),
            b(self.allow_overlap),
            b(self.allow_skipped),
            b(self.no_punch),
            b(self.no_receipt),
            self.batch,
            self.punch_min,
            self.checkpoint_every
        )
    }

    /// Unknown keys are ignored and missing ones keep their defaults, so later versions can add
    /// fields.
    fn decode(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != OPTS_MAGIC {
            return None;
        }
        let mut s = Self::of(&ConsumeFlags::default_values());
        for l in lines {
            let Some((k, v)) = l.split_once('=') else {
                continue;
            };
            let flag = v == "1";
            match k {
                "verify_media" => s.verify_media = flag,
                "allow_unjournaled" => s.allow_unjournaled = flag,
                "allow_sync" => s.allow_sync = flag,
                "allow_overlap" => s.allow_overlap = flag,
                "allow_skipped" => s.allow_skipped = flag,
                "no_punch" => s.no_punch = flag,
                "no_receipt" => s.no_receipt = flag,
                "batch" => s.batch = v.parse().ok()?,
                "punch_min" => s.punch_min = v.parse().ok()?,
                "checkpoint_every" => s.checkpoint_every = v.parse().ok()?,
                _ => {}
            }
        }
        Some(s)
    }

    /// The flags that differ from the defaults, as they would be typed.
    fn describe(&self) -> Vec<String> {
        let d = Self::of(&ConsumeFlags::default_values());
        let mut out = Vec::new();
        for (on, name) in [
            (self.verify_media, "--verify-media"),
            (self.allow_unjournaled, "--allow-unjournaled"),
            (self.allow_sync, "--allow-sync"),
            (self.allow_overlap, "--allow-overlap"),
            (self.allow_skipped, "--allow-skipped"),
            (self.no_punch, "--no-punch"),
            (self.no_receipt, "--no-receipt"),
        ] {
            if on {
                out.push(name.to_string());
            }
        }
        for (v, dv, name) in [
            (self.batch, d.batch, "--batch"),
            (self.punch_min, d.punch_min, "--punch-min"),
            (
                self.checkpoint_every,
                d.checkpoint_every,
                "--checkpoint-every",
            ),
        ] {
            if v != dv {
                out.push(format!("{name} {}", size_flag(v)));
            }
        }
        out
    }
}

/// Where the flags a consume started with are kept: `<archive>.trncj.opts`.
fn opts_path(archive: &Path) -> PathBuf {
    let mut s = zipconsume::journal_path(archive).into_os_string();
    s.push(".opts");
    PathBuf::from(s)
}

fn read_saved(archive: &Path) -> Option<SavedFlags> {
    let text = std::fs::read_to_string(opts_path(archive)).ok()?;
    SavedFlags::decode(&text)
}

/// Record the flags durably before the first destructive step: written to a temporary file,
/// flushed, renamed into place, and the folder flushed.
fn write_saved(fs: &OsFs, archive: &Path, saved: &SavedFlags) -> Result<()> {
    use trunc_fs::{FsBackend, OpenMode, Share};
    let path = opts_path(archive);
    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let h = fs.open(&tmp, OpenMode::CreateOrTruncate, Share::Shared)?;
    h.write_all_at(saved.encode().as_bytes(), 0)?;
    h.flush_data()?;
    drop(h);
    match fs.remove_file(&path) {
        Ok(()) | Err(trunc_fs::FsError::NotFound { .. }) => {}
        Err(e) => return Err(e.into()),
    }
    fs.rename(&tmp, &path)?;
    fs.flush_dir(&parent_dir(archive))?;
    Ok(())
}

fn remove_saved(fs: &OsFs, archive: &Path) {
    use trunc_fs::FsBackend;
    let _ = fs.remove_file(&opts_path(archive));
    let _ = fs.flush_dir(&parent_dir(archive));
}

fn parent_dir(p: &Path) -> PathBuf {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

impl ConsumeFlags {
    fn default_values() -> Self {
        Self {
            yes: false,
            allow_unjournaled: false,
            allow_sync: false,
            no_receipt: false,
            ignore_space: false,
            verify_media: false,
            batch: 256 << 20,
            allow_overlap: false,
            allow_skipped: false,
            no_punch: false,
            punch_min: 256 << 20,
            checkpoint_every: 64 << 20,
            explicit: Vec::new(),
        }
    }

    /// These flags with what a resumed consume recorded at its start applied: switches set
    /// then stay set, and sizes not given now come from the record.
    fn with_saved(&self, s: &SavedFlags) -> Self {
        let given = |id: &str| self.explicit.contains(&id);
        Self {
            verify_media: self.verify_media || s.verify_media,
            allow_unjournaled: self.allow_unjournaled || s.allow_unjournaled,
            allow_sync: self.allow_sync || s.allow_sync,
            allow_overlap: self.allow_overlap || s.allow_overlap,
            allow_skipped: self.allow_skipped || s.allow_skipped,
            no_punch: self.no_punch || s.no_punch,
            no_receipt: self.no_receipt || s.no_receipt,
            batch: if given("batch") { self.batch } else { s.batch },
            punch_min: if given("punch_min") {
                self.punch_min
            } else {
                s.punch_min
            },
            checkpoint_every: if given("checkpoint_every") {
                self.checkpoint_every
            } else {
                s.checkpoint_every
            },
            yes: self.yes,
            ignore_space: self.ignore_space,
            explicit: self.explicit.clone(),
        }
    }

    fn options(&self, stream: StreamOptions, trust: TrustPolicy, threads: usize) -> ConsumeOptions {
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
            verify_media: self.verify_media,
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
            stream,
        }
    }
}

/// Where an archive stands with respect to consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Never consumed (or not an archive trunc knows): read it normally.
    Fresh,
    /// A consume started and was interrupted or paused; its front may already be gone.
    Partly { dest: Option<PathBuf> },
    /// The `.trnc` receipt left by a finished consume: header and manifest, no file data.
    Receipt,
}

/// Detect a consume in progress from its journal (ZIP, ISO, tar, compressed tarballs and
/// files), its resume note (`.trnc`), or a `.trnc` whose leading blocks are gone.
pub fn state(archive: &Path) -> State {
    let fs = OsFs::new();
    if zipconsume::journal_path(archive).exists() {
        let dest = zipconsume::journal_dest(&fs, archive)
            .or_else(|| streamconsume::journal_dest(&fs, archive));
        return State::Partly { dest };
    }
    if let Some(n) = consume::read_resume_note(&fs, archive) {
        return State::Partly { dest: Some(n.dest) };
    }
    match trunc_engine::Archive::open(archive) {
        Ok(a) if a.consumed() > 0 && a.consumed() >= a.manifest().blocks.len() => State::Receipt,
        Ok(a) if a.consumed() > 0 => State::Partly { dest: None },
        _ => State::Fresh,
    }
}

pub fn partly_consumed_error(archive: &Path, dest: Option<&Path>) -> anyhow::Error {
    let a = archive.display();
    match dest {
        Some(d) => anyhow::anyhow!(
            "{a} is partly consumed (interrupted while extracting into {}). Nothing is lost: \
             run `trunc resume {a}`.",
            d.display()
        ),
        None => anyhow::anyhow!(
            "{a} is partly consumed (an interrupted --consume). Nothing is lost: run \
             `trunc resume {a} -C <destination>`."
        ),
    }
}

pub fn receipt_error(archive: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "{} is the receipt of a finished consume; it holds no file data",
        archive.display()
    )
}

/// Non-destructive reads (`x` without `--consume`, `verify`, `plan`) of an archive a consume
/// has started on would find its front missing and report it as corrupt; say what it is.
pub fn refuse_consumed(archive: &Path) -> Result<()> {
    match state(archive) {
        State::Fresh => Ok(()),
        State::Partly { dest } => Err(partly_consumed_error(archive, dest.as_deref())),
        State::Receipt => Err(receipt_error(archive)),
    }
}

/// Free space a normal extract and a consume need at `dest`, from the figures `plan` prints.
/// None when they are not cheap to get (compressed streams must be decoded in full).
fn space_figures(
    kind: Kind,
    archive: &Path,
    dest: &Path,
    flags: &ConsumeFlags,
) -> Option<(u64, u64)> {
    let fs = OsFs::new();
    let punch = !flags.no_punch;
    let layout = |l: &trunc_legacy::zip::Layout| {
        crate::zip_cmd::layout_figures(archive, dest, punch, l)
            .ok()
            .map(|f| (f.sp.extract_extra, f.consume_needs))
    };
    match kind {
        Kind::Trnc => {
            let a = trunc_engine::Archive::open(archive).ok()?;
            let params = SpaceParams {
                batch_max_u: flags.batch,
                ..SpaceParams::default()
            };
            let p = trunc_engine::preflight::assess(&fs, &a, dest, params).ok()?;
            Some((p.bound.extract_extra, p.consume_needs))
        }
        Kind::Zip => layout(&zipconsume::open_layout(&fs, archive).ok()?),
        Kind::Iso => layout(&isoconsume::open_image(&fs, archive).ok()?.layout),
        Kind::Tar => layout(&tarconsume::open_tar(&fs, archive).ok()?.layout),
        Kind::SevenZ | Kind::Stream(..) => None,
    }
}

fn confirm(
    archive: &Path,
    dest: &Path,
    kind: Kind,
    flags: &ConsumeFlags,
    resuming: bool,
) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "--consume destroys the archive; pass --yes to confirm when not running interactively"
        );
    }
    let name = archive.display();
    let mut msg = String::new();
    if resuming {
        msg.push_str(&format!(
            "This continues consuming {name} into {}; part of it is already gone.\n",
            dest.display()
        ));
    } else {
        let size = std::fs::metadata(archive)
            .map(|m| format!(" ({})", bytes(m.len())))
            .unwrap_or_default();
        msg.push_str(&format!(
            "This deletes {name}{size} as it extracts into {}.\n",
            dest.display()
        ));
        match space_figures(kind, archive, dest, flags) {
            Some((extract, consume)) if extract > consume => msg.push_str(&format!(
                "It saves {} of free space over a normal extract.\n",
                bytes(extract - consume)
            )),
            Some((extract, consume)) => msg.push_str(&format!(
                "Warning: it saves {} over a normal extract here{}; `trunc x` without --consume \
                 keeps the archive.\n",
                bytes(0),
                if consume > extract {
                    format!(" and needs {} more free space", bytes(consume - extract))
                } else {
                    String::new()
                }
            )),
            None => msg.push_str(&format!(
                "`trunc plan {name}` shows how much space it saves.\n"
            )),
        }
        if kind != Kind::Trnc {
            msg.push_str(&format!(
                "Other {kind} tools cannot open the file once the first step has run.\n"
            ));
        }
    }
    eprint!("{msg}If interrupted, run: trunc resume {name}\nContinue? [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

pub fn run(
    archive: &Path,
    dest: &Path,
    flags: &ConsumeFlags,
    stream: &StreamOptions,
    trust: TrustPolicy,
    threads: usize,
) -> Result<ExitCode> {
    let fs = OsFs::new();
    let kind = Kind::detect(archive, stream.raw);
    crate::refuse_trust_flags(&trust, kind)?;
    if kind == Kind::SevenZ {
        bail!(crate::sevenz_cmd::NO_CONSUME);
    }
    if stream.raw && !matches!(kind, Kind::Stream(..)) {
        bail!("--raw applies only to compressed tarballs");
    }
    if !matches!(kind, Kind::Stream(..))
        && trunc_engine::source::split_parts(&fs, archive)?.is_some()
    {
        bail!(
            "--consume does not support split {kind} archives yet; extract without --consume, \
             or join the parts into one file first"
        );
    }
    let state = state(archive);
    if state == State::Receipt {
        return Err(receipt_error(archive));
    }
    let resuming = matches!(state, State::Partly { .. });
    let merged;
    let flags = if resuming {
        if let Some(saved) = read_saved(archive) {
            merged = flags.with_saved(&saved);
            let d = SavedFlags::of(&merged).describe();
            if !d.is_empty() {
                eprintln!("resuming with: {}", d.join(" "));
            }
            &merged
        } else {
            eprintln!(
                "note: the flags this consume started with were not recorded (started by an \
                 older trunc, or the record is gone); if you used --verify-media, --batch, \
                 --checkpoint-every, --punch-min, --no-punch, --no-receipt or an --allow-* \
                 flag, pass it again"
            );
            flags
        }
    } else {
        flags
    };
    if !flags.yes && !confirm(archive, dest, kind, flags, resuming)? {
        eprintln!("cancelled; nothing was changed");
        return Ok(ExitCode::FAILURE);
    }
    if !resuming {
        // Durable before the engine takes its first destructive step.
        write_saved(&fs, archive, &SavedFlags::of(flags))?;
    }
    let opts = flags.options(*stream, trust, threads);
    let unit = match kind {
        Kind::Zip | Kind::SevenZ => "entries",
        Kind::Iso | Kind::Tar => "files",
        Kind::Stream(..) => "checkpoints",
        Kind::Trnc => "blocks",
    };
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
                let line = format!(
                    "{blocks_done}/{blocks_total} {unit}  {} written  archive now {}",
                    bytes(bytes_written),
                    bytes(archive_len)
                );
                // Padded so a shorter update covers the tail of a longer one; no escape codes,
                // which older Windows consoles print literally.
                eprint!("\r{line:<78}");
            }
        }
        Progress::Renaming => {
            if tty {
                eprintln!();
            }
            eprintln!("all {unit} consumed; moving files into place");
        }
    };
    let result = match kind {
        Kind::Zip => zipconsume::consume_zip(&fs, archive, dest, &opts, &mut progress),
        Kind::Iso => isoconsume::consume_iso(
            &fs,
            archive,
            dest,
            &opts,
            flags.allow_skipped,
            &mut progress,
        ),
        Kind::SevenZ => unreachable!("refused above"),
        Kind::Tar => tarconsume::consume_tar(&fs, archive, dest, &opts, &mut progress),
        Kind::Stream(..) => streamconsume::consume_stream(&fs, archive, dest, &opts, &mut progress),
        Kind::Trnc => consume::consume(&fs, archive, dest, &opts, &mut progress),
    };
    match result {
        Ok(s) => {
            remove_saved(&fs, archive);
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
            if s.specials_skipped > 0 {
                println!(
                    "devices   {} device or FIFO entries skipped",
                    s.specials_skipped
                );
            }
            crate::iso_cmd::summary_lines(&s);
            match &s.receipt {
                Some(r) => println!("archive   consumed; receipt kept at {}", r.display()),
                None => println!("archive   consumed and removed"),
            }
            let steps = if kind == Kind::Trnc {
                "batches"
            } else {
                "steps"
            };
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
                "paused safely: {what}, then run `trunc resume {}`.",
                archive.display()
            );
            eprintln!("nothing has been lost: the remaining data is still in the archive.");
            Ok(ExitCode::from(EXIT_PAUSED))
        }
        Err(e) => {
            // Refused before anything was destroyed: drop the record of the flags too.
            if !resuming && self::state(archive) == State::Fresh {
                remove_saved(&fs, archive);
            }
            Err(e.into())
        }
    }
}

/// Destination for `trunc resume`: the explicit one, else the one recorded when consumption
/// started (journal, or `.trnc` resume note). Refuses archives that were never
/// started, so `resume` cannot begin a fresh destructive run by accident.
pub fn resume_dest(archive: &Path, dest: Option<PathBuf>) -> Result<PathBuf> {
    let recorded = match state(archive) {
        State::Partly { dest } => dest,
        State::Receipt => bail!(
            "{}: this is the receipt of a finished consume; nothing to resume",
            archive.display()
        ),
        State::Fresh if std::fs::symlink_metadata(archive).is_err() => {
            let receipt = consume::receipt_path(archive);
            if receipt.exists() {
                bail!(
                    "{} was already consumed (its receipt is {}); nothing to resume",
                    archive.display(),
                    receipt.display()
                );
            }
            bail!("{}: not found", archive.display());
        }
        State::Fresh => bail!(
            "nothing to resume: {} has not been partly consumed (start with `trunc x --consume`)",
            archive.display()
        ),
    };
    match (dest, recorded) {
        (Some(d), _) | (None, Some(d)) => Ok(d),
        (None, None) => bail!(
            "no resume note or journal found next to {}; pass the destination with -C",
            archive.display()
        ),
    }
}

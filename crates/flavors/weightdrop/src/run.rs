//! Planning and unpacking a shard set with trunc's stream consumer.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use trunc_core::space::SpaceParams;
use trunc_engine::consume::{ConsumeOptions, Progress};
use trunc_engine::preflight;
use trunc_engine::streamconsume::{self, Mode, StreamLayout, StreamOptions};
use trunc_engine::zipconsume::ZipOptions;
use trunc_fs::OsFs;
use trunc_legacy::tar::Kind;

use crate::fmt_bytes;
use crate::inputs;
use crate::plan::{self, SetPlan, ShardSpace};
use crate::shards;
use crate::state::{Layout, ShardState, State, Status};

/// Options for [`unpack`].
#[derive(Debug, Clone)]
pub struct UnpackOptions {
    /// Files, directories or globs naming the shards.
    pub inputs: Vec<String>,
    pub dest: PathBuf,
    /// Non-destructive: extract and keep the archives.
    pub keep: bool,
    /// All shards straight into `dest`; refuse if names collide.
    pub flatten: bool,
    /// Start even if the plan says the set will not fit.
    pub ignore_space: bool,
    /// Test hook: stop (as if interrupted) after this many shards were unpacked in this run.
    #[doc(hidden)]
    pub stop_after: Option<usize>,
}

impl UnpackOptions {
    pub fn new(inputs: Vec<String>, dest: impl Into<PathBuf>) -> Self {
        Self {
            inputs,
            dest: dest.into(),
            keep: false,
            flatten: false,
            ignore_space: false,
            stop_after: None,
        }
    }
}

/// What [`unpack`] reports while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A line of information (layout chosen, resuming, plan summary).
    Note(String),
    ShardStart {
        /// 1-based position in the whole set.
        number: usize,
        count: usize,
        name: String,
        resumed: bool,
    },
    /// Output bytes written in this run, out of the bytes this run will write (0 if unknown).
    Bytes { done: u64, total: u64 },
    ShardDone {
        number: usize,
        count: usize,
        name: String,
        bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackSummary {
    pub shards: usize,
    /// Shards unpacked by this run.
    pub unpacked: usize,
    pub bytes: u64,
    pub files: usize,
    pub layout: Layout,
    /// Stopped early by the test hook; run again to continue.
    pub stopped: bool,
}

/// A scanned shard: trunc's layout and its space figures.
#[derive(Debug)]
pub struct Scanned {
    pub layout: StreamLayout,
    pub space: ShardSpace,
}

/// Per-shard and whole-set planning figures.
#[derive(Debug)]
pub struct PlanReport {
    pub shards: Vec<ShardSpace>,
    pub plan: SetPlan,
    pub same_volume: bool,
    pub can_dealloc: bool,
    pub dest_free: Option<u64>,
    pub dest_fs: String,
    /// Shards already finished by an earlier run (from the state file).
    pub already_done: usize,
    pub notes: Vec<String>,
}

fn every() -> u64 {
    ZipOptions::default().checkpoint_every
}

fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    loop {
        if cur.exists() {
            return cur;
        }
        match cur.parent() {
            Some(parent) => cur = parent.to_path_buf(),
            None => return cur,
        }
    }
}

fn display_name(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// The shard list for `inputs`: from the destination's state file when a run was started
/// there, else freshly detected (with every check on names and numbering).
fn jobs(inputs: &[String], dest: &Path) -> Result<(Option<State>, Vec<ShardState>, Vec<String>)> {
    let found = inputs::resolve(inputs)?;
    let mut notes = Vec::new();
    if let Some(st) = State::load(dest)? {
        let known: BTreeSet<PathBuf> = st
            .shards
            .iter()
            .map(|s| std::path::absolute(&s.path).unwrap_or_else(|_| s.path.clone()))
            .collect();
        let names: Vec<String> = found.keys().cloned().collect();
        if let Ok(d) = shards::detect(&names) {
            for set in &d.sets {
                for sh in &set.shards {
                    let p = std::path::absolute(&found[&sh.name])?;
                    if !known.contains(&p) {
                        bail!(
                            "{} holds an unfinished weightdrop run for a different set ({} is not \
                             part of it); finish that run or pick another destination",
                            dest.display(),
                            p.display()
                        );
                    }
                }
            }
        }
        let shards = st.shards.clone();
        return Ok((Some(st), shards, notes));
    }
    let names: Vec<String> = found.keys().cloned().collect();
    let d = shards::detect(&names).map_err(|e| anyhow!(e))?;
    if d.shard_count() == 0 {
        bail!(
            "no archives found (looked for .tar.zst, .tar.gz, .tgz, .tar.xz, .tar.bz2, and split \
             parts .001/.aa of them)"
        );
    }
    if !d.ignored.is_empty() {
        notes.push(format!(
            "ignoring {} file(s) that are not archives: {}",
            d.ignored.len(),
            d.ignored
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let mut out = Vec::new();
    for set in &d.sets {
        for sh in &set.shards {
            if sh.is_plain_tar() {
                bail!(
                    "{} is an uncompressed .tar; weightdrop (trunc) can only consume compressed \
                     tarballs so far (.tar.zst, .tar.gz, .tar.xz, .tar.bz2)",
                    sh.name
                );
            }
            let path = std::path::absolute(&found[&sh.name])?;
            if !path.exists() {
                bail!("{}: no such file", path.display());
            }
            out.push(ShardState {
                status: Status::Pending,
                subdir: sh.stem.clone(),
                path,
            });
        }
    }
    if d.sets.len() > 1 {
        notes.push(format!(
            "{} shard sets found ({}); unpacking them one after another",
            d.sets.len(),
            d.sets
                .iter()
                .map(|s| format!("{:?} x{}", s.prefix, s.shards.len()))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok((None, out, notes))
}

fn has_journal(fs: &OsFs, p: &Path) -> bool {
    streamconsume::journal_dest(fs, p).is_some()
}

/// Scan one shard (a full read-only decode) and size it with trunc's planner.
fn scan(fs: &OsFs, path: &Path, dest: &Path) -> Result<(Scanned, preflight::VolumeCheck)> {
    match streamconsume::detect(fs, path, false) {
        Some((_, Mode::Tar)) => {}
        Some((_, Mode::Single)) => bail!(
            "{} is a compressed file but not a tarball; unpack it with `trunc x --consume`",
            path.display()
        ),
        None => bail!(
            "{} is not a gzip, bzip2, xz or zstd compressed tarball",
            path.display()
        ),
    }
    let layout = streamconsume::open_layout(fs, path, every(), &StreamOptions::default())
        .with_context(|| format!("scanning {}", path.display()))?;
    let largest = layout
        .entries
        .iter()
        .max_by_key(|e| e.size)
        .map(|e| (e.name.as_str(), e.size));
    let vc = preflight::check_volumes(fs, path, &existing_ancestor(dest), largest)?;
    let can_dealloc = vc.archive_volume.supports_sparse && vc.archive_volume.sparse_granularity > 0;
    let params = SpaceParams {
        cluster_size: u64::from(vc.destination.cluster_size.max(1)),
        ..SpaceParams::default()
    };
    let sp = streamconsume::stream_space(
        &layout,
        can_dealloc,
        u64::from(vc.archive_volume.sparse_granularity.max(1)),
        &trunc_engine::source::part_sizes(fs, path)?,
        // TODO: take this from the destination filesystem (FAT/exFAT copy hard links).
        true,
        &params,
    );
    let space = ShardSpace {
        name: display_name(path),
        archive_len: layout.file_len,
        content: sp.content,
        extract_extra: sp.extract_extra,
        consume_peak: sp.consume_peak,
    };
    Ok((Scanned { layout, space }, vc))
}

/// What a shard will create in its target folder: top-level names when consuming (trunc moves
/// those into place), every file path when extracting.
fn claims(layout: &StreamLayout, keep: bool) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut claimed = BTreeSet::new();
    let mut dirs = BTreeSet::new();
    for e in &layout.entries {
        if keep {
            if e.kind == Kind::Dir {
                dirs.insert(e.name.clone());
            } else {
                claimed.insert(e.name.clone());
            }
            let mut p = trunc_core::path::parent(&e.name);
            while let Some(d) = p {
                dirs.insert(d.to_owned());
                p = trunc_core::path::parent(d);
            }
        } else {
            let top = e.name.split('/').next().unwrap_or(&e.name);
            claimed.insert(top.to_owned());
        }
    }
    (claimed, dirs)
}

/// The first name two shards would both create in a flat layout.
pub fn first_clash(
    per_shard: &[(String, BTreeSet<String>, BTreeSet<String>)],
) -> Option<(String, String, String)> {
    let mut owner: BTreeMap<String, &str> = BTreeMap::new();
    let mut dir_owner: BTreeMap<String, &str> = BTreeMap::new();
    for (shard, claimed, dirs) in per_shard {
        for c in claimed {
            let k = trunc_core::path::host_key(c);
            if let Some(o) = owner.get(&k).or(dir_owner.get(&k)) {
                return Some((c.clone(), (*o).to_owned(), shard.clone()));
            }
            owner.insert(k, shard);
        }
        for d in dirs {
            let k = trunc_core::path::host_key(d);
            if let Some(o) = owner.get(&k) {
                return Some((d.clone(), (*o).to_owned(), shard.clone()));
            }
            dir_owner.entry(k).or_insert(shard);
        }
    }
    None
}

fn consume_opts(ignore_space: bool) -> ConsumeOptions {
    ConsumeOptions {
        skip_space_check: ignore_space,
        ..ConsumeOptions::default()
    }
}

fn target(dest: &Path, sh: &ShardState, layout: Layout) -> PathBuf {
    match layout {
        Layout::Flat => dest.to_path_buf(),
        Layout::PerShard => dest.join(&sh.subdir),
    }
}

/// Scan the shards still to do and plan them. Used by both `plan` and `unpack`.
struct Prepared {
    st: Option<State>,
    all: Vec<ShardState>,
    /// Index into `all` and scan, for every shard still to unpack (not done, no journal).
    scanned: Vec<(usize, Scanned)>,
    report: PlanReport,
}

fn prepare(fs: &OsFs, inputs: &[String], dest: &Path, keep: bool) -> Result<Prepared> {
    let (st, all, notes) = jobs(inputs, dest)?;
    let mut scanned = Vec::new();
    let (mut same_volume, mut can_dealloc) = (true, true);
    let (mut dest_free, mut dest_fs) = (None, String::new());
    let mut already_done = 0;
    for (i, sh) in all.iter().enumerate() {
        if sh.status == Status::Done {
            already_done += 1;
            continue;
        }
        if !keep && has_journal(fs, &sh.path) {
            continue; // half consumed; trunc's journal knows the rest
        }
        if !sh.path.exists() {
            if sh.status == Status::Started {
                already_done += 1; // finished just before the state file was updated
                continue;
            }
            bail!("{}: no such file", sh.path.display());
        }
        let (s, vc) = scan(fs, &sh.path, dest)?;
        same_volume &= vc.same_volume;
        can_dealloc &= vc.archive_volume.supports_sparse;
        dest_free = vc.destination.free_bytes;
        dest_fs.clone_from(&vc.destination.fs_name);
        scanned.push((i, s));
    }
    let spaces: Vec<ShardSpace> = scanned.iter().map(|(_, s)| s.space.clone()).collect();
    let plan = plan::plan(&spaces, same_volume);
    Ok(Prepared {
        st,
        all,
        scanned,
        report: PlanReport {
            shards: spaces,
            plan,
            same_volume,
            can_dealloc,
            dest_free,
            dest_fs,
            already_done,
            notes,
        },
    })
}

/// `weightdrop plan`: scan every shard (read-only) and plan the set.
pub fn plan_set(inputs: &[String], dest: &Path) -> Result<PlanReport> {
    Ok(prepare(&OsFs::new(), inputs, dest, false)?.report)
}

/// `weightdrop unpack`. Safe to run again after any interruption: it continues where the
/// previous run stopped.
#[allow(clippy::too_many_lines)]
pub fn unpack(opts: &UnpackOptions, events: &mut dyn FnMut(Event)) -> Result<UnpackSummary> {
    let fs = OsFs::new();
    let dest = std::path::absolute(&opts.dest)?;
    let Prepared {
        st,
        all,
        scanned,
        report,
    } = prepare(&fs, &opts.inputs, &dest, opts.keep)?;
    for n in &report.notes {
        events(Event::Note(n.clone()));
    }
    let count = all.len();

    // Layout: fixed by the first run; otherwise chosen now, before anything is destroyed.
    let per_shard: Vec<(String, BTreeSet<String>, BTreeSet<String>)> = scanned
        .iter()
        .map(|(i, s)| {
            let (c, d) = claims(&s.layout, opts.keep);
            (display_name(&all[*i].path), c, d)
        })
        .collect();
    let layout = match &st {
        Some(st) => {
            if st.keep != opts.keep {
                bail!(
                    "this destination was started {}; run again {} --keep",
                    if st.keep {
                        "with --keep"
                    } else {
                        "without --keep"
                    },
                    if st.keep { "with" } else { "without" }
                );
            }
            if opts.flatten && st.layout == Layout::PerShard {
                bail!("this destination was started with per-shard folders; drop --flatten");
            }
            events(Event::Note(format!(
                "resuming: {} of {count} shards already unpacked",
                report.already_done
            )));
            st.layout
        }
        None => match first_clash(&per_shard) {
            None => Layout::Flat,
            Some((name, a, b)) if opts.flatten => bail!(
                "--flatten: {a} and {b} both contain {name:?}; nothing was changed. Drop \
                 --flatten to give each shard its own folder"
            ),
            Some((name, a, b)) => {
                events(Event::Note(format!(
                    "{a} and {b} both contain {name:?}: each shard gets its own folder"
                )));
                Layout::PerShard
            }
        },
    };
    let flat = st.as_ref().is_some_and(|s| s.layout == Layout::Flat);
    if let Some((name, a, b)) = first_clash(&per_shard).filter(|_| flat) {
        bail!("{a} and {b} both contain {name:?}; nothing more was changed");
    }

    // Nothing a shard creates may exist already (outputs of shards started earlier aside).
    for ((i, _), (_, claimed, _)) in scanned.iter().zip(&per_shard) {
        let sh = &all[*i];
        if sh.status == Status::Started {
            continue;
        }
        let t = target(&dest, sh, layout);
        if let Some(c) = claimed.iter().find(|c| t.join(c).exists()) {
            bail!(
                "{} already exists (it would be written by {}); nothing was changed",
                t.join(c).display(),
                display_name(&sh.path)
            );
        }
    }

    // Space for the whole set.
    let need = if opts.keep {
        report.plan.extract_extra
    } else {
        report.plan.consume_extra
    };
    if let Some(free) = report.dest_free {
        events(Event::Note(format!(
            "needs {} free at the destination ({} free); a plain extract would need {}",
            fmt_bytes(need),
            fmt_bytes(free),
            fmt_bytes(report.plan.extract_extra)
        )));
        if free < need && !opts.ignore_space {
            bail!(
                "not enough free space: unpacking these {} shards needs about {}, {} is free \
                 (nothing was changed; --ignore-space to try anyway)",
                scanned.len(),
                fmt_bytes(need),
                fmt_bytes(free)
            );
        }
    }

    std::fs::create_dir_all(&dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut st = st.unwrap_or_else(|| State {
        keep: opts.keep,
        layout,
        shards: all.clone(),
    });
    st.save(&dest)?;

    let total: u64 = scanned.iter().map(|(_, s)| s.space.content).sum();
    let mut done_bytes = 0u64;
    let mut summary = UnpackSummary {
        shards: count,
        unpacked: 0,
        bytes: 0,
        files: 0,
        layout,
        stopped: false,
    };
    for i in 0..count {
        let sh = st.shards[i].clone();
        if sh.status == Status::Done {
            continue;
        }
        let journaled = !opts.keep && has_journal(&fs, &sh.path);
        if !journaled && !sh.path.exists() && sh.status == Status::Started {
            st.shards[i].status = Status::Done;
            st.save(&dest)?;
            continue;
        }
        if opts.stop_after.is_some_and(|n| summary.unpacked >= n) {
            summary.stopped = true;
            return Ok(summary);
        }
        let name = display_name(&sh.path);
        let resumed = sh.status == Status::Started;
        events(Event::ShardStart {
            number: i + 1,
            count,
            name: name.clone(),
            resumed,
        });
        st.shards[i].status = Status::Started;
        st.save(&dest)?;
        let t = target(&dest, &sh, layout);
        std::fs::create_dir_all(&t)?;
        let base = done_bytes;
        let s = if opts.keep {
            streamconsume::extract_stream(&fs, &sh.path, &t, resumed, &StreamOptions::default())?
        } else {
            let mut progress = |p: Progress| {
                if let Progress::Batch { bytes_written, .. } = p {
                    events(Event::Bytes {
                        done: base + bytes_written,
                        total,
                    });
                }
            };
            streamconsume::consume_stream(
                &fs,
                &sh.path,
                &t,
                &consume_opts(opts.ignore_space),
                &mut progress,
            )
            .map_err(|e| match e {
                trunc_engine::Error::Paused(r) => anyhow!(
                    "paused safely: {r}. Nothing was lost; run the same command \
                     again to continue"
                ),
                e => anyhow::Error::from(e),
            })?
        };
        done_bytes += s.bytes_written;
        events(Event::Bytes {
            done: done_bytes,
            total,
        });
        st.shards[i].status = Status::Done;
        st.save(&dest)?;
        summary.unpacked += 1;
        summary.bytes += s.bytes_written;
        summary.files += s.files;
        events(Event::ShardDone {
            number: i + 1,
            count,
            name,
            bytes: s.bytes_written,
        });
    }
    State::remove(&dest)?;
    Ok(summary)
}

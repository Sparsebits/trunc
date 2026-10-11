//! `trunc` — create, inspect, verify and extract `.trnc` archives.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use trunc_codec::CodecChoice;
use trunc_core::space::SpaceParams;
use trunc_core::{CodecId, EntryKind};
use trunc_engine::extract::{ExtractOptions, TrustPolicy};
use trunc_engine::producer::{CreateOptions, DictMode};
use trunc_engine::streamconsume::{self, Mode};
use trunc_engine::{Archive, keys};
use trunc_legacy::stream::Codec;

mod consume_cmd;
mod fmt;
mod image_cmd;
mod iso_cmd;
mod sevenz_cmd;
mod stream_cmd;
mod tar_cmd;
mod zip_cmd;
use fmt::{bytes, parse_size};

#[derive(Debug, Parser)]
#[command(
    name = "trunc",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("TRUNC_COMMIT"), ")"),
    about = "Self-consuming archives: extract using only the space the output needs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Profile the run: write a Chrome trace to FILE (open it in ui.perfetto.dev) and
    /// print where the time went. `-` prints the summary only. Also TRUNC_PROFILE=FILE.
    #[arg(long, global = true, value_name = "FILE")]
    profile: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a .trnc archive from files and directories.
    Create(CreateArgs),
    /// Extract an archive (non-destructive unless --consume).
    #[command(alias = "x")]
    Extract(ExtractArgs),
    /// Continue an interrupted or paused --consume.
    Resume(ResumeArgs),
    /// Show an archive's header, manifest summary and space requirements.
    Inspect(InspectArgs),
    /// Check every block and entry hash without extracting.
    Verify(VerifyArgs),
    /// Report how much free space extraction and consumption need.
    Plan(PlanArgs),
    /// Manage signing keys.
    #[command(subcommand)]
    Key(KeyCmd),
}

#[derive(Debug, Args)]
struct CreateArgs {
    /// Output archive path (conventionally *.trnc).
    out: PathBuf,
    /// Files and directories to add.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    /// Decoded bytes per block (e.g. 4M, 8M, 32M).
    #[arg(long, default_value = "8M", value_parser = parse_block_size)]
    block_size: u64,
    /// store, lz4, zstd or zstd:LEVEL (-7..22)
    #[arg(long, default_value = "zstd:9", value_parser = parse_codec)]
    codec: CodecChoice,
    /// "train" to train a zstd dictionary from the inputs, or a path to a dictionary file.
    #[arg(long)]
    dict: Option<String>,
    /// Secret key file to sign the manifest with (see `trunc key gen`).
    #[arg(long)]
    sign: Option<PathBuf>,
    /// Compression threads (0 = all cores).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Replace the output file if it exists.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct TrustArgs {
    /// Refuse unsigned archives.
    #[arg(long)]
    require_signed: bool,
    /// Accept only archives signed by this public key (hex). Repeatable.
    #[arg(long = "trust-key", value_name = "HEX")]
    trust_keys: Vec<String>,
}

impl TrustArgs {
    fn policy(&self) -> Result<TrustPolicy> {
        Ok(TrustPolicy {
            require_signed: self.require_signed,
            trusted_keys: self
                .trust_keys
                .iter()
                .map(|k| keys::parse_public(k))
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Debug, Args)]
struct ExtractArgs {
    archive: PathBuf,
    /// Destination directory.
    #[arg(short = 'C', long = "dest", default_value = ".")]
    dest: PathBuf,
    /// Destructive mode: truncate the archive as files are extracted, so extraction needs
    /// only about (output size - archive size) of free space. The archive is gone afterwards.
    #[arg(long)]
    consume: bool,
    #[command(flatten)]
    consume_flags: consume_cmd::ConsumeFlags,
    #[command(flatten)]
    stream: stream_cmd::StreamArgs,
    #[command(flatten)]
    image: image_cmd::ImageArgs,
    /// Replace existing files at destination paths.
    #[arg(long)]
    overwrite: bool,
    /// Create symlink entries that resolve inside the destination.
    #[arg(long)]
    allow_symlinks: bool,
    #[command(flatten)]
    trust: TrustArgs,
    /// Decode threads (0 = all cores).
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Debug, Args)]
struct ResumeArgs {
    archive: PathBuf,
    /// Destination directory (default: the one recorded when the consume started).
    #[arg(short = 'C', long = "dest")]
    dest: Option<PathBuf>,
    #[command(flatten)]
    consume_flags: consume_cmd::ConsumeFlags,
    #[command(flatten)]
    stream: stream_cmd::StreamArgs,
    #[command(flatten)]
    trust: TrustArgs,
    /// Decode threads (0 = all cores).
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Debug, Args)]
struct InspectArgs {
    archive: PathBuf,
    /// List entries.
    #[arg(long)]
    entries: bool,
    /// List blocks.
    #[arg(long)]
    blocks: bool,
    #[command(flatten)]
    stream: stream_cmd::StreamArgs,
    #[command(flatten)]
    image: image_cmd::ImageArgs,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    archive: PathBuf,
    #[command(flatten)]
    trust: TrustArgs,
    #[command(flatten)]
    stream: stream_cmd::StreamArgs,
    #[command(flatten)]
    image: image_cmd::ImageArgs,
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Debug, Args)]
struct PlanArgs {
    archive: PathBuf,
    /// Destination directory (need not exist yet).
    #[arg(short = 'C', long = "dest", default_value = ".")]
    dest: PathBuf,
    /// Decoded bytes per consume batch (one flush + truncate per batch).
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    batch: u64,
    #[command(flatten)]
    stream: stream_cmd::StreamArgs,
}

#[derive(Debug, Subcommand)]
enum KeyCmd {
    /// Generate a new signing key and print its public key.
    Gen {
        /// Where to write the secret key (refuses to overwrite).
        out: PathBuf,
    },
    /// Print the public key of a secret key file.
    Show { key: PathBuf },
}

fn parse_codec(s: &str) -> Result<CodecChoice, String> {
    CodecChoice::parse(s)
        .ok_or_else(|| format!("unknown codec {s:?}; use store, lz4, zstd or zstd:<-7..22>"))
}

fn parse_block_size(s: &str) -> Result<u64, String> {
    let v = parse_size(s)?;
    if !(trunc_chunk::MIN_BLOCK_SIZE..=trunc_chunk::MAX_BLOCK_SIZE).contains(&v) {
        return Err(format!(
            "block size must be between {} and {}",
            bytes(trunc_chunk::MIN_BLOCK_SIZE),
            bytes(trunc_chunk::MAX_BLOCK_SIZE)
        ));
    }
    Ok(v)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let profile = cli
        .profile
        .clone()
        .or_else(|| std::env::var_os("TRUNC_PROFILE").map(PathBuf::from));
    if profile.is_some() {
        trunc_prof::enable();
    }
    let span = trunc_prof::span(match &cli.cmd {
        Cmd::Create(_) => "cli.create",
        Cmd::Extract(_) => "cli.extract",
        Cmd::Resume(_) => "cli.resume",
        Cmd::Inspect(_) => "cli.inspect",
        Cmd::Verify(_) => "cli.verify",
        Cmd::Plan(_) => "cli.plan",
        Cmd::Key(_) => "cli.key",
    });
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    };
    drop(span);
    if let Some(path) = profile {
        write_profile(&path);
    }
    code
}

/// Print the profile summary and write the Chrome trace (unless the path is `-`).
fn write_profile(path: &std::path::Path) {
    let (events, dropped) = trunc_prof::take();
    eprintln!();
    eprint!("{}", trunc_prof::summary(&events, dropped, 30));
    if path.as_os_str() == "-" {
        return;
    }
    let process = format!(
        "trunc {}",
        std::env::args().skip(1).collect::<Vec<_>>().join(" ")
    );
    match std::fs::write(path, trunc_prof::chrome_trace(&events, &process)) {
        Ok(()) => eprintln!(
            "trace written to {} (open it in https://ui.perfetto.dev or chrome://tracing)",
            path.display()
        ),
        Err(e) => eprintln!(
            "warning: could not write the trace to {}: {e}",
            path.display()
        ),
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Create(a) => create(a),
        Cmd::Extract(a) => extract(a),
        Cmd::Resume(a) => {
            let dest = consume_cmd::resume_dest(&a.archive, a.dest)?;
            consume_cmd::run(
                &a.archive,
                &dest,
                &a.consume_flags,
                &a.stream.options(),
                a.trust.policy()?,
                a.threads,
            )
        }
        Cmd::Inspect(a) => inspect(a),
        Cmd::Verify(a) => verify(a),
        Cmd::Plan(a) => plan(a),
        Cmd::Key(k) => key(k),
    }
}

fn create(a: CreateArgs) -> Result<ExitCode> {
    let dict = match a.dict.as_deref() {
        None => DictMode::None,
        Some("train") => DictMode::Train,
        Some(p) => {
            DictMode::Bytes(std::fs::read(p).with_context(|| format!("reading dictionary {p}"))?)
        }
    };
    let signing_key = a.sign.as_deref().map(keys::load_secret).transpose()?;
    let opts = CreateOptions {
        block_size: a.block_size,
        codec: a.codec,
        dict,
        signing_key,
        threads: a.threads,
        overwrite: a.force,
    };
    let t = Instant::now();
    let s = trunc_engine::producer::create(&a.out, &a.inputs, &opts)?;
    let secs = t.elapsed().as_secs_f64();
    println!("created   {}", a.out.display());
    println!("entries   {}", s.entries);
    println!("blocks    {}", s.blocks);
    println!(
        "size      {} -> {} ({:.1}% of original)",
        bytes(s.total_u),
        bytes(s.archive_len),
        pct(s.archive_len, s.total_u)
    );
    if s.dict_len > 0 {
        println!("dict      {}", bytes(s.dict_len));
    }
    if s.dict_training_skipped {
        println!("note      too few files to train a dictionary; created without one");
    }
    println!("id        {}", hex::encode(s.archive_id));
    println!("time      {secs:.2}s ({}/s)", bytes(rate(s.total_u, secs)));
    Ok(ExitCode::SUCCESS)
}

fn extract(a: ExtractArgs) -> Result<ExitCode> {
    if image_cmd::detect(&a.archive, &a.stream) {
        image_cmd::refuse_flags(&a.trust.policy()?, a.allow_symlinks)?;
        match image_cmd::extract(
            &a.archive,
            &a.dest,
            a.consume,
            a.overwrite,
            a.consume_flags.ignore_space,
            &a.image,
            &a.stream,
            a.threads,
        ) {
            Err(e) if image_cmd::not_an_image(&e, &a.archive) => {}
            r => return r,
        }
    }
    if a.consume {
        if a.overwrite || a.allow_symlinks {
            anyhow::bail!("--overwrite and --allow-symlinks are not supported with --consume");
        }
        return consume_cmd::run(
            &a.archive,
            &a.dest,
            &a.consume_flags,
            &a.stream.options(),
            a.trust.policy()?,
            a.threads,
        );
    }
    let kind = Kind::detect(&a.archive, a.stream.raw);
    if kind != Kind::Trnc {
        refuse_trust_flags(&a.trust.policy()?, kind)?;
        if a.allow_symlinks {
            anyhow::bail!("--allow-symlinks is not supported for {kind} archives");
        }
    }
    match kind {
        Kind::Stream(..) => {
            return stream_cmd::extract(
                &a.archive,
                &a.dest,
                a.overwrite,
                a.consume_flags.ignore_space,
                &a.stream.options(),
            );
        }
        Kind::Zip => {
            return zip_cmd::extract(
                &a.archive,
                &a.dest,
                a.overwrite,
                a.consume_flags.ignore_space,
            );
        }
        Kind::Iso => {
            return iso_cmd::extract(
                &a.archive,
                &a.dest,
                a.overwrite,
                a.consume_flags.ignore_space,
                a.consume_flags.allow_overlap,
            );
        }
        Kind::SevenZ => {
            return sevenz_cmd::extract(
                &a.archive,
                &a.dest,
                a.overwrite,
                a.consume_flags.ignore_space,
                a.stream.max_window.max(1),
            );
        }
        Kind::Tar => {
            return tar_cmd::extract(
                &a.archive,
                &a.dest,
                a.overwrite,
                a.consume_flags.ignore_space,
            );
        }
        Kind::Trnc => {}
    }
    if a.stream.raw {
        anyhow::bail!("--raw applies only to compressed tarballs");
    }
    let archive = Archive::open(&a.archive)?;
    // Refuse up front when the declared output cannot fit (guards against archives that expand
    // to far more than the disk holds).
    if !a.consume_flags.ignore_space {
        let p = trunc_engine::preflight::assess(
            &trunc_fs::OsFs::new(),
            &archive,
            &a.dest,
            SpaceParams::default(),
        )?;
        if p.extract_fits == Some(false) {
            anyhow::bail!(
                "not enough free space at {}: extracting needs about {}, {} are free (--consume needs about {}; --ignore-space to try anyway)",
                a.dest.display(),
                bytes(p.bound.extract_extra),
                bytes(p.destination.free_bytes.unwrap_or(0)),
                bytes(p.consume_needs)
            );
        }
    }
    let opts = ExtractOptions {
        overwrite: a.overwrite,
        allow_symlinks: a.allow_symlinks,
        trust: a.trust.policy()?,
        threads: a.threads,
    };
    let t = Instant::now();
    let s = trunc_engine::extract::extract(&archive, &a.dest, &opts)?;
    let secs = t.elapsed().as_secs_f64();
    println!(
        "extracted {} files, {} directories, {} into {}",
        s.files,
        s.dirs,
        bytes(s.bytes),
        a.dest.display()
    );
    if s.symlinks_created > 0 {
        println!("symlinks  {} created", s.symlinks_created);
    }
    if s.symlinks_skipped > 0 {
        println!(
            "symlinks  {} skipped (use --allow-symlinks; links escaping the destination are always skipped)",
            s.symlinks_skipped
        );
    }
    println!("time      {secs:.2}s ({}/s)", bytes(rate(s.bytes, secs)));
    Ok(ExitCode::SUCCESS)
}

/// What an archive is, detected by content (never by its name). Archives being consumed are
/// recognised by their journal, since their front may already be gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Trnc,
    Zip,
    Iso,
    SevenZ,
    Tar,
    Stream(Codec, Mode),
}

impl Kind {
    pub(crate) fn detect(archive: &std::path::Path, raw: bool) -> Self {
        let fs = trunc_fs::OsFs::new();
        if let Some((codec, mode)) = streamconsume::detect(&fs, archive, raw) {
            Kind::Stream(codec, mode)
        } else if iso_cmd::is_iso(archive) {
            // Before ZIP: a ZIP stored as an image's last file would also parse as a ZIP.
            Kind::Iso
        } else if sevenz_cmd::is_7z(archive) {
            Kind::SevenZ
        } else if tar_cmd::is_tar(archive) {
            // Before ZIP too: a ZIP stored as the last file of a tar could also parse as a ZIP.
            Kind::Tar
        } else if zip_cmd::is_zip(archive) {
            Kind::Zip
        } else {
            Kind::Trnc
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Trnc => f.write_str(".trnc"),
            Kind::Zip => f.write_str("ZIP"),
            Kind::Iso => f.write_str("ISO"),
            Kind::SevenZ => f.write_str("7z"),
            Kind::Tar => f.write_str("tar"),
            Kind::Stream(c, m) => f.write_str(&stream_cmd::label(*c, *m)),
        }
    }
}

/// Only `.trnc` archives carry signatures. Asking for one must not be silently ignored: a file
/// named `.trnc` might really be a ZIP.
pub(crate) fn refuse_trust_flags(trust: &TrustPolicy, kind: Kind) -> Result<()> {
    if kind != Kind::Trnc && (trust.require_signed || !trust.trusted_keys.is_empty()) {
        anyhow::bail!(
            "this is a {kind} archive, which cannot be signed; --require-signed and --trust-key \
             apply only to .trnc archives"
        );
    }
    Ok(())
}

fn signer_line(archive: &Archive) -> String {
    match archive.signer() {
        Some(k) => format!("signed by {}", keys::public_hex(&k)),
        None => "unsigned".into(),
    }
}

fn inspect(a: InspectArgs) -> Result<ExitCode> {
    if image_cmd::detect(&a.archive, &a.stream) {
        match image_cmd::inspect(&a.archive, a.entries, &a.image, &a.stream) {
            Err(e) if image_cmd::not_an_image(&e, &a.archive) => {}
            r => return r,
        }
    }
    match Kind::detect(&a.archive, a.stream.raw) {
        Kind::Stream(..) => {
            return stream_cmd::inspect(&a.archive, a.entries, &a.stream.options());
        }
        Kind::Zip => return zip_cmd::inspect(&a.archive, a.entries),
        Kind::Iso => return iso_cmd::inspect(&a.archive, a.entries),
        Kind::SevenZ => {
            return sevenz_cmd::inspect(&a.archive, a.entries, a.stream.max_window.max(1));
        }
        Kind::Tar => return tar_cmd::inspect(&a.archive, a.entries),
        Kind::Trnc => {}
    }
    let archive = Archive::open(&a.archive)?;
    let m = archive.manifest();
    let h = archive.header();
    let (files, others) = m.entry_counts();
    let n = m.blocks.len();
    println!("archive    {}", a.archive.display());
    println!("id         {}", hex::encode(m.archive_id));
    println!("producer   {}", m.producer);
    println!("created    {} (unix)", m.created_unix);
    println!("signature  {}", signer_line(&archive));
    println!(
        "manifest   {} (hash {})",
        bytes(h.manifest_len),
        hex::encode(archive.manifest_hash())
    );
    println!(
        "dictionary {}",
        if h.dict_len > 0 {
            bytes(h.dict_len)
        } else {
            "none".into()
        }
    );
    println!("entries    {files} files, {others} directories/links");
    println!("content    {}", bytes(m.total_u));
    println!(
        "stored     {} in {n} blocks ({:.1}% of content)",
        bytes(m.total_c),
        pct(m.total_c, m.total_u)
    );
    let mut by_codec = [0usize; 3];
    for b in &m.blocks {
        by_codec[usize::from(b.codec).min(2)] += 1;
    }
    println!(
        "codecs     {} zstd, {} lz4, {} stored",
        by_codec[CodecId::Zstd as usize],
        by_codec[CodecId::Lz4 as usize],
        by_codec[CodecId::Store as usize]
    );
    println!("file size  {}", bytes(archive.file_len()));
    if archive.is_complete() {
        println!("state      complete");
    } else {
        println!(
            "state      partially consumed: {} of {n} blocks consumed",
            archive.consumed()
        );
    }
    if a.entries {
        println!();
        for e in &m.entries {
            let kind = match &e.kind {
                EntryKind::File => format!("{:>12}", e.size),
                EntryKind::Dir => format!("{:>12}", "<dir>"),
                EntryKind::Symlink { target } => format!("{:>12} -> {target}", "<link>"),
            };
            println!("{kind}  {}", e.path);
        }
    }
    if a.blocks {
        println!();
        println!(
            "{:>8} {:>14} {:>12} {:>12} {:>6} {:>14}",
            "block", "stream_off", "u_len", "c_len", "codec", "file_off"
        );
        for (i, b) in m.blocks.iter().enumerate() {
            let codec = CodecId::try_from(b.codec).map(CodecId::name).unwrap_or("?");
            let state = if i < archive.consumed() {
                " consumed"
            } else {
                ""
            };
            println!(
                "{i:>8} {:>14} {:>12} {:>12} {codec:>6} {:>14}{state}",
                b.stream_off,
                b.u_len,
                b.c_len,
                archive.block_offset(i)
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn verify(a: VerifyArgs) -> Result<ExitCode> {
    if image_cmd::detect(&a.archive, &a.stream) {
        image_cmd::refuse_flags(&a.trust.policy()?, false)?;
        match image_cmd::verify(&a.archive, &a.image, &a.stream, a.threads) {
            Err(e) if image_cmd::not_an_image(&e, &a.archive) => {}
            r => return r,
        }
    }
    let kind = Kind::detect(&a.archive, a.stream.raw);
    refuse_trust_flags(&a.trust.policy()?, kind)?;
    match kind {
        Kind::Stream(..) => return stream_cmd::verify(&a.archive, &a.stream.options()),
        Kind::Zip => return zip_cmd::verify(&a.archive),
        Kind::Iso => return iso_cmd::verify(&a.archive),
        Kind::SevenZ => {
            return sevenz_cmd::verify(&a.archive, a.stream.max_window.max(1), a.threads);
        }
        Kind::Tar => return tar_cmd::verify(&a.archive),
        Kind::Trnc => {}
    }
    let archive = Archive::open(&a.archive)?;
    let t = Instant::now();
    let s = trunc_engine::extract::verify(&archive, &a.trust.policy()?, a.threads)?;
    println!(
        "ok: {} blocks, {} entries, {} verified in {:.2}s ({})",
        s.blocks,
        s.entries,
        bytes(s.bytes),
        t.elapsed().as_secs_f64(),
        signer_line(&archive)
    );
    Ok(ExitCode::SUCCESS)
}

/// Exit codes for `plan`: both fit, only `--consume` fits, neither fits.
const PLAN_ONLY_CONSUME: u8 = 2;
const PLAN_NEITHER: u8 = 3;

fn volume_line(v: &trunc_fs::VolumeInfo) -> String {
    let free = v.free_bytes.map_or("free space unknown".into(), |f| {
        format!("{} free", bytes(f))
    });
    let journal = if v.journaled() {
        "journaled"
    } else {
        "NOT journaled"
    };
    let root = v
        .root
        .as_ref()
        .map_or(String::new(), |r| format!("{} ", r.display()));
    format!(
        "{root}{} ({journal}, cluster {}), {free}",
        v.fs_name,
        bytes(u64::from(v.cluster_size))
    )
}

fn fits(f: Option<bool>) -> &'static str {
    match f {
        Some(true) => "fits",
        Some(false) => "DOES NOT FIT",
        None => "unknown",
    }
}

fn plan(a: PlanArgs) -> Result<ExitCode> {
    if image_cmd::detect(&a.archive, &a.stream) {
        anyhow::bail!(
            "plan does not support container images yet; `trunc inspect` shows the layer sizes"
        );
    }
    match Kind::detect(&a.archive, a.stream.raw) {
        Kind::Stream(..) => {
            return stream_cmd::plan(&a.archive, &a.dest, &a.stream.options());
        }
        Kind::Zip => return zip_cmd::plan(&a.archive, &a.dest, true),
        Kind::Iso => return iso_cmd::plan(&a.archive, &a.dest),
        Kind::SevenZ => {
            return sevenz_cmd::plan(&a.archive, &a.dest, a.stream.max_window.max(1));
        }
        Kind::Tar => return tar_cmd::plan(&a.archive, &a.dest),
        Kind::Trnc => {}
    }
    use trunc_engine::preflight::{self, Severity};
    let archive = Archive::open(&a.archive)?;
    let params = SpaceParams {
        batch_max_u: a.batch,
        ..SpaceParams::default()
    };
    let p = preflight::assess(&trunc_fs::OsFs::new(), &archive, &a.dest, params)?;
    let b = &p.bound;
    println!("destination   {}", volume_line(&p.destination));
    if p.same_volume {
        println!("archive       same volume");
    } else {
        println!("archive       {}", volume_line(&p.archive_volume));
    }
    println!("archive now   {}", bytes(b.archive_len));
    println!("content       {} to write", bytes(b.remaining_u));
    println!(
        "allowances    {} rounding/metadata + {} margin",
        bytes(b.slack),
        bytes(b.margin)
    );
    println!();
    println!("free space needed at the destination:");
    println!(
        "  extract (keeps archive)   {:>12}   {}",
        bytes(b.extract_extra),
        fits(p.extract_fits)
    );
    println!(
        "  consume (--consume)       {:>12}   {}   (peak occupancy {}, {} batch{})",
        bytes(p.consume_needs),
        fits(p.consume_fits),
        bytes(b.consume_peak),
        b.batches,
        if b.batches == 1 { "" } else { "es" }
    );
    if p.same_volume && b.extract_extra > 0 {
        println!(
            "  consume saves {} ({:.1}%)",
            bytes(b.extract_extra.saturating_sub(p.consume_needs)),
            100.0 - pct(p.consume_needs, b.extract_extra)
        );
    }
    if !p.findings.is_empty() {
        println!();
        for f in &p.findings {
            let tag = match f.severity() {
                Severity::Blocker => "blocks --consume",
                Severity::Warning => "warning",
                Severity::Note => "note",
            };
            println!("[{tag}] {f}");
        }
    }
    println!();
    println!("figures are conservative upper bounds, not exact predictions");
    Ok(match (p.extract_fits, p.consume_fits) {
        (Some(false), Some(true)) => ExitCode::from(PLAN_ONLY_CONSUME),
        (Some(false), Some(false)) => ExitCode::from(PLAN_NEITHER),
        _ => ExitCode::SUCCESS,
    })
}

fn key(k: KeyCmd) -> Result<ExitCode> {
    match k {
        KeyCmd::Gen { out } => {
            let key = keys::generate()?;
            keys::save_secret(&out, &key)?;
            println!("secret key written to {} (keep it private)", out.display());
            println!(
                "public key {}",
                keys::public_hex(&key.verifying_key().to_bytes())
            );
        }
        KeyCmd::Show { key } => {
            let k = keys::load_secret(&key)?;
            println!("{}", keys::public_hex(&k.verifying_key().to_bytes()));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Bytes per second, saturating.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn rate(n: u64, secs: f64) -> u64 {
    (n as f64 / secs.max(1e-9)) as u64
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

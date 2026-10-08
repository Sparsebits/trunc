//! `trunc` — create, inspect, verify and extract `.trnc` archives.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use trunc_codec::CodecChoice;
use trunc_core::space::{self, SpaceParams};
use trunc_core::{CodecId, EntryKind};
use trunc_engine::extract::{ExtractOptions, TrustPolicy};
use trunc_engine::producer::{CreateOptions, DictMode};
use trunc_engine::{Archive, keys};

mod fmt;
use fmt::{bytes, parse_size};

#[derive(Debug, Parser)]
#[command(
    name = "trunc",
    version,
    about = "Self-consuming archives: extract using only the space the output needs"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create a .trnc archive from files and directories.
    Create(CreateArgs),
    /// Extract an archive (non-destructive unless --consume).
    #[command(alias = "x")]
    Extract(ExtractArgs),
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
    /// Destructive mode: consume the archive while extracting (phase 3).
    #[arg(long)]
    consume: bool,
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
struct InspectArgs {
    archive: PathBuf,
    /// List entries.
    #[arg(long)]
    entries: bool,
    /// List blocks.
    #[arg(long)]
    blocks: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    archive: PathBuf,
    #[command(flatten)]
    trust: TrustArgs,
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Debug, Args)]
struct PlanArgs {
    archive: PathBuf,
    /// Destination filesystem cluster size.
    #[arg(long, default_value = "4K", value_parser = parse_size)]
    cluster: u64,
    /// Decoded bytes per consume batch (one flush + truncate per batch).
    #[arg(long, default_value = "256M", value_parser = parse_size)]
    batch: u64,
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
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Create(a) => create(a),
        Cmd::Extract(a) => extract(a),
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
    if a.consume {
        bail!("--consume (destructive extraction) is not implemented yet; it arrives in phase 3");
    }
    let archive = Archive::open(&a.archive)?;
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

fn signer_line(archive: &Archive) -> String {
    match archive.signer() {
        Some(k) => format!("signed by {}", keys::public_hex(&k)),
        None => "unsigned".into(),
    }
}

fn inspect(a: InspectArgs) -> Result<ExitCode> {
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

fn plan(a: PlanArgs) -> Result<ExitCode> {
    let archive = Archive::open(&a.archive)?;
    let params = SpaceParams {
        cluster_size: a.cluster,
        batch_max_u: a.batch,
        ..SpaceParams::default()
    };
    let b = space::bound(
        archive.manifest(),
        archive.header().first_block_off(),
        archive.consumed(),
        &params,
    );
    println!("archive now            {}", bytes(b.archive_len));
    println!("content to write       {}", bytes(b.remaining_u));
    println!(
        "allowances             {} rounding/metadata + {} margin",
        bytes(b.slack),
        bytes(b.margin)
    );
    println!("free space needed:");
    println!("  extract (keeps archive)   {}", bytes(b.extract_extra));
    println!(
        "  consume (--consume)       {}  (peak occupancy {}, {} batches)",
        bytes(b.consume_extra),
        bytes(b.consume_peak),
        b.batches
    );
    if b.extract_extra > 0 {
        println!(
            "consume saves {} ({:.1}%) of free space",
            bytes(b.extract_extra.saturating_sub(b.consume_extra)),
            100.0 - pct(b.consume_extra, b.extract_extra)
        );
    }
    println!(
        "note: this is a conservative upper bound; volume probing (free space, filesystem, snapshots) arrives in phase 2"
    );
    Ok(ExitCode::SUCCESS)
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

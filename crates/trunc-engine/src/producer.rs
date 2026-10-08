//! Creating `.trnc` archives.
//!
//! The manifest sits before the blocks but describes all of them, and blocks are written in
//! reverse order. So the producer compresses blocks in logical order into a temporary spool
//! file next to the output, then writes the final file: header, manifest, dictionary, and the
//! spooled payloads from last block to first, each followed by its footer. The output is
//! written as `<out>.partial` and renamed into place only after it is flushed.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rayon::prelude::*;
use trunc_codec::{CodecChoice, Dict};
use trunc_core::manifest::DictInfo;
use trunc_core::{
    BlockRecord, Entry, EntryKind, FORMAT_VERSION, Header, MAX_BLOCK_U, MAX_DICT_LEN, Manifest,
    SignedManifest,
};

use crate::error::{Error, IoContext, Result, at};
use crate::io::{len_usize, read_exact_at};
use crate::walk::{ItemKind, walk_inputs};

/// How to obtain a zstd dictionary.
#[derive(Debug, Clone, Default)]
pub enum DictMode {
    #[default]
    None,
    /// Train one from samples of the input files.
    Train,
    /// Use these dictionary bytes.
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Decoded bytes per block.
    pub block_size: u64,
    pub codec: CodecChoice,
    pub dict: DictMode,
    pub signing_key: Option<SigningKey>,
    /// Worker threads for compression; 0 = all cores.
    pub threads: usize,
    /// Replace an existing output file.
    pub overwrite: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            block_size: trunc_chunk::DEFAULT_BLOCK_SIZE,
            codec: CodecChoice::Zstd { level: 9 },
            dict: DictMode::None,
            signing_key: None,
            threads: 0,
            overwrite: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateSummary {
    pub entries: usize,
    pub blocks: usize,
    pub total_u: u64,
    pub total_c: u64,
    pub archive_len: u64,
    pub archive_id: [u8; 16],
    pub manifest_hash: [u8; 32],
    pub dict_len: u64,
    /// Set when dictionary training was requested but produced nothing usable.
    pub dict_training_skipped: bool,
}

const DICT_SAMPLE_BYTES: usize = 16 << 10;
const DICT_MAX_SAMPLES: usize = 4096;
const DICT_TARGET_SIZE: usize = 110 << 10;
/// Cap on decoded bytes held in memory per parallel compression round.
const ROUND_BYTES: u64 = 512 << 20;

/// Create an archive at `out` from `inputs`.
pub fn create(out: &Path, inputs: &[PathBuf], opts: &CreateOptions) -> Result<CreateSummary> {
    if opts.block_size == 0 || opts.block_size > MAX_BLOCK_U {
        return Err(Error::Input(format!(
            "block size {} out of range",
            opts.block_size
        )));
    }
    if inputs.is_empty() {
        return Err(Error::Input("no inputs given".into()));
    }
    if !opts.overwrite && fs::symlink_metadata(out).is_ok() {
        return Err(Error::Refused(format!("{} already exists", out.display())));
    }
    if !matches!(opts.dict, DictMode::None) && !matches!(opts.codec, CodecChoice::Zstd { .. }) {
        return Err(Error::Input("a dictionary requires the zstd codec".into()));
    }

    let items = walk_inputs(inputs)?;
    let mut entries = Vec::with_capacity(items.len());
    let mut off = 0u64;
    for it in &items {
        let kind = match &it.kind {
            ItemKind::File => EntryKind::File,
            ItemKind::Dir => EntryKind::Dir,
            ItemKind::Symlink(t) => EntryKind::Symlink { target: t.clone() },
        };
        entries.push(Entry {
            path: it.rel.clone(),
            kind,
            size: it.size,
            mode: it.mode,
            mtime_unix: it.mtime_unix,
            mtime_nanos: it.mtime_nanos,
            stream_off: off,
            blake3: trunc_hash::blake3(b""),
        });
        off += it.size;
    }
    let total_u = off;
    // Reject unportable or hostile paths before doing any work.
    for e in &entries {
        trunc_core::path::validate(&e.path)?;
    }

    let (dict, dict_training_skipped) = match &opts.dict {
        DictMode::None => (None, false),
        DictMode::Bytes(b) => {
            if b.is_empty() || b.len() as u64 > MAX_DICT_LEN {
                return Err(Error::Input(format!(
                    "dictionary size {} out of range",
                    b.len()
                )));
            }
            (Some(Dict(b.clone())), false)
        }
        DictMode::Train => match train(&items)? {
            Some(d) => (Some(d), false),
            None => (None, true),
        },
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.threads)
        .build()
        .map_err(|e| Error::Input(format!("cannot start worker threads: {e}")))?;
    let threads = pool.current_num_threads().max(1) as u64;
    let per_round = (ROUND_BYTES / opts.block_size).clamp(1, threads * 2);

    let out_dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let spool = tempfile::Builder::new()
        .prefix(".trunc-spool-")
        .suffix(".spool")
        .tempfile_in(out_dir)
        .ctx(at("creating spool file in", out_dir))?;

    // Compress the logical stream into the spool, block by block in logical order.
    let mut reader = StreamReader::new(&items);
    let mut blocks: Vec<BlockRecord> = Vec::new();
    let mut spool_offs: Vec<u64> = Vec::new();
    let mut spool_w = BufWriter::with_capacity(1 << 20, spool.as_file());
    let mut spool_pos = 0u64;
    let mut stream_pos = 0u64;
    let mut chunks = trunc_chunk::FixedChunker::new(total_u, opts.block_size).peekable();
    while chunks.peek().is_some() {
        let mut raw_blocks = Vec::new();
        for r in chunks.by_ref().take(len_usize(per_round)) {
            let mut buf = vec![0u8; len_usize(r.end - r.start)];
            reader.fill(&mut buf)?;
            raw_blocks.push(buf);
        }
        let compressed: Vec<Result<_>> = pool.install(|| {
            raw_blocks
                .par_iter()
                .map(|raw| {
                    let (codec, comp) = trunc_codec::compress(opts.codec, raw, dict.as_ref())?;
                    Ok((codec, comp, trunc_hash::blake3(raw)))
                })
                .collect()
        });
        for (res, raw) in compressed.into_iter().zip(&raw_blocks) {
            let (codec, comp, blake3_u) = res?;
            spool_w
                .write_all(&comp)
                .ctx(at("writing spool in", out_dir))?;
            blocks.push(BlockRecord {
                stream_off: stream_pos,
                u_len: raw.len() as u64,
                c_len: comp.len() as u64,
                codec: codec.as_u16(),
                blake3_c: trunc_hash::blake3(&comp),
                blake3_u,
            });
            spool_offs.push(spool_pos);
            spool_pos += comp.len() as u64;
            stream_pos += raw.len() as u64;
        }
    }
    spool_w.flush().ctx(at("writing spool in", out_dir))?;
    drop(spool_w);
    for (i, h) in reader.finish()? {
        entries[i].blake3 = h;
    }

    let mut archive_id = [0u8; 16];
    getrandom::fill(&mut archive_id)
        .map_err(|e| Error::Input(format!("OS random source failed: {e}")))?;
    let leaves: Vec<[u8; 32]> = blocks.iter().map(|b| b.blake3_u).collect();
    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        archive_id,
        created_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0),
        producer: crate::PRODUCER.into(),
        total_c: blocks.iter().map(|b| b.c_len).sum(),
        total_u,
        merkle_root: trunc_hash::merkle::root(&leaves),
        dict: dict.as_ref().map(|d| DictInfo {
            len: d.0.len() as u64,
            blake3: trunc_hash::blake3(&d.0),
        }),
        entries,
        blocks,
    };
    manifest.validate()?;
    let body = manifest.encode_body();
    let manifest_hash = trunc_hash::blake3(&body);
    let region = SignedManifest::new(body, opts.signing_key.as_ref()).encode();
    let header = Header::for_manifest(&region, dict.as_ref().map_or(0, |d| d.0.len() as u64));

    // Write the final file: header, manifest, dict, then blocks n-1 .. 0.
    let partial = partial_path(out);
    let pf = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&partial)
        .ctx(at("creating", &partial))?;
    let mut w = BufWriter::with_capacity(1 << 20, &pf);
    let wctx = || format!("writing {}", partial.display());
    w.write_all(&header.encode()).ctx(wctx)?;
    w.write_all(&region).ctx(wctx)?;
    if let Some(d) = &dict {
        w.write_all(&d.0).ctx(wctx)?;
    }
    let spool_file = spool.as_file();
    let mut copy_buf = vec![0u8; 1 << 20];
    for i in (0..manifest.blocks.len()).rev() {
        let b = &manifest.blocks[i];
        let mut pos = spool_offs[i];
        let mut left = b.c_len;
        while left > 0 {
            let n = left.min(copy_buf.len() as u64);
            let chunk = &mut copy_buf[..len_usize(n)];
            read_exact_at(spool_file, chunk, pos).ctx(at("reading spool in", out_dir))?;
            w.write_all(chunk).ctx(wctx)?;
            pos += n;
            left -= n;
        }
        w.write_all(&manifest.footer_for(i).encode()).ctx(wctx)?;
    }
    w.flush().ctx(wctx)?;
    drop(w);
    pf.sync_all().ctx(at("flushing", &partial))?;
    drop(pf);
    drop(spool);

    if opts.overwrite && fs::symlink_metadata(out).is_ok() {
        fs::remove_file(out).ctx(at("replacing", out))?;
    }
    fs::rename(&partial, out).ctx(at("renaming into place", out))?;

    let archive_len = manifest.archive_len(header.first_block_off());
    let (entries, blocks) = (manifest.entries.len(), manifest.blocks.len());
    Ok(CreateSummary {
        entries,
        blocks,
        total_u,
        total_c: manifest.total_c,
        archive_len,
        archive_id,
        manifest_hash,
        dict_len: header.dict_len,
        dict_training_skipped,
    })
}

fn partial_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_owned();
    s.push(".partial");
    PathBuf::from(s)
}

/// Train a dictionary from the first bytes of each input file. `None` if there is too little
/// material for zstd to train on.
fn train(items: &[crate::walk::Item]) -> Result<Option<Dict>> {
    let mut samples = Vec::new();
    for it in items
        .iter()
        .filter(|i| i.kind == ItemKind::File && i.size > 0)
    {
        if samples.len() >= DICT_MAX_SAMPLES {
            break;
        }
        let mut f = File::open(&it.abs).ctx(at("opening", &it.abs))?;
        let mut buf = vec![0u8; len_usize(it.size.min(DICT_SAMPLE_BYTES as u64))];
        f.read_exact(&mut buf).ctx(at("reading", &it.abs))?;
        samples.push(buf);
    }
    if samples.len() < 8 {
        return Ok(None);
    }
    Ok(trunc_codec::train_dict(&samples, DICT_TARGET_SIZE).ok())
}

/// Reads the concatenated contents of all file items in order, hashing each file.
struct StreamReader<'a> {
    items: &'a [crate::walk::Item],
    next: usize,
    current: Option<(usize, File, u64, trunc_hash::Blake3Hasher)>,
    done: Vec<(usize, [u8; 32])>,
}

impl<'a> StreamReader<'a> {
    fn new(items: &'a [crate::walk::Item]) -> Self {
        Self {
            items,
            next: 0,
            current: None,
            done: Vec::new(),
        }
    }

    /// Fill `buf` completely with the next stream bytes.
    fn fill(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            if self.current.is_none() {
                self.open_next()?;
            }
            let (idx, file, left, hasher) = self
                .current
                .as_mut()
                .expect("open_next sets current or errors");
            let it = &self.items[*idx];
            let want = buf.len().min(len_usize((*left).min(usize::MAX as u64)));
            let n = file.read(&mut buf[..want]).ctx(at("reading", &it.abs))?;
            if n == 0 {
                return Err(Error::Input(format!(
                    "{} shrank while being archived",
                    it.abs.display()
                )));
            }
            hasher.update(&buf[..n]);
            *left -= n as u64;
            buf = &mut buf[n..];
            if *left == 0 {
                let (idx, _, _, hasher) = self.current.take().expect("current is set");
                self.done.push((idx, *hasher.finalize().as_bytes()));
            }
        }
        Ok(())
    }

    fn open_next(&mut self) -> Result<()> {
        while self.next < self.items.len() {
            let idx = self.next;
            self.next += 1;
            let it = &self.items[idx];
            if it.kind != ItemKind::File || it.size == 0 {
                continue;
            }
            let f = File::open(&it.abs).ctx(at("opening", &it.abs))?;
            self.current = Some((idx, f, it.size, trunc_hash::Blake3Hasher::new()));
            return Ok(());
        }
        Err(Error::Input(
            "inputs ended before the expected total size".into(),
        ))
    }

    /// Per-file hashes of every non-empty file read.
    fn finish(self) -> Result<Vec<(usize, [u8; 32])>> {
        if self.current.is_some() {
            return Err(Error::Input("stream reader finished mid-file".into()));
        }
        Ok(self.done)
    }
}

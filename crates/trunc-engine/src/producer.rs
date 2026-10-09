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

    let items = trunc_prof::time("create.walk", || walk_inputs(inputs))?;
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
        let ranges: Vec<_> = chunks.by_ref().take(len_usize(per_round)).collect();
        let round_len: u64 = ranges.iter().map(|r| r.end - r.start).sum();
        let mut round = vec![0u8; len_usize(round_len)];
        trunc_prof::time("create.read_inputs", || {
            pool.install(|| reader.fill(&mut round))
        })?;
        let mut raw_blocks: Vec<&[u8]> = Vec::with_capacity(ranges.len());
        let mut from = 0usize;
        for r in &ranges {
            let n = len_usize(r.end - r.start);
            raw_blocks.push(&round[from..from + n]);
            from += n;
        }
        let compressed: Vec<Result<_>> = pool.install(|| {
            raw_blocks
                .par_iter()
                .map(|raw| {
                    let _prof = trunc_prof::span("create.compress").bytes(raw.len() as u64);
                    let (codec, comp) = trunc_codec::compress(opts.codec, raw, dict.as_ref())?;
                    Ok((
                        codec,
                        comp,
                        trunc_prof::time("hash.blake3", || trunc_hash::blake3(raw)),
                    ))
                })
                .collect()
        });
        let _spool = trunc_prof::span("create.spool");
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
    let assemble = trunc_prof::span("create.assemble");
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
    drop(assemble);
    trunc_prof::time("create.sync", || pf.sync_all()).ctx(at("flushing", &partial))?;
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

/// Reads the concatenated contents of all file items in order, hashing each file. A fill reads
/// the pieces of every file it covers on several threads (opening and reading many small files
/// is mostly waiting); each file's hash still advances in order.
struct StreamReader<'a> {
    items: &'a [crate::walk::Item],
    /// Non-empty files: (item index, offset in the stream, size).
    files: Vec<(usize, u64, u64)>,
    /// First file not yet completely read.
    cursor: usize,
    /// Stream offset of the next byte.
    pos: u64,
    /// Hashes of files read partway.
    partial: std::collections::HashMap<usize, trunc_hash::Blake3Hasher>,
    done: Vec<(usize, [u8; 32])>,
}

impl<'a> StreamReader<'a> {
    fn new(items: &'a [crate::walk::Item]) -> Self {
        let mut files = Vec::new();
        let mut off = 0u64;
        for (i, it) in items.iter().enumerate() {
            if it.kind == ItemKind::File && it.size > 0 {
                files.push((i, off, it.size));
                off += it.size;
            }
        }
        Self {
            items,
            files,
            cursor: 0,
            pos: 0,
            partial: std::collections::HashMap::new(),
            done: Vec::new(),
        }
    }

    /// Fill `buf` completely with the next stream bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        let end = self.pos + buf.len() as u64;
        // The pieces of the files this range covers, in order; they tile it exactly.
        struct Piece<'b> {
            item: usize,
            file_off: u64,
            last: bool,
            out: &'b mut [u8],
            hasher: trunc_hash::Blake3Hasher,
        }
        let mut pieces: Vec<Piece<'_>> = Vec::new();
        let mut rest: &mut [u8] = buf;
        let mut k = self.cursor;
        while !rest.is_empty() {
            let &(item, off, size) = self.files.get(k).ok_or_else(|| {
                Error::Input("inputs ended before the expected total size".into())
            })?;
            let start = self.pos.max(off);
            let stop = end.min(off + size);
            let (out, tail) = std::mem::take(&mut rest).split_at_mut(len_usize(stop - start));
            rest = tail;
            let hasher = self.partial.remove(&item).unwrap_or_default();
            pieces.push(Piece {
                item,
                file_off: start - off,
                last: stop == off + size,
                out,
                hasher,
            });
            if stop == off + size {
                k += 1;
            }
        }
        let items = self.items;
        let read: Vec<Result<(usize, bool, trunc_hash::Blake3Hasher)>> = pieces
            .into_par_iter()
            .map(|mut p| {
                let it = &items[p.item];
                let f = File::open(&it.abs).ctx(at("opening", &it.abs))?;
                match read_exact_at(&f, p.out, p.file_off) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Err(Error::Input(format!(
                            "{} shrank while being archived",
                            it.abs.display()
                        )));
                    }
                    Err(e) => return Err(e).ctx(at("reading", &it.abs)),
                }
                p.hasher.update(p.out);
                Ok((p.item, p.last, p.hasher))
            })
            .collect();
        for r in read {
            let (item, last, hasher) = r?;
            if last {
                self.done.push((item, *hasher.finalize().as_bytes()));
            } else {
                self.partial.insert(item, hasher);
            }
        }
        self.cursor = k;
        self.pos = end;
        Ok(())
    }

    /// Per-file hashes of every non-empty file read.
    fn finish(self) -> Result<Vec<(usize, [u8; 32])>> {
        if !self.partial.is_empty() || self.cursor != self.files.len() {
            return Err(Error::Input("stream reader finished mid-file".into()));
        }
        Ok(self.done)
    }
}

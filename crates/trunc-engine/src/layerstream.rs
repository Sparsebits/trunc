//! Container image layers extracted in a single pass from sequential streams (a registry pull),
//! to the merged root filesystem of the image. The tarball path ([`crate::image`]) scans every
//! layer first and writes only the winning entries; a network stream can be read only once, so
//! here each layer is decoded, verified and applied as it arrives:
//!
//! - every blob is hashed while it streams (its digest) and its decoded tar hashed again (its
//!   `diff_id`), with trunc's own gzip/zstd decoders reading the stream through a forward-only
//!   window;
//! - entries are written into a staging directory as they appear; a whiteout, an opaque marker
//!   or a later entry replacing an earlier one deletes what earlier layers wrote *inside the
//!   staging directory* (whiteouts only ever hide lower layers, never entries of their own
//!   layer, wherever they appear in it);
//! - only when every layer has been read and every digest checked is the merged tree renamed
//!   into the destination. On any failure the staging directory is removed and the destination
//!   is left as it was.
//!
//! Symlinks, devices and FIFOs are skipped (counted), as for image tarballs.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use trunc_fs::{Dealloc, FileHandle, FileId, FsBackend, FsError};
use trunc_hash::Sha256Hasher;
use trunc_legacy::stream::{self, Codec, Input, Limits, NoHistory, StreamError};
use trunc_legacy::tar::{self, Kind};

use crate::error::{Error, Result};
use crate::image::{
    Declared, ImageSummary, MergeStats, check_digest, declared, digest_hex, random_hex,
    remove_tree, stream_err, tar_err,
};
use crate::stage::{
    Item, ItemKind, StageGuard, ensure_dir, first_existing, join_rel, open_staged_output,
    rename_into_place, top_level_names,
};
use crate::walk::system_time;

/// Bytes pulled from a stream at a time.
const PULL_CHUNK: usize = 1 << 20;
/// Bytes kept behind the furthest read, for decoders that step back a little.
const KEEP_BEHIND: u64 = 4 << 20;

const OPAQUE: &str = ".wh..wh..opq";
const WHITEOUT: &str = ".wh.";

/// One layer as an image manifest and config describe it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerSpec {
    pub media_type: String,
    /// `sha256:<hex>` of the blob.
    pub digest: String,
    /// Size of the blob in bytes.
    pub size: u64,
    /// `sha256:<hex>` of the uncompressed tar.
    pub diff_id: String,
}

/// Settings for [`extract_layer_streams`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamOptions {
    /// Refuse zstd streams whose decoder window is larger than this (0: the default).
    pub max_window: u64,
}

/// A source of layer blobs, opened one at a time in order.
pub type OpenLayer<'a> = dyn FnMut(usize, &LayerSpec) -> Result<Box<dyn Read + Send>> + 'a;

// ---------------------------------------------------------------------------------------------
// A stream as a file.

struct Window {
    r: Box<dyn Read + Send>,
    /// Bytes `[start, start + buf.len())` of the stream.
    buf: Vec<u8>,
    start: u64,
    hash: Sha256Hasher,
    failed: Option<String>,
}

/// A sequential stream of `len` bytes presented as a file to trunc's decoders, which read
/// forward (with small steps back) when they run on one thread without safe points. Everything
/// pulled is hashed in order.
struct StreamBlob {
    path: PathBuf,
    len: u64,
    w: Mutex<Window>,
}

impl std::fmt::Debug for StreamBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamBlob")
            .field("path", &self.path)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl StreamBlob {
    fn new(name: &str, len: u64, r: Box<dyn Read + Send>) -> Self {
        Self {
            path: PathBuf::from(name),
            len,
            w: Mutex::new(Window {
                r,
                buf: Vec::new(),
                start: 0,
                hash: Sha256Hasher::new(),
                failed: None,
            }),
        }
    }

    fn io(&self, kind: std::io::ErrorKind, msg: String) -> FsError {
        FsError::Io {
            op: "downloading",
            path: self.path.clone(),
            source: std::io::Error::new(kind, msg),
        }
    }

    /// Pull until `end` bytes of the stream have been seen.
    fn pull_to(&self, w: &mut Window, end: u64) -> trunc_fs::Result<()> {
        if let Some(m) = &w.failed {
            return Err(self.io(std::io::ErrorKind::Other, m.clone()));
        }
        let mut chunk = vec![0u8; PULL_CHUNK];
        while w.start + (w.buf.len() as u64) < end {
            let seen = w.start + w.buf.len() as u64;
            let want = usize::try_from((self.len - seen).min(PULL_CHUNK as u64)).expect("<= chunk");
            let n = match w.r.read(&mut chunk[..want]) {
                Ok(0) => {
                    let m = format!(
                        "the blob ended after {seen} of its {} bytes (truncated download?)",
                        self.len
                    );
                    w.failed = Some(m.clone());
                    return Err(self.io(std::io::ErrorKind::UnexpectedEof, m));
                }
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    let m = format!("reading the blob: {e}");
                    w.failed = Some(m.clone());
                    return Err(self.io(e.kind(), m));
                }
            };
            w.hash.update(&chunk[..n]);
            w.buf.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    }

    /// Read the rest of the stream, check it ends where its descriptor says, and return the
    /// sha256 of everything.
    fn finish(self) -> Result<[u8; 32]> {
        let mut w = self.w.into_inner().unwrap_or_else(PoisonError::into_inner);
        let this = StreamBlob {
            path: self.path,
            len: self.len,
            w: Mutex::new(Window {
                r: Box::new(std::io::empty()),
                buf: Vec::new(),
                start: 0,
                hash: Sha256Hasher::new(),
                failed: None,
            }),
        };
        while w.start + (w.buf.len() as u64) < this.len {
            let seen = w.start + w.buf.len() as u64;
            this.pull_to(&mut w, (seen + PULL_CHUNK as u64).min(this.len))?;
            w.start += w.buf.len() as u64;
            w.buf.clear();
        }
        let mut one = [0u8; 1];
        loop {
            match w.r.read(&mut one) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(Error::Integrity(format!(
                        "{}: the blob is longer than the {} bytes its descriptor gives",
                        this.path.display(),
                        this.len
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(this.io(e.kind(), format!("reading the blob: {e}")).into()),
            }
        }
        Ok(w.hash.finalize())
    }

    fn unsupported(&self, op: &'static str) -> FsError {
        FsError::Unsupported {
            op,
            path: self.path.clone(),
        }
    }
}

impl FileHandle for StreamBlob {
    fn path(&self) -> &Path {
        &self.path
    }

    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> trunc_fs::Result<()> {
        let end = off
            .checked_add(buf.len() as u64)
            .filter(|&e| e <= self.len)
            .ok_or_else(|| {
                self.io(
                    std::io::ErrorKind::UnexpectedEof,
                    "read past the end of a layer blob".into(),
                )
            })?;
        let mut w = self.w.lock().unwrap_or_else(PoisonError::into_inner);
        if off < w.start {
            return Err(self.io(
                std::io::ErrorKind::Unsupported,
                format!(
                    "the decoder went back to byte {off} of a stream already read past byte {}",
                    w.start
                ),
            ));
        }
        self.pull_to(&mut w, end)?;
        let at = usize::try_from(off - w.start).expect("in window");
        buf.copy_from_slice(&w.buf[at..at + buf.len()]);
        // Drop what lies well behind this read.
        let keep_from = off.saturating_sub(KEEP_BEHIND);
        if keep_from > w.start + 2 * KEEP_BEHIND {
            let drop = usize::try_from(keep_from - w.start).expect("in window");
            w.buf.drain(..drop);
            w.start = keep_from;
        }
        Ok(())
    }

    fn write_all_at(&self, _buf: &[u8], _off: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("writing a layer stream"))
    }

    fn size(&self) -> trunc_fs::Result<u64> {
        Ok(self.len)
    }

    fn set_len(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("resizing a layer stream"))
    }

    fn preallocate(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("preallocating a layer stream"))
    }

    fn flush_data(&self) -> trunc_fs::Result<()> {
        Ok(())
    }

    fn deallocate(&self, _start: u64, _end: u64) -> trunc_fs::Result<Dealloc> {
        Ok(Dealloc::Unsupported)
    }

    fn allocated_ranges(&self) -> trunc_fs::Result<Vec<std::ops::Range<u64>>> {
        Ok(std::iter::once(0..self.len).collect())
    }

    fn file_id(&self) -> trunc_fs::Result<FileId> {
        Err(self.unsupported("identifying a layer stream"))
    }

    fn set_modified(&self, _t: std::time::SystemTime) -> trunc_fs::Result<()> {
        Err(self.unsupported("changing a layer stream"))
    }
}

// ---------------------------------------------------------------------------------------------
// The merged tree, applied to the staging directory as layers arrive.

#[derive(Debug, Clone)]
struct Node {
    name: String,
    kind: Kind,
    layer: usize,
    entry: Option<tar::Entry>,
}

struct Merger<'a> {
    fs: &'a dyn FsBackend,
    stage: &'a Path,
    tree: BTreeMap<String, Node>,
    stats: MergeStats,
    written: u64,
}

fn case_clash(a: &str, b: &str) -> Error {
    Error::Refused(format!(
        "layers name the same path as {a:?} and {b:?}, which differ only in case on this \
         computer; refusing to merge them"
    ))
}

impl Merger<'_> {
    fn path(&self, name: &str) -> PathBuf {
        join_rel(self.stage, name)
    }

    fn count_shadowed(&mut self, n: &Node) {
        if let Some(e) = &n.entry {
            self.stats.shadowed += 1;
            if e.kind == Kind::File {
                self.stats.shadowed_bytes += e.size;
            }
        }
    }

    /// Delete `key` (unless `children_only`) and everything below it that came from a layer
    /// before `layer`, from the tree and from the staging directory. A directory that still
    /// holds entries of `layer` itself stays (and now belongs to `layer`).
    fn remove_lower(&mut self, key: &str, layer: usize, children_only: bool) -> Result<()> {
        let mut keys: Vec<String> = if key.is_empty() {
            self.tree.keys().cloned().collect()
        } else {
            let lo = format!("{key}/");
            let hi = format!("{key}0");
            self.tree.range(lo..hi).map(|(k, _)| k.clone()).collect()
        };
        if !children_only && self.tree.contains_key(key) {
            keys.insert(0, key.to_owned());
        }
        // Deepest first: descendants sort after their ancestors.
        for k in keys.into_iter().rev() {
            let Some(n) = self.tree.get(&k).cloned() else {
                continue;
            };
            if n.layer >= layer && n.kind != Kind::Dir {
                continue;
            }
            if n.kind == Kind::Dir {
                let lo = format!("{k}/");
                let hi = format!("{k}0");
                if self.tree.range(lo..hi).next().is_some() {
                    if let Some(m) = self.tree.get_mut(&k) {
                        m.layer = m.layer.max(layer);
                    }
                    continue;
                }
                if n.layer >= layer {
                    continue;
                }
                self.fs.remove_dir(&self.path(&n.name))?;
            } else if matches!(n.kind, Kind::File) {
                self.fs.remove_file(&self.path(&n.name))?;
            }
            self.tree.remove(&k);
            self.count_shadowed(&n);
        }
        Ok(())
    }

    /// Delete `key` and everything below it, whatever layer it came from.
    fn remove_all(&mut self, key: &str) -> Result<()> {
        self.remove_lower(key, usize::MAX, false)
    }

    fn whiteout(
        &mut self,
        li: usize,
        e: &tar::Entry,
        base: &str,
        parent: Option<&str>,
    ) -> Result<()> {
        if e.kind == Kind::Dir {
            return Err(Error::Refused(format!(
                "layer {}: whiteout {:?} is a directory",
                li + 1,
                e.name
            )));
        }
        let target = &base[WHITEOUT.len()..];
        if base == OPAQUE {
            let key = trunc_core::path::host_key(parent.unwrap_or(""));
            self.remove_lower(&key, li, true)?;
            self.stats.opaques += 1;
        } else if target.starts_with(WHITEOUT) {
            // Other `.wh..wh.` names are aufs bookkeeping: ignored, like Docker does.
        } else if target.is_empty() || target == "." || target == ".." || target.contains('\\') {
            return Err(Error::Refused(format!(
                "layer {}: whiteout {:?} names no valid entry",
                li + 1,
                e.name
            )));
        } else {
            let victim = match parent {
                Some(p) => format!("{p}/{target}"),
                None => target.to_owned(),
            };
            let key = trunc_core::path::host_key(&victim);
            if let Some(n) = self.tree.get(&key) {
                if n.name != victim {
                    return Err(case_clash(&n.name, &victim));
                }
            }
            self.remove_lower(&key, li, false)?;
            self.stats.whiteouts += 1;
        }
        Ok(())
    }

    /// Make room for entry `e` of layer `li` and create it (an empty file for a file; its
    /// content follows). Returns whether its content is to be written.
    fn place(&mut self, li: usize, e: &tar::Entry) -> Result<bool> {
        let parent = trunc_core::path::parent(&e.name);
        let base = e.name.rsplit('/').next().unwrap_or(&e.name);
        if let Some(p) = parent {
            if p.split('/').any(|c| c.starts_with(WHITEOUT)) {
                return Err(Error::Refused(format!(
                    "layer {}: {:?} is inside a whiteout",
                    li + 1,
                    e.name
                )));
            }
        }
        if base.starts_with(WHITEOUT) {
            self.whiteout(li, e, base, parent)?;
            return Ok(false);
        }
        // Every ancestor must be a directory: make it one.
        let mut end = 0usize;
        while let Some(i) = e.name[end..].find('/') {
            let a = &e.name[..end + i];
            end += i + 1;
            let key = trunc_core::path::host_key(a);
            match self.tree.get(&key) {
                Some(n) if n.name != a => return Err(case_clash(&n.name, a)),
                Some(n) if n.kind == Kind::Dir => continue,
                Some(_) => self.remove_all(&key)?,
                None => {}
            }
            self.fs.create_dir(&self.path(a))?;
            self.tree.insert(
                key,
                Node {
                    name: a.to_owned(),
                    kind: Kind::Dir,
                    layer: li,
                    entry: None,
                },
            );
        }
        let key = trunc_core::path::host_key(&e.name);
        let mut dir_exists = false;
        if let Some(n) = self.tree.get(&key) {
            if n.name != e.name {
                return Err(case_clash(&n.name, &e.name));
            }
            if n.kind == Kind::Dir && e.kind == Kind::Dir {
                dir_exists = true;
                let n = n.clone();
                self.count_shadowed(&n);
            } else {
                self.remove_all(&key)?;
            }
        }
        match e.kind {
            Kind::Dir if !dir_exists => self.fs.create_dir(&self.path(&e.name))?,
            _ => {}
        }
        self.tree.insert(
            key,
            Node {
                name: e.name.clone(),
                kind: e.kind,
                layer: li,
                entry: Some(e.clone()),
            },
        );
        Ok(e.kind == Kind::File)
    }
}

// ---------------------------------------------------------------------------------------------
// Entry point.

/// Extract the merged root filesystem of an image whose layers arrive as sequential streams
/// into `dest` (created if missing). `open` is called once per layer, in order, for a reader of
/// its blob. Top-level names that already exist in `dest` are refused. `dest` gains either the
/// whole tree, after every digest has been checked, or nothing (a `dest` this call created is
/// removed again on failure). `on_layer` is told when each layer is done.
pub fn extract_layer_streams(
    fs: &dyn FsBackend,
    dest: &Path,
    layers: &[LayerSpec],
    opts: &StreamOptions,
    open: &mut OpenLayer<'_>,
    on_layer: &mut dyn FnMut(usize, &LayerSpec),
) -> Result<ImageSummary> {
    let _prof = trunc_prof::span("image.stream");
    for l in layers {
        digest_hex(&l.digest)?;
        digest_hex(&l.diff_id)?;
        declared(&l.media_type)?;
    }
    let created_dest = fs.metadata(dest)?.is_none();
    ensure_dir(fs, dest)?;
    let stage = dest.join(format!(".layerless-stage-{}", random_hex()));
    fs.create_dir(&stage)?;
    let r = run(fs, dest, &stage, layers, opts, open, on_layer);
    if r.is_err() {
        remove_tree(fs, &stage);
        if created_dest {
            let _ = fs.remove_dir(dest);
        }
    }
    r
}

#[allow(clippy::too_many_lines)]
fn run(
    fs: &dyn FsBackend,
    dest: &Path,
    stage: &Path,
    layers: &[LayerSpec],
    opts: &StreamOptions,
    open: &mut OpenLayer<'_>,
    on_layer: &mut dyn FnMut(usize, &LayerSpec),
) -> Result<ImageSummary> {
    let mut m = Merger {
        fs,
        stage,
        tree: BTreeMap::new(),
        stats: MergeStats::default(),
        written: 0,
    };
    let protected = |_: &FileId| false;
    let guard = StageGuard {
        root: stage,
        protected: &protected,
    };
    let limits = Limits {
        max_out: u64::MAX,
        max_window: if opts.max_window == 0 {
            Limits::DEFAULT_MAX_WINDOW
        } else {
            opts.max_window
        },
        // One thread and no safe points: the decoders then read their input front to back.
        threads: 1,
    };
    for (li, spec) in layers.iter().enumerate() {
        let what = format!("layer {} ({})", li + 1, spec.digest);
        let body = open(li, spec)?;
        let blob = StreamBlob::new(&what, spec.size, body);
        let mut reader = tar::Reader::new();
        let mut diff = Sha256Hasher::new();
        // The entry whose content is being written: (entry, handle).
        let mut cur: Option<(tar::Entry, Box<dyn FileHandle>)> = None;
        let mut seen = 0usize;
        let mut sink = |b: &[u8]| -> Result<()> {
            diff.update(b);
            let pos = reader.position();
            reader.feed(b).map_err(tar_err(&what))?;
            let end = pos + b.len() as u64;
            // Content of the entry already open.
            let write = |e: &tar::Entry, h: &dyn FileHandle, written: &mut u64| {
                let lo = e.data_offset.max(pos);
                let hi = (e.data_offset + e.size).min(end);
                if lo < hi {
                    let from = usize::try_from(lo - pos).expect("in chunk");
                    let to = usize::try_from(hi - pos).expect("in chunk");
                    h.write_all_at(&b[from..to], lo - e.data_offset)?;
                    *written += (to - from) as u64;
                }
                Ok::<bool, Error>(hi == e.data_offset + e.size)
            };
            if let Some((e, h)) = &cur {
                if write(e, h.as_ref(), &mut m.written)? {
                    h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                    cur = None;
                }
            }
            while seen < reader.entries().len() {
                let e = reader.entries()[seen].clone();
                seen += 1;
                m.stats.entries += 1;
                if !m.place(li, &e)? {
                    continue;
                }
                let (h, _) = open_staged_output(fs, &guard, &join_rel(stage, &e.name))?;
                if e.size == 0 || write(&e, h.as_ref(), &mut m.written)? {
                    h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                } else {
                    cur = Some((e, h));
                }
            }
            Ok(())
        };
        match declared(&spec.media_type)? {
            Declared::Tar | Declared::Unknown => {
                let mut at = 0u64;
                let mut buf = vec![0u8; PULL_CHUNK];
                while at < spec.size {
                    let n =
                        usize::try_from((spec.size - at).min(PULL_CHUNK as u64)).expect("<= chunk");
                    blob.read_exact_at(&mut buf[..n], at)?;
                    sink(&buf[..n])?;
                    at += n as u64;
                }
            }
            d => {
                let codec = if d == Declared::Gzip {
                    Codec::Gzip
                } else {
                    Codec::Zstd
                };
                let failure: std::cell::RefCell<Option<Error>> = std::cell::RefCell::new(None);
                let r = stream::decode(
                    codec,
                    Input {
                        src: &blob,
                        len: spec.size,
                    },
                    None,
                    &mut NoHistory,
                    limits,
                    0,
                    &mut |b| {
                        sink(b).map_err(|e| {
                            *failure.borrow_mut() = Some(e);
                            StreamError::Stopped
                        })
                    },
                    &mut |_| Ok(()),
                );
                if let Some(e) = failure.into_inner() {
                    return Err(e);
                }
                r.map_err(|e| match stream_err(e) {
                    Error::Integrity(s) => Error::Integrity(format!("{what}: {s}")),
                    Error::Input(s) => Error::Input(format!("{what}: {s}")),
                    e => e,
                })?;
            }
        }
        if cur.is_some() {
            return Err(Error::Integrity(format!(
                "{what}: the layer ends inside a file"
            )));
        }
        reader.finish().map_err(tar_err(&what))?;
        let blob_hash = blob.finish()?;
        check_digest(&what, &spec.digest, &blob_hash)?;
        check_digest(
            &format!("{what} (uncompressed)"),
            &spec.diff_id,
            &diff.finalize(),
        )?;
        on_layer(li, spec);
    }
    // Every digest checked: move the tree into place.
    let items: Vec<Item> = m
        .tree
        .values()
        .filter_map(|n| {
            let kind = match n.kind {
                Kind::File => ItemKind::File,
                Kind::Dir => ItemKind::Dir,
                Kind::Symlink => ItemKind::Symlink,
                Kind::Special => return None,
            };
            let e = n.entry.as_ref();
            Some(Item {
                path: n.name.clone(),
                kind,
                size: e.map_or(0, |e| e.size),
                mode: e.and_then(|e| e.mode),
                mtime_unix: e.map_or(0, |e| e.mtime_unix),
                mtime_nanos: e.map_or(0, |e| e.mtime_nanos),
            })
        })
        .collect();
    let tops = top_level_names(&items);
    if let Some(p) = first_existing(fs, dest, &tops)? {
        return Err(Error::Refused(format!(
            "{} already exists; pull the image into an empty directory",
            p.display()
        )));
    }
    let count = |k: ItemKind| items.iter().filter(|i| i.kind == k).count();
    let summary = ImageSummary {
        files: count(ItemKind::File),
        dirs: count(ItemKind::Dir),
        bytes_written: m.written,
        symlinks_skipped: count(ItemKind::Symlink),
        specials_skipped: m.tree.values().filter(|n| n.kind == Kind::Special).count(),
        stats: m.stats,
    };
    if tops.is_empty() {
        fs.remove_dir(stage)?;
        return Ok(summary);
    }
    crate::stage::flush_staging_tree(fs, stage, dest)?;
    rename_into_place(fs, &items, dest, stage)?;
    Ok(summary)
}

//! Container image tarballs: `docker save` output and OCI image layouts packed as a tar
//! (`oci-archive`), extracted to the merged root filesystem of the image (what `docker export`
//! of a container made from it would hold). See ADR-0016.
//!
//! 1. **Metadata.** The outer tar is indexed (uncompressed: by reading its headers only; gzip,
//!    bzip2, xz or zstd: decompressed into a temporary file first). `manifest.json` (Docker) or
//!    `index.json` (OCI, nested indexes followed) selects one image and platform, its config
//!    gives the layers' `diff_ids`. Every JSON blob reached through a digest is checked against
//!    it.
//! 2. **Scan** (read-only). Each layer blob is hashed (its digest), decoded with trunc's own
//!    decoders, hashed again (its `diff_id`) and its tar headers parsed and validated. The layers
//!    are then merged in order with OCI whiteout semantics into the final tree: which entry of
//!    which layer wins for every path. Nothing has been written yet.
//! 3. **Extract.** Only the winning entries are written, into a staging directory, which is then
//!    renamed into place. Files a later layer deletes or replaces are never written, so nothing
//!    is ever deleted. Digests are checked again while decoding the second time.
//!
//! Symlinks, devices and FIFOs in the image are skipped (counted), as for tarballs. Paths this
//! computer cannot create (names Windows forbids, names that differ only in case on Windows and
//! macOS) are left out of the tree after the merge and reported; see [`Skipped`].

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use trunc_fs::{Dealloc, FileHandle, FileId, FsBackend, FsError, NodeKind, OpenMode, Share};
use trunc_hash::Sha256Hasher;
use trunc_legacy::stream::{self, Codec, Input, Limits, NoHistory, StreamError};
use trunc_legacy::tar::{self, Kind};

use crate::error::{Error, Result};
use crate::json::Json;
use crate::source;
use crate::stage::{
    Item, ItemKind, StageGuard, build_structure, ensure_dir, first_existing, join_rel,
    open_staged_output, rename_into_place, top_level_names,
};
use crate::walk::system_time;

/// Largest JSON document read from an image (manifests, indexes, configs).
const MAX_JSON: u64 = 16 << 20;
/// Deepest chain of nested indexes followed.
const MAX_INDEX_DEPTH: usize = 4;
/// Decoded bytes looked at to recognise a compressed image tarball.
const PEEK_BYTES: usize = 64 << 10;
/// Largest metadata file decoded past [`PEEK_BYTES`] to confirm a compressed image tarball.
const PEEK_META: u64 = 1 << 20;
/// Most descriptors followed through an image's indexes.
const MAX_DESCRIPTORS: usize = 4096;
/// Free space left untouched by the temporary copy of a compressed outer tar.
const TEMP_RESERVE: u64 = 64 << 20;
/// Start of the error for archives that turn out not to be images (see [`is_not_an_image`]).
const NOT_AN_IMAGE: &str = "not a container image";
const READ_CHUNK: usize = 1 << 20;

/// Settings for container images.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageOptions {
    /// `os/arch[/variant]` to pick from a multi-platform image (default: this computer's, or
    /// the only one).
    pub platform: Option<String>,
    /// Image to pick when the archive holds several: a repository tag (`name:tag`) or an OCI
    /// reference name.
    pub image: Option<String>,
    /// Refuse zstd and xz streams whose decoder window is larger than this (0: the default).
    pub max_window: u64,
    /// Decode threads (0: one per core).
    pub threads: usize,
    /// Skip the free-space check for the temporary copy of a compressed outer tar.
    pub ignore_space: bool,
}

impl ImageOptions {
    fn limits(&self) -> Limits {
        Limits {
            max_out: u64::MAX,
            max_window: if self.max_window == 0 {
                Limits::DEFAULT_MAX_WINDOW
            } else {
                self.max_window
            },
            threads: self.threads,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// `docker save`: `manifest.json` (newer Docker also writes an OCI layout alongside).
    Docker,
    /// An OCI image layout: `oci-layout`, `index.json`, `blobs/<alg>/<hex>`.
    Oci,
}

/// One layer of the selected image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// The blob's path inside the outer tar.
    pub path: String,
    pub media_type: Option<String>,
    /// `sha256:<hex>` of the blob as stored, when the image records it.
    pub digest: Option<String>,
    /// `sha256:<hex>` of the uncompressed layer tar, from the image config.
    pub diff_id: String,
    /// Size of the blob as stored.
    pub size: u64,
    /// How the blob is compressed (`None`: a plain tar).
    pub codec: Option<Codec>,
}

/// The selected image and what the archive holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub format: ImageFormat,
    /// Repository tags or reference names of the selected image.
    pub names: Vec<String>,
    /// `os/arch[/variant]` from the image config.
    pub platform: String,
    /// `sha256:<hex>` of the image config.
    pub config_digest: Option<String>,
    pub layers: Vec<Layer>,
    /// Other images or platforms in the archive that were not selected.
    pub others: Vec<String>,
    /// Compression of the outer tar itself.
    pub outer_codec: Option<Codec>,
    /// Size of the archive file.
    pub file_len: u64,
}

impl ImageInfo {
    /// Total size of the layer blobs.
    pub fn blob_bytes(&self) -> u64 {
        self.layers.iter().map(|l| l.size).sum()
    }
}

/// One path of the merged root filesystem: the entry that wins it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Winner {
    /// Index of the layer the entry comes from.
    pub layer: usize,
    /// The entry. Directories only implied by deeper paths have no entry of their own; they
    /// are listed with `kind: Dir` and `data_offset: u64::MAX`.
    pub entry: tar::Entry,
}

/// Counts from merging the layers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Entries in all layers (whiteouts included).
    pub entries: usize,
    /// `.wh.<name>` whiteouts applied.
    pub whiteouts: usize,
    /// `.wh..wh..opq` opaque-directory markers applied.
    pub opaques: usize,
    /// Entries that a later layer deleted or replaced, and so are never written.
    pub shadowed: usize,
    /// Bytes of file content in shadowed entries.
    pub shadowed_bytes: u64,
    /// Paths of the merged tree left out because this computer cannot create them (see
    /// [`Skipped`]), everything below a skipped directory included.
    pub skipped: usize,
}

/// A path of the merged tree that this computer cannot create, left out with everything below
/// it. Its layers are still decoded and checked; only writing is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The path, as the image names it.
    pub path: String,
    /// Whether it is a directory (or has paths below it in the tree).
    pub dir: bool,
    /// Paths of the merged tree left out with it, itself included. Can be 0 for one of a group
    /// of names that differ only in case, when later layers deleted it.
    pub entries: usize,
    /// Why: the name this computer forbids, or the names it clashes with.
    pub reason: String,
}

/// What the scan learned: every digest checked, every layer parsed, the final tree.
#[derive(Debug, Clone)]
pub struct ImageScan {
    pub info: ImageInfo,
    /// Decoded size of each layer tar.
    pub layer_tar_len: Vec<u64>,
    /// Entries in each layer.
    pub layer_entries: Vec<usize>,
    /// The merged root filesystem, sorted by path.
    pub tree: Vec<Winner>,
    pub stats: MergeStats,
    /// Paths left out of `tree` because this computer cannot create them, sorted by path.
    pub skipped: Vec<Skipped>,
}

impl ImageScan {
    /// Bytes of file content in the merged tree.
    pub fn content_bytes(&self) -> u64 {
        self.tree
            .iter()
            .filter(|w| w.entry.kind == Kind::File)
            .map(|w| w.entry.size)
            .sum()
    }
}

/// What an extraction did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageSummary {
    pub files: usize,
    pub dirs: usize,
    pub bytes_written: u64,
    pub symlinks_skipped: usize,
    pub specials_skipped: usize,
    pub stats: MergeStats,
    /// Paths not written because this computer cannot create them.
    pub skipped: Vec<Skipped>,
}

// ---------------------------------------------------------------------------------------------
// The outer tar.

/// A read-only window `[off, off + len)` of another file, so a layer blob inside the outer tar
/// can be handed to a decoder as a file of its own.
#[derive(Debug)]
pub(crate) struct Region<'a> {
    pub(crate) h: &'a dyn FileHandle,
    pub(crate) off: u64,
    pub(crate) len: u64,
}

impl Region<'_> {
    fn unsupported(&self, op: &'static str) -> FsError {
        FsError::Unsupported {
            op,
            path: self.h.path().to_path_buf(),
        }
    }
}

impl FileHandle for Region<'_> {
    fn path(&self) -> &Path {
        self.h.path()
    }

    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> trunc_fs::Result<()> {
        if off
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.len)
        {
            return Err(FsError::Io {
                op: "reading",
                path: self.h.path().to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "read past the end of an embedded stream",
                ),
            });
        }
        self.h.read_exact_at(buf, self.off + off)
    }

    fn write_all_at(&self, _buf: &[u8], _off: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("writing a layer blob"))
    }

    fn size(&self) -> trunc_fs::Result<u64> {
        Ok(self.len)
    }

    fn set_len(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("resizing a layer blob"))
    }

    fn preallocate(&self, _len: u64) -> trunc_fs::Result<()> {
        Err(self.unsupported("preallocating a layer blob"))
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
        self.h.file_id()
    }

    fn set_modified(&self, _t: std::time::SystemTime) -> trunc_fs::Result<()> {
        Err(self.unsupported("changing a layer blob"))
    }
}

/// The outer tar, indexed: where each regular file's data lies.
#[derive(Debug)]
struct Outer {
    h: Box<dyn FileHandle>,
    /// Name → (offset, size) of every regular file.
    files: HashMap<String, (u64, u64)>,
    codec: Option<Codec>,
    file_len: u64,
}

pub(crate) fn tar_err(what: &str) -> impl Fn(tar::TarError) -> Error + '_ {
    move |e| match e {
        tar::TarError::Name { .. } => Error::Refused(format!("{what}: {e}")),
        _ => Error::Input(format!("{what}: {e}")),
    }
}

pub(crate) fn stream_err(e: StreamError) -> Error {
    match e {
        StreamError::Fs(f) => f.into(),
        StreamError::Corrupt(m) => Error::Integrity(m),
        StreamError::Format(m) | StreamError::Unsupported(m) => Error::Input(m),
        StreamError::Stopped => Error::Integrity("decoding stopped unexpectedly".into()),
    }
}

/// Decode `input` with `codec`, passing the output to `sink`; the sink's errors come back as
/// they are.
fn decode(
    codec: Codec,
    input: Input<'_>,
    limits: Limits,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let failure: RefCell<Option<Error>> = RefCell::new(None);
    let r = stream::decode(
        codec,
        input,
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
    Ok(r.map_err(stream_err)?.out_len)
}

/// Index an uncompressed tar by reading its headers only: file contents are skipped (fed to
/// the parser as zeros) rather than read.
pub(crate) fn index_tar(h: &dyn FileHandle, len: u64, what: &str) -> Result<Vec<tar::Entry>> {
    let mut r = tar::Reader::new();
    let zeros = vec![0u8; 64 << 10];
    let mut block = [0u8; 512];
    let mut known = 0usize;
    while r.position() < len {
        let pos = r.position();
        let n = usize::try_from((len - pos).min(512)).expect("<= 512");
        h.read_exact_at(&mut block[..n], pos)?;
        r.feed(&block[..n]).map_err(tar_err(what))?;
        if r.entries().len() > known {
            known = r.entries().len();
            let e = &r.entries()[known - 1];
            if e.kind == Kind::File && e.size > 0 && e.data_offset == r.position() {
                if e.data_offset
                    .checked_add(e.size)
                    .is_none_or(|end| end > len)
                {
                    return Err(Error::Input(format!(
                        "{what}: {} runs past the end of the archive (truncated?)",
                        e.name
                    )));
                }
                let padded = e.size.div_ceil(512).saturating_mul(512);
                let mut left = padded.min(len - e.data_offset);
                while left > 0 {
                    let take = usize::try_from(left.min(zeros.len() as u64)).expect("<= buffer");
                    r.feed(&zeros[..take]).map_err(tar_err(what))?;
                    left -= take as u64;
                }
            }
        }
    }
    r.finish().map_err(tar_err(what))
}

/// A temporary file, removed when dropped (on errors and panics too) unless removed already.
struct TempFile<'a> {
    fs: &'a dyn FsBackend,
    path: PathBuf,
    live: bool,
}

impl TempFile<'_> {
    fn remove(mut self) -> Result<()> {
        self.live = false;
        Ok(self.fs.remove_file(&self.path)?)
    }
}

impl Drop for TempFile<'_> {
    fn drop(&mut self) {
        if self.live {
            let _ = self.fs.remove_file(&self.path);
        }
    }
}

/// The indexed outer tar and its temporary decompressed copy, if any. Fields drop in order:
/// the copy's handle is closed before the copy is removed.
struct Opened<'a> {
    outer: Outer,
    temp: Option<TempFile<'a>>,
}

fn is_temp_name(n: &str) -> bool {
    n.strip_prefix(".trunc-image-")
        .and_then(|r| r.strip_suffix(".tar"))
        .is_some_and(|h| h.len() == 16 && h.bytes().all(|c| c.is_ascii_hexdigit()))
}

/// Temporary copies of compressed outer tars (`.trunc-image-<hex>.tar`) that an interrupted
/// run left in `dir`, each with whether it was removed. A copy still in use is held
/// exclusively by its run and so left alone; where that cannot be told (neither Windows nor
/// Linux), nothing is removed.
pub fn stale_temp_files(fs: &dyn FsBackend, dir: &Path) -> Vec<(PathBuf, bool)> {
    let Ok(names) = fs.read_dir(dir) else {
        return Vec::new();
    };
    names
        .into_iter()
        .filter(|n| is_temp_name(n))
        .map(|n| {
            let p = dir.join(n);
            let removed = cfg!(any(windows, target_os = "linux"))
                && fs
                    .open(&p, OpenMode::ReadWrite, Share::Exclusive)
                    .map(drop)
                    .is_ok()
                && fs.remove_file(&p).is_ok();
            (p, removed)
        })
        .collect()
}

impl Outer {
    /// Open and index the outer tar. A compressed one is decompressed into a new file in
    /// `temp_dir`, removed when the result is dropped.
    fn open<'a>(
        fs: &'a dyn FsBackend,
        archive: &Path,
        temp_dir: &Path,
        opts: &ImageOptions,
    ) -> Result<Opened<'a>> {
        let h = source::open_read(fs, archive)?;
        let file_len = h.size()?;
        let codec = Codec::sniff(&head(h.as_ref(), file_len)?);
        let what = archive.display().to_string();
        let Some(c) = codec else {
            let entries = index_tar(h.as_ref(), file_len, &what)?;
            return Ok(Opened {
                outer: Self::from_entries(h, &entries, None, file_len),
                temp: None,
            });
        };
        // The copy is at least about as large as the archive and may be much larger: refuse
        // up front when even the archive's size does not fit, and stop decoding (rather than
        // fill the volume) when the copy outgrows the free space.
        let budget = match fs.probe_volume(temp_dir).ok().and_then(|v| v.free_bytes) {
            Some(free) if !opts.ignore_space => free.saturating_sub(TEMP_RESERVE),
            _ => u64::MAX,
        };
        let no_room = || {
            Error::Refused(format!(
                "not enough free space in {} for the decompressed copy of the archive that \
                 reading a compressed image needs (about {} MiB usable); free some space, or \
                 decompress the archive first (`trunc x --raw`)",
                temp_dir.display(),
                budget >> 20
            ))
        };
        if file_len > budget {
            return Err(no_room());
        }
        // The guard is declared before the handle, so on a panic too the handle is closed
        // before the file is removed; it is armed only once the file is ours.
        let mut temp = Some(TempFile {
            fs,
            path: temp_dir.join(format!(".trunc-image-{}.tar", random_hex())),
            live: false,
        });
        let guard = temp.as_mut().expect("just set");
        let out = fs.open(&guard.path, OpenMode::CreateNew, Share::Exclusive)?;
        guard.live = true;
        let result = (|| -> Result<Vec<tar::Entry>> {
            let mut reader = tar::Reader::new();
            let mut at = 0u64;
            decode(
                c,
                Input {
                    src: h.as_ref(),
                    len: file_len,
                },
                opts.limits(),
                &mut |b| {
                    if at.saturating_add(b.len() as u64) > budget {
                        return Err(no_room());
                    }
                    reader.feed(b).map_err(tar_err(&what))?;
                    out.write_all_at(b, at)?;
                    at += b.len() as u64;
                    Ok(())
                },
            )?;
            reader.finish().map_err(tar_err(&what))
        })();
        match result {
            Ok(entries) => Ok(Opened {
                outer: Self::from_entries(out, &entries, Some(c), file_len),
                temp: temp.take(),
            }),
            Err(e) => {
                // Close the copy before the guard removes it.
                drop(out);
                drop(temp);
                Err(e)
            }
        }
    }

    fn from_entries(
        h: Box<dyn FileHandle>,
        entries: &[tar::Entry],
        codec: Option<Codec>,
        file_len: u64,
    ) -> Self {
        let files = entries
            .iter()
            .filter(|e| e.kind == Kind::File)
            .map(|e| (e.name.clone(), (e.data_offset, e.size)))
            .collect();
        Self {
            h,
            files,
            codec,
            file_len,
        }
    }

    fn region(&self, path: &str) -> Option<Region<'_>> {
        self.files.get(path).map(|&(off, len)| Region {
            h: self.h.as_ref(),
            off,
            len,
        })
    }

    /// A metadata file named in the outer tar, read whole.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some(r) = self.region(path) else {
            return Ok(None);
        };
        if r.len > MAX_JSON {
            return Err(Error::Input(format!(
                "{path} is {} bytes; image metadata larger than {MAX_JSON} bytes is refused",
                r.len
            )));
        }
        let mut b = vec![0u8; usize::try_from(r.len).expect("bounded")];
        r.read_exact_at(&mut b, 0)?;
        Ok(Some(b))
    }

    /// The JSON blob a descriptor points at, checked against its digest and size.
    fn read_blob_json(&self, d: &Descriptor) -> Result<Json> {
        let path = blob_path(&d.digest)?;
        let b = self
            .read_file(&path)?
            .ok_or_else(|| missing(&path, Some(&d.digest)))?;
        if let Some(size) = d.size.filter(|&s| s != b.len() as u64) {
            return Err(Error::Integrity(format!(
                "{path}: {} bytes, but its descriptor says {size}",
                b.len()
            )));
        }
        check_digest(&path, &d.digest, &trunc_hash::sha256(&b))?;
        Json::parse(&b).map_err(|e| Error::Input(format!("{path}: invalid JSON: {e}")))
    }
}

fn head(h: &dyn FileHandle, len: u64) -> Result<Vec<u8>> {
    let mut b = vec![0u8; usize::try_from(len.min(16)).expect("<= 16")];
    h.read_exact_at(&mut b, 0)?;
    Ok(b)
}

pub(crate) fn random_hex() -> String {
    let mut b = [0u8; 8];
    // A clash only makes the CreateNew fail; the clock is a fine fallback.
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        #[allow(clippy::cast_possible_truncation)] // any 64 bits of the clock will do
        let t = t as u64;
        b = t.to_le_bytes();
    }
    hex::encode(b)
}

fn missing(path: &str, digest: Option<&str>) -> Error {
    let what = match digest {
        Some(d) => format!("blob {d} ({path})"),
        None => path.to_owned(),
    };
    Error::Input(format!(
        "{what} is not in the archive (a foreign or non-distributable layer, or an incomplete \
         export?)"
    ))
}

/// `blobs/sha256/<hex>` for a `sha256:<hex>` digest. Anything else is refused, so a digest can
/// never name a path outside `blobs/`.
fn blob_path(digest: &str) -> Result<String> {
    Ok(format!("blobs/sha256/{}", digest_hex(digest)?))
}

pub(crate) fn digest_hex(digest: &str) -> Result<&str> {
    let (alg, hex) = digest
        .split_once(':')
        .ok_or_else(|| Error::Input(format!("invalid digest {digest:?}")))?;
    if alg != "sha256" {
        return Err(Error::Input(format!(
            "digest {digest:?} uses {alg:?}; only sha256 is supported"
        )));
    }
    if hex.len() != 64 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Input(format!("invalid digest {digest:?}")));
    }
    Ok(hex)
}

pub(crate) fn check_digest(what: &str, want: &str, got: &[u8; 32]) -> Result<()> {
    if digest_hex(want)? != hex::encode(got) {
        return Err(Error::Integrity(format!(
            "{what}: sha256 is sha256:{}, but the image says {want}",
            hex::encode(got)
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Image metadata.

#[derive(Debug, Clone)]
struct Descriptor {
    media_type: Option<String>,
    digest: String,
    size: Option<u64>,
    platform: Option<String>,
    name: Option<String>,
    attestation: bool,
}

fn descriptor(j: &Json, what: &str) -> Result<Descriptor> {
    let digest = j
        .get_str("digest")
        .ok_or_else(|| Error::Input(format!("{what}: descriptor without a digest")))?
        .to_owned();
    let size = match j.get("size") {
        None => None,
        Some(s) => Some(
            s.u64()
                .ok_or_else(|| Error::Input(format!("{what}: invalid descriptor size")))?,
        ),
    };
    let platform = j.get("platform").map(platform_of);
    let annotations = j.get("annotations");
    let ann = |k: &str| annotations.and_then(|a| a.get_str(k)).map(str::to_owned);
    let name = ann("io.containerd.image.name").or_else(|| ann("org.opencontainers.image.ref.name"));
    let attestation = ann("vnd.docker.reference.type").as_deref() == Some("attestation-manifest")
        || platform
            .as_deref()
            .is_some_and(|p| p.starts_with("unknown/"));
    Ok(Descriptor {
        media_type: j.get_str("mediaType").map(str::to_owned),
        digest,
        size,
        platform,
        name,
        attestation,
    })
}

/// `os/arch[/variant]` from a platform object or an image config.
fn platform_of(j: &Json) -> String {
    let os = j.get_str("os").unwrap_or("unknown");
    let arch = j.get_str("architecture").unwrap_or("unknown");
    match j.get_str("variant") {
        Some(v) if !v.is_empty() => format!("{os}/{arch}/{v}"),
        _ => format!("{os}/{arch}"),
    }
}

/// This computer's platform, in OCI terms.
pub fn host_platform() -> (&'static str, &'static str) {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        o => o,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "powerpc64" => "ppc64le",
        a => a,
    };
    (os, arch)
}

/// Whether `have` (`os/arch[/variant]`) is what `want` asks for; a request without a variant
/// matches any variant.
pub fn platform_matches(have: &str, want: &str) -> bool {
    if have == want {
        return true;
    }
    let (h, w): (Vec<&str>, Vec<&str>) = (have.split('/').collect(), want.split('/').collect());
    w.len() == 2 && h.len() == 3 && h[..2] == w[..]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Declared {
    /// Not recorded (`docker save` layers): sniffed.
    Unknown,
    Tar,
    Gzip,
    Zstd,
}

pub(crate) fn declared(media_type: &str) -> Result<Declared> {
    const LAYER: [&str; 4] = [
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.docker.image.rootfs.foreign.diff.tar",
    ];
    for base in LAYER {
        if let Some(rest) = media_type.strip_prefix(base) {
            return match rest {
                "" => Ok(Declared::Tar),
                "+gzip" | ".gzip" => Ok(Declared::Gzip),
                "+zstd" => Ok(Declared::Zstd),
                _ => Err(Error::Input(format!(
                    "layer media type {media_type:?} is not supported (encrypted?)"
                ))),
            };
        }
    }
    Err(Error::Input(format!(
        "layer media type {media_type:?} is not supported"
    )))
}

const INDEX_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// An image manifest that could be selected.
#[derive(Debug, Clone)]
struct Candidate {
    names: Vec<String>,
    platform: Option<String>,
    kind: CandidateKind,
}

#[derive(Debug, Clone)]
enum CandidateKind {
    /// A `manifest.json` entry.
    Docker { config: String, layers: Vec<String> },
    /// An OCI manifest (already read and checked against its descriptor).
    Oci(Json),
}

impl Candidate {
    fn label(&self) -> String {
        let name = if self.names.is_empty() {
            "<unnamed>".to_owned()
        } else {
            self.names.join(", ")
        };
        match &self.platform {
            Some(p) => format!("{name} ({p})"),
            None => name,
        }
    }
}

/// Pick one candidate by `--image` and `--platform`, defaulting to the only one, or else the
/// one for this computer's platform.
fn choose(cands: Vec<Candidate>, opts: &ImageOptions) -> Result<(Candidate, Vec<String>)> {
    let all: Vec<String> = cands.iter().map(Candidate::label).collect();
    let mut pool = cands;
    if let Some(want) = &opts.image {
        pool.retain(|c| c.names.iter().any(|n| n == want));
        if pool.is_empty() {
            return Err(Error::Input(format!(
                "no image named {want:?} in the archive; it holds: {}",
                all.join("; ")
            )));
        }
    }
    if let Some(want) = &opts.platform {
        pool.retain(|c| {
            c.platform
                .as_deref()
                .is_none_or(|p| platform_matches(p, want))
        });
        if pool.is_empty() {
            return Err(Error::Input(format!(
                "no image for platform {want:?} in the archive; it holds: {}",
                all.join("; ")
            )));
        }
    }
    if pool.len() > 1 && opts.platform.is_none() {
        let (os, arch) = host_platform();
        for want in [format!("{os}/{arch}"), format!("linux/{arch}")] {
            let fit: Vec<Candidate> = pool
                .iter()
                .filter(|c| {
                    c.platform
                        .as_deref()
                        .is_some_and(|p| platform_matches(p, &want))
                })
                .cloned()
                .collect();
            if fit.len() == 1 {
                pool = fit;
                break;
            }
        }
    }
    if pool.len() != 1 {
        return Err(Error::Input(format!(
            "the archive holds several images; choose one with --image NAME and/or --platform \
             OS/ARCH: {}",
            pool.iter()
                .map(Candidate::label)
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    let chosen = pool.remove(0);
    let chosen_label = chosen.label();
    let others = all.into_iter().filter(|l| *l != chosen_label).collect();
    Ok((chosen, others))
}

/// Candidates from `manifest.json`.
fn docker_candidates(j: &Json) -> Result<Vec<Candidate>> {
    let bad = |why: &str| Error::Input(format!("manifest.json: {why}"));
    let arr = j.arr().ok_or_else(|| bad("not an array"))?;
    if arr.is_empty() {
        return Err(bad("lists no images"));
    }
    arr.iter()
        .map(|m| {
            let config = m
                .get_str("Config")
                .ok_or_else(|| bad("an entry has no Config"))?;
            let layers = m
                .get("Layers")
                .and_then(Json::arr)
                .ok_or_else(|| bad("an entry has no Layers"))?
                .iter()
                .map(|l| {
                    l.str()
                        .map(str::to_owned)
                        .ok_or_else(|| bad("bad layer path"))
                })
                .collect::<Result<Vec<_>>>()?;
            let names = m
                .get("RepoTags")
                .and_then(Json::arr)
                .unwrap_or(&[])
                .iter()
                .filter_map(|t| t.str().map(str::to_owned))
                .collect();
            Ok(Candidate {
                names,
                platform: None,
                kind: CandidateKind::Docker {
                    config: config.to_owned(),
                    layers,
                },
            })
        })
        .collect()
}

/// State of a walk through an OCI index: blobs already read (by digest, with their length),
/// descriptors followed so far, and the candidates already found.
#[derive(Default)]
struct OciWalk {
    blobs: HashMap<String, (u64, Rc<Json>)>,
    descriptors: usize,
    found: HashSet<(String, Option<String>, Option<String>)>,
    out: Vec<Candidate>,
}

impl OciWalk {
    /// The JSON blob `d` points at, read and checked once per digest.
    fn blob(&mut self, outer: &Outer, d: &Descriptor) -> Result<Rc<Json>> {
        if let Some((len, j)) = self.blobs.get(&d.digest) {
            if let Some(size) = d.size.filter(|s| s != len) {
                return Err(Error::Integrity(format!(
                    "{}: {len} bytes, but its descriptor says {size}",
                    blob_path(&d.digest)?
                )));
            }
            return Ok(Rc::clone(j));
        }
        let path = blob_path(&d.digest)?;
        let len = outer.files.get(&path).map_or(0, |&(_, len)| len);
        let j = Rc::new(outer.read_blob_json(d)?);
        self.blobs.insert(d.digest.clone(), (len, Rc::clone(&j)));
        Ok(j)
    }
}

/// Candidates reachable from an OCI index, following nested indexes. Manifests whose blob is
/// not in the archive (other platforms of a multi-platform image that was saved for one) are
/// left out, and so are repeats of the same manifest, name and platform.
fn oci_candidates(
    outer: &Outer,
    index: &Json,
    what: &str,
    inherited: Option<&str>,
    depth: usize,
    walk: &mut OciWalk,
) -> Result<()> {
    if depth > MAX_INDEX_DEPTH {
        return Err(Error::Input(format!(
            "{what}: image indexes nested more than {MAX_INDEX_DEPTH} deep"
        )));
    }
    let list = index
        .get("manifests")
        .and_then(Json::arr)
        .ok_or_else(|| Error::Input(format!("{what}: no manifests list")))?;
    for m in list {
        walk.descriptors += 1;
        if walk.descriptors > MAX_DESCRIPTORS {
            return Err(Error::Input(format!(
                "{what}: the image indexes list more than {MAX_DESCRIPTORS} manifests"
            )));
        }
        let d = descriptor(m, what)?;
        if d.attestation {
            continue;
        }
        let path = blob_path(&d.digest)?;
        if !outer.files.contains_key(&path) {
            continue;
        }
        let name = d.name.as_deref().or(inherited);
        let blob = walk.blob(outer, &d)?;
        let mt = d
            .media_type
            .as_deref()
            .or_else(|| blob.get_str("mediaType"))
            .unwrap_or("");
        let is_index =
            INDEX_TYPES.contains(&mt) || (mt.is_empty() && blob.get("manifests").is_some());
        let is_manifest =
            MANIFEST_TYPES.contains(&mt) || (mt.is_empty() && blob.get("layers").is_some());
        if is_index {
            oci_candidates(outer, &blob, &path, name, depth + 1, walk)?;
        } else if is_manifest {
            let key = (
                d.digest.clone(),
                name.map(str::to_owned),
                d.platform.clone(),
            );
            if walk.found.insert(key) {
                walk.out.push(Candidate {
                    names: name.map(|n| vec![n.to_owned()]).unwrap_or_default(),
                    platform: d.platform.clone(),
                    kind: CandidateKind::Oci(Json::clone(&blob)),
                });
            }
        } else {
            return Err(Error::Input(format!(
                "{path}: unsupported manifest media type {mt:?}"
            )));
        }
    }
    Ok(())
}

fn diff_ids(config: &Json, what: &str) -> Result<Vec<String>> {
    let ids = config
        .get("rootfs")
        .and_then(|r| r.get("diff_ids"))
        .and_then(Json::arr)
        .ok_or_else(|| Error::Input(format!("{what}: no rootfs.diff_ids")))?;
    ids.iter()
        .map(|d| {
            let s = d
                .str()
                .ok_or_else(|| Error::Input(format!("{what}: bad diff_id")))?;
            digest_hex(s)?;
            Ok(s.to_owned())
        })
        .collect()
}

/// Whether `manifest.json` has the shape `docker save` writes: a non-empty array of objects
/// with a `Config` path and a `Layers` list.
fn docker_manifest_ok(j: &Json) -> bool {
    j.arr().is_some_and(|a| {
        !a.is_empty()
            && a.iter().all(|m| {
                m.get_str("Config").is_some() && m.get("Layers").and_then(Json::arr).is_some()
            })
    })
}

fn oci_layout_ok(j: &Json) -> bool {
    j.get_str("imageLayoutVersion").is_some()
}

/// Whether `index.json` is an OCI index: a `manifests` list of descriptors.
fn oci_index_ok(j: &Json) -> bool {
    j.get("manifests")
        .and_then(Json::arr)
        .is_some_and(|a| a.iter().all(|d| d.get_str("digest").is_some()))
}

/// The image structure of the outer tar, if it has one: `manifest.json` (preferred: it carries
/// the repository tags) or `oci-layout` with `index.json`.
enum Structure {
    Docker(Json),
    Oci(Json),
}

fn structure(outer: &Outer) -> Option<Structure> {
    let json = |name: &str| {
        outer
            .read_file(name)
            .ok()
            .flatten()
            .and_then(|b| Json::parse(&b).ok())
    };
    if let Some(m) = json("manifest.json").filter(docker_manifest_ok) {
        return Some(Structure::Docker(m));
    }
    if json("oci-layout").is_some_and(|l| oci_layout_ok(&l)) {
        if let Some(i) = json("index.json").filter(oci_index_ok) {
            return Some(Structure::Oci(i));
        }
    }
    None
}

/// Whether `e` says the archive is not a container image after all (a tarball whose first
/// entries looked like one): it can then be handled as an ordinary tarball.
pub fn is_not_an_image(e: &Error) -> bool {
    matches!(e, Error::Input(m) if m.starts_with(NOT_AN_IMAGE))
}

/// Each layer's blob path, with its descriptor when the image has one.
type LayerRefs = Vec<(String, Option<Descriptor>)>;

/// A candidate's image config (checked against its digest when known), its digest and its
/// layers.
fn config_of(outer: &Outer, c: &Candidate) -> Result<(Json, Option<String>, LayerRefs)> {
    match &c.kind {
        CandidateKind::Docker { config, layers } => {
            // Classic `docker save` names the config after its digest (the image id).
            let digest = digest_from_blob_path(config).or_else(|| {
                let d = format!("sha256:{}", config.strip_suffix(".json")?);
                digest_hex(&d).is_ok().then_some(d)
            });
            let b = outer.read_file(config)?.ok_or_else(|| {
                Error::Input(format!(
                    "manifest.json: config {config} is not in the archive"
                ))
            })?;
            if let Some(d) = &digest {
                check_digest(config, d, &trunc_hash::sha256(&b))?;
            }
            let j = Json::parse(&b)
                .map_err(|e| Error::Input(format!("{config}: invalid JSON: {e}")))?;
            Ok((
                j,
                digest,
                layers.iter().map(|l| (l.clone(), None)).collect(),
            ))
        }
        CandidateKind::Oci(m) => {
            let cd = descriptor(
                m.get("config")
                    .ok_or_else(|| Error::Input("image manifest has no config".into()))?,
                "image manifest",
            )?;
            let j = outer.read_blob_json(&cd)?;
            let layers = m
                .get("layers")
                .and_then(Json::arr)
                .ok_or_else(|| Error::Input("image manifest has no layers".into()))?
                .iter()
                .map(|l| {
                    let d = descriptor(l, "image manifest")?;
                    Ok((blob_path(&d.digest)?, Some(d)))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((j, Some(cd.digest), layers))
        }
    }
}

/// Read the image metadata and select one image.
fn metadata(outer: &Outer, opts: &ImageOptions) -> Result<ImageInfo> {
    let (format, mut cands) = match structure(outer) {
        Some(Structure::Docker(m)) => (ImageFormat::Docker, docker_candidates(&m)?),
        Some(Structure::Oci(index)) => {
            let mut walk = OciWalk::default();
            oci_candidates(outer, &index, "index.json", None, 0, &mut walk)?;
            if walk.out.is_empty() {
                return Err(Error::Input(
                    "index.json: no image manifest whose blob is in the archive".into(),
                ));
            }
            (ImageFormat::Oci, walk.out)
        }
        None => {
            return Err(Error::Input(format!(
                "{NOT_AN_IMAGE}: no valid manifest.json, nor oci-layout with index.json"
            )));
        }
    };
    // `docker save` entries and descriptors without a platform: take it from the config, so
    // `--platform` and the host default can tell them apart. A config that cannot be read
    // here fails later, if its image is the one chosen.
    if cands.len() > 1 {
        for c in &mut cands {
            if c.platform.is_none() {
                c.platform = config_of(outer, c).ok().map(|(j, _, _)| platform_of(&j));
            }
        }
    }
    let (chosen, others) = choose(cands, opts)?;
    let (config_json, config_digest, layer_refs) = config_of(outer, &chosen)?;
    let platform = platform_of(&config_json);
    if let Some(want) = &opts.platform {
        if !platform_matches(&platform, want) {
            return Err(Error::Input(format!(
                "the image is for {platform}, not {want}"
            )));
        }
    }
    let ids = diff_ids(&config_json, "image config")?;
    if ids.len() != layer_refs.len() {
        return Err(Error::Input(format!(
            "the image lists {} layers but its config has {} diff_ids",
            layer_refs.len(),
            ids.len()
        )));
    }
    let mut layers = Vec::with_capacity(ids.len());
    for ((path, d), diff_id) in layer_refs.into_iter().zip(ids) {
        let digest = match &d {
            Some(d) => Some(d.digest.clone()),
            None => digest_from_blob_path(&path),
        };
        let region = outer
            .region(&path)
            .ok_or_else(|| missing(&path, digest.as_deref()))?;
        if let Some(size) = d.as_ref().and_then(|d| d.size).filter(|&s| s != region.len) {
            return Err(Error::Integrity(format!(
                "{path}: {} bytes, but its descriptor says {size}",
                region.len
            )));
        }
        let media_type = d.as_ref().and_then(|d| d.media_type.clone());
        let want = match &media_type {
            Some(mt) => declared(mt)?,
            None => Declared::Unknown,
        };
        let sniffed = Codec::sniff(&head(&region, region.len)?);
        let codec = match (want, sniffed) {
            (Declared::Unknown, c) => c,
            (Declared::Tar, None) => None,
            (Declared::Gzip, Some(Codec::Gzip)) => Some(Codec::Gzip),
            (Declared::Zstd, Some(Codec::Zstd)) => Some(Codec::Zstd),
            (_, got) => {
                return Err(Error::Input(format!(
                    "{path}: media type {:?} but the blob is {}",
                    media_type.as_deref().unwrap_or(""),
                    got.map_or("an uncompressed tar", Codec::name)
                )));
            }
        };
        layers.push(Layer {
            size: region.len,
            path,
            media_type,
            digest,
            diff_id,
            codec,
        });
    }
    Ok(ImageInfo {
        format,
        names: chosen.names,
        platform,
        config_digest,
        layers,
        others,
        outer_codec: outer.codec,
        file_len: outer.file_len,
    })
}

/// `sha256:<hex>` for a `blobs/sha256/<hex>` path (newer `docker save`), else nothing.
fn digest_from_blob_path(path: &str) -> Option<String> {
    let hex = path.strip_prefix("blobs/sha256/")?;
    let d = format!("sha256:{hex}");
    if digest_hex(&d).is_ok() {
        Some(d)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Layers.

/// Decode one layer, passing the tar stream to `sink`, and check the blob's digest and the
/// layer's diff_id. Returns the decoded length.
fn read_layer(
    outer: &Outer,
    i: usize,
    layer: &Layer,
    opts: &ImageOptions,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let _prof = trunc_prof::span("image.layer").bytes(layer.size);
    let region = outer
        .region(&layer.path)
        .ok_or_else(|| missing(&layer.path, layer.digest.as_deref()))?;
    let what = format!("layer {} ({})", i + 1, layer.path);
    let mut diff = Sha256Hasher::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut blob_hash = |hash_as_diff: bool, sink: &mut dyn FnMut(&[u8]) -> Result<()>| {
        let mut h = Sha256Hasher::new();
        let mut at = 0u64;
        while at < region.len {
            let n = usize::try_from((region.len - at).min(READ_CHUNK as u64)).expect("<= chunk");
            region.read_exact_at(&mut buf[..n], at)?;
            h.update(&buf[..n]);
            if hash_as_diff {
                sink(&buf[..n])?;
            }
            at += n as u64;
        }
        Ok::<_, Error>(h.finalize())
    };
    let (blob, out_len) = match layer.codec {
        None => {
            let h = blob_hash(true, sink)?;
            (h, region.len)
        }
        Some(c) => {
            let h = blob_hash(false, &mut |_| Ok(()))?;
            if let Some(d) = &layer.digest {
                check_digest(&what, d, &h)?;
            }
            // Decoder errors get the layer named; the sink's already name it.
            let sink_failed = std::cell::Cell::new(false);
            let n = decode(
                c,
                Input {
                    src: &region,
                    len: region.len,
                },
                opts.limits(),
                &mut |b| {
                    diff.update(b);
                    sink(b).inspect_err(|_| sink_failed.set(true))
                },
            )
            .map_err(|e| match e {
                Error::Integrity(m) if !sink_failed.get() => {
                    Error::Integrity(format!("{what}: {m}"))
                }
                Error::Input(m) if !sink_failed.get() => Error::Input(format!("{what}: {m}")),
                e => e,
            })?;
            (h, n)
        }
    };
    if let Some(d) = &layer.digest {
        check_digest(&what, d, &blob)?;
    }
    let diff = if layer.codec.is_none() {
        blob
    } else {
        diff.finalize()
    };
    check_digest(&format!("{what} (uncompressed)"), &layer.diff_id, &diff)?;
    Ok(out_len)
}

// ---------------------------------------------------------------------------------------------
// Merging.

const OPAQUE: &str = ".wh..wh..opq";
const WHITEOUT: &str = ".wh.";
/// Prefix of aufs bookkeeping names (`.wh..wh.plnk/`, `.wh..wh.orph/`, `.wh..wh.aufs`).
const AUFS: &str = ".wh..wh.";

#[derive(Debug, Clone)]
struct Node {
    name: String,
    kind: Kind,
    layer: usize,
    /// Index in the layer's entries; `None` for a directory only implied by deeper paths.
    entry: Option<usize>,
}

/// Remove `key` and everything below it.
fn remove_subtree(tree: &mut BTreeMap<String, Node>, key: &str) -> Vec<Node> {
    let mut gone: Vec<Node> = tree.remove(key).into_iter().collect();
    gone.extend(remove_children(tree, key));
    gone
}

/// Remove everything below `key` (everything at all for the root, `""`).
fn remove_children(tree: &mut BTreeMap<String, Node>, key: &str) -> Vec<Node> {
    if key.is_empty() {
        return std::mem::take(tree).into_values().collect();
    }
    // Children sort between "key/" and "key0" ('0' follows '/').
    let lo = format!("{key}/");
    let hi = format!("{key}0");
    let keys: Vec<String> = tree.range(lo..hi).map(|(k, _)| k.clone()).collect();
    keys.into_iter().filter_map(|k| tree.remove(&k)).collect()
}

/// Record that `a` and `b`, at tree key `key`, differ only in case on this computer.
fn note_clash(clashes: &mut BTreeMap<String, BTreeSet<String>>, key: &str, a: &str, b: &str) {
    let names = clashes.entry(key.to_owned()).or_default();
    names.insert(a.to_owned());
    names.insert(b.to_owned());
}

/// Take out of the tree what this computer cannot create, each with everything below it:
/// paths with a name it forbids ([`trunc_core::path::host_unusable`]: on Windows `:`, trailing
/// dots, device names like `aux.h`, ...), and every name of a group that differs only in case
/// (`clashes`), since keeping one would silently change what the others hold.
fn leave_out(
    tree: &mut BTreeMap<String, Node>,
    clashes: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Skipped> {
    // Tree key of each path to leave out: its names, and why (`None`: a case clash).
    let mut roots: BTreeMap<String, (BTreeSet<String>, Option<&'static str>)> = clashes
        .iter()
        .map(|(k, names)| (k.clone(), (names.clone(), None)))
        .collect();
    for n in tree.values() {
        if let Some((part, why)) = trunc_core::path::host_unusable(&n.name) {
            roots
                .entry(trunc_core::path::host_key(part))
                .or_insert_with(|| (BTreeSet::from([part.to_owned()]), Some(why)));
        }
    }
    if roots.is_empty() {
        return Vec::new();
    }
    let below_another = |key: &str| {
        key.match_indices('/')
            .any(|(i, _)| roots.contains_key(&key[..i]))
    };
    let mut out = Vec::new();
    for (key, (names, why)) in &roots {
        if below_another(key) {
            continue;
        }
        let depth = key.split('/').count();
        // Each name of the group, with its own part of the subtree: (dir, entries).
        let mut per: BTreeMap<String, (bool, usize)> =
            names.iter().map(|n| (n.clone(), (false, 0))).collect();
        for n in remove_subtree(tree, key) {
            let comps: Vec<&str> = n.name.split('/').collect();
            let slot = per.entry(comps[..depth].join("/")).or_default();
            slot.0 |= n.kind == Kind::Dir || comps.len() > depth;
            slot.1 += 1;
        }
        for (path, &(dir, entries)) in &per {
            let reason = match why {
                Some(w) => (*w).to_owned(),
                None => format!(
                    "differs only in case from {}",
                    per.keys()
                        .filter(|o| *o != path)
                        .map(|o| format!("{o:?}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            out.push(Skipped {
                path: path.clone(),
                dir,
                entries,
                reason,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn case_clash(a: &str, b: &str) -> Error {
    Error::Refused(format!(
        "layers name the same path as {a:?} and {b:?}, which differ only in case on this          computer; refusing to merge them"
    ))
}

/// Check the ancestors of the whiteout or opaque marker `path` (in layer `li`) against the
/// tree: each one there must be named exactly as in `path` (not only up to case), and must not
/// be a symlink.
/// Runtimes resolve such a path through the symlink (`lib/x` with `lib -> usr/lib` lands in
/// `usr/lib/x`); that is not supported yet, so it is refused rather than merged wrongly.
fn check_ancestors(tree: &BTreeMap<String, Node>, path: &str, li: usize) -> Result<()> {
    let mut end = 0usize;
    while let Some(i) = path[end..].find('/') {
        let a = &path[..end + i];
        end += i + 1;
        if let Some(n) = tree.get(&trunc_core::path::host_key(a)) {
            if n.name != a {
                return Err(case_clash(&n.name, a));
            }
            if n.kind == Kind::Symlink {
                return Err(through_symlink(li, path, a, n.layer));
            }
        }
    }
    Ok(())
}

fn through_symlink(li: usize, path: &str, link: &str, link_layer: usize) -> Error {
    Error::Refused(format!(
        "layer {}: {path:?} is reached through {link:?}, a symlink from layer {}; images that \
         write through symlinks (such as /lib -> usr/lib in merged-/usr bases) are not \
         supported yet",
        li + 1,
        link_layer + 1
    ))
}

/// Merge the layers' entries in order with OCI whiteout semantics into the final tree.
///
/// In each layer, its whiteouts (`.wh.<name>`: delete `<name>` from the layers below) and
/// opaque markers (`.wh..wh..opq`: hide everything the layers below have in this directory)
/// apply first, so they never affect entries of the same layer; then its entries are added,
/// replacing what is at their path (a directory over a directory keeps the contents below,
/// anything else replaces the whole subtree). A path through a lower file replaces it with a
/// directory; a path (or whiteout) through a symlink is refused (see [`check_ancestors`]), as
/// is a whiteout that names a path only up to case. Whiteout files themselves are never part
/// of the tree, and aufs bookkeeping (any name under a `.wh..wh.` component, other than the
/// opaque marker) is skipped.
///
/// Paths this computer cannot create are then left out of the tree and returned (see
/// [`leave_out`]); whiteouts and opaque markers have applied to them as to any path.
pub fn merge_layers(layers: &[Vec<tar::Entry>]) -> Result<(Vec<Winner>, MergeStats, Vec<Skipped>)> {
    // Tarballs make hard links from staged targets; layers would need that across the merge
    // (a later layer may delete or replace the target), which is not supported yet.
    for (li, layer) in layers.iter().enumerate() {
        if let Some(e) = layer.iter().find(|e| matches!(e.kind, Kind::HardLink(_))) {
            return Err(Error::Refused(format!(
                "layer {}: hard link {:?}; hard links in container images are not supported yet",
                li + 1,
                e.name
            )));
        }
    }
    let mut tree: BTreeMap<String, Node> = BTreeMap::new();
    let mut stats = MergeStats::default();
    // Tree keys that entries named in different case: every name each was given.
    let mut clashes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let size_of = |n: &Node| -> u64 {
        match n.entry {
            Some(i) if n.kind == Kind::File => layers[n.layer][i].size,
            _ => 0,
        }
    };
    let shadow = |gone: Vec<Node>, stats: &mut MergeStats| {
        for n in gone {
            if n.entry.is_some() {
                stats.shadowed += 1;
                stats.shadowed_bytes += size_of(&n);
            }
        }
    };
    for (li, entries) in layers.iter().enumerate() {
        stats.entries += entries.len();
        let mut regular = Vec::with_capacity(entries.len());
        // (target, whiteout entry name)
        let mut opaque: Vec<(String, &str)> = Vec::new();
        let mut deleted: Vec<(String, &str)> = Vec::new();
        for (ei, e) in entries.iter().enumerate() {
            let comps: Vec<&str> = e.name.split('/').collect();
            let last = comps.len() - 1;
            if comps.iter().enumerate().any(|(i, c)| {
                c.starts_with(AUFS) && !(i == last && *c == OPAQUE && e.kind != Kind::Dir)
            }) {
                // aufs bookkeeping (`.wh..wh.plnk/<hard link>`, `.wh..wh.orph/`, ...),
                // whatever its type: skipped, like Docker does.
                continue;
            }
            let parent = trunc_core::path::parent(&e.name);
            let base = comps[last];
            if comps[..last].iter().any(|c| c.starts_with(WHITEOUT)) {
                return Err(Error::Refused(format!(
                    "layer {}: {:?} is inside a whiteout",
                    li + 1,
                    e.name
                )));
            }
            let Some(target) = base.strip_prefix(WHITEOUT) else {
                regular.push(ei);
                continue;
            };
            if e.kind == Kind::Dir {
                return Err(Error::Refused(format!(
                    "layer {}: whiteout {:?} is a directory",
                    li + 1,
                    e.name
                )));
            }
            if base == OPAQUE {
                opaque.push((parent.unwrap_or("").to_owned(), &e.name));
            } else if target.is_empty() || target == "." || target == ".." || target.contains('\\')
            {
                return Err(Error::Refused(format!(
                    "layer {}: whiteout {:?} names no valid entry",
                    li + 1,
                    e.name
                )));
            } else {
                deleted.push((
                    match parent {
                        Some(p) => format!("{p}/{target}"),
                        None => target.to_owned(),
                    },
                    &e.name,
                ));
            }
        }
        for (d, marker) in &opaque {
            check_ancestors(&tree, marker, li)?;
            let gone = remove_children(&mut tree, &trunc_core::path::host_key(d));
            shadow(gone, &mut stats);
            stats.opaques += 1;
        }
        for (d, marker) in &deleted {
            check_ancestors(&tree, marker, li)?;
            let key = trunc_core::path::host_key(d);
            // `.wh.Foo` must not delete `foo` just because this computer folds case.
            if let Some(n) = tree.get(&key).filter(|n| n.name != *d) {
                return Err(case_clash(&n.name, d));
            }
            let gone = remove_subtree(&mut tree, &key);
            shadow(gone, &mut stats);
            stats.whiteouts += 1;
        }
        for ei in regular {
            let e = &entries[ei];
            // Every ancestor must be a directory: make it one.
            let mut end = 0usize;
            while let Some(i) = e.name[end..].find('/') {
                let a = &e.name[..end + i];
                end += i + 1;
                let key = trunc_core::path::host_key(a);
                if let Some(n) = tree.get(&key).filter(|n| n.name != a) {
                    note_clash(&mut clashes, &key, &n.name, a);
                }
                match tree.get(&key) {
                    Some(n) if n.kind == Kind::Dir => continue,
                    Some(n) if n.kind == Kind::Symlink => {
                        return Err(through_symlink(li, &e.name, a, n.layer));
                    }
                    Some(_) => {
                        let gone = remove_subtree(&mut tree, &key);
                        shadow(gone, &mut stats);
                    }
                    None => {}
                }
                tree.insert(
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
            if let Some(n) = tree.get(&key) {
                if n.name != e.name {
                    note_clash(&mut clashes, &key, &n.name, &e.name);
                }
                let gone = if n.kind == Kind::Dir && e.kind == Kind::Dir {
                    tree.remove(&key).into_iter().collect()
                } else {
                    remove_subtree(&mut tree, &key)
                };
                shadow(gone, &mut stats);
            }
            tree.insert(
                key,
                Node {
                    name: e.name.clone(),
                    kind: e.kind,
                    layer: li,
                    entry: Some(ei),
                },
            );
        }
    }
    let skipped = leave_out(&mut tree, &clashes);
    stats.skipped = skipped.iter().map(|s| s.entries).sum();
    let winners = tree
        .into_values()
        .map(|n| Winner {
            layer: n.layer,
            entry: match n.entry {
                Some(i) => layers[n.layer][i].clone(),
                None => tar::Entry {
                    name: n.name,
                    kind: Kind::Dir,
                    size: 0,
                    data_offset: u64::MAX,
                    mode: None,
                    mtime_unix: 0,
                    mtime_nanos: 0,
                    sparse: None,
                },
            },
        })
        .collect();
    Ok((winners, stats, skipped))
}

// ---------------------------------------------------------------------------------------------
// Entry points.

/// Whether the file at `path` is a container image tarball. Uncompressed tars are confirmed
/// from their structure (a valid `manifest.json`, or `oci-layout` with a valid `index.json`,
/// read through the headers only). Compressed ones are judged by their first entries decoded:
/// the same metadata files when they are among them (so an ordinary tarball with a root
/// `index.json` is not taken for an image), else `blobs/sha256/<hex>` or `<hex>/layer.tar`
/// entries; such an archive is confirmed once decompressed, and [`is_not_an_image`] tells the
/// caller when it was not one. An archive with a consume journal is never an image: it is
/// being consumed, and resumed through its journal.
pub fn detect(fs: &dyn FsBackend, path: &Path) -> bool {
    if matches!(
        fs.metadata(&crate::zipconsume::journal_path(path)),
        Ok(Some(_))
    ) {
        return false;
    }
    let Ok(h) = source::open_read(fs, path) else {
        return false;
    };
    let Ok(len) = h.size() else {
        return false;
    };
    let Ok(first) = head(h.as_ref(), len) else {
        return false;
    };
    match Codec::sniff(&first) {
        None => {
            let mut block = [0u8; 512];
            if len < 512
                || h.read_exact_at(&mut block, 0).is_err()
                || !tar::looks_like_header(&block)
            {
                return false;
            }
            match index_tar(h.as_ref(), len, "") {
                Ok(entries) => structure(&Outer::from_entries(h, &entries, None, len)).is_some(),
                Err(_) => false,
            }
        }
        Some(c) => prefix_is_image(c, h.as_ref(), len),
    }
}

/// [`detect`] for a compressed outer tar, from its first entries.
fn prefix_is_image(c: Codec, h: &dyn FileHandle, len: u64) -> bool {
    const META: [&str; 3] = ["manifest.json", "oci-layout", "index.json"];
    let peek = |n: usize| stream::peek(c, Input { src: h, len }, n).ok();
    let entries = |p: &[u8]| {
        let mut r = tar::Reader::new();
        let _ = r.feed(p);
        r.entries().to_vec()
    };
    let Some(mut prefix) = peek(PEEK_BYTES) else {
        return false;
    };
    if prefix.len() < 512 || !tar::looks_like_header(&prefix[..512]) {
        return false;
    }
    let mut es = entries(&prefix);
    // A metadata file cut off by the end of the prefix: decode a little further.
    let end = es
        .iter()
        .filter(|e| e.kind == Kind::File && META.contains(&e.name.as_str()) && e.size <= PEEK_META)
        .map(|e| e.data_offset.saturating_add(e.size))
        .max();
    if let Some(end) = end.filter(|&end| end > prefix.len() as u64) {
        if let Some(p) = peek(usize::try_from(end).unwrap_or(usize::MAX)) {
            prefix = p;
            es = entries(&prefix);
        }
    }
    // `None`: not among the first entries (or not whole); else whether it is valid.
    let check = |name: &str, ok: fn(&Json) -> bool| -> Option<bool> {
        let e = es.iter().find(|e| e.kind == Kind::File && e.name == name)?;
        let start = usize::try_from(e.data_offset).ok()?;
        let b = prefix.get(start..start.checked_add(usize::try_from(e.size).ok()?)?)?;
        Some(Json::parse(b).is_ok_and(|j| ok(&j)))
    };
    let docker = check("manifest.json", docker_manifest_ok);
    let layout = check("oci-layout", oci_layout_ok);
    let index = check("index.json", oci_index_ok);
    if docker == Some(true) || (layout == Some(true) && index != Some(false)) {
        return true;
    }
    if [docker, layout, index].contains(&Some(false)) {
        return false;
    }
    let hex64 = |s: &str| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit());
    es.iter().any(|e| {
        e.name.strip_prefix("blobs/sha256/").is_some_and(hex64)
            || e.name.strip_suffix("/layer.tar").is_some_and(hex64)
    })
}

/// Run `f` on the indexed outer tar, removing any temporary decompressed copy afterwards.
fn with_outer<T>(
    fs: &dyn FsBackend,
    archive: &Path,
    temp_dir: &Path,
    opts: &ImageOptions,
    f: impl FnOnce(&Outer) -> Result<T>,
) -> Result<T> {
    let opened = Outer::open(fs, archive, temp_dir, opts)?;
    let r = f(&opened.outer);
    let Opened { outer, temp } = opened;
    drop(outer);
    if let Some(t) = temp {
        let removed = t.remove();
        if r.is_ok() {
            removed?;
        }
    }
    r
}

/// The image metadata, without decoding any layer (digests of layers are not checked).
/// `temp_dir` holds the decompressed copy of a compressed outer tar while it is read.
pub fn inspect_image(
    fs: &dyn FsBackend,
    archive: &Path,
    temp_dir: &Path,
    opts: &ImageOptions,
) -> Result<ImageInfo> {
    with_outer(fs, archive, temp_dir, opts, |outer| metadata(outer, opts))
}

fn scan_outer(outer: &Outer, opts: &ImageOptions) -> Result<ImageScan> {
    let _prof = trunc_prof::span("image.scan");
    let info = metadata(outer, opts)?;
    let mut all = Vec::with_capacity(info.layers.len());
    let mut lens = Vec::with_capacity(info.layers.len());
    for (i, layer) in info.layers.iter().enumerate() {
        let what = format!("layer {} ({})", i + 1, layer.path);
        // Names this computer cannot create are left out after the merge, not refused here.
        let mut reader = tar::Reader::with_safe_names();
        let len = read_layer(outer, i, layer, opts, &mut |b| {
            reader.feed(b).map_err(tar_err(&what))
        })?;
        let entries = reader.finish().map_err(tar_err(&what))?;
        lens.push(len);
        all.push(entries);
    }
    let (tree, stats, skipped) = merge_layers(&all)?;
    Ok(ImageScan {
        layer_entries: all.iter().map(Vec::len).collect(),
        info,
        layer_tar_len: lens,
        tree,
        stats,
        skipped,
    })
}

/// Check everything without writing (except the temporary copy of a compressed outer tar in
/// `temp_dir`): every JSON blob, layer blob digest and diff_id, every layer's tar headers and
/// names, and that the layers merge. Paths [`extract_image`] would skip are checked all the
/// same and listed in [`ImageScan::skipped`].
pub fn verify_image(
    fs: &dyn FsBackend,
    archive: &Path,
    temp_dir: &Path,
    opts: &ImageOptions,
) -> Result<ImageScan> {
    with_outer(fs, archive, temp_dir, opts, |outer| scan_outer(outer, opts))
}

/// Remove a staging tree left by a failed extraction (best effort; links are removed, never
/// followed).
pub(crate) fn remove_tree(fs: &dyn FsBackend, p: &Path) {
    match fs.metadata(p) {
        Ok(Some(m)) if m.kind == NodeKind::Dir => {
            if let Ok(names) = fs.read_dir(p) {
                for n in names {
                    remove_tree(fs, &p.join(n));
                }
            }
            let _ = fs.remove_dir(p);
        }
        Ok(Some(_)) => {
            let _ = fs.remove_file(p);
        }
        _ => {}
    }
}

/// Extract the merged root filesystem of the image into `dest`. Everything is checked first
/// (see [`verify_image`]); the tree is then written into a staging directory under `dest` and
/// renamed into place, so `dest` gains either the whole tree or nothing. Top-level names that
/// already exist in `dest` are refused. `before_write` sees the scan before anything is
/// written (to check free space, say) and can stop the extraction.
pub fn extract_image(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    opts: &ImageOptions,
    before_write: &mut dyn FnMut(&ImageScan) -> Result<()>,
) -> Result<ImageSummary> {
    let _prof = trunc_prof::span("image.extract");
    ensure_dir(fs, dest)?;
    with_outer(fs, archive, dest, opts, |outer| {
        let scan = scan_outer(outer, opts)?;
        before_write(&scan)?;
        let items: Vec<Item> = scan
            .tree
            .iter()
            .filter_map(|w| {
                let e = &w.entry;
                let kind = match e.kind {
                    Kind::File => ItemKind::File,
                    Kind::Dir => ItemKind::Dir,
                    Kind::Symlink => ItemKind::Symlink,
                    #[allow(unreachable_patterns)]
                    _ => return None,
                };
                Some(Item {
                    path: e.name.clone(),
                    kind,
                    size: e.size,
                    len: e.size,
                    mode: e.mode,
                    mtime_unix: e.mtime_unix,
                    mtime_nanos: e.mtime_nanos,
                })
            })
            .collect();
        let tops = top_level_names(&items);
        if let Some(p) = first_existing(fs, dest, &tops)? {
            return Err(Error::Refused(format!(
                "{} already exists; extract the image into an empty directory",
                p.display()
            )));
        }
        let stage = dest.join(format!(".trunc-stage-{}", random_hex()));
        // Held until the tree is renamed into place (or cleaned up): every confined call under
        // the staging directory goes through the directory opened here.
        let stage_hold = fs.hold_root(&stage, true)?;
        let r = write_tree(fs, outer, &scan, &items, dest, &stage, opts);
        if r.is_err() {
            remove_tree(fs, &stage);
        }
        drop(stage_hold);
        r
    })
}

fn write_tree(
    fs: &dyn FsBackend,
    outer: &Outer,
    scan: &ImageScan,
    items: &[Item],
    dest: &Path,
    stage: &Path,
    opts: &ImageOptions,
) -> Result<ImageSummary> {
    let mut cs = crate::consume::ConsumeSummary::default();
    build_structure(fs, items, dest, stage, &mut cs)?;
    let protected_id = outer.h.file_id()?;
    let protected = move |id: &FileId| *id == protected_id;
    let guard = StageGuard {
        root: stage,
        protected: &protected,
    };
    let mut written = 0u64;
    for (li, layer) in scan.info.layers.iter().enumerate() {
        // The non-empty files this layer contributes, in stream order.
        let mut wins: Vec<&tar::Entry> = scan
            .tree
            .iter()
            .filter(|w| w.layer == li && w.entry.kind == Kind::File && w.entry.size > 0)
            .map(|w| &w.entry)
            .collect();
        if wins.is_empty() {
            continue;
        }
        wins.sort_by_key(|e| e.data_offset);
        let mut k = 0usize;
        let mut pos = 0u64;
        let mut open: Option<Box<dyn FileHandle>> = None;
        let len = read_layer(outer, li, layer, opts, &mut |mut b: &[u8]| {
            while !b.is_empty() && k < wins.len() {
                let e = wins[k];
                let end = e.data_offset + e.size;
                if pos + (b.len() as u64) <= e.data_offset {
                    break;
                }
                if pos < e.data_offset {
                    let skip = usize::try_from(e.data_offset - pos).expect("< len");
                    b = &b[skip..];
                    pos = e.data_offset;
                }
                let take = usize::try_from((end - pos).min(b.len() as u64)).expect("<= len");
                if open.is_none() {
                    let (h, _) = open_staged_output(fs, &guard, &join_rel(stage, &e.name))?;
                    open = Some(h);
                }
                let h = open.as_ref().expect("opened above");
                h.write_all_at(&b[..take], pos - e.data_offset)?;
                written += take as u64;
                b = &b[take..];
                pos += take as u64;
                if pos == end {
                    if let Some(h) = open.take() {
                        h.set_modified(system_time(e.mtime_unix, e.mtime_nanos))?;
                    }
                    k += 1;
                }
            }
            pos += b.len() as u64;
            Ok(())
        })?;
        if k != wins.len() || len != scan.layer_tar_len[li] {
            return Err(Error::Integrity(format!(
                "layer {} changed between the scan and extraction",
                li + 1
            )));
        }
    }
    rename_into_place(fs, items, dest, stage)?;
    Ok(ImageSummary {
        files: cs.files,
        dirs: cs.dirs,
        bytes_written: written,
        symlinks_skipped: cs.symlinks_skipped,
        specials_skipped: scan
            .tree
            .iter()
            .filter(|w| !matches!(w.entry.kind, Kind::File | Kind::Dir | Kind::Symlink))
            .count(),
        stats: scan.stats,
        skipped: scan.skipped.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, kind: Kind, size: u64) -> tar::Entry {
        tar::Entry {
            name: name.into(),
            kind,
            size,
            data_offset: 512,
            mode: None,
            mtime_unix: 0,
            mtime_nanos: 0,
            sparse: None,
        }
    }

    fn f(name: &str) -> tar::Entry {
        e(name, Kind::File, 1)
    }

    fn d(name: &str) -> tar::Entry {
        e(name, Kind::Dir, 0)
    }

    fn names(layers: &[Vec<tar::Entry>]) -> Vec<(String, usize, Kind)> {
        let (w, _, skipped) = merge_layers(layers).unwrap();
        assert_eq!(skipped, vec![]);
        w.into_iter()
            .map(|w| (w.entry.name, w.layer, w.entry.kind))
            .collect()
    }

    #[test]
    fn whiteouts_and_opaque_dirs() {
        let got = names(&[
            vec![d("a"), f("a/x"), f("a/y"), d("b"), f("b/z"), f("c")],
            vec![f("a/.wh.x"), f("b/.wh..wh..opq"), f("b/new"), f(".wh.c")],
        ]);
        assert_eq!(
            got,
            vec![
                ("a".into(), 0, Kind::Dir),
                ("a/y".into(), 0, Kind::File),
                ("b".into(), 0, Kind::Dir),
                ("b/new".into(), 1, Kind::File),
            ]
        );
    }

    #[test]
    fn whiteouts_do_not_hide_their_own_layer() {
        let got = names(&[vec![f("a")], vec![f("a"), f(".wh.a")]]);
        assert_eq!(got, vec![("a".into(), 1, Kind::File)]);
    }

    #[test]
    fn file_and_directory_replace_each_other() {
        let (w, stats, _) = merge_layers(&[
            vec![d("p"), f("p/1"), f("p/2"), f("q")],
            vec![f("p"), f("q/inner")],
        ])
        .unwrap();
        let got: Vec<_> = w
            .iter()
            .map(|w| (w.entry.name.as_str(), w.entry.kind))
            .collect();
        assert_eq!(
            got,
            vec![("p", Kind::File), ("q", Kind::Dir), ("q/inner", Kind::File)]
        );
        assert_eq!(stats.shadowed, 4); // p/, p/1, p/2, q
    }

    #[test]
    fn root_opaque_clears_everything() {
        let got = names(&[
            vec![f("a"), d("b"), f("b/c")],
            vec![f(".wh..wh..opq"), f("z")],
        ]);
        assert_eq!(got, vec![("z".into(), 1, Kind::File)]);
    }

    #[test]
    fn bad_whiteouts_are_refused() {
        for bad in ["a/.wh..", "a/.wh...", ".wh."] {
            assert!(merge_layers(&[vec![f(bad)]]).is_err(), "{bad}");
        }
        assert!(merge_layers(&[vec![f(".wh.x/y")]]).is_err());
        assert!(merge_layers(&[vec![d(".wh.x")]]).is_err());
        // aufs bookkeeping is ignored.
        assert_eq!(names(&[vec![f(".wh..wh.plnk")]]), vec![]);
    }

    #[test]
    fn case_only_twins_are_all_left_out_where_names_ignore_case() {
        let layers = [
            vec![d("t"), d("t/E"), f("t/E/foo"), f("t/keep")],
            vec![d("t/e"), f("t/e/bar"), f("t/e/baz")],
        ];
        let (w, stats, skipped) = merge_layers(&layers).unwrap();
        let got: Vec<&str> = w.iter().map(|w| w.entry.name.as_str()).collect();
        if cfg!(any(windows, target_os = "macos")) {
            assert_eq!(got, ["t", "t/keep"]);
            let s: Vec<_> = skipped
                .iter()
                .map(|s| (s.path.as_str(), s.dir, s.entries))
                .collect();
            assert_eq!(s, [("t/E", true, 1), ("t/e", true, 3)]);
            assert_eq!(skipped[0].reason, "differs only in case from \"t/e\"");
            assert_eq!(stats.skipped, 4);
        } else {
            assert_eq!(
                got,
                ["t", "t/E", "t/E/foo", "t/e", "t/e/bar", "t/e/baz", "t/keep"]
            );
            assert_eq!(skipped, vec![]);
        }
        // A twin deleted before the other arrives is no clash.
        let layers = [vec![d("E"), f("E/x")], vec![f(".wh.E"), d("e"), f("e/y")]];
        let (w, _, skipped) = merge_layers(&layers).unwrap();
        let got: Vec<&str> = w.iter().map(|w| w.entry.name.as_str()).collect();
        assert_eq!(got, ["e", "e/y"]);
        assert_eq!(skipped, vec![]);
    }

    #[test]
    fn names_windows_forbids_are_left_out_there() {
        let layers = [
            vec![
                f("man3/IO::File.3pm"),
                f("man3/ok.3pm"),
                d("dots."),
                f("dots./a"),
                f("dots./b:c"),
                f("inc/aux.h"),
                f("inc/gone:1"),
            ],
            // Whiteouts reach paths that are left out like any other.
            vec![f("inc/.wh.gone:1"), f("dots./.wh..wh..opq")],
        ];
        let (w, stats, skipped) = merge_layers(&layers).unwrap();
        let got: Vec<&str> = w.iter().map(|w| w.entry.name.as_str()).collect();
        let s: Vec<_> = skipped
            .iter()
            .map(|s| (s.path.as_str(), s.dir, s.entries))
            .collect();
        if cfg!(windows) {
            assert_eq!(got, ["inc", "man3", "man3/ok.3pm"]);
            assert_eq!(
                s,
                [
                    ("dots.", true, 1),
                    ("inc/aux.h", false, 1),
                    ("man3/IO::File.3pm", false, 1)
                ]
            );
            assert_eq!(skipped[1].reason, "reserved Windows device name");
            assert_eq!(stats.skipped, 3);
        } else {
            assert_eq!(got.len(), 6, "{got:?}");
            assert_eq!(s, []);
        }
    }

    #[test]
    fn aufs_bookkeeping_is_skipped_whatever_its_type() {
        let got = names(&[vec![
            d(".wh..wh.plnk"),
            f(".wh..wh.plnk/123.456"),
            d(".wh..wh.orph"),
            d(".wh..wh.orph/sub"),
            f(".wh..wh.aufs"),
            d(".wh..wh..opq"),
            d("etc"),
            f("etc/.wh..wh.foo"),
            f("etc/hostname"),
        ]]);
        assert_eq!(
            got,
            vec![
                ("etc".into(), 0, Kind::Dir),
                ("etc/hostname".into(), 0, Kind::File),
            ]
        );
    }

    fn l(name: &str) -> tar::Entry {
        e(name, Kind::Symlink, 0)
    }

    #[test]
    fn paths_through_symlinks_are_refused() {
        let base = vec![d("usr"), d("usr/lib"), f("usr/lib/libc"), l("lib")];
        for top in [
            vec![f("lib/extra")],
            vec![f("lib/.wh.libc")],
            vec![f("lib/.wh..wh..opq")],
            vec![d("lib/sub")],
        ] {
            let e = merge_layers(&[base.clone(), top.clone()]).unwrap_err();
            assert!(e.to_string().contains("symlink"), "{top:?}: {e}");
        }
        // Within one layer too.
        assert!(merge_layers(&[vec![l("lib"), f("lib/x")]]).is_err());
        // An entry of its own replaces the symlink first, as runtimes do.
        let got = names(&[base.clone(), vec![d("lib"), f("lib/x")]]);
        assert!(got.contains(&("lib/x".into(), 1, Kind::File)), "{got:?}");
        // Deleting or replacing the symlink itself is fine.
        assert!(merge_layers(&[base.clone(), vec![f(".wh.lib")]]).is_ok());
        assert!(merge_layers(&[base, vec![f("lib")]]).is_ok());
    }

    #[test]
    fn whiteouts_match_names_exactly() {
        let r = merge_layers(&[vec![d("Etc"), f("Etc/Passwd")], vec![f("Etc/.wh.passwd")]]);
        let r2 = merge_layers(&[vec![d("Etc"), f("Etc/Passwd")], vec![f(".wh.etc")]]);
        let r3 = merge_layers(&[vec![d("Etc"), f("Etc/x")], vec![f("etc/.wh..wh..opq")]]);
        if cfg!(any(windows, target_os = "macos")) {
            for r in [r, r2, r3] {
                assert!(r.unwrap_err().to_string().contains("only in case"));
            }
        } else {
            // Different names on Linux: the whiteouts name nothing that exists.
            assert_eq!(r.unwrap().0.len(), 2);
            assert_eq!(r2.unwrap().0.len(), 2);
            assert_eq!(r3.unwrap().0.len(), 2);
        }
    }

    #[test]
    fn temp_names() {
        assert!(is_temp_name(".trunc-image-0123456789abcdef.tar"));
        for n in [
            ".trunc-image-0123.tar",
            ".trunc-image-0123456789abcdef.tar.gz",
            "trunc-image-0123456789abcdef.tar",
            ".trunc-image-0123456789abcdeg.tar",
        ] {
            assert!(!is_temp_name(n), "{n}");
        }
    }

    #[test]
    fn platforms() {
        assert!(platform_matches("linux/arm64/v8", "linux/arm64"));
        assert!(!platform_matches("linux/arm64", "linux/arm64/v8"));
        assert!(platform_matches("linux/amd64", "linux/amd64"));
        assert!(!platform_matches("linux/amd64", "linux/arm64"));
    }

    #[test]
    fn digests() {
        let ok = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            blob_path(&ok).unwrap(),
            format!("blobs/sha256/{}", "a".repeat(64))
        );
        for bad in [
            "sha256:../../etc/passwd".to_owned(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha512:{}", "a".repeat(128)),
            "a".repeat(64),
        ] {
            assert!(blob_path(&bad).is_err(), "{bad}");
        }
    }
}

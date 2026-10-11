//! Uncompressed tar archives: extraction, structure verification and destructive extraction.
//!
//! A plain `.tar` stores every file's content as one contiguous byte range after its header(s),
//! so, like an ISO image ([`crate::isoconsume`]), it is described as a ZIP layout of stored
//! entries and the ZIP machinery does the rest: [`crate::zipconsume`] extracts it, and consumes
//! it with the same journal, ordering, punch mode and crash recovery (ADR-0015).
//!
//! Headers are parsed with [`trunc_legacy::tar::Reader`] (ustar, GNU long names, PAX, base-256
//! sizes) without reading file contents. Each entry's region runs from the end of the previous
//! entry (so it includes this entry's headers and the previous file's padding) to the end of its
//! own content; regions are contiguous and never overlap. Hard links, sparse files and
//! multi-volume archives are refused by the reader, as for compressed tarballs.
//!
//! Tar has no content checksums. Before a consumption starts, every file's CRC-32 is computed in
//! a read-only pass and stored in the journal with the layout, as for ISO images, so a file whose
//! bytes change before its extraction (or a resume) is caught before its source is released.

use std::path::{Path, PathBuf};

use trunc_fs::{FileHandle, FsBackend};
use trunc_journal::Journal;
use trunc_legacy::tar;
use trunc_legacy::zip::{Entry, Kind, Layout, Method};

use crate::consume::{ConsumeOptions, ConsumeSummary, Progress};
use crate::error::Result;
use crate::zipconsume::{self, Format};

/// First bytes of the journal preamble of a plain tar consumption (ZIP's is `TZJP1`).
pub(crate) const PREAMBLE_MAGIC: &[u8; 5] = b"TTJP1";

/// A parsed plain tar archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarFile {
    /// Entries as stored ZIP entries. `crc32` is 0 until a consumption computes it.
    pub layout: Layout,
    /// Device, FIFO and socket entries: not extracted.
    pub specials_skipped: usize,
}

/// Where the journal for `archive` lives (the same place as for a ZIP).
pub fn journal_path(archive: &Path) -> PathBuf {
    zipconsume::journal_path(archive)
}

/// Describe a plain tar as a layout of stored entries.
fn layout_of(h: &dyn FileHandle, what: &str) -> Result<TarFile> {
    let file_len = h.size()?;
    let entries = crate::image::index_tar(h, file_len, what)?;
    let mut out = Vec::with_capacity(entries.len());
    let mut specials = 0usize;
    let mut prev_end = 0u64;
    for e in entries {
        let kind = match e.kind {
            tar::Kind::File => Kind::File,
            tar::Kind::Dir => Kind::Dir,
            tar::Kind::Symlink => Kind::Symlink,
            tar::Kind::Special => {
                // Its header stays inside the next entry's region.
                specials += 1;
                continue;
            }
        };
        let size = if kind == Kind::File { e.size } else { 0 };
        // `index_tar` checked that every file's content lies inside the archive.
        let region_end = e.data_offset + size;
        out.push(Entry {
            name: e.name,
            kind,
            method: Method::Stored,
            crc32: 0,
            compressed_size: size,
            size,
            region_start: prev_end,
            data_offset: e.data_offset,
            region_end,
            mode: e.mode,
            mtime_unix: e.mtime_unix,
        });
        prev_end = region_end;
    }
    let overlaps = trunc_legacy::zip::overlaps(&out);
    debug_assert!(overlaps.is_empty(), "tar regions are contiguous");
    Ok(TarFile {
        layout: Layout {
            entries: out,
            cd_start: prev_end,
            file_len,
            overlaps,
        },
        specials_skipped: specials,
    })
}

fn parse(fs: &dyn FsBackend, archive: &Path) -> Result<(Box<dyn FileHandle>, TarFile)> {
    let h = crate::source::open_read(fs, archive)?;
    let t = layout_of(h.as_ref(), &archive.display().to_string())?;
    Ok((h, t))
}

/// Parse a plain tar for inspection or planning.
pub fn open_tar(fs: &dyn FsBackend, archive: &Path) -> Result<TarFile> {
    parse(fs, archive).map(|(_, t)| t)
}

fn overlap_refusal(n: usize) -> String {
    // Unreachable for layouts built here (regions are contiguous); kept for the interface.
    format!("{n} entries overlap another entry's data; pass --allow-overlap to process them")
}

/// Consume a plain tar into `dest`. Safe to call again after any crash or pause.
pub fn consume_tar(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    opts: &ConsumeOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<ConsumeSummary> {
    let parallel = fs.parallel_io();
    let what = archive_path.display().to_string();
    let specials = std::cell::Cell::new(0usize);
    let format = Format {
        magic: PREAMBLE_MAGIC,
        scan: &|h| {
            let t = layout_of(h, &what)?;
            specials.set(t.specials_skipped);
            crate::isoconsume::checksummed(h, t.layout, parallel)
        },
        overlap_refusal: &overlap_refusal,
    };
    let mut s = zipconsume::consume_layout(fs, archive_path, dest, opts, progress, &format)?;
    // Counted by the scan, so only on a fresh start (a resume does not re-parse the archive).
    s.specials_skipped = specials.get();
    Ok(s)
}

/// Non-destructive extraction of a plain tar into `dest`. Symlinks and devices are skipped.
pub fn extract_tar(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
) -> Result<ConsumeSummary> {
    let (h, t) = parse(fs, archive)?;
    let mut s = zipconsume::extract_layout(fs, h.as_ref(), &t.layout, dest, overwrite, false)?;
    s.specials_skipped = t.specials_skipped;
    Ok(s)
}

/// Check a plain tar's structure without extracting: every header parsed and its checksum
/// valid, names safe, contents inside the file, a clean end. Tar has no content checksums.
pub fn verify_tar(fs: &dyn FsBackend, archive: &Path) -> Result<TarFile> {
    open_tar(fs, archive)
}

/// Content bytes of the files in a tar.
pub fn content_bytes(t: &TarFile) -> u64 {
    t.layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .map(|e| e.size)
        .sum()
}

/// True if `path` starts with a ustar or GNU tar header (magic at byte 257, valid checksum), or
/// is a plain tar being consumed (its journal exists). Compressed tarballs and container images
/// are detected separately, before this.
pub fn is_tar(fs: &dyn FsBackend, path: &Path) -> bool {
    if let Ok((_, pre, _)) = Journal::open(fs, &journal_path(path)) {
        return pre.starts_with(PREAMBLE_MAGIC);
    }
    let Ok(h) = crate::source::open_read(fs, path) else {
        return false;
    };
    let mut block = [0u8; 512];
    if h.read_exact_at(&mut block, 0).is_err() {
        return false;
    }
    &block[257..262] == b"ustar" && tar::looks_like_header(&block)
}

/// Destination recorded in the journal of a plain tar being consumed.
pub fn journal_dest(fs: &dyn FsBackend, archive: &Path) -> Option<PathBuf> {
    let (_, pre, _) = Journal::open(fs, &journal_path(archive)).ok()?;
    if !pre.starts_with(PREAMBLE_MAGIC) {
        return None;
    }
    zipconsume::journal_dest(fs, archive)
}

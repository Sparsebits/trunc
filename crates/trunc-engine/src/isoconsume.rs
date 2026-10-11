//! ISO 9660 images: extraction, structure verification and destructive extraction.
//!
//! An ISO image is an uncompressed container whose files are contiguous byte ranges, so
//! `trunc_legacy::iso` describes its files as stored ZIP entries and the ZIP machinery does the
//! rest: [`crate::zipconsume`] extracts them, and consumes them with the same journal, ordering,
//! punch mode and crash recovery (ADR-0015).
//!
//! ISO 9660 has no checksums. Before a consumption starts, every file's CRC-32 is computed in a
//! read-only pass and stored in the journal with the layout. The ZIP consumer's checks then work
//! unchanged: a file whose bytes change between the scan and its extraction (or a resume) is
//! detected before its source is released, and `--verify-media` has a value to compare against.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use trunc_core::path::CaseMode;
use trunc_fs::{FileHandle, FsBackend};
use trunc_journal::Journal;
use trunc_legacy::iso::{self, Image, IsoError};
use trunc_legacy::zip::{Kind, Layout};

use crate::consume::{ConsumeOptions, ConsumeSummary, Progress};
use crate::error::{Error, Result};
use crate::zipconsume::{self, Format};

/// First bytes of the journal preamble of an ISO consumption (ZIP's is `TZJP1`).
pub(crate) const PREAMBLE_MAGIC: &[u8; 5] = b"TIJP1";

/// Where the journal for `archive` lives (the same place as for a ZIP).
pub fn journal_path(archive: &Path) -> PathBuf {
    zipconsume::journal_path(archive)
}

fn parse_err(archive: &Path, e: IsoError) -> Error {
    match e {
        IsoError::Fs(f) => f.into(),
        other => Error::Input(format!("{}: {other}", archive.display())),
    }
}

fn parse(
    fs: &dyn FsBackend,
    archive: &Path,
    case: CaseMode,
) -> Result<(Box<dyn FileHandle>, Image)> {
    let h = crate::source::open_read(fs, archive)?;
    let img = iso::parse_with(h.as_ref(), case).map_err(|e| parse_err(archive, e))?;
    Ok((h, img))
}

/// Parse an image for inspection or planning.
pub fn open_image(fs: &dyn FsBackend, archive: &Path) -> Result<Image> {
    parse(fs, archive, CaseMode::host()).map(|(_, img)| img)
}

/// Fill in every file's CRC-32 by reading its data once.
pub(crate) fn checksummed(
    h: &dyn FileHandle,
    mut layout: Layout,
    parallel: bool,
) -> Result<Layout> {
    let _prof = trunc_prof::span("iso.checksum");
    let crc = |e: &trunc_legacy::zip::Entry| -> Result<u32> {
        let mut c = crc32fast::Hasher::new();
        let mut buf = vec![0u8; usize::try_from(e.size.min(1 << 20)).expect("<= 1 MiB")];
        let mut off = 0u64;
        while off < e.size {
            let n = usize::try_from((e.size - off).min(buf.len() as u64)).expect("<= 1 MiB");
            h.read_exact_at(&mut buf[..n], e.data_offset + off)?;
            c.update(&buf[..n]);
            off += n as u64;
        }
        Ok(c.finalize())
    };
    let crcs: Vec<Result<u32>> = if parallel {
        use rayon::prelude::*;
        layout.entries.par_iter().map(crc).collect()
    } else {
        layout.entries.iter().map(crc).collect()
    };
    for (e, c) in layout.entries.iter_mut().zip(crcs) {
        e.crc32 = c?;
    }
    Ok(layout)
}

fn overlap_refusal(n: usize) -> String {
    format!(
        "{n} files overlap or share their data with another file (hard links, or a crafted \
         image); pass --allow-overlap to process them"
    )
}

/// Entries an image holds that extraction never creates, as a refusal message for `--consume`
/// (which destroys them with the image), or `None` if there are none.
pub fn skipped_refusal(img: &Image) -> Option<String> {
    let mut what = Vec::new();
    if img.associated_skipped > 0 {
        what.push(format!(
            "{} associated files (resource forks)",
            img.associated_skipped
        ));
    }
    if img.specials_skipped > 0 {
        what.push(format!(
            "{} devices, FIFOs or sockets",
            img.specials_skipped
        ));
    }
    (!what.is_empty()).then(|| {
        format!(
            "the image holds {} that are not extracted and would be destroyed with it; \
             extract without --consume, or pass --allow-skipped to lose them",
            what.join(" and ")
        )
    })
}

/// The image's skipped and hidden entry counts, in a summary.
fn add_counts(s: &mut ConsumeSummary, img: &Image) {
    s.specials_skipped = img.specials_skipped;
    s.associated_skipped = img.associated_skipped;
    s.hidden = img.hidden;
}

/// (specials, associated, hidden) of an image.
type Counts = (usize, usize, usize);

/// Consume an ISO image into `dest`. Safe to call again after any crash or pause.
///
/// Associated files and devices are never extracted, so they would be lost with the image: a
/// fresh consumption refuses such an image unless `allow_skipped`.
pub fn consume_iso(
    fs: &dyn FsBackend,
    archive_path: &Path,
    dest: &Path,
    opts: &ConsumeOptions,
    allow_skipped: bool,
    progress: &mut dyn FnMut(Progress),
) -> Result<ConsumeSummary> {
    let parallel = fs.parallel_io();
    // What the scan (fresh starts only) found that the summary should report.
    let scanned: Cell<Option<Counts>> = Cell::new(None);
    let format = Format {
        magic: PREAMBLE_MAGIC,
        scan: &|h, case| {
            let img = iso::parse_with(h, case).map_err(|e| parse_err(archive_path, e))?;
            if let Some(why) = skipped_refusal(&img).filter(|_| !allow_skipped) {
                return Err(Error::Refused(why));
            }
            scanned.set(Some((
                img.specials_skipped,
                img.associated_skipped,
                img.hidden,
            )));
            checksummed(h, img.layout, parallel)
        },
        overlap_refusal: &overlap_refusal,
    };
    let mut s = zipconsume::consume_layout(fs, archive_path, dest, opts, progress, &format)?;
    if let Some((specials, associated, hidden)) = scanned.get() {
        s.specials_skipped = specials;
        s.associated_skipped = associated;
        s.hidden = hidden;
    }
    Ok(s)
}

/// Non-destructive extraction of an ISO image into `dest`. Files sharing their data (hard
/// links) are each written in full; files whose data partly overlaps another's are refused
/// unless `allow_overlap`. Symlinks, devices and associated files are skipped.
pub fn extract_iso(
    fs: &dyn FsBackend,
    archive: &Path,
    dest: &Path,
    overwrite: bool,
    allow_overlap: bool,
) -> Result<ConsumeSummary> {
    let (h, img) = parse(fs, archive, crate::stage::dest_case(fs, dest)?)?;
    if img.partial_overlaps > 0 && !allow_overlap {
        return Err(Error::Refused(format!(
            "{} files partly overlap another file's data, which no ISO authoring tool writes; \
             pass --allow-overlap to extract them anyway",
            img.partial_overlaps
        )));
    }
    let mut s = zipconsume::extract_layout(fs, h.as_ref(), &img.layout, dest, overwrite, false)?;
    add_counts(&mut s, &img);
    Ok(s)
}

/// Check an image's structure without extracting: every directory record parsed, names valid,
/// extents inside the file, no loops, and no file partly overlapping another (sharing a whole
/// extent, as hard links do, is allowed). ISO 9660 has no checksums to verify.
pub fn verify_iso(fs: &dyn FsBackend, archive: &Path) -> Result<Image> {
    let img = open_image(fs, archive)?;
    if img.partial_overlaps > 0 {
        return Err(Error::Integrity(format!(
            "{}: {} files partly overlap another file's data",
            archive.display(),
            img.partial_overlaps
        )));
    }
    Ok(img)
}

/// Content bytes of the files in an image.
pub fn content_bytes(img: &Image) -> u64 {
    img.layout
        .entries
        .iter()
        .filter(|e| e.kind == Kind::File)
        .map(|e| e.size)
        .sum()
}

/// True if `path` looks like an ISO 9660 (or UDF) image, or is one being consumed (its journal
/// exists).
pub fn is_iso(fs: &dyn FsBackend, path: &Path) -> bool {
    if let Ok((_, pre, _)) = Journal::open(fs, &journal_path(path)) {
        return pre.starts_with(PREAMBLE_MAGIC);
    }
    let Ok(h) = crate::source::open_read(fs, path) else {
        return false;
    };
    // A stored `.trnc` could hold "CD001" at the descriptor offset by chance; its own magic
    // comes first.
    let mut magic = [0u8; 6];
    if h.read_exact_at(&mut magic, 0).is_ok() && magic == trunc_core::header::HEADER_MAGIC {
        return false;
    }
    iso::looks_like_image(h.as_ref())
}

/// Destination recorded in the journal of an ISO image being consumed.
pub fn journal_dest(fs: &dyn FsBackend, archive: &Path) -> Option<PathBuf> {
    let (_, pre, _) = Journal::open(fs, &journal_path(archive)).ok()?;
    if !pre.starts_with(PREAMBLE_MAGIC) {
        return None;
    }
    zipconsume::journal_dest(fs, archive)
}

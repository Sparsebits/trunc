//! ISO 9660 image parsing for extraction.
//!
//! The directory tree is walked from the root directory record of the chosen volume descriptor
//! (the path table is never trusted). Names come from Rock Ridge (`NM`) when the primary volume
//! carries it, else from a Joliet supplementary volume, else from the plain ISO 9660 names with
//! their `;1` version suffix stripped. Multi-extent files (ISO level 3) are joined, provided their
//! sections are contiguous.
//!
//! Files are returned as stored ZIP entries ([`crate::zip::Entry`], method `Stored`), so the ZIP
//! extractor and consumer handle them unchanged: each file is one contiguous byte range of the
//! image. ISO 9660 has no checksums, so `crc32` is left 0 for the caller to fill in.
//!
//! Hostile images are bounded everywhere: directory loops and shared directory extents, extents
//! outside the file, file data overlapping directory records, overlong continuation chains, and
//! absurd entry counts or depths are refused. Names are validated exactly as for ZIP and tar
//! ([`trunc_core::path::validate_host`]).

use std::collections::{HashMap, HashSet};

use trunc_fs::FileHandle;
use unicode_normalization::UnicodeNormalization;

use crate::zip::{Entry, Kind, Layout, Method};

/// Logical block size: the only one supported (and the only one real images use).
pub const SECTOR: u64 = 2048;
const SECTOR_BYTES: usize = 2048;
/// The volume descriptor set starts at sector 16, after the system area.
const FIRST_DESCRIPTOR: u64 = 16;
/// Volume descriptors read before giving up on finding the set terminator.
const MAX_DESCRIPTORS: u64 = 64;
/// Total directory-record bytes read (bounds memory and time on hostile input).
const MAX_DIR_BYTES: u64 = 512 << 20;
/// Entries in one image.
const MAX_ENTRIES: usize = 1 << 21;
/// System-use bytes per record, including continuation areas.
const MAX_SUSP: usize = 64 << 10;
/// Continuation areas chained from one record.
const MAX_CONTINUATIONS: usize = 16;
/// Continuation-area bytes read for the whole image (bounds time on hostile input).
const MAX_CE_TOTAL: usize = 64 << 20;
/// Raw bytes in one Rock Ridge name.
const MAX_NM: usize = 4096;
/// Bytes of full entry names in one image (bounds memory: every name is a full path).
const MAX_NAME_BYTES: usize = 512 << 20;

const FLAG_HIDDEN: u8 = 1;
const FLAG_DIR: u8 = 2;
const FLAG_ASSOCIATED: u8 = 4;
const FLAG_MULTI_EXTENT: u8 = 0x80;

#[derive(Debug, thiserror::Error)]
pub enum IsoError {
    #[error("not an ISO 9660 image: {0}")]
    NotIso(&'static str),
    #[error("unsupported ISO image: {0}")]
    Unsupported(String),
    #[error("corrupt ISO image: {0}")]
    Corrupt(String),
    #[error("unsafe or invalid entry name {name:?}: {reason}")]
    Name { name: String, reason: String },
    #[error(transparent)]
    Fs(#[from] trunc_fs::FsError),
}

type Result<T> = std::result::Result<T, IsoError>;

fn corrupt(msg: impl Into<String>) -> IsoError {
    IsoError::Corrupt(msg.into())
}

/// Where entry names came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Names {
    RockRidge,
    Joliet,
    Iso9660,
}

impl std::fmt::Display for Names {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Names::RockRidge => "Rock Ridge",
            Names::Joliet => "Joliet",
            Names::Iso9660 => "ISO 9660",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Entries as stored ZIP entries (directories and symlinks have empty regions at 0; so do
    /// empty files, whose extent is meaningless). `crc32` is 0.
    pub layout: Layout,
    pub names: Names,
    pub volume_id: String,
    /// Files whose data is exactly another file's (hard links, or deduplication by the
    /// authoring tool).
    pub shared: usize,
    /// Neighbouring pairs of files whose data partly overlaps (never written by real tools).
    pub partial_overlaps: usize,
    /// Associated files (ISO 9660 "associated" flag, e.g. Mac resource forks): not extracted.
    pub associated_skipped: usize,
    /// Rock Ridge devices, FIFOs and sockets: not extracted.
    pub specials_skipped: usize,
    /// Files with the "hidden" (existence) flag; extracted like any other.
    pub hidden: usize,
}

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn read(src: &dyn FileHandle, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    src.read_exact_at(&mut v, off)?;
    Ok(v)
}

/// Byte offset of a logical block, checked.
fn block_offset(lba: u32) -> u64 {
    u64::from(lba) * SECTOR
}

/// True if `[off, off + len)` lies within the file.
fn in_bounds(off: u64, len: u64, file_len: u64) -> bool {
    off.checked_add(len).is_some_and(|end| end <= file_len)
}

/// Whether the bytes at the start of the volume descriptor area look like ISO 9660 or UDF
/// (whose volume recognition sequence lives in the same place). Used for format detection; the
/// parser gives UDF-only images a clear refusal.
pub fn looks_like_image(src: &dyn FileHandle) -> bool {
    let mut id = [0u8; 5];
    if src
        .read_exact_at(&mut id, FIRST_DESCRIPTOR * SECTOR + 1)
        .is_err()
    {
        return false;
    }
    &id == b"CD001" || &id == b"BEA01"
}

/// The descriptors the walk needs.
struct Descriptors {
    primary: Vec<u8>,
    joliet: Option<Vec<u8>>,
}

fn read_descriptors(src: &dyn FileHandle, file_len: u64) -> Result<Descriptors> {
    let mut primary = None;
    let mut joliet = None;
    let mut udf = false;
    for i in 0..MAX_DESCRIPTORS {
        let off = (FIRST_DESCRIPTOR + i) * SECTOR;
        if !in_bounds(off, SECTOR, file_len) {
            break;
        }
        let d = read(src, off, SECTOR_BYTES)?;
        match &d[1..6] {
            b"CD001" => {}
            b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01" => {
                udf = true;
                continue;
            }
            _ if primary.is_none() && joliet.is_none() => break,
            _ => continue,
        }
        match d[0] {
            1 if primary.is_none() => primary = Some(d),
            2 if joliet.is_none() && d[6] == 1 && is_joliet(&d) => joliet = Some(d),
            255 => break,
            _ => {}
        }
    }
    match primary {
        Some(primary) => Ok(Descriptors { primary, joliet }),
        None if udf => Err(IsoError::Unsupported(
            "UDF-only image (no ISO 9660 volume descriptors); UDF is not supported".into(),
        )),
        None => Err(IsoError::NotIso(
            "no primary volume descriptor at sector 16",
        )),
    }
}

/// A supplementary volume descriptor whose escape sequences announce Joliet (UCS-2 level 1-3).
fn is_joliet(d: &[u8]) -> bool {
    let esc = &d[88..120];
    [b"%/@", b"%/C", b"%/E"]
        .iter()
        .any(|seq| esc.windows(3).any(|w| w == *seq))
}

/// One directory record.
#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    xa_len: u8,
    lba: u32,
    size: u32,
    date: &'a [u8],
    flags: u8,
    interleaved: bool,
    name: &'a [u8],
    system_use: &'a [u8],
}

fn record(b: &[u8]) -> Result<Record<'_>> {
    let len = usize::from(b[0]);
    if len < 34 || len > b.len() {
        return Err(corrupt("directory record length out of range"));
    }
    let nlen = usize::from(b[32]);
    let su_start = 33 + nlen + usize::from(nlen % 2 == 0);
    if 33 + nlen > len {
        return Err(corrupt("directory record name overruns the record"));
    }
    Ok(Record {
        xa_len: b[1],
        lba: le32(b, 2),
        size: le32(b, 10),
        date: &b[18..25],
        flags: b[25],
        interleaved: b[26] != 0 || b[27] != 0,
        name: &b[33..33 + nlen],
        system_use: b.get(su_start..len).unwrap_or(&[]),
    })
}

/// Recording date (years since 1900, month, day, hour, minute, second, GMT offset in 15-minute
/// units) to Unix seconds; `None` when all zero ("not specified").
fn record_time(d: &[u8]) -> Option<i64> {
    if d.iter().all(|&b| b == 0) {
        return None;
    }
    Some(civil_seconds(
        1900 + i64::from(d[0]),
        [d[1], d[2], d[3], d[4], d[5]].map(i64::from),
        i8::from_le_bytes([d[6]]),
    ))
}

/// A volume descriptor date ("YYYYMMDDHHMMSScc" in ASCII digits, then the GMT offset in
/// 15-minute units) to Unix seconds; `None` when unset (all zero digits or bytes) or malformed.
fn descriptor_time(d: &[u8]) -> Option<i64> {
    let digits = &d[..16];
    if !digits.iter().all(u8::is_ascii_digit) || digits.iter().all(|&c| c == b'0') {
        return None;
    }
    let num = |i: usize, n: usize| -> i64 {
        digits[i..i + n]
            .iter()
            .fold(0, |acc, &c| acc * 10 + i64::from(c - b'0'))
    };
    Some(civil_seconds(
        num(0, 4),
        [num(4, 2), num(6, 2), num(8, 2), num(10, 2), num(12, 2)],
        i8::from_le_bytes([d[16]]),
    ))
}

/// Calendar date and time (month, day, hour, minute, second) at a GMT offset in 15-minute units
/// to Unix seconds.
fn civil_seconds(y: i64, [m, day, hh, mm, ss]: [i64; 5], gmt_offset: i8) -> i64 {
    let m = m.clamp(1, 12);
    let day = day.clamp(1, 31);
    let offset = i64::from(gmt_offset) * 900;
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hh * 3600 + mm * 60 + ss - offset
}

/// What the System Use Sharing Protocol fields of one record say (Rock Ridge).
#[derive(Debug, Default)]
struct Susp {
    /// SUSP indicator (`SP`), with the number of bytes to skip in every other record.
    sp_skip: Option<usize>,
    /// Rock Ridge evidence: `PX`, `ER` or the old `RR` field.
    rock_ridge: bool,
    name: Option<Vec<u8>>,
    mode: Option<u32>,
    symlink: bool,
    /// Relocated directory (`CL`): the real location of the directory this record stands for.
    child_link: Option<u32>,
    /// This directory was relocated (`RE`); it is listed under its `CL` placeholder instead.
    relocated: bool,
}

/// Parse a record's system use fields, following continuation areas (bounded).
fn parse_susp(
    src: &dyn FileHandle,
    file_len: u64,
    area: &[u8],
    skip: usize,
    budget: &mut usize,
) -> Result<Susp> {
    let mut out = Susp::default();
    let mut name = Vec::new();
    let mut name_done = false;
    let mut current: Vec<u8> = area.get(skip..).unwrap_or(&[]).to_vec();
    let mut total = current.len();
    let mut hops = 0usize;
    loop {
        let mut next = None;
        let mut p = 0usize;
        while p + 4 <= current.len() {
            let (sig, len, ver) = (
                &current[p..p + 2],
                usize::from(current[p + 2]),
                current[p + 3],
            );
            if len < 4 || p + len > current.len() {
                break; // padding or a damaged field: stop reading this area
            }
            let d = &current[p + 4..p + len];
            match (sig, ver) {
                (b"ST", _) => break,
                (b"SP", _) if d.len() >= 3 && d[..2] == [0xBE, 0xEF] => {
                    out.sp_skip = Some(usize::from(d[2]));
                }
                (b"CE", _) if d.len() >= 24 => {
                    next = Some((le32(d, 0), le32(d, 8), le32(d, 16)));
                }
                (b"ER" | b"RR", _) => out.rock_ridge = true,
                (b"PX", _) if d.len() >= 4 => {
                    out.rock_ridge = true;
                    out.mode = Some(le32(d, 0));
                }
                (b"SL", _) => out.symlink = true,
                (b"CL", _) if d.len() >= 4 => out.child_link = Some(le32(d, 0)),
                (b"RE", _) => out.relocated = true,
                (b"NM", _) if !d.is_empty() && !name_done => {
                    let flags = d[0];
                    if flags & 0x06 != 0 {
                        // "current" / "parent" names: not a real name.
                        name_done = true;
                    } else {
                        name.extend_from_slice(&d[1..]);
                        if name.len() > MAX_NM {
                            return Err(corrupt("Rock Ridge name too long"));
                        }
                        out.name = Some(name.clone());
                        name_done = flags & 0x01 == 0;
                    }
                }
                _ => {}
            }
            p += len;
        }
        let Some((lba, off, len)) = next else { break };
        hops += 1;
        let start = block_offset(lba) + u64::from(off);
        let len = len as usize;
        total += len;
        *budget = budget.checked_sub(len).ok_or_else(|| {
            IsoError::Unsupported(format!(
                "more than {} MiB of Rock Ridge continuation areas",
                MAX_CE_TOTAL >> 20
            ))
        })?;
        if hops > MAX_CONTINUATIONS || total > MAX_SUSP {
            return Err(corrupt("Rock Ridge continuation areas too long or looping"));
        }
        if !in_bounds(start, len as u64, file_len) {
            return Err(corrupt("Rock Ridge continuation area outside the image"));
        }
        current = read(src, start, len)?;
    }
    Ok(out)
}

/// Strip an ISO 9660 version suffix (`;1`).
fn strip_version(s: &str) -> &str {
    match s.rfind(';') {
        Some(i) if s[i + 1..].bytes().all(|c| c.is_ascii_digit()) => &s[..i],
        _ => s,
    }
}

/// Decode a record's name for the tree in use.
fn decode_name(
    r: &Record<'_>,
    names: Names,
    rr_name: Option<&[u8]>,
    is_dir: bool,
) -> Result<String> {
    let raw = match (names, rr_name) {
        (Names::RockRidge, Some(n)) => {
            return Ok(match std::str::from_utf8(n) {
                Ok(s) => s.to_owned(),
                Err(_) => n.iter().map(|&c| char::from(c)).collect(),
            });
        }
        (Names::Joliet, _) => {
            if r.name.len() % 2 != 0 {
                return Err(corrupt("Joliet name of odd length"));
            }
            let units = r
                .name
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]));
            char::decode_utf16(units)
                .collect::<std::result::Result<String, _>>()
                .map_err(|_| IsoError::Name {
                    name: String::from_utf8_lossy(r.name).into_owned(),
                    reason: "invalid UCS-2 in Joliet name".into(),
                })?
        }
        _ => r.name.iter().map(|&c| char::from(c)).collect(),
    };
    if is_dir {
        return Ok(raw);
    }
    let s = strip_version(&raw);
    // A plain ISO 9660 file name without an extension still has its separator dot.
    Ok(if names != Names::Joliet {
        s.strip_suffix('.').unwrap_or(s)
    } else {
        s
    }
    .to_owned())
}

/// A multi-extent file being assembled from consecutive records.
struct Pending {
    raw_name: Vec<u8>,
    data_offset: u64,
    size: u64,
}

struct Dir {
    lba: u32,
    /// Extended attribute record length in blocks: the records start after it.
    xa_len: u8,
    size: u32,
    path: String,
    depth: usize,
    /// This directory's own entry in the layout (none for the root).
    entry: Option<usize>,
}

/// Mode type bits.
const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFLNK: u32 = 0o120_000;

/// Parse an ISO 9660 image and validate it for extraction.
pub fn parse(src: &dyn FileHandle) -> Result<Image> {
    parse_with(src, MAX_NAME_BYTES)
}

fn parse_with(src: &dyn FileHandle, max_name_bytes: usize) -> Result<Image> {
    let file_len = src.size()?;
    let vds = read_descriptors(src, file_len)?;
    let pvd = &vds.primary;
    if u64::from(le16(pvd, 128)) != SECTOR {
        return Err(IsoError::Unsupported(format!(
            "logical block size {}",
            le16(pvd, 128)
        )));
    }
    if le16(pvd, 120) > 1 {
        return Err(IsoError::Unsupported("multi-volume set".into()));
    }
    let volume_id = String::from_utf8_lossy(&pvd[40..72]).trim_end().to_owned();
    // Records with no recording date get the volume's creation date (or the epoch).
    let default_time = descriptor_time(&pvd[813..830]).unwrap_or(0);
    let root = record(&pvd[156..190])?;

    // Rock Ridge lives in the primary tree; its SUSP indicator is in the root's "." record.
    let rr_skip = rock_ridge(src, file_len, &root)?;
    let (root_rec, names) = match (&rr_skip, &vds.joliet) {
        (Some(_), _) => (root, Names::RockRidge),
        (None, Some(j)) => {
            if u64::from(le16(j, 128)) != SECTOR {
                return Err(IsoError::Unsupported(format!(
                    "Joliet logical block size {}",
                    le16(j, 128)
                )));
            }
            (record(&j[156..190])?, Names::Joliet)
        }
        (None, None) => (root, Names::Iso9660),
    };
    let skip = rr_skip.unwrap_or(0);

    let mut img = Image {
        layout: Layout {
            entries: Vec::new(),
            cd_start: 0,
            file_len,
            overlaps: Vec::new(),
        },
        names,
        volume_id,
        shared: 0,
        partial_overlaps: 0,
        associated_skipped: 0,
        specials_skipped: 0,
        hidden: 0,
    };
    // Directories by the offset of their records.
    let mut visited: HashSet<u64> = HashSet::new();
    let mut dir_ranges: Vec<(u64, u64)> = Vec::new();
    let mut dir_bytes = 0u64;
    let mut ce_budget = MAX_CE_TOTAL;
    let mut name_bytes = 0usize;
    // Rock Ridge relocated directories (`RE`) by extent, with the directory listing them, and the
    // extents `CL` placeholders link to: every relocated directory must be linked.
    let mut relocated: HashMap<u32, String> = HashMap::new();
    let mut linked: HashSet<u32> = HashSet::new();
    // Top-level directories holding nothing but relocated directories (`rr_moved`).
    let mut moved_only: Vec<usize> = Vec::new();
    let mut stack = vec![Dir {
        lba: root_rec.lba,
        xa_len: root_rec.xa_len,
        size: root_rec.size,
        path: String::new(),
        depth: 0,
        entry: None,
    }];
    while let Some(dir) = stack.pop() {
        let start = block_offset(dir.lba) + u64::from(dir.xa_len) * SECTOR;
        if !visited.insert(start) {
            return Err(corrupt(format!(
                "directory loop: {:?} reuses the records of another directory",
                display_path(&dir.path)
            )));
        }
        let size = u64::from(dir.size);
        dir_bytes += size;
        if dir_bytes > MAX_DIR_BYTES {
            return Err(IsoError::Unsupported(format!(
                "more than {} MiB of directory records",
                MAX_DIR_BYTES >> 20
            )));
        }
        if size == 0 || !in_bounds(start, size, file_len) {
            return Err(corrupt(format!(
                "directory {:?} lies outside the image",
                display_path(&dir.path)
            )));
        }
        dir_ranges.push((start, start + size));
        let buf = read(src, start, usize::try_from(size).expect("<= 4 GiB"))?;
        let mut children = Vec::new();
        // Names in this directory: duplicates can only be siblings.
        let mut seen: HashSet<String> = HashSet::new();
        let (mut listed, mut moved) = (0usize, 0usize);
        let mut pending: Option<Pending> = None;
        let mut p = 0usize;
        while p < buf.len() {
            if buf[p] == 0 {
                // Records never cross a sector; the rest of this one is padding.
                p = (p / SECTOR_BYTES + 1) * SECTOR_BYTES;
                continue;
            }
            let r = record(&buf[p..])?;
            p += usize::from(buf[p]);
            if r.name == [0] || r.name == [1] {
                continue; // "." and ".."
            }
            listed += 1;
            let su = if names == Names::RockRidge {
                parse_susp(src, file_len, r.system_use, skip, &mut ce_budget)?
            } else {
                Susp::default()
            };
            if su.relocated {
                // Listed where its CL placeholder is; checked to be linked after the walk.
                if r.flags & FLAG_DIR == 0 || su.child_link.is_some() {
                    return Err(corrupt(format!(
                        "Rock Ridge relocated entry in {:?} is not a directory",
                        display_path(&dir.path)
                    )));
                }
                if relocated.insert(r.lba, dir.path.clone()).is_some() {
                    return Err(corrupt("Rock Ridge directory relocated twice"));
                }
                moved += 1;
                continue;
            }
            if r.interleaved {
                return Err(IsoError::Unsupported("interleaved files".into()));
            }
            let is_dir = r.flags & FLAG_DIR != 0 || su.child_link.is_some();
            if r.flags & FLAG_ASSOCIATED != 0 {
                if pending.is_some() {
                    return Err(corrupt("multi-extent file interrupted by another record"));
                }
                img.associated_skipped += 1;
                continue;
            }

            // Multi-extent files: sections must be consecutive records of one name, each but the
            // last a whole number of blocks, and (for a single byte range) contiguous.
            let data_offset = block_offset(r.lba) + u64::from(r.xa_len) * SECTOR;
            let (data_offset, size) = match pending.take() {
                Some(pd) => {
                    if pd.raw_name != r.name || is_dir {
                        return Err(corrupt("multi-extent file interrupted by another record"));
                    }
                    if pd.size % SECTOR != 0 || data_offset != pd.data_offset + pd.size {
                        return Err(IsoError::Unsupported(
                            "multi-extent file whose sections are not contiguous".into(),
                        ));
                    }
                    (pd.data_offset, pd.size + u64::from(r.size))
                }
                None => (data_offset, u64::from(r.size)),
            };
            if r.flags & FLAG_MULTI_EXTENT != 0 {
                if is_dir {
                    return Err(corrupt("multi-extent directory"));
                }
                pending = Some(Pending {
                    raw_name: r.name.to_vec(),
                    data_offset,
                    size,
                });
                continue;
            }

            let kind = if is_dir {
                Kind::Dir
            } else if su.symlink || su.mode.is_some_and(|m| m & S_IFMT == S_IFLNK) {
                Kind::Symlink
            } else if su
                .mode
                .is_some_and(|m| m & S_IFMT != S_IFREG && m & S_IFMT != 0 && m & S_IFMT != S_IFDIR)
            {
                img.specials_skipped += 1;
                continue;
            } else {
                Kind::File
            };
            let comp = decode_name(&r, names, su.name.as_deref(), is_dir)?;
            name_bytes += dir.path.len() + 1 + comp.len();
            if name_bytes > max_name_bytes {
                return Err(IsoError::Unsupported(format!(
                    "more than {} MiB of entry names",
                    max_name_bytes >> 20
                )));
            }
            let name = full_name(&dir.path, &comp)?;
            let last = name.rsplit('/').next().unwrap_or(&name);
            if !seen.insert(trunc_core::path::host_key(last)) {
                return Err(IsoError::Name {
                    name,
                    reason: if cfg!(any(windows, target_os = "macos")) {
                        "duplicate entry (names differ only in case)"
                    } else {
                        "duplicate entry"
                    }
                    .into(),
                });
            }
            if img.layout.entries.len() >= MAX_ENTRIES {
                return Err(IsoError::Unsupported(format!(
                    "more than {MAX_ENTRIES} entries"
                )));
            }
            if r.flags & FLAG_HIDDEN != 0 {
                img.hidden += 1;
            }
            let mode = su.mode.map(|m| m & 0o7777);
            let mtime_unix = record_time(r.date).unwrap_or(default_time);
            match kind {
                Kind::Dir => {
                    if dir.depth + 1 >= trunc_core::path::MAX_DEPTH {
                        return Err(corrupt("directory tree too deep"));
                    }
                    let (lba, xa_len, size) = match su.child_link {
                        Some(lba) => {
                            linked.insert(lba);
                            (lba, 0, relocated_size(src, file_len, lba)?)
                        }
                        None => (r.lba, r.xa_len, r.size),
                    };
                    children.push(Dir {
                        lba,
                        xa_len,
                        size,
                        path: name.clone(),
                        depth: dir.depth + 1,
                        entry: Some(img.layout.entries.len()),
                    });
                    img.layout
                        .entries
                        .push(empty_entry(name, Kind::Dir, mode, mtime_unix));
                }
                Kind::Symlink => {
                    img.layout
                        .entries
                        .push(empty_entry(name, Kind::Symlink, mode, mtime_unix));
                }
                Kind::File if size == 0 => {
                    img.layout
                        .entries
                        .push(empty_entry(name, Kind::File, mode, mtime_unix));
                }
                Kind::File => {
                    if !in_bounds(data_offset, size, file_len) {
                        return Err(corrupt(format!("data of {name:?} lies outside the image")));
                    }
                    img.layout.entries.push(Entry {
                        name,
                        kind: Kind::File,
                        method: Method::Stored,
                        crc32: 0,
                        compressed_size: size,
                        size,
                        region_start: data_offset,
                        data_offset,
                        region_end: data_offset + size,
                        mode,
                        mtime_unix,
                    });
                }
            }
        }
        if pending.is_some() {
            return Err(corrupt("multi-extent file without its final section"));
        }
        if dir.depth == 1 && listed > 0 && moved == listed {
            moved_only.extend(dir.entry);
        }
        // Depth-first, in directory order.
        stack.extend(children.into_iter().rev());
    }
    if let Some(parent) = relocated
        .iter()
        .filter(|(lba, _)| !linked.contains(lba))
        .map(|(_, parent)| parent)
        .min()
    {
        return Err(corrupt(format!(
            "Rock Ridge relocated directory in {:?} is not linked from any CL entry",
            display_path(parent)
        )));
    }
    if !moved_only.is_empty() {
        // An `rr_moved` directory is an artifact of relocation, not content.
        moved_only.sort_unstable();
        let mut i = 0usize;
        img.layout.entries.retain(|_| {
            i += 1;
            moved_only.binary_search(&(i - 1)).is_err()
        });
    }
    check_extents(&mut img, &mut dir_ranges)?;
    Ok(img)
}

fn display_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

/// The size of a relocated directory, from its own "." record (which carries Rock Ridge fields,
/// so it is longer than a bare record: read its whole sector).
fn relocated_size(src: &dyn FileHandle, file_len: u64, lba: u32) -> Result<u32> {
    let off = block_offset(lba);
    if !in_bounds(off, 34, file_len) {
        return Err(corrupt("relocated directory outside the image"));
    }
    let len = (file_len - off).min(SECTOR);
    let b = read(src, off, usize::try_from(len).expect("<= 2048"))?;
    let r = record(&b)?;
    if r.name != [0] || r.lba != lba {
        return Err(corrupt(
            "relocated directory link does not point at a directory",
        ));
    }
    Ok(r.size)
}

/// Whether the root's "." record announces Rock Ridge; returns the SUSP skip length.
fn rock_ridge(src: &dyn FileHandle, file_len: u64, root: &Record<'_>) -> Result<Option<usize>> {
    let off = block_offset(root.lba) + u64::from(root.xa_len) * SECTOR;
    if !in_bounds(off, SECTOR, file_len) || root.size < 34 {
        return Err(corrupt("root directory lies outside the image"));
    }
    let b = read(src, off, SECTOR_BYTES)?;
    let dot = record(&b)?;
    if dot.name != [0] {
        return Ok(None);
    }
    let mut budget = MAX_CE_TOTAL;
    let su = parse_susp(src, file_len, dot.system_use, 0, &mut budget)?;
    Ok(match su.sp_skip {
        Some(skip) if su.rock_ridge => Some(skip),
        _ => None,
    })
}

fn empty_entry(name: String, kind: Kind, mode: Option<u32>, mtime_unix: i64) -> Entry {
    Entry {
        name,
        kind,
        method: Method::Stored,
        crc32: 0,
        compressed_size: 0,
        size: 0,
        region_start: 0,
        data_offset: 0,
        region_end: 0,
        mode,
        mtime_unix,
    }
}

/// Join and validate a path, exactly as ZIP and tar entry names are validated.
fn full_name(parent: &str, comp: &str) -> Result<String> {
    let full = if parent.is_empty() {
        comp.to_owned()
    } else {
        format!("{parent}/{comp}")
    };
    let name_err = |reason: String| IsoError::Name {
        name: full.clone(),
        reason,
    };
    if comp.contains(['/', '\0']) {
        return Err(name_err("'/' or NUL inside a name".into()));
    }
    let nfc: String = full.nfc().collect();
    trunc_core::path::validate_host(&nfc).map_err(|e| name_err(e.to_string()))?;
    Ok(nfc)
}

/// Directory extents must not overlap each other or any file's data. Count shared and partly
/// overlapping file extents, and record the overlaps for the consumer.
fn check_extents(img: &mut Image, dirs: &mut [(u64, u64)]) -> Result<()> {
    dirs.sort_unstable();
    if dirs.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(corrupt("directory extents overlap"));
    }
    let entries = &img.layout.entries;
    let mut files: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].kind == Kind::File && entries[i].size > 0)
        .collect();
    for &i in &files {
        let e = &entries[i];
        // The last directory starting before the file ends is the only one that can overlap it.
        let k = dirs.partition_point(|d| d.0 < e.region_end);
        if k > 0 && dirs[k - 1].1 > e.region_start {
            return Err(corrupt(format!(
                "data of {:?} overlaps directory records",
                e.name
            )));
        }
    }
    files.sort_by_key(|&i| (entries[i].region_start, entries[i].region_end));
    for w in files.windows(2) {
        let (a, b) = (&entries[w[0]], &entries[w[1]]);
        if a.region_start == b.region_start && a.region_end == b.region_end {
            img.shared += 1;
        } else if a.region_end > b.region_start {
            img.partial_overlaps += 1;
        }
    }
    img.layout.overlaps = crate::zip::overlaps(entries);
    img.layout.cd_start = entries.iter().map(|e| e.region_end).max().unwrap_or(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_dots() {
        assert_eq!(strip_version("README.TXT;1"), "README.TXT");
        assert_eq!(strip_version("A;B"), "A;B");
        assert_eq!(strip_version("X;"), "X");
    }

    #[test]
    fn total_name_bytes_are_bounded() {
        use trunc_fs::{FsBackend, OpenMode, Share};
        use trunc_testkit::isobuild::{IsoBuilder, Spec};
        use trunc_testkit::{CrashModel, FaultFs};

        let mut b = IsoBuilder::new().rock_ridge(true);
        let dir = "d".repeat(100);
        for i in 0..20 {
            b.add(Spec::file(&format!("{dir}/{i:03}"), b"x"));
        }
        let fs = FaultFs::new(CrashModel::WriteThrough);
        fs.put_file(std::path::Path::new("/i.iso"), &b.build().bytes);
        let h = fs
            .open(
                std::path::Path::new("/i.iso"),
                OpenMode::Read,
                Share::Shared,
            )
            .expect("open");
        // 101 bytes for the directory, then 104 per file (its full path and a separator).
        let need = 101 + 20 * 104;
        assert!(parse_with(h.as_ref(), need).is_ok());
        match parse_with(h.as_ref(), need - 1) {
            Err(IsoError::Unsupported(m)) => assert!(m.contains("entry names"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn times() {
        // 2024-02-29 13:45:58 UTC, then the same wall time at GMT+1.
        let d = [124, 2, 29, 13, 45, 58, 0];
        assert_eq!(record_time(&d), Some(1_709_214_358));
        let d = [124, 2, 29, 13, 45, 58, 4];
        assert_eq!(record_time(&d), Some(1_709_214_358 - 3600));
        assert_eq!(record_time(&[0; 7]), None);
        let mut d = *b"2024022913455800\x04";
        assert_eq!(descriptor_time(&d), Some(1_709_214_358 - 3600));
        d[..16].fill(b'0');
        assert_eq!(descriptor_time(&d), None);
        assert_eq!(descriptor_time(&[0; 17]), None);
    }
}

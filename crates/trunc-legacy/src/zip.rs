//! ZIP parsing for extraction.
//!
//! Every central-directory entry is cross-checked against its local header (name, method,
//! flags, and CRC/sizes unless a data descriptor is used), so that what is extracted is what the
//! directory describes. The result records each entry's byte *region* in the file, from its local
//! header to the end of its data (and data descriptor), which is what destructive extraction
//! frees.

use std::collections::HashSet;

use trunc_fs::FileHandle;
use unicode_normalization::UnicodeNormalization;

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;
const SIG_DESCRIPTOR: u32 = 0x0807_4b50;
const EOCD_LEN: u64 = 22;
const EOCD_BYTES: usize = 22;
const MAX_COMMENT: u64 = 0xFFFF;
const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DESCRIPTOR: u16 = 1 << 3;
const FLAG_UTF8: u16 = 1 << 11;
/// Refuse central directories larger than this (bounds memory on hostile input).
const MAX_CD: u64 = 512 << 20;

#[derive(Debug, thiserror::Error)]
pub enum ZipError {
    #[error("not a ZIP archive: {0}")]
    NotZip(&'static str),
    #[error("unsupported ZIP feature: {0}")]
    Unsupported(String),
    #[error("corrupt ZIP: {0}")]
    Corrupt(String),
    #[error("unsafe or invalid entry name {name:?}: {reason}")]
    Name { name: String, reason: String },
    #[error(transparent)]
    Fs(#[from] trunc_fs::FsError),
}

type Result<T> = std::result::Result<T, ZipError>;

fn corrupt(msg: impl Into<String>) -> ZipError {
    ZipError::Corrupt(msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflate,
    /// Method 12: complete bzip2 streams.
    Bzip2,
    /// Method 93: zstd frames.
    Zstd,
    /// Method 95: a complete xz stream.
    Xz,
}

impl Method {
    /// The method for a ZIP method number, or why it is refused.
    pub fn from_raw(m: u16) -> std::result::Result<Self, String> {
        Ok(match m {
            0 => Method::Stored,
            8 => Method::Deflate,
            12 => Method::Bzip2,
            93 => Method::Zstd,
            95 => Method::Xz,
            m => {
                let name = match m {
                    1 => " (shrink)",
                    2..=5 => " (reduce)",
                    6 => " (implode)",
                    9 => " (deflate64)",
                    14 => " (LZMA)",
                    96 => " (JPEG)",
                    97 => " (WavPack)",
                    98 => " (PPMd)",
                    99 => " (AES encryption)",
                    _ => "",
                };
                return Err(format!(
                    "compression method {m}{name}; supported: stored, deflate, bzip2, zstd, xz"
                ));
            }
        })
    }

    /// The ZIP method number.
    pub fn raw(self) -> u16 {
        match self {
            Method::Stored => 0,
            Method::Deflate => 8,
            Method::Bzip2 => 12,
            Method::Zstd => 93,
            Method::Xz => 95,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Stored => "stored",
            Method::Deflate => "deflate",
            Method::Bzip2 => "bzip2",
            Method::Zstd => "zstd",
            Method::Xz => "xz",
        }
    }

    /// Code in the serialized layout (0 and 1 keep their original stored/deflate meaning).
    fn code(self) -> u8 {
        match self {
            Method::Stored => 0,
            Method::Deflate => 1,
            Method::Bzip2 => 2,
            Method::Zstd => 3,
            Method::Xz => 4,
        }
    }

    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Method::Stored,
            1 => Method::Deflate,
            2 => Method::Bzip2,
            3 => Method::Zstd,
            4 => Method::Xz,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// Unix symlink (target is the entry's content). Never created by the extractor.
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Validated relative path, `/`-separated, NFC (directories without the trailing `/`).
    pub name: String,
    pub kind: Kind,
    pub method: Method,
    pub crc32: u32,
    pub compressed_size: u64,
    pub size: u64,
    /// Offset of the local header.
    pub region_start: u64,
    /// Offset of the compressed data.
    pub data_offset: u64,
    /// End of the data and data descriptor.
    pub region_end: u64,
    /// Unix permission bits, if the archive was made on Unix.
    pub mode: Option<u32>,
    pub mtime_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub entries: Vec<Entry>,
    /// Start of the central directory (everything from here to EOF is directory and trailer).
    pub cd_start: u64,
    pub file_len: u64,
    /// Pairs of entry indices whose regions overlap.
    pub overlaps: Vec<(usize, usize)>,
}

fn le16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

fn le64(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

fn read(src: &dyn FileHandle, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    src.read_exact_at(&mut v, off)?;
    Ok(v)
}

/// Extra-field records as (id, data).
fn extras(mut b: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while b.len() >= 4 {
        let (id, n) = (le16(b, 0), usize::from(le16(b, 2)));
        if b.len() < 4 + n {
            break;
        }
        out.push((id, &b[4..4 + n]));
        b = &b[4 + n..];
    }
    out
}

/// DOS date/time (local time, treated as UTC) to Unix seconds.
fn dos_time(date: u16, time: u16) -> i64 {
    let y = i64::from(date >> 9) + 1980;
    let m = i64::from((date >> 5) & 0xF).clamp(1, 12);
    let d = i64::from(date & 0x1F).max(1);
    let (hh, mm, ss) = (
        i64::from(time >> 11),
        i64::from((time >> 5) & 0x3F),
        i64::from(time & 0x1F) * 2,
    );
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hh * 3600 + mm * 60 + ss
}

fn decode_name(raw: &[u8], flags: u16, extra: &[(u16, &[u8])]) -> String {
    // Info-ZIP Unicode Path extra (0x7075): version 1, CRC-32 of the raw name, UTF-8 name.
    for &(id, d) in extra {
        if id == 0x7075 && d.len() > 5 && d[0] == 1 && le32(d, 1) == crc32fast::hash(raw) {
            if let Ok(s) = std::str::from_utf8(&d[5..]) {
                return s.to_owned();
            }
        }
    }
    if flags & FLAG_UTF8 != 0 {
        if let Ok(s) = std::str::from_utf8(raw) {
            return s.to_owned();
        }
    }
    crate::cp437::decode(raw)
}

/// Turn a raw ZIP name into a validated relative path. Returns the path and whether the name
/// marked a directory (trailing slash).
fn clean_name(name: &str) -> Result<(String, bool)> {
    let name_err = |reason: String| ZipError::Name {
        name: name.to_owned(),
        reason,
    };
    let unified = name.replace('\\', "/");
    let is_dir = unified.ends_with('/');
    let trimmed = unified.trim_end_matches('/');
    let nfc: String = trimmed.nfc().collect();
    trunc_core::path::validate_host(&nfc).map_err(|e| name_err(e.to_string()))?;
    Ok((nfc, is_dir))
}

struct Eocd {
    pos: u64,
    entries: u64,
    cd_size: u64,
    cd_offset: u64,
}

fn find_eocd(src: &dyn FileHandle, len: u64) -> Result<Eocd> {
    if len < EOCD_LEN {
        return Err(ZipError::NotZip("too short"));
    }
    let tail_len = len.min(EOCD_LEN + MAX_COMMENT);
    let tail = read(
        src,
        len - tail_len,
        usize::try_from(tail_len).expect("< 64 KiB"),
    )?;
    let mut i = tail.len() - EOCD_BYTES;
    loop {
        if le32(&tail, i) == SIG_EOCD
            && i + EOCD_BYTES + usize::from(le16(&tail, i + 20)) == tail.len()
        {
            let b = &tail[i..];
            let pos = len - tail_len + i as u64;
            if le16(b, 4) != 0 || le16(b, 6) != 0 {
                return Err(ZipError::Unsupported("multi-disk (spanned) archive".into()));
            }
            let mut e = Eocd {
                pos,
                entries: u64::from(le16(b, 10)),
                cd_size: u64::from(le32(b, 12)),
                cd_offset: u64::from(le32(b, 16)),
            };
            // Zip64 locator immediately precedes the EOCD.
            if pos >= 20 {
                let loc = read(src, pos - 20, 20)?;
                if le32(&loc, 0) == SIG_ZIP64_LOCATOR {
                    let z_off = le64(&loc, 8);
                    if z_off.checked_add(56).is_none_or(|end| end > pos) {
                        return Err(corrupt("Zip64 end record out of range"));
                    }
                    let z = read(src, z_off, 56)?;
                    if le32(&z, 0) != SIG_ZIP64_EOCD {
                        return Err(corrupt("bad Zip64 end record signature"));
                    }
                    e.entries = le64(&z, 32);
                    e.cd_size = le64(&z, 40);
                    e.cd_offset = le64(&z, 48);
                    e.pos = z_off;
                }
            }
            return Ok(e);
        }
        if i == 0 {
            return Err(ZipError::NotZip("no end-of-central-directory record"));
        }
        i -= 1;
    }
}

/// Parse a ZIP archive and validate it for extraction.
pub fn parse(src: &dyn FileHandle) -> Result<Layout> {
    let file_len = src.size()?;
    let eocd = find_eocd(src, file_len)?;
    if eocd.cd_size > MAX_CD || eocd.cd_size > eocd.pos {
        return Err(corrupt("central directory size out of range"));
    }
    // Self-extracting archives prepend a stub: the directory really starts at pos - size.
    let cd_start = eocd.pos - eocd.cd_size;
    let shift = cd_start
        .checked_sub(eocd.cd_offset)
        .ok_or_else(|| corrupt("central directory offset past its end"))?;
    let cd = read(
        src,
        cd_start,
        usize::try_from(eocd.cd_size).expect("<= 512 MiB"),
    )?;

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut p = 0usize;
    for _ in 0..eocd.entries {
        if p + 46 > cd.len() || le32(&cd, p) != SIG_CENTRAL {
            return Err(corrupt("central directory entry missing or truncated"));
        }
        let h = &cd[p..];
        let made_by = le16(h, 4);
        let flags = le16(h, 8);
        let method_raw = le16(h, 10);
        let (time, date) = (le16(h, 12), le16(h, 14));
        let crc32 = le32(h, 16);
        let mut csize = u64::from(le32(h, 20));
        let mut usize_ = u64::from(le32(h, 24));
        let (nlen, xlen, clen) = (
            usize::from(le16(h, 28)),
            usize::from(le16(h, 30)),
            usize::from(le16(h, 32)),
        );
        let ext_attr = le32(h, 38);
        let mut lho = u64::from(le32(h, 42));
        if p + 46 + nlen + xlen + clen > cd.len() {
            return Err(corrupt("central directory entry overruns the directory"));
        }
        let raw_name = &h[46..46 + nlen];
        let extra = extras(&h[46 + nlen..46 + nlen + xlen]);
        p += 46 + nlen + xlen + clen;

        // Zip64 extra: present fields replace the 0xFFFFFFFF placeholders, in this order.
        if let Some(&(_, z)) = extra.iter().find(|(id, _)| *id == 1) {
            let mut i = 0;
            let mut take = |v: &mut u64| -> Result<()> {
                if *v == 0xFFFF_FFFF {
                    *v = le64(
                        z.get(i..i + 8)
                            .ok_or_else(|| corrupt("short Zip64 extra field"))?,
                        0,
                    );
                    i += 8;
                }
                Ok(())
            };
            take(&mut usize_)?;
            take(&mut csize)?;
            take(&mut lho)?;
        }
        if flags & FLAG_ENCRYPTED != 0 {
            return Err(ZipError::Unsupported("encrypted entries".into()));
        }
        let method = Method::from_raw(method_raw).map_err(ZipError::Unsupported)?;
        if method == Method::Stored && csize != usize_ {
            return Err(corrupt(
                "stored entry with different compressed and uncompressed sizes",
            ));
        }

        let display = decode_name(raw_name, flags, &extra);
        let (name, dir_name) = clean_name(&display)?;
        let unix_mode = (made_by >> 8 == 3)
            .then_some(ext_attr >> 16)
            .filter(|m| *m != 0);
        let is_dir = dir_name
            || ext_attr & 0x10 != 0
            || unix_mode.is_some_and(|m| m & 0o170_000 == 0o040_000);
        let kind = if is_dir {
            Kind::Dir
        } else if unix_mode.is_some_and(|m| m & 0o170_000 == 0o120_000) {
            Kind::Symlink
        } else {
            Kind::File
        };
        if is_dir && usize_ != 0 {
            return Err(corrupt(format!("directory {name:?} has content")));
        }
        if !seen.insert(trunc_core::path::host_key(&name)) {
            return Err(ZipError::Name {
                name,
                reason: if cfg!(any(windows, target_os = "macos")) {
                    "duplicate entry (names differ only in case)"
                } else {
                    "duplicate entry"
                }
                .into(),
            });
        }
        let mtime_unix = extra
            .iter()
            .find(|(id, d)| *id == 0x5455 && d.len() >= 5 && d[0] & 1 != 0)
            .map_or_else(
                || dos_time(date, time),
                |(_, d)| i64::from(le32(d, 1) as i32),
            );

        // Cross-check the local header.
        let region_start = lho
            .checked_add(shift)
            .ok_or_else(|| corrupt("offset overflow"))?;
        if region_start
            .checked_add(30)
            .is_none_or(|end| end > cd_start)
        {
            return Err(corrupt(format!(
                "local header of {name:?} outside the data area"
            )));
        }
        let lh = read(src, region_start, 30)?;
        if le32(&lh, 0) != SIG_LOCAL {
            return Err(corrupt(format!("missing local header for {name:?}")));
        }
        let (lflags, lmethod) = (le16(&lh, 6), le16(&lh, 8));
        let (lnlen, lxlen) = (u64::from(le16(&lh, 26)), u64::from(le16(&lh, 28)));
        let lname = read(src, region_start + 30, usize::try_from(lnlen).expect("u16"))?;
        let lextra_raw = read(
            src,
            region_start + 30 + lnlen,
            usize::try_from(lxlen).expect("u16"),
        )?;
        if lmethod != method_raw
            || lname != raw_name
            || (lflags & FLAG_DESCRIPTOR) != (flags & FLAG_DESCRIPTOR)
        {
            return Err(corrupt(format!(
                "local header of {name:?} does not match the central directory"
            )));
        }
        let local_zip64 = extras(&lextra_raw).iter().any(|(id, _)| *id == 1);
        if flags & FLAG_DESCRIPTOR == 0 {
            let lcrc = le32(&lh, 14);
            let (lc, lu) = (u64::from(le32(&lh, 18)), u64::from(le32(&lh, 22)));
            let sizes_ok =
                (lc == csize || lc == 0xFFFF_FFFF) && (lu == usize_ || lu == 0xFFFF_FFFF);
            if lcrc != crc32 || !sizes_ok {
                return Err(corrupt(format!(
                    "local header of {name:?} disagrees on CRC or sizes"
                )));
            }
        }
        let data_offset = region_start + 30 + lnlen + lxlen;
        let data_end = data_offset
            .checked_add(csize)
            .ok_or_else(|| corrupt("size overflow"))?;
        let mut region_end = data_end;
        if flags & FLAG_DESCRIPTOR != 0 {
            let big = local_zip64 || csize >= 0xFFFF_FFFF || usize_ >= 0xFFFF_FFFF;
            let want = if big { 20 } else { 12 };
            let d = read(src, data_end, want + 4).or_else(|_| read(src, data_end, want))?;
            let (body, sig) = if le32(&d, 0) == SIG_DESCRIPTOR {
                (&d[4..], 4)
            } else {
                (&d[..], 0)
            };
            if le32(body, 0) != crc32 {
                return Err(corrupt(format!(
                    "data descriptor of {name:?} disagrees on CRC"
                )));
            }
            region_end = data_end
                .checked_add(sig + want as u64)
                .ok_or_else(|| corrupt("size overflow"))?;
        }
        if region_end > cd_start {
            return Err(corrupt(format!(
                "data of {name:?} runs into the central directory"
            )));
        }
        entries.push(Entry {
            name,
            kind,
            method,
            crc32,
            compressed_size: csize,
            size: usize_,
            region_start,
            data_offset,
            region_end,
            mode: unix_mode.map(|m| m & 0o7777),
            mtime_unix,
        });
    }

    // No entry may live under a file entry ("a" plus "a/b").
    let files: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind != Kind::Dir)
        .map(|e| trunc_core::path::host_key(&e.name))
        .collect();
    for e in &entries {
        let mut parent = trunc_core::path::parent(&e.name);
        while let Some(pp) = parent {
            if files.contains(&trunc_core::path::host_key(pp)) {
                return Err(ZipError::Name {
                    name: e.name.clone(),
                    reason: "nested under a file".into(),
                });
            }
            parent = trunc_core::path::parent(pp);
        }
    }

    let overlaps = overlaps(&entries);
    Ok(Layout {
        entries,
        cd_start,
        file_len,
        overlaps,
    })
}

/// Pairs of entries whose regions overlap, found among neighbours in order of region start.
/// Not every overlapping pair is listed, but the list is empty only if no regions overlap.
pub fn overlaps(entries: &[Entry]) -> Vec<(usize, usize)> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| (entries[i].region_start, entries[i].region_end));
    order
        .windows(2)
        .filter(|w| entries[w[0]].region_end > entries[w[1]].region_start)
        .map(|w| (w[0], w[1]))
        .collect()
}

impl Layout {
    /// Serialize for the consume journal (so a resume works after the directory is truncated).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"TZL1");
        for v in [self.cd_start, self.file_len, self.entries.len() as u64] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for e in &self.entries {
            let kind = match e.kind {
                Kind::File => 0u8,
                Kind::Dir => 1,
                Kind::Symlink => 2,
            };
            b.push(kind);
            b.push(e.method.code());
            b.extend_from_slice(&e.crc32.to_le_bytes());
            for v in [
                e.compressed_size,
                e.size,
                e.region_start,
                e.data_offset,
                e.region_end,
            ] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&e.mode.unwrap_or(u32::MAX).to_le_bytes());
            b.extend_from_slice(&e.mtime_unix.to_le_bytes());
            b.extend_from_slice(&u32::try_from(e.name.len()).expect("<= 4096").to_le_bytes());
            b.extend_from_slice(e.name.as_bytes());
        }
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut r = Cursor { b, i: 0 };
        if r.take(4)? != b"TZL1" {
            return None;
        }
        let (cd_start, file_len, n) = (r.u64()?, r.u64()?, r.u64()?);
        let mut entries = Vec::new();
        for _ in 0..n {
            let kind = match r.take(1)?[0] {
                0 => Kind::File,
                1 => Kind::Dir,
                2 => Kind::Symlink,
                _ => return None,
            };
            let method = Method::from_code(r.take(1)?[0])?;
            let crc32 = r.u32()?;
            let (compressed_size, size, region_start, data_offset, region_end) =
                (r.u64()?, r.u64()?, r.u64()?, r.u64()?, r.u64()?);
            let mode = Some(r.u32()?).filter(|m| *m != u32::MAX);
            let mtime_unix = i64::from_le_bytes(r.take(8)?.try_into().ok()?);
            let nl = r.u32()? as usize;
            let name = String::from_utf8(r.take(nl)?.to_vec()).ok()?;
            trunc_core::path::validate_host(&name).ok()?;
            entries.push(Entry {
                name,
                kind,
                method,
                crc32,
                compressed_size,
                size,
                region_start,
                data_offset,
                region_end,
                mode,
                mtime_unix,
            });
        }
        if r.i != b.len() {
            return None;
        }
        let overlaps = overlaps(&entries);
        Some(Self {
            entries,
            cd_start,
            file_len,
            overlaps,
        })
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_times() {
        // 2024-02-29 13:45:58
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (45 << 5) | (58 / 2);
        assert_eq!(dos_time(date, time), 1_709_214_358);
        assert_eq!(dos_time((1 << 5) | 1, 0), 315_532_800); // 1980-01-01
    }

    #[test]
    fn names() {
        assert_eq!(clean_name("dir/").unwrap(), ("dir".into(), true));
        assert_eq!(clean_name("a\\b.txt").unwrap(), ("a/b.txt".into(), false));
        for bad in ["../x", "/abs", "C:/x", "a/../../b", ""] {
            assert!(clean_name(bad).is_err(), "{bad:?} accepted");
        }
    }
}

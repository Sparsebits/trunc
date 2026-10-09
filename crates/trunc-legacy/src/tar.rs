//! Streaming tar reader for extraction: POSIX ustar, GNU (long names and links, base-256
//! numbers) and PAX extended headers.
//!
//! [`Reader`] is fed the decompressed stream in pieces and records each entry with the offset of
//! its data in that stream, so a second pass can route bytes to files without parsing again.
//! Names are validated like ZIP names: relative, NFC, no `..`, valid on this computer (see
//! [`trunc_core::path::validate_host`]), no duplicates and nothing nested under a file. Hard links, GNU sparse files and
//! multi-volume archives are refused.

use std::collections::HashSet;

use unicode_normalization::UnicodeNormalization;

pub const BLOCK: u64 = 512;
const BLOCK_BYTES: usize = 512;
/// Largest GNU long name/link or PAX header accepted (bounds memory on hostile input).
const MAX_META: u64 = 1 << 20;
/// Largest number of entries accepted (bounds memory: each costs about 100 bytes).
pub const MAX_ENTRIES: usize = 10_000_000;

#[derive(Debug, thiserror::Error)]
pub enum TarError {
    #[error("not a tar archive")]
    NotTar,
    #[error("corrupt tar at byte {0}: {1}")]
    Corrupt(u64, String),
    #[error("unsupported tar feature at byte {0}: {1}")]
    Unsupported(u64, String),
    #[error("unsafe or invalid entry name {name:?}: {reason}")]
    Name { name: String, reason: String },
}

type Result<T> = std::result::Result<T, TarError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// Never created by the extractor.
    Symlink,
    /// Character or block device, or FIFO: no data, never created.
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// Bytes of content (0 for everything but files).
    pub size: u64,
    /// Offset of the content in the (decompressed) tar stream.
    pub data_offset: u64,
    pub mode: Option<u32>,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
}

/// Metadata that applies to the next real header.
#[derive(Debug, Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    pax_path: Option<String>,
    pax_size: Option<u64>,
    pax_mtime: Option<(i64, u32)>,
}

#[derive(Debug, Clone, Copy)]
enum State {
    /// Collecting a 512-byte header.
    Header,
    /// Skipping (or, for metadata, collecting) `remaining` bytes, then `pad` bytes of padding.
    /// `data`: the bytes are a file's content.
    Body {
        meta: Option<Meta>,
        data: bool,
        remaining: u64,
        pad: u64,
    },
    /// After the end-of-archive marker: only zeros may follow.
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Meta {
    LongName,
    LongLink,
    Pax,
    PaxGlobal,
}

#[derive(Debug)]
pub struct Reader {
    pos: u64,
    state: State,
    buf: Vec<u8>,
    zero_blocks: u32,
    pending: Pending,
    entries: Vec<Entry>,
    seen: HashSet<String>,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    pub fn new() -> Self {
        Self {
            pos: 0,
            state: State::Header,
            buf: Vec::with_capacity(BLOCK_BYTES),
            zero_blocks: 0,
            pending: Pending::default(),
            entries: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Bytes of the stream consumed so far.
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Entries parsed so far.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Consume the next bytes of the stream.
    pub fn feed(&mut self, b: &[u8]) -> Result<()> {
        self.feed_data(b, &mut |_| {})
    }

    /// [`feed`](Self::feed), passing each piece of file content to `on_data` in order.
    pub fn feed_data(&mut self, mut b: &[u8], on_data: &mut dyn FnMut(&[u8])) -> Result<()> {
        while !b.is_empty() {
            match self.state {
                State::Header => {
                    let take = (BLOCK_BYTES - self.buf.len()).min(b.len());
                    self.buf.extend_from_slice(&b[..take]);
                    b = &b[take..];
                    self.pos += take as u64;
                    if self.buf.len() == BLOCK_BYTES {
                        let block = std::mem::take(&mut self.buf);
                        self.header(&block)?;
                    }
                }
                State::Body {
                    meta,
                    data,
                    mut remaining,
                    mut pad,
                } => {
                    if remaining > 0 {
                        let take = usize::try_from(remaining.min(b.len() as u64)).expect("<= len");
                        if meta.is_some() {
                            self.buf.extend_from_slice(&b[..take]);
                        } else if data {
                            on_data(&b[..take]);
                        }
                        remaining -= take as u64;
                        b = &b[take..];
                        self.pos += take as u64;
                        if remaining == 0 {
                            if let Some(m) = meta {
                                let data = std::mem::take(&mut self.buf);
                                self.meta(m, &data)?;
                            }
                        }
                    } else {
                        let take = usize::try_from(pad.min(b.len() as u64)).expect("<= len");
                        pad -= take as u64;
                        b = &b[take..];
                        self.pos += take as u64;
                    }
                    self.state = if remaining == 0 && pad == 0 {
                        State::Header
                    } else {
                        State::Body {
                            meta,
                            data,
                            remaining,
                            pad,
                        }
                    };
                }
                State::End => {
                    if b.iter().any(|&c| c != 0) {
                        return Err(TarError::Unsupported(
                            self.pos,
                            "data after the end-of-archive marker (concatenated archives?)".into(),
                        ));
                    }
                    self.pos += b.len() as u64;
                    b = &[];
                }
            }
        }
        Ok(())
    }

    /// The stream ended: check it ended cleanly and return the entries.
    pub fn finish(self) -> Result<Vec<Entry>> {
        let clean = match self.state {
            State::End => true,
            // Some writers omit the end-of-archive marker; accept a stream that stops between
            // entries, but not one that stops inside a header or an entry.
            State::Header => self.buf.is_empty() && self.pending_is_empty(),
            State::Body { .. } => false,
        };
        if !clean {
            return Err(TarError::Corrupt(
                self.pos,
                "unexpected end of archive".into(),
            ));
        }
        if self.pos == 0 {
            return Err(TarError::NotTar);
        }
        check_nesting(&self.entries)?;
        Ok(self.entries)
    }

    fn pending_is_empty(&self) -> bool {
        let p = &self.pending;
        p.long_name.is_none()
            && p.pax_path.is_none()
            && p.pax_size.is_none()
            && p.pax_mtime.is_none()
    }

    fn header(&mut self, h: &[u8]) -> Result<()> {
        let at = self.pos - BLOCK;
        if h.iter().all(|&c| c == 0) {
            self.zero_blocks += 1;
            if self.zero_blocks == 2 {
                self.state = State::End;
            }
            return Ok(());
        }
        if self.zero_blocks > 0 {
            return Err(TarError::Corrupt(
                at,
                "lone zero block inside the archive".into(),
            ));
        }
        if !checksum_ok(h) {
            return Err(if self.entries.is_empty() && at == 0 {
                TarError::NotTar
            } else {
                TarError::Corrupt(at, "header checksum mismatch".into())
            });
        }
        let corrupt = |why: &str| TarError::Corrupt(at, why.to_owned());
        let unsupported = |why: String| TarError::Unsupported(at, why);
        let header_size = number(&h[124..136]).ok_or_else(|| corrupt("bad size field"))?;
        let typeflag = h[156];
        let body = |meta: Option<Meta>, data: bool, size: u64| {
            if size == 0 {
                State::Header
            } else {
                State::Body {
                    meta,
                    data,
                    remaining: size,
                    // Not `next_multiple_of`: a hostile size near 2^64 must not overflow.
                    pad: (BLOCK - size % BLOCK) % BLOCK,
                }
            }
        };
        let meta = match typeflag {
            b'L' => Some(Meta::LongName),
            b'K' => Some(Meta::LongLink),
            b'x' => Some(Meta::Pax),
            b'g' => Some(Meta::PaxGlobal),
            _ => None,
        };
        if let Some(m) = meta {
            if header_size > MAX_META {
                return Err(unsupported(format!(
                    "metadata header of {header_size} bytes"
                )));
            }
            self.buf.clear();
            self.state = body(Some(m), false, header_size);
            return Ok(());
        }

        let pending = std::mem::take(&mut self.pending);
        let size = pending.pax_size.unwrap_or(header_size);
        let ustar = &h[257..263] == b"ustar\0";
        let raw_name: Vec<u8> = if let Some(p) = pending.pax_path {
            p.into_bytes()
        } else if let Some(n) = pending.long_name {
            n
        } else {
            let name = cstr(&h[..100]);
            let prefix = if ustar { cstr(&h[345..500]) } else { &[] };
            if prefix.is_empty() {
                name.to_vec()
            } else {
                [prefix, b"/", name].concat()
            }
        };
        let mut kind = match typeflag {
            b'0' | 0 | b'7' => Kind::File,
            b'5' => Kind::Dir,
            b'2' => Kind::Symlink,
            b'3' | b'4' | b'6' => Kind::Special,
            b'1' => {
                return Err(unsupported(format!(
                    "hard link {:?}; hard links are not supported yet",
                    String::from_utf8_lossy(&raw_name)
                )));
            }
            b'S' => return Err(unsupported("GNU sparse file".into())),
            b'M' => return Err(unsupported("multi-volume archive".into())),
            b'V' => {
                // A volume label carries no file.
                self.state = body(None, false, size);
                return Ok(());
            }
            other => {
                return Err(unsupported(format!("entry type {:?}", char::from(other))));
            }
        };
        // Old (V7) archives mark directories with a trailing slash on a regular entry.
        if kind == Kind::File && raw_name.ends_with(b"/") && size == 0 {
            kind = Kind::Dir;
        }
        let name = normalize_name(&raw_name, at)?;
        let mode = number(&h[100..108]).and_then(|m| u32::try_from(m & 0o7777).ok());
        let (mtime_unix, mtime_nanos) = match pending.pax_mtime {
            Some(t) => t,
            None => (
                number(&h[136..148])
                    .and_then(|t| i64::try_from(t).ok())
                    .ok_or_else(|| corrupt("bad mtime field"))?,
                0,
            ),
        };
        let data_offset = self.pos;
        let Some(name) = name else {
            // The archive root ("." or "./"): nothing to create. Only a directory can be the
            // root; a file there would carry content that belongs to no output.
            if kind != Kind::Dir {
                return Err(TarError::Name {
                    name: String::from_utf8_lossy(&raw_name).into_owned(),
                    reason: "the archive root can only be a directory".into(),
                });
            }
            self.state = body(None, false, size);
            return Ok(());
        };
        self.state = body(None, kind == Kind::File, size);
        if !self.seen.insert(trunc_core::path::host_key(&name)) {
            return Err(TarError::Name {
                name,
                reason: DUPLICATE.into(),
            });
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(unsupported(format!("more than {MAX_ENTRIES} entries")));
        }
        self.entries.push(Entry {
            name,
            kind,
            size: if kind == Kind::File { size } else { 0 },
            data_offset,
            mode,
            mtime_unix,
            mtime_nanos,
        });
        Ok(())
    }

    fn meta(&mut self, m: Meta, data: &[u8]) -> Result<()> {
        let at = self.pos;
        match m {
            Meta::LongName => self.pending.long_name = Some(cstr(data).to_vec()),
            Meta::LongLink => {} // link targets are not used: links are never created
            Meta::PaxGlobal => {
                // Global records (git archive writes a commit id here) apply to all entries;
                // refuse the ones that would change what is extracted.
                for (k, _) in pax_records(data, at)? {
                    if matches!(k.as_str(), "path" | "size") || k.starts_with("GNU.sparse") {
                        return Err(TarError::Unsupported(
                            at,
                            format!("global PAX record {k:?}"),
                        ));
                    }
                }
            }
            Meta::Pax => {
                for (k, v) in pax_records(data, at)? {
                    match k.as_str() {
                        "path" => self.pending.pax_path = Some(v),
                        "size" => {
                            self.pending.pax_size = Some(v.parse().map_err(|_| {
                                TarError::Corrupt(at, format!("bad PAX size {v:?}"))
                            })?);
                        }
                        "mtime" => self.pending.pax_mtime = parse_pax_time(&v),
                        k if k.starts_with("GNU.sparse") => {
                            return Err(TarError::Unsupported(at, "GNU sparse file".into()));
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

/// True if `block` (512 bytes) is a tar header with a valid checksum.
pub fn looks_like_header(block: &[u8]) -> bool {
    block.len() == BLOCK_BYTES && block.iter().any(|&c| c != 0) && checksum_ok(block)
}

/// Header checksum: the sum of all bytes with the checksum field read as spaces. Some old
/// writers summed signed bytes, so both sums are accepted.
fn checksum_ok(h: &[u8]) -> bool {
    let Some(stored) = number(&h[148..156]) else {
        return false;
    };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &c) in h.iter().enumerate() {
        let c = if (148..156).contains(&i) { b' ' } else { c };
        unsigned += u64::from(c);
        #[allow(clippy::cast_possible_wrap)] // reinterpreting the byte as signed is the point
        let s = c as i8;
        signed += i64::from(s);
    }
    stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed)
}

/// A numeric field: octal text (space/NUL padded), or GNU base-256 when the top bit is set.
fn number(f: &[u8]) -> Option<u64> {
    if f.first().is_some_and(|&c| c & 0x80 != 0) {
        if f[0] == 0xFF {
            return None; // negative
        }
        let mut v: u64 = u64::from(f[0] & 0x7F);
        for &c in &f[1..] {
            v = v.checked_mul(256)?.checked_add(u64::from(c))?;
        }
        return Some(v);
    }
    let s = f.iter().skip_while(|&&c| c == b' ' || c == 0);
    let mut v = 0u64;
    let mut any = false;
    for &c in s {
        match c {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add(u64::from(c - b'0'))?;
                any = true;
            }
            b' ' | 0 => break,
            _ => return None,
        }
    }
    let _ = any; // an all-blank field means 0
    Some(v)
}

/// Bytes up to the first NUL.
/// Why a second entry with the same name (as this computer compares names) is refused.
const DUPLICATE: &str = if cfg!(any(windows, target_os = "macos")) {
    "duplicate entry (names differ only in case)"
} else {
    "duplicate entry"
};

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Validate and normalize an entry name; `None` for the archive root itself.
fn normalize_name(raw: &[u8], at: u64) -> Result<Option<String>> {
    let s = std::str::from_utf8(raw).map_err(|_| TarError::Name {
        name: String::from_utf8_lossy(raw).into_owned(),
        reason: "not valid UTF-8".into(),
    })?;
    let mut s: &str = s.trim_end_matches('/');
    while let Some(rest) = s.strip_prefix("./") {
        s = rest.trim_start_matches('/');
    }
    if s.is_empty() || s == "." {
        return Ok(None);
    }
    let name: String = s.nfc().collect();
    trunc_core::path::validate_host(&name).map_err(|e| TarError::Name {
        name: name.clone(),
        reason: format!("{e} (at byte {at})"),
    })?;
    Ok(Some(name))
}

/// PAX records: `"<len> <key>=<value>\n"`, where `<len>` counts the whole record.
fn pax_records(data: &[u8], at: u64) -> Result<Vec<(String, String)>> {
    let bad = |why: &str| TarError::Corrupt(at, format!("PAX header: {why}"));
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < data.len() {
        if data[p] == 0 {
            break; // trailing padding
        }
        let sp = data[p..]
            .iter()
            .position(|&c| c == b' ')
            .ok_or_else(|| bad("missing length"))?;
        let len: usize = std::str::from_utf8(&data[p..p + sp])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("bad length"))?;
        let rec = data
            .get(p..p + len)
            .ok_or_else(|| bad("record overruns the header"))?;
        if len <= sp + 1 || rec.last() != Some(&b'\n') {
            return Err(bad("malformed record"));
        }
        let kv = std::str::from_utf8(&rec[sp + 1..len - 1]).map_err(|_| bad("not UTF-8"))?;
        let (k, v) = kv.split_once('=').ok_or_else(|| bad("missing '='"))?;
        out.push((k.to_owned(), v.to_owned()));
        p += len;
    }
    Ok(out)
}

/// PAX time: decimal seconds with an optional fraction.
fn parse_pax_time(v: &str) -> Option<(i64, u32)> {
    let (secs, frac) = v.split_once('.').unwrap_or((v, ""));
    let secs: i64 = secs.parse().ok()?;
    let digits: String = frac.chars().take(9).collect();
    let nanos = if digits.is_empty() {
        0
    } else {
        digits.parse::<u32>().ok()? * 10u32.pow(9 - u32::try_from(digits.len()).ok()?)
    };
    Some((secs, nanos))
}

/// No entry may live under a file entry ("a" plus "a/b").
fn check_nesting(entries: &[Entry]) -> Result<()> {
    let files: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind != Kind::Dir)
        .map(|e| trunc_core::path::host_key(&e.name))
        .collect();
    for e in entries {
        let mut parent = trunc_core::path::parent(&e.name);
        while let Some(pp) = parent {
            if files.contains(&trunc_core::path::host_key(pp)) {
                return Err(TarError::Name {
                    name: e.name.clone(),
                    reason: "nested under a file".into(),
                });
            }
            parent = trunc_core::path::parent(pp);
        }
    }
    Ok(())
}

/// Serialization of the entry list for the consume journal.
pub fn entries_to_bytes(entries: &[Entry]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for e in entries {
        b.extend_from_slice(
            &u32::try_from(e.name.len())
                .expect("validated length")
                .to_le_bytes(),
        );
        b.extend_from_slice(e.name.as_bytes());
        b.push(match e.kind {
            Kind::File => 0,
            Kind::Dir => 1,
            Kind::Symlink => 2,
            Kind::Special => 3,
        });
        b.extend_from_slice(&e.size.to_le_bytes());
        b.extend_from_slice(&e.data_offset.to_le_bytes());
        b.extend_from_slice(&e.mode.unwrap_or(u32::MAX).to_le_bytes());
        b.extend_from_slice(&e.mtime_unix.to_le_bytes());
        b.extend_from_slice(&e.mtime_nanos.to_le_bytes());
    }
    b
}

/// Inverse of [`entries_to_bytes`]; returns the entries and the bytes consumed.
pub fn entries_from_bytes(b: &[u8]) -> Option<(Vec<Entry>, usize)> {
    let n = usize::try_from(u64::from_le_bytes(b.get(..8)?.try_into().ok()?)).ok()?;
    if n > MAX_ENTRIES {
        return None;
    }
    let mut p = 8usize;
    let mut out = Vec::with_capacity(n.min(1 << 16));
    for _ in 0..n {
        let nl = u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?) as usize;
        p += 4;
        let name = std::str::from_utf8(b.get(p..p.checked_add(nl)?)?)
            .ok()?
            .to_owned();
        p += nl;
        let kind = match *b.get(p)? {
            0 => Kind::File,
            1 => Kind::Dir,
            2 => Kind::Symlink,
            3 => Kind::Special,
            _ => return None,
        };
        p += 1;
        let u64_at = |i: usize| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let (size, data_offset) = (u64_at(p)?, u64_at(p + 8)?);
        let mode = u32::from_le_bytes(b.get(p + 16..p + 20)?.try_into().ok()?);
        let mtime_unix = i64::from_le_bytes(b.get(p + 20..p + 28)?.try_into().ok()?);
        let mtime_nanos = u32::from_le_bytes(b.get(p + 28..p + 32)?.try_into().ok()?);
        p += 32;
        out.push(Entry {
            name,
            kind,
            size,
            data_offset,
            mode: (mode != u32::MAX).then_some(mode),
            mtime_unix,
            mtime_nanos,
        });
    }
    Some((out, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(number(b"0000644\0"), Some(0o644));
        assert_eq!(number(b"   644 \0"), Some(0o644));
        assert_eq!(number(b"\0\0\0\0\0\0\0\0"), Some(0));
        assert_eq!(number(b"12345670123\0"), Some(0o123_4567_0123));
        assert_eq!(number(b"0009\0"), None);
        let mut big = [0u8; 12];
        big[0] = 0x80;
        big[4..].copy_from_slice(&(20u64 << 30).to_be_bytes());
        assert_eq!(number(&big), Some(20 << 30));
        assert_eq!(number(&[0xFF; 12]), None);
        let mut huge = [0xFFu8; 12];
        huge[0] = 0x80 | 0x7F;
        assert_eq!(number(&huge), None, "does not fit in u64");
    }

    #[test]
    fn pax_parsing() {
        let rec = b"29 path=dir/a long file name\n20 size=21474836480\n";
        let r = pax_records(rec, 0).unwrap();
        assert_eq!(r[0], ("path".into(), "dir/a long file name".into()));
        assert_eq!(r[1], ("size".into(), "21474836480".into()));
        assert!(pax_records(b"99 path=x\n", 0).is_err());
        assert!(pax_records(b"5 a=b\n", 0).is_err());
        assert_eq!(
            parse_pax_time("1700000000.5"),
            Some((1_700_000_000, 500_000_000))
        );
        assert_eq!(parse_pax_time("1700000000"), Some((1_700_000_000, 0)));
    }

    #[test]
    fn names() {
        assert_eq!(
            normalize_name(b"./a/b/", 0).unwrap().as_deref(),
            Some("a/b")
        );
        assert_eq!(normalize_name(b"./", 0).unwrap(), None);
        assert_eq!(normalize_name(b".", 0).unwrap(), None);
        assert!(normalize_name(b"../etc/passwd", 0).is_err());
        assert!(normalize_name(b"/etc/passwd", 0).is_err());
        assert!(normalize_name(b"a/../../b", 0).is_err());
        assert!(normalize_name(b"\xff", 0).is_err());
    }

    #[test]
    fn entry_list_round_trips() {
        let e = vec![
            Entry {
                name: "a/b.txt".into(),
                kind: Kind::File,
                size: 5,
                data_offset: 1024,
                mode: Some(0o644),
                mtime_unix: -3,
                mtime_nanos: 7,
            },
            Entry {
                name: "a".into(),
                kind: Kind::Dir,
                size: 0,
                data_offset: 512,
                mode: None,
                mtime_unix: 0,
                mtime_nanos: 0,
            },
        ];
        let b = entries_to_bytes(&e);
        assert_eq!(entries_from_bytes(&b), Some((e, b.len())));
        assert_eq!(entries_from_bytes(&b[..b.len() - 1]), None);
    }
}

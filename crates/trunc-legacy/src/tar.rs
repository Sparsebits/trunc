//! Streaming tar reader for extraction: POSIX ustar, GNU (long names and links, base-256
//! numbers, sparse files) and PAX extended headers (including GNU sparse formats 0.0, 0.1 and
//! 1.0).
//!
//! [`Reader`] is fed the decompressed stream in pieces and records each entry with the offset of
//! its data in that stream, so a second pass can route bytes to files without parsing again.
//! Names are validated like ZIP names: relative, NFC, no `..`, valid on this computer (see
//! [`trunc_core::path::validate_host`]), no duplicates and nothing nested under a file. A hard
//! link must name an earlier regular file of the same archive, validated the same way. A sparse
//! file's map must be sorted, non-overlapping, inside the file and cover exactly the bytes
//! stored. Multi-volume archives are refused.

use std::collections::{HashMap, HashSet};

use trunc_core::path::CaseMode;
use unicode_normalization::UnicodeNormalization;

pub const BLOCK: u64 = 512;
const BLOCK_BYTES: usize = 512;
/// Largest GNU long name/link or PAX header accepted (bounds memory on hostile input).
const MAX_META: u64 = 1 << 20;
/// Largest number of entries accepted (bounds memory: each costs about 150 bytes plus twice its
/// name, which [`MAX_NAME_BYTES`] bounds).
pub const MAX_ENTRIES: usize = 10_000_000;
/// Largest total of entry name bytes accepted. Names are kept twice (entry list and duplicate
/// check), and up to 4 KiB each, so without this a small compressed tar of many long names
/// could need tens of gigabytes.
pub const MAX_NAME_BYTES: usize = 1 << 30;
/// Largest number of sparse-map segments accepted in one archive (bounds memory: each costs
/// 24 bytes, here and in the consume journal).
pub const MAX_SPARSE_SEGMENTS: usize = 1 << 20;

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
    /// Another name for the regular file at this index of the entry list (always earlier).
    HardLink(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// Bytes of content in the stream (0 for everything but files). For a sparse file, only
    /// its data segments are stored.
    pub size: u64,
    /// Offset of the content in the (decompressed) tar stream.
    pub data_offset: u64,
    pub mode: Option<u32>,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
    /// Where a sparse file's stored content goes.
    pub sparse: Option<Box<SparseMap>>,
}

impl Entry {
    /// Length of the file once extracted: a sparse file's real size, else `size`.
    pub fn file_size(&self) -> u64 {
        self.sparse.as_ref().map_or(self.size, |s| s.real_size())
    }
}

/// A sparse file: its stored content is a series of data segments, each at its own offset in
/// the file; everything else is a hole (reads as zeros).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMap {
    real_size: u64,
    /// `(offset in the file, length)`: sorted, disjoint, non-empty, not touching.
    segments: Vec<(u64, u64)>,
    /// Offset of each segment in the stored content.
    stored: Vec<u64>,
}

impl SparseMap {
    /// Validate a map as an archive gives it: segments sorted and disjoint, inside `real_size`,
    /// their lengths adding up to the `stored` bytes. Empty segments (GNU tar ends every map
    /// with one at the real size) are dropped and touching ones merged.
    pub fn new(
        real_size: u64,
        map: &[(u64, u64)],
        stored: u64,
    ) -> std::result::Result<Self, String> {
        let mut segments: Vec<(u64, u64)> = Vec::with_capacity(map.len());
        let mut starts = Vec::with_capacity(map.len());
        let (mut end, mut total) = (0u64, 0u64);
        for &(off, len) in map {
            let e = off
                .checked_add(len)
                .filter(|&e| e <= real_size)
                .ok_or_else(|| format!("segment at {off} of {len} bytes lies past the end"))?;
            if off < end {
                return Err(format!(
                    "segment at {off} overlaps or precedes the one before"
                ));
            }
            end = e;
            if len == 0 {
                continue;
            }
            match segments.last_mut() {
                Some((o, l)) if *o + *l == off => *l += len,
                _ => {
                    segments.push((off, len));
                    starts.push(total);
                }
            }
            total = total.checked_add(len).ok_or("map overflows")?;
        }
        if total != stored {
            return Err(format!(
                "map covers {total} bytes but the entry stores {stored}"
            ));
        }
        Ok(Self {
            real_size,
            segments,
            stored: starts,
        })
    }

    /// Size of the file with its holes.
    pub fn real_size(&self) -> u64 {
        self.real_size
    }

    /// `(offset in the file, length)` of each data segment, in order.
    pub fn segments(&self) -> &[(u64, u64)] {
        &self.segments
    }

    /// Where stored bytes `[at, at + len)` go: `(offset in the file, length)` pieces in order.
    pub fn pieces(&self, at: u64, len: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        let mut k = self.stored.partition_point(|&s| s <= at).saturating_sub(1);
        let (mut at, mut left) = (at, len);
        std::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            let (off, seg_len) = *self.segments.get(k)?;
            let within = at - self.stored[k];
            let n = seg_len.saturating_sub(within).min(left);
            if n == 0 {
                return None;
            }
            at += n;
            left -= n;
            k += 1;
            Some((off + within, n))
        })
    }

    /// Length of the file once the first `at` stored bytes are in place (holes after them not
    /// yet extended).
    pub fn file_len_at(&self, at: u64) -> u64 {
        if at == 0 {
            return 0;
        }
        self.pieces(at - 1, 1).next().map_or(0, |(off, _)| off + 1)
    }

    /// Where the last data segment ends (the real size may extend past it as a hole).
    pub fn data_end(&self) -> u64 {
        self.segments.last().map_or(0, |&(o, l)| o + l)
    }
}

/// Sparse-file records of a PAX header (GNU formats 0.0, 0.1 and 1.0).
#[derive(Debug, Default)]
struct PaxSparse {
    major: Option<u64>,
    minor: Option<u64>,
    name: Option<String>,
    real_size: Option<u64>,
    numblocks: Option<u64>,
    map: Vec<(u64, u64)>,
    /// Format 0.0: a `GNU.sparse.offset` waiting for its `GNU.sparse.numbytes`.
    offset: Option<u64>,
}

/// Metadata that applies to the next real header.
#[derive(Debug, Default)]
struct Pending {
    long_name: Option<Vec<u8>>,
    long_link: Option<Vec<u8>>,
    pax_path: Option<String>,
    pax_linkpath: Option<String>,
    pax_size: Option<u64>,
    pax_mtime: Option<(i64, u32)>,
    sparse: Option<Box<PaxSparse>>,
}

/// A sparse file entry waiting for the rest of its map: old GNU extension headers, or the
/// PAX 1.0 map at the start of its data.
#[derive(Debug)]
struct Deferred {
    entry: Entry,
    real_size: u64,
    map: Vec<(u64, u64)>,
    text: MapText,
}

/// Incremental parser for the PAX 1.0 sparse map: decimal numbers, each ending in a newline;
/// the segment count, then an offset and a length per segment.
#[derive(Debug, Default)]
struct MapText {
    count: Option<u64>,
    offset: Option<u64>,
    cur: Option<u64>,
    digits: u32,
}

impl MapText {
    /// Parse the next block; true once the map is complete (the rest of the block is padding).
    fn feed(
        &mut self,
        block: &[u8],
        map: &mut Vec<(u64, u64)>,
        budget: usize,
    ) -> std::result::Result<bool, String> {
        for &c in block {
            match c {
                b'0'..=b'9' => {
                    self.digits += 1;
                    let v = self.cur.unwrap_or(0);
                    self.cur = Some(
                        v.checked_mul(10)
                            .and_then(|v| v.checked_add(u64::from(c - b'0')))
                            .filter(|_| self.digits <= 20)
                            .ok_or("number too large")?,
                    );
                }
                b'\n' => {
                    let v = self.cur.take().ok_or("empty line")?;
                    self.digits = 0;
                    match (self.count, self.offset.take()) {
                        (None, _) => {
                            if v > budget as u64 {
                                return Err(format!("{v} segments"));
                            }
                            self.count = Some(v);
                        }
                        (Some(_), None) => self.offset = Some(v),
                        (Some(_), Some(off)) => map.push((off, v)),
                    }
                    if self.count.is_some_and(|c| map.len() as u64 == c) && self.offset.is_none() {
                        return Ok(true);
                    }
                }
                _ => return Err(format!("unexpected byte {c:#04x}")),
            }
        }
        Ok(false)
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    /// Collecting a 512-byte header.
    Header,
    /// Collecting old GNU sparse extension headers for the deferred entry, which stores
    /// `size` bytes after them.
    SparseExt { size: u64 },
    /// Collecting the PAX 1.0 sparse map, block by block, at the start of the deferred entry's
    /// `remaining` bytes.
    SparseMap { remaining: u64 },
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
    /// Entry index by name, under [`Reader::key`].
    seen: HashMap<String, usize>,
    deferred: Option<Box<Deferred>>,
    /// Sparse-map segments still accepted.
    sparse_left: usize,
    name_bytes: usize,
    /// Names must be valid on this computer; otherwise only the safety rules apply.
    host_names: bool,
    /// How names are compared for the duplicate, nesting and hard-link checks (exactly,
    /// [`CaseMode::Sensitive`], without `host_names`).
    case: CaseMode,
}

impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}

impl Reader {
    /// A reader that validates names for extraction on this computer.
    pub fn new() -> Self {
        Self::with_case(CaseMode::host())
    }

    /// A reader that validates names for a destination that compares them as `case` says.
    pub fn with_case(case: CaseMode) -> Self {
        Self {
            pos: 0,
            state: State::Header,
            buf: Vec::with_capacity(BLOCK_BYTES),
            zero_blocks: 0,
            pending: Pending::default(),
            entries: Vec::new(),
            seen: HashMap::new(),
            deferred: None,
            sparse_left: MAX_SPARSE_SEGMENTS,
            name_bytes: 0,
            host_names: true,
            case,
        }
    }

    /// A reader that checks names against the safety rules alone
    /// ([`trunc_core::path::validate_safe`]) and compares them exactly, so `a:b` is accepted on
    /// Windows and `E` and `e` are two entries everywhere. For callers that decide themselves
    /// what to do with names this computer cannot create (container image layers).
    pub fn with_safe_names() -> Self {
        Self {
            host_names: false,
            ..Self::with_case(CaseMode::Sensitive)
        }
    }

    /// Key for the duplicate, nesting and hard-link checks.
    fn key(&self, name: &str) -> String {
        self.case.key(name)
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
                State::Header | State::SparseExt { .. } | State::SparseMap { .. } => {
                    let take = (BLOCK_BYTES - self.buf.len()).min(b.len());
                    self.buf.extend_from_slice(&b[..take]);
                    b = &b[take..];
                    self.pos += take as u64;
                    if self.buf.len() == BLOCK_BYTES {
                        let block = std::mem::take(&mut self.buf);
                        match self.state {
                            State::SparseExt { size } => self.sparse_ext(&block, size)?,
                            State::SparseMap { remaining } => self.sparse_map(&block, remaining)?,
                            _ => self.header(&block)?,
                        }
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
            State::Body { .. } | State::SparseExt { .. } | State::SparseMap { .. } => false,
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
        check_nesting(&self.entries, self.case)?;
        Ok(self.entries)
    }

    fn pending_is_empty(&self) -> bool {
        let p = &self.pending;
        p.long_name.is_none()
            && p.long_link.is_none()
            && p.pax_path.is_none()
            && p.pax_linkpath.is_none()
            && p.pax_size.is_none()
            && p.pax_mtime.is_none()
            && p.sparse.is_none()
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
        let sparse = pending.sparse;
        let raw_name: Vec<u8> = if let Some(n) = sparse.as_ref().and_then(|s| s.name.clone()) {
            // PAX sparse files keep their real name here; the header holds a made-up one.
            n.into_bytes()
        } else if let Some(p) = pending.pax_path {
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
            b'0' | 0 | b'7' | b'S' => Kind::File,
            b'5' => Kind::Dir,
            b'2' => Kind::Symlink,
            b'3' | b'4' | b'6' => Kind::Special,
            b'1' => {
                let target = if let Some(p) = pending.pax_linkpath {
                    p.into_bytes()
                } else if let Some(l) = pending.long_link {
                    l
                } else {
                    cstr(&h[157..257]).to_vec()
                };
                Kind::HardLink(self.link_target(&target, at)?)
            }
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
        if sparse.is_some() && (kind != Kind::File || typeflag == b'S') {
            return Err(corrupt(
                "PAX sparse records on an entry that is not a plain file",
            ));
        }
        // Old (V7) archives mark directories with a trailing slash on a regular entry.
        if kind == Kind::File
            && typeflag != b'S'
            && sparse.is_none()
            && raw_name.ends_with(b"/")
            && size == 0
        {
            kind = Kind::Dir;
        }
        let name = normalize_name(&raw_name, at, self.host_names)?;
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
        let key = self.key(&name);
        if self.seen.contains_key(&key) {
            return Err(TarError::Name {
                name,
                reason: duplicate(self.case).into(),
            });
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(unsupported(format!("more than {MAX_ENTRIES} entries")));
        }
        self.name_bytes += name.len();
        if self.name_bytes > MAX_NAME_BYTES {
            return Err(unsupported(format!(
                "entry names total more than {MAX_NAME_BYTES} bytes"
            )));
        }
        self.seen.insert(key, self.entries.len());
        let entry = Entry {
            name,
            kind,
            size: if kind == Kind::File { size } else { 0 },
            data_offset,
            mode,
            mtime_unix,
            mtime_nanos,
            sparse: None,
        };
        if typeflag == b'S' {
            // Old GNU sparse: four map entries here, more in extension headers if flagged.
            let real_size = number(&h[483..495]).ok_or_else(|| corrupt("bad sparse size"))?;
            let mut map = Vec::new();
            gnu_sparse_entries(&h[386..482], &mut map).ok_or_else(|| corrupt("bad sparse map"))?;
            let d = Deferred {
                entry,
                real_size,
                map,
                text: MapText::default(),
            };
            if h[482] != 0 {
                self.deferred = Some(Box::new(d));
                self.state = State::SparseExt { size };
                return Ok(());
            }
            return self.finish_sparse(d, size, at);
        }
        if let Some(sp) = sparse {
            let PaxSparse {
                major,
                minor,
                real_size,
                numblocks,
                map,
                offset,
                ..
            } = *sp;
            if offset.is_some() {
                return Err(corrupt("GNU.sparse.offset without GNU.sparse.numbytes"));
            }
            let real_size = real_size.ok_or_else(|| corrupt("sparse file without a real size"))?;
            let d = Deferred {
                entry,
                real_size,
                map,
                text: MapText::default(),
            };
            return match (major, minor) {
                // 0.0 and 0.1: the map was in the PAX header.
                (None | Some(0), _) => {
                    if numblocks.is_some_and(|n| n != d.map.len() as u64) {
                        return Err(corrupt("GNU.sparse.numblocks does not match the map"));
                    }
                    self.finish_sparse(d, size, at)
                }
                // 1.0: the map is at the start of the data, padded to a block.
                (Some(1), None | Some(0)) => {
                    if !d.map.is_empty() || size < BLOCK {
                        return Err(corrupt("bad PAX 1.0 sparse file"));
                    }
                    self.deferred = Some(Box::new(d));
                    self.state = State::SparseMap { remaining: size };
                    Ok(())
                }
                (Some(a), b) => Err(unsupported(format!(
                    "GNU sparse format {a}.{}",
                    b.unwrap_or(0)
                ))),
            };
        }
        self.state = body(None, kind == Kind::File, size);
        self.entries.push(entry);
        Ok(())
    }

    /// The entry a hard link names: an earlier regular file (a link to a link leads to its
    /// file). The name is validated like an entry name.
    fn link_target(&self, raw: &[u8], at: u64) -> Result<usize> {
        let refuse = |name: String, reason: &str| TarError::Name {
            name,
            reason: format!("hard link target: {reason}"),
        };
        let target = match normalize_name(raw, at, self.host_names) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return Err(refuse(
                    String::from_utf8_lossy(raw).into_owned(),
                    "the archive root",
                ));
            }
            Err(TarError::Name { name, reason }) => return Err(refuse(name, &reason)),
            Err(e) => return Err(e),
        };
        let Some(&i) = self.seen.get(&self.key(&target)) else {
            return Err(refuse(target, "no earlier entry has this name"));
        };
        match self.entries[i].kind {
            Kind::File => Ok(i),
            Kind::HardLink(t) => Ok(t),
            _ => Err(refuse(target, "not a regular file")),
        }
    }

    /// An old GNU sparse extension header for the deferred entry.
    fn sparse_ext(&mut self, block: &[u8], size: u64) -> Result<()> {
        let at = self.pos - BLOCK;
        let mut d = self
            .deferred
            .take()
            .expect("an entry waits for its sparse map");
        gnu_sparse_entries(&block[..504], &mut d.map)
            .ok_or_else(|| TarError::Corrupt(at, "bad sparse extension header".into()))?;
        if d.map.len() > self.sparse_left {
            return Err(TarError::Unsupported(
                at,
                format!("more than {MAX_SPARSE_SEGMENTS} sparse segments"),
            ));
        }
        if block[504] != 0 {
            self.deferred = Some(d);
            return Ok(());
        }
        self.finish_sparse(*d, size, at)
    }

    /// A block of the PAX 1.0 sparse map of the deferred entry.
    fn sparse_map(&mut self, block: &[u8], remaining: u64) -> Result<()> {
        let at = self.pos - BLOCK;
        let mut d = self
            .deferred
            .take()
            .expect("an entry waits for its sparse map");
        let remaining = remaining - BLOCK;
        let Deferred { map, text, .. } = &mut *d;
        let done = text
            .feed(block, map, self.sparse_left)
            .map_err(|why| TarError::Corrupt(at, format!("sparse map: {why}")))?;
        if done {
            return self.finish_sparse(*d, remaining, at);
        }
        if remaining < BLOCK {
            return Err(TarError::Corrupt(
                at,
                "sparse map runs past the end of its entry".into(),
            ));
        }
        self.deferred = Some(d);
        self.state = State::SparseMap { remaining };
        Ok(())
    }

    /// Validate a sparse entry's map and record the entry; its `size` stored bytes follow.
    fn finish_sparse(&mut self, d: Deferred, size: u64, at: u64) -> Result<()> {
        let Deferred {
            mut entry,
            real_size,
            map,
            ..
        } = d;
        if map.len() > self.sparse_left {
            return Err(TarError::Unsupported(
                at,
                format!("more than {MAX_SPARSE_SEGMENTS} sparse segments"),
            ));
        }
        let m = SparseMap::new(real_size, &map, size).map_err(|why| {
            TarError::Corrupt(at, format!("sparse map of {:?}: {why}", entry.name))
        })?;
        self.sparse_left -= map.len();
        entry.size = size;
        entry.data_offset = self.pos;
        entry.sparse = Some(Box::new(m));
        self.state = body(None, true, size);
        self.entries.push(entry);
        Ok(())
    }

    fn meta(&mut self, m: Meta, data: &[u8]) -> Result<()> {
        let at = self.pos;
        match m {
            Meta::LongName => self.pending.long_name = Some(cstr(data).to_vec()),
            Meta::LongLink => self.pending.long_link = Some(cstr(data).to_vec()),
            Meta::PaxGlobal => {
                // Global records (git archive writes a commit id here) apply to all entries;
                // refuse the ones that would change what is extracted.
                for (k, _) in pax_records(data, at)? {
                    if matches!(k.as_str(), "path" | "size" | "linkpath")
                        || k.starts_with("GNU.sparse")
                    {
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
                        "linkpath" => self.pending.pax_linkpath = Some(v),
                        "size" => {
                            self.pending.pax_size = Some(v.parse().map_err(|_| {
                                TarError::Corrupt(at, format!("bad PAX size {v:?}"))
                            })?);
                        }
                        "mtime" => self.pending.pax_mtime = parse_pax_time(&v),
                        k if k.starts_with("GNU.sparse.") => {
                            let budget = self.sparse_left;
                            let sp = self.pending.sparse.get_or_insert_with(Box::default);
                            pax_sparse(sp, k, v, budget).map_err(|why| {
                                TarError::Corrupt(at, format!("PAX record {k:?}: {why}"))
                            })?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

/// The state that reads `size` bytes of body (metadata to collect, file content, or bytes to
/// skip), then the padding to the next block.
fn body(meta: Option<Meta>, data: bool, size: u64) -> State {
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
}

/// Old GNU sparse map entries (24 bytes each: offset and length, as header numbers), up to the
/// first empty one. `None` if a number is malformed.
fn gnu_sparse_entries(b: &[u8], map: &mut Vec<(u64, u64)>) -> Option<()> {
    for e in b.chunks_exact(24) {
        if e[0] == 0 {
            break;
        }
        map.push((number(&e[..12])?, number(&e[12..])?));
    }
    Some(())
}

/// Apply one `GNU.sparse.*` PAX record.
fn pax_sparse(
    sp: &mut PaxSparse,
    key: &str,
    v: String,
    budget: usize,
) -> std::result::Result<(), String> {
    let num = |s: &str| s.parse::<u64>().map_err(|_| format!("bad number {s:?}"));
    let push = |map: &mut Vec<(u64, u64)>, seg| {
        if map.len() >= budget {
            return Err(format!("more than {MAX_SPARSE_SEGMENTS} sparse segments"));
        }
        map.push(seg);
        Ok(())
    };
    match key {
        "GNU.sparse.major" => sp.major = Some(num(&v)?),
        "GNU.sparse.minor" => sp.minor = Some(num(&v)?),
        "GNU.sparse.name" => sp.name = Some(v),
        "GNU.sparse.size" | "GNU.sparse.realsize" => sp.real_size = Some(num(&v)?),
        "GNU.sparse.numblocks" => sp.numblocks = Some(num(&v)?),
        // Format 0.0 repeats these two, in pairs.
        "GNU.sparse.offset" => {
            if sp.offset.replace(num(&v)?).is_some() {
                return Err("two offsets in a row".into());
            }
        }
        "GNU.sparse.numbytes" => {
            let off = sp.offset.take().ok_or("a length without an offset")?;
            push(&mut sp.map, (off, num(&v)?))?;
        }
        // Format 0.1: "offset,length,offset,length,...".
        "GNU.sparse.map" => {
            let mut it = v.split(',').filter(|s| !s.is_empty());
            while let Some(off) = it.next() {
                let len = it.next().ok_or("odd number of values")?;
                push(&mut sp.map, (num(off)?, num(len)?))?;
            }
        }
        _ => return Err("unknown record".into()),
    }
    Ok(())
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

/// Why a second entry with the same name (as the destination compares names) is refused.
fn duplicate(case: CaseMode) -> &'static str {
    match case {
        CaseMode::Insensitive => "duplicate entry (names differ only in case)",
        CaseMode::Sensitive => "duplicate entry",
    }
}

/// Bytes up to the first NUL.
fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// Validate and normalize an entry name (`host`: for this computer, else for safety only);
/// `None` for the archive root itself.
fn normalize_name(raw: &[u8], at: u64, host: bool) -> Result<Option<String>> {
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
    let valid = if host {
        trunc_core::path::validate_host(&name)
    } else {
        trunc_core::path::validate_safe(&name)
    };
    valid.map_err(|e| TarError::Name {
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
fn check_nesting(entries: &[Entry], case: CaseMode) -> Result<()> {
    let files: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind != Kind::Dir)
        .map(|e| case.key(&e.name))
        .collect();
    for e in entries {
        let mut parent = trunc_core::path::parent(&e.name);
        while let Some(pp) = parent {
            if files.contains(&case.key(pp)) {
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

/// Serialization of the entry list for the consume journal. Hard links and sparse files have
/// kinds of their own (4 and 5) with extra fields after the common ones, so lists without them
/// are encoded as before.
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
        b.push(match (e.kind, &e.sparse) {
            (Kind::File, None) => 0,
            (Kind::Dir, _) => 1,
            (Kind::Symlink, _) => 2,
            (Kind::Special, _) => 3,
            (Kind::HardLink(_), _) => 4,
            (Kind::File, Some(_)) => 5,
        });
        b.extend_from_slice(&e.size.to_le_bytes());
        b.extend_from_slice(&e.data_offset.to_le_bytes());
        b.extend_from_slice(&e.mode.unwrap_or(u32::MAX).to_le_bytes());
        b.extend_from_slice(&e.mtime_unix.to_le_bytes());
        b.extend_from_slice(&e.mtime_nanos.to_le_bytes());
        if let Kind::HardLink(t) = e.kind {
            b.extend_from_slice(&(t as u64).to_le_bytes());
        }
        if let Some(s) = e.sparse.as_deref().filter(|_| e.kind == Kind::File) {
            b.extend_from_slice(&s.real_size.to_le_bytes());
            b.extend_from_slice(&(s.segments.len() as u64).to_le_bytes());
            for &(off, len) in &s.segments {
                b.extend_from_slice(&off.to_le_bytes());
                b.extend_from_slice(&len.to_le_bytes());
            }
        }
    }
    b
}

/// Inverse of [`entries_to_bytes`]; returns the entries and the bytes consumed.
pub fn entries_from_bytes(b: &[u8]) -> Option<(Vec<Entry>, usize)> {
    let n = usize::try_from(u64::from_le_bytes(b.get(..8)?.try_into().ok()?)).ok()?;
    if n > MAX_ENTRIES {
        return None;
    }
    let u64_at = |i: usize| {
        Some(u64::from_le_bytes(
            b.get(i..i.checked_add(8)?)?.try_into().ok()?,
        ))
    };
    let mut p = 8usize;
    let mut out: Vec<Entry> = Vec::with_capacity(n.min(1 << 16));
    for _ in 0..n {
        let nl = u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?) as usize;
        p += 4;
        let name = std::str::from_utf8(b.get(p..p.checked_add(nl)?)?)
            .ok()?
            .to_owned();
        p += nl;
        let code = *b.get(p)?;
        p += 1;
        let (size, data_offset) = (u64_at(p)?, u64_at(p + 8)?);
        let mode = u32::from_le_bytes(b.get(p + 16..p + 20)?.try_into().ok()?);
        let mtime_unix = i64::from_le_bytes(b.get(p + 20..p + 28)?.try_into().ok()?);
        let mtime_nanos = u32::from_le_bytes(b.get(p + 28..p + 32)?.try_into().ok()?);
        p += 32;
        let mut sparse = None;
        let kind = match code {
            0 => Kind::File,
            1 => Kind::Dir,
            2 => Kind::Symlink,
            3 => Kind::Special,
            4 => {
                let t = usize::try_from(u64_at(p)?).ok()?;
                p += 8;
                // Only to an earlier file, as the reader guarantees.
                if out.get(t)?.kind != Kind::File {
                    return None;
                }
                Kind::HardLink(t)
            }
            5 => {
                let (real_size, count) = (u64_at(p)?, usize::try_from(u64_at(p + 8)?).ok()?);
                p += 16;
                if count > b.len().saturating_sub(p) / 16 {
                    return None;
                }
                let map: Vec<(u64, u64)> = (0..count)
                    .map(|k| Some((u64_at(p + 16 * k)?, u64_at(p + 16 * k + 8)?)))
                    .collect::<Option<_>>()?;
                p += 16 * count;
                sparse = Some(Box::new(SparseMap::new(real_size, &map, size).ok()?));
                Kind::File
            }
            _ => return None,
        };
        out.push(Entry {
            name,
            kind,
            size,
            data_offset,
            mode: (mode != u32::MAX).then_some(mode),
            mtime_unix,
            mtime_nanos,
            sparse,
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
            normalize_name(b"./a/b/", 0, true).unwrap().as_deref(),
            Some("a/b")
        );
        assert_eq!(normalize_name(b"./", 0, true).unwrap(), None);
        assert_eq!(normalize_name(b".", 0, true).unwrap(), None);
        assert!(normalize_name(b"../etc/passwd", 0, true).is_err());
        assert!(normalize_name(b"/etc/passwd", 0, true).is_err());
        assert!(normalize_name(b"a/../../b", 0, true).is_err());
        assert!(normalize_name(b"\xff", 0, true).is_err());
        // Safety rules alone: names only Windows forbids pass, hostile ones never do.
        for ok in ["man3/IO::File.3pm", "inc/aux.h", "dots.", "a\\x2db"] {
            let got = normalize_name(ok.as_bytes(), 0, false).unwrap();
            assert_eq!(got.as_deref(), Some(ok));
            assert_eq!(
                normalize_name(ok.as_bytes(), 0, true).is_err(),
                cfg!(windows)
            );
        }
        for bad in [
            "../etc/passwd",
            "/etc/passwd",
            "a/../../b",
            "C:/x",
            "a\0b",
            "a//b",
        ] {
            assert!(normalize_name(bad.as_bytes(), 0, false).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn entry_list_round_trips() {
        let plain = |name: &str, kind, size, data_offset| Entry {
            name: name.into(),
            kind,
            size,
            data_offset,
            mode: None,
            mtime_unix: 0,
            mtime_nanos: 0,
            sparse: None,
        };
        let mut e = vec![
            Entry {
                mode: Some(0o644),
                mtime_unix: -3,
                mtime_nanos: 7,
                ..plain("a/b.txt", Kind::File, 5, 1024)
            },
            plain("a", Kind::Dir, 0, 512),
        ];
        let b = entries_to_bytes(&e);
        assert_eq!(entries_from_bytes(&b), Some((e.clone(), b.len())));
        assert_eq!(entries_from_bytes(&b[..b.len() - 1]), None);

        // Hard links and sparse files add fields of their own.
        e.push(plain("a/link", Kind::HardLink(0), 0, 2048));
        e.push(Entry {
            sparse: Some(Box::new(
                SparseMap::new(1 << 40, &[(4096, 10), (1 << 39, 20)], 30).unwrap(),
            )),
            ..plain("a/sparse", Kind::File, 30, 2560)
        });
        let b = entries_to_bytes(&e);
        assert_eq!(entries_from_bytes(&b), Some((e.clone(), b.len())));
        assert_eq!(entries_from_bytes(&b[..b.len() - 1]), None);
        // A link may only lead to an earlier file.
        e[2].kind = Kind::HardLink(1);
        assert_eq!(entries_from_bytes(&entries_to_bytes(&e)), None);
    }

    #[test]
    fn sparse_maps_validate_and_locate() {
        let m = SparseMap::new(100, &[(10, 5), (15, 5), (40, 0), (50, 10), (100, 0)], 20).unwrap();
        assert_eq!(
            m.segments(),
            &[(10, 10), (50, 10)],
            "merged, empty ones dropped"
        );
        assert_eq!(
            m.pieces(0, 20).collect::<Vec<_>>(),
            vec![(10, 10), (50, 10)]
        );
        assert_eq!(m.pieces(8, 4).collect::<Vec<_>>(), vec![(18, 2), (50, 2)]);
        assert_eq!(m.pieces(19, 1).collect::<Vec<_>>(), vec![(59, 1)]);
        assert_eq!(m.file_len_at(0), 0);
        assert_eq!(m.file_len_at(10), 20);
        assert_eq!(m.file_len_at(11), 51);
        assert_eq!(m.data_end(), 60);
        // Refused: overlapping, unsorted, past the end, overflowing, not matching the data.
        for (map, stored) in [
            (vec![(0, 10), (5, 10)], 20),
            (vec![(50, 10), (0, 10)], 20),
            (vec![(95, 10)], 10),
            (vec![(u64::MAX, 2)], 2),
            (vec![(0, 10)], 11),
        ] {
            assert!(SparseMap::new(100, &map, stored).is_err(), "{map:?}");
        }
    }
}

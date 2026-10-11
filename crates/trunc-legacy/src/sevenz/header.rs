//! The 7z signature header and header (7zFormat.txt), parsed into a validated [`Layout`].

use std::collections::HashSet;

use trunc_fs::FileHandle;
use unicode_normalization::UnicodeNormalization;

use super::{Coder, Entry, Folder, Kind, Layout, Method, Result, SevenZError, corrupt};

const K_END: u8 = 0x00;
const K_HEADER: u8 = 0x01;
const K_ARCHIVE_PROPERTIES: u8 = 0x02;
const K_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
const K_MAIN_STREAMS_INFO: u8 = 0x04;
const K_FILES_INFO: u8 = 0x05;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SUBSTREAMS_INFO: u8 = 0x08;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_NUM_UNPACK_STREAM: u8 = 0x0D;
const K_EMPTY_STREAM: u8 = 0x0E;
const K_EMPTY_FILE: u8 = 0x0F;
const K_ANTI: u8 = 0x10;
const K_NAME: u8 = 0x11;
const K_MTIME: u8 = 0x14;
const K_WIN_ATTRIBUTES: u8 = 0x15;
const K_ENCODED_HEADER: u8 = 0x17;

const SIGNATURE_HEADER_LEN: u64 = 32;
/// Refuse headers (stored or decoded) larger than this; bounds memory on hostile input.
const MAX_HEADER: u64 = 256 << 20;
/// Coders per folder. Real archives use at most a filter or two in front of a codec.
const MAX_CODERS: u64 = 4;
/// An encoded header may itself be encoded; real archives nest once.
const MAX_NESTING: usize = 4;

const ATTR_DIRECTORY: u32 = 0x10;
/// p7zip and 7-Zip on Unix put the Unix mode in the high 16 bits and set this bit.
const ATTR_UNIX_EXTENSION: u32 = 0x8000;
/// Seconds between 1601-01-01 (FILETIME) and 1970-01-01.
const FILETIME_UNIX_DIFF: u64 = 11_644_473_600;

/// Bounded reader over header bytes.
struct Rd<'a> {
    b: &'a [u8],
    p: usize,
}

fn short() -> SevenZError {
    corrupt("header ends early")
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    fn left(&self) -> usize {
        self.b.len() - self.p
    }

    fn u8(&mut self) -> Result<u8> {
        let v = *self.b.get(self.p).ok_or_else(short)?;
        self.p += 1;
        Ok(v)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or_else(short)?;
        let s = self.b.get(self.p..end).ok_or_else(short)?;
        self.p = end;
        Ok(s)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().expect("8")))
    }

    /// 7z NUMBER: the leading one bits of the first byte say how many bytes follow.
    fn number(&mut self) -> Result<u64> {
        let first = self.u8()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                let high = u64::from(first & (mask.wrapping_sub(1)));
                return Ok(value | (high << (8 * i)));
            }
            value |= u64::from(self.u8()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// A count of items that each take at least a byte of what follows: bounded by the bytes
    /// left, so hostile counts cannot drive allocations.
    fn count(&mut self, what: &str) -> Result<usize> {
        let n = self.number()?;
        let cap = self.left().saturating_add(1);
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= cap)
            .ok_or_else(|| corrupt(format!("{what} count {n} is larger than the header allows")))
    }

    fn size(&mut self) -> Result<usize> {
        let n = self.number()?;
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.left())
            .ok_or_else(short)
    }

    /// A property this parser does not use: its size, then its bytes.
    fn skip_data(&mut self) -> Result<()> {
        let n = self.size()?;
        self.bytes(n)?;
        Ok(())
    }

    /// `n` bits, most significant first.
    fn bits(&mut self, n: usize) -> Result<Vec<bool>> {
        let raw = self.bytes(n.div_ceil(8))?;
        Ok((0..n)
            .map(|i| raw[i / 8] & (0x80 >> (i % 8)) != 0)
            .collect())
    }

    /// "All defined" byte, else a bit vector.
    fn defined(&mut self, n: usize) -> Result<Vec<bool>> {
        if self.u8()? != 0 {
            Ok(vec![true; n])
        } else {
            self.bits(n)
        }
    }

    fn digests(&mut self, n: usize) -> Result<Vec<Option<u32>>> {
        let defined = self.defined(n)?;
        defined
            .into_iter()
            .map(|d| d.then(|| self.u32()).transpose())
            .collect()
    }

    fn expect(&mut self, id: u8, what: &str) -> Result<()> {
        if self.u8()? != id {
            return Err(corrupt(format!("expected {what}")));
        }
        Ok(())
    }
}

/// A folder as the header describes it, before its pack stream is located.
struct RawFolder {
    coders: Vec<Coder>,
    unpack_size: u64,
    crc: Option<u32>,
}

/// Coders of a folder before unpack sizes are known: method, props, out-stream index order.
struct FolderGraph {
    /// (method, props) per coder in header order.
    coders: Vec<(Method, Vec<u8>)>,
    /// Header-order coder indexes in decoding order.
    chain: Vec<usize>,
}

/// Per folder: (size, crc) of each substream.
type Substreams = Vec<Vec<(u64, Option<u32>)>>;

#[derive(Default)]
struct StreamsInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    folders: Vec<RawFolder>,
    /// Per folder: (size, crc) of each substream.
    substreams: Option<Substreams>,
}

fn method_of(id: &[u8]) -> std::result::Result<Method, String> {
    Ok(match id {
        [0x00] => Method::Copy,
        [0x03, 0x01, 0x01] => Method::Lzma,
        [0x21] => Method::Lzma2,
        [0x03, 0x03, 0x01, 0x03] => Method::BcjX86,
        [0x03] => Method::Delta,
        _ => {
            return Err(match id {
                [0x06, 0xF1, 0x07, 0x01] => "AES".into(),
                [0x03, 0x03, 0x01, 0x1B] => "BCJ2".into(),
                [0x03, 0x04, 0x01] => "PPMd".into(),
                [0x04, 0x02, 0x02] => "BZip2".into(),
                [0x04, 0x01, 0x08] => "Deflate".into(),
                [0x04, 0x01, 0x09] => "Deflate64".into(),
                [0x0A] => "ARM64".into(),
                [0x0B] => "RISC-V".into(),
                [0x03, 0x03, 0x05, 0x01] => "ARM".into(),
                [0x03, 0x03, 0x07, 0x01] => "ARM Thumb".into(),
                [0x03, 0x03, 0x02, 0x05] => "PowerPC".into(),
                [0x03, 0x03, 0x04, 0x01] => "IA-64".into(),
                [0x03, 0x03, 0x08, 0x05] => "SPARC".into(),
                [0x04, 0xF7, 0x11, 0x01] => "Zstandard".into(),
                [0x04, 0xF7, 0x11, 0x02] => "Brotli".into(),
                [0x04, 0xF7, 0x11, 0x04] => "LZ4".into(),
                [0x04, 0xF7, 0x11, 0x05] => "LZ5".into(),
                [0x04, 0xF7, 0x11, 0x06] => "Lizard".into(),
                other => {
                    let hex: Vec<String> = other.iter().map(|b| format!("{b:02X}")).collect();
                    format!("id {}", hex.join(" "))
                }
            });
        }
    })
}

fn unsupported_method(name: &str) -> SevenZError {
    if name == "AES" {
        return SevenZError::Unsupported(
            "the archive is encrypted (7zAES); encrypted 7z archives are not supported".into(),
        );
    }
    SevenZError::Unsupported(format!(
        "compression method {name} is not supported (supported: Copy, LZMA, LZMA2, BCJ x86, Delta)"
    ))
}

/// Parse one folder's coders and bind pairs into a linear decoding chain.
fn read_folder(r: &mut Rd<'_>) -> Result<FolderGraph> {
    let n = r.number()?;
    if n == 0 {
        return Err(corrupt("folder without coders"));
    }
    if n > 64 {
        return Err(corrupt(format!("folder with {n} coders")));
    }
    let mut coders = Vec::new();
    let mut refused: Option<String> = None;
    let (mut total_in, mut total_out) = (0u64, 0u64);
    for _ in 0..n {
        let flags = r.u8()?;
        if flags & 0x80 != 0 {
            return Err(SevenZError::Unsupported(
                "coders with alternative methods".into(),
            ));
        }
        let id = r.bytes(usize::from(flags & 0x0F))?;
        let (nin, nout) = if flags & 0x10 != 0 {
            (r.number()?, r.number()?)
        } else {
            (1, 1)
        };
        if nin > 64 || nout > 64 {
            return Err(corrupt("coder with too many streams"));
        }
        let props = if flags & 0x20 != 0 {
            let len = r.size()?;
            r.bytes(len)?.to_vec()
        } else {
            Vec::new()
        };
        total_in += nin;
        total_out += nout;
        match method_of(id) {
            // Encryption is reported first: it is the reason the archive cannot be opened.
            Err(name) if name == "AES" => return Err(unsupported_method(&name)),
            Err(name) => refused = refused.or(Some(name)),
            Ok(_) if nin != 1 || nout != 1 => {
                return Err(corrupt("simple coder with several streams"));
            }
            Ok(m) => coders.push((m, props)),
        }
    }
    let nbind = total_out
        .checked_sub(1)
        .ok_or_else(|| corrupt("folder without output"))?;
    let mut binds = Vec::new();
    for _ in 0..nbind {
        let (i, o) = (r.number()?, r.number()?);
        if i >= total_in || o >= total_out {
            return Err(corrupt("bind pair out of range"));
        }
        binds.push((i, o));
    }
    let npacked = total_in
        .checked_sub(nbind)
        .filter(|&p| p >= 1)
        .ok_or_else(|| corrupt("folder without a packed stream"))?;
    let packed = if npacked == 1 {
        (0..total_in)
            .find(|i| !binds.iter().any(|b| b.0 == *i))
            .ok_or_else(|| corrupt("no unbound packed stream"))?
    } else {
        for _ in 0..npacked {
            r.number()?;
        }
        u64::MAX
    };
    if let Some(name) = refused {
        return Err(unsupported_method(&name));
    }
    if npacked != 1 {
        return Err(SevenZError::Unsupported(
            "folders with several packed streams".into(),
        ));
    }
    // Every coder is simple here: coder i owns in-stream i and out-stream i. Walk from the
    // unbound output back to the packed stream.
    let main = (0..total_out)
        .filter(|o| !binds.iter().any(|b| b.1 == *o))
        .collect::<Vec<_>>();
    let [main] = main[..] else {
        return Err(corrupt("folder without exactly one output"));
    };
    let mut chain = vec![main];
    let mut cur = main;
    while cur != packed {
        let (_, from) = binds
            .iter()
            .find(|b| b.0 == cur)
            .copied()
            .ok_or_else(|| corrupt("coder input bound to nothing"))?;
        if chain.contains(&from) {
            return Err(corrupt("bind pairs form a cycle"));
        }
        chain.push(from);
        cur = from;
    }
    if chain.len() as u64 != n {
        return Err(corrupt("folder has coders outside its chain"));
    }
    if n > MAX_CODERS {
        return Err(SevenZError::Unsupported(format!("folders with {n} coders")));
    }
    chain.reverse();
    Ok(FolderGraph {
        coders,
        chain: chain
            .into_iter()
            .map(|c| usize::try_from(c).expect("< 64"))
            .collect(),
    })
}

/// Check a coder's properties and its dictionary against the window limit.
fn check_coder(method: Method, props: &[u8], max_window: u64) -> Result<()> {
    let dict = match method {
        Method::Copy | Method::BcjX86 => {
            // BCJ may carry a 4-byte start offset; only 0 (or none) is supported.
            if !props.is_empty() && !(method == Method::BcjX86 && props == [0; 4]) {
                return Err(SevenZError::Unsupported(format!(
                    "{} coder with properties",
                    method.name()
                )));
            }
            return Ok(());
        }
        Method::Delta => {
            if props.len() != 1 {
                return Err(corrupt("bad Delta properties"));
            }
            return Ok(());
        }
        Method::Lzma => {
            if props.len() != 5 || props[0] >= 9 * 5 * 5 {
                return Err(corrupt("bad LZMA properties"));
            }
            u64::from(u32::from_le_bytes(props[1..5].try_into().expect("4")))
        }
        Method::Lzma2 => {
            let [bits] = props[..] else {
                return Err(corrupt("bad LZMA2 properties"));
            };
            if bits > 40 {
                return Err(corrupt("bad LZMA2 dictionary size"));
            }
            let bits = u32::from(bits);
            if bits == 40 {
                u64::from(u32::MAX)
            } else {
                u64::from((2 | (bits & 1)) << (bits / 2 + 11))
            }
        }
    };
    if dict > max_window {
        return Err(SevenZError::Unsupported(format!(
            "{} dictionary of {} MiB exceeds the window limit of {} MiB (--max-window)",
            method.name(),
            dict >> 20,
            max_window >> 20
        )));
    }
    Ok(())
}

fn read_pack_info(r: &mut Rd<'_>, si: &mut StreamsInfo) -> Result<()> {
    si.pack_pos = r.number()?;
    let n = r.count("packed stream")?;
    loop {
        match r.u8()? {
            K_END => break,
            K_SIZE => {
                si.pack_sizes = (0..n).map(|_| r.number()).collect::<Result<_>>()?;
            }
            K_CRC => {
                r.digests(n)?;
            }
            _ => r.skip_data()?,
        }
    }
    if si.pack_sizes.len() != n {
        return Err(corrupt("packed stream sizes missing"));
    }
    Ok(())
}

fn read_unpack_info(r: &mut Rd<'_>, si: &mut StreamsInfo, max_window: u64) -> Result<()> {
    r.expect(K_FOLDER, "folder list")?;
    let n = r.count("folder")?;
    if r.u8()? != 0 {
        return Err(SevenZError::Unsupported("external folder data".into()));
    }
    let graphs = (0..n).map(|_| read_folder(r)).collect::<Result<Vec<_>>>()?;
    r.expect(K_CODERS_UNPACK_SIZE, "coder unpack sizes")?;
    let mut folders = Vec::with_capacity(n);
    for g in graphs {
        let sizes = (0..g.coders.len())
            .map(|_| r.number())
            .collect::<Result<Vec<_>>>()?;
        let coders = g
            .chain
            .iter()
            .map(|&i| {
                let (method, props) = &g.coders[i];
                check_coder(*method, props, max_window)?;
                Ok(Coder {
                    method: *method,
                    props: props.clone(),
                    unpack_size: sizes[i],
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let unpack_size = coders.last().expect("at least one coder").unpack_size;
        folders.push(RawFolder {
            coders,
            unpack_size,
            crc: None,
        });
    }
    loop {
        match r.u8()? {
            K_END => break,
            K_CRC => {
                for (f, c) in folders.iter_mut().zip(r.digests(n)?) {
                    f.crc = c;
                }
            }
            _ => r.skip_data()?,
        }
    }
    si.folders = folders;
    Ok(())
}

fn read_substreams(r: &mut Rd<'_>, si: &mut StreamsInfo) -> Result<()> {
    let nf = si.folders.len();
    let mut counts = vec![1usize; nf];
    let mut id = r.u8()?;
    // Each substream but the last of a folder has a size of at least one byte below; the last
    // ones and the folders themselves are already bounded.
    while id == K_NUM_UNPACK_STREAM || !matches!(id, K_SIZE | K_CRC | K_END) {
        if id == K_NUM_UNPACK_STREAM {
            let mut total = 0usize;
            for c in &mut counts {
                *c = r.count("substream")?;
                total = total.saturating_add(*c);
            }
            if total > r.left().saturating_add(nf) {
                return Err(corrupt("substream count is larger than the header allows"));
            }
        } else {
            r.skip_data()?;
        }
        id = r.u8()?;
    }
    let mut streams: Vec<Vec<(u64, Option<u32>)>> = Vec::with_capacity(nf);
    let has_sizes = id == K_SIZE;
    for (f, &c) in si.folders.iter().zip(&counts) {
        let mut v = Vec::with_capacity(c);
        if c > 0 {
            let mut sum = 0u64;
            if has_sizes {
                for _ in 1..c {
                    let s = r.number()?;
                    sum = sum
                        .checked_add(s)
                        .ok_or_else(|| corrupt("substream sizes overflow"))?;
                    v.push((s, None));
                }
            } else if c > 1 {
                return Err(corrupt("substream sizes missing"));
            }
            let last = f.unpack_size.checked_sub(sum).ok_or_else(|| {
                corrupt("substream sizes add up to more than their folder's output")
            })?;
            v.push((last, None));
            if c == 1 {
                v[0].1 = f.crc;
            }
        }
        streams.push(v);
    }
    if has_sizes {
        id = r.u8()?;
    }
    while id != K_END {
        if id == K_CRC {
            let need: usize = si
                .folders
                .iter()
                .zip(&counts)
                .map(|(f, &c)| if c == 1 && f.crc.is_some() { 0 } else { c })
                .sum();
            let mut d = r.digests(need)?.into_iter();
            for (f, v) in si.folders.iter().zip(&mut streams) {
                if v.len() == 1 && f.crc.is_some() {
                    continue;
                }
                for s in v.iter_mut() {
                    s.1 = d.next().flatten();
                }
            }
        } else {
            r.skip_data()?;
        }
        id = r.u8()?;
    }
    si.substreams = Some(streams);
    Ok(())
}

fn read_streams_info(r: &mut Rd<'_>, max_window: u64) -> Result<StreamsInfo> {
    let mut si = StreamsInfo::default();
    loop {
        match r.u8()? {
            K_END => break,
            K_PACK_INFO => read_pack_info(r, &mut si)?,
            K_UNPACK_INFO => read_unpack_info(r, &mut si, max_window)?,
            K_SUBSTREAMS_INFO => read_substreams(r, &mut si)?,
            other => {
                return Err(corrupt(format!(
                    "unexpected property 0x{other:02x} in streams info"
                )));
            }
        }
    }
    Ok(si)
}

/// Locate every folder's packed stream; they must lie between the signature header and the
/// header.
fn place_folders(si: &StreamsInfo, header_offset: u64) -> Result<Vec<Folder>> {
    if si.pack_sizes.len() != si.folders.len() {
        return Err(corrupt("packed stream count differs from folder count"));
    }
    let mut off = SIGNATURE_HEADER_LEN
        .checked_add(si.pack_pos)
        .ok_or_else(|| corrupt("packed stream offset overflows"))?;
    let mut out = Vec::with_capacity(si.folders.len());
    for (f, &size) in si.folders.iter().zip(&si.pack_sizes) {
        let end = off
            .checked_add(size)
            .filter(|&e| e <= header_offset)
            .ok_or_else(|| corrupt("packed stream extends past the header (truncated archive?)"))?;
        out.push(Folder {
            coders: f.coders.clone(),
            pack_offset: off,
            pack_size: size,
            unpack_size: f.unpack_size,
            crc: f.crc,
            entries: Vec::new(),
        });
        off = end;
    }
    Ok(out)
}

/// UTF-16LE names, each ending in a 0 code unit.
fn read_names(b: &[u8], n: usize) -> Result<Vec<String>> {
    if b.len() % 2 != 0 {
        return Err(corrupt("odd-length file names"));
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let names: Vec<&[u16]> = units.split(|&u| u == 0).collect();
    // `split` yields one empty piece after the final terminator.
    if names.len() != n + 1 || !names[n].is_empty() {
        return Err(corrupt("file name count differs from file count"));
    }
    names[..n]
        .iter()
        .map(|u| String::from_utf16(u).map_err(|_| corrupt("file name is not valid UTF-16")))
        .collect()
}

/// A property vector of optional values (times, attributes): defined bits, an external byte,
/// then the defined values.
fn read_optional<T>(
    r: &mut Rd<'_>,
    n: usize,
    mut value: impl FnMut(&mut Rd<'_>) -> Result<T>,
) -> Result<Vec<Option<T>>> {
    let defined = r.defined(n)?;
    if r.u8()? != 0 {
        return Err(SevenZError::Unsupported("external file properties".into()));
    }
    defined
        .into_iter()
        .map(|d| if d { value(r).map(Some) } else { Ok(None) })
        .collect()
}

/// Turn a stored name into a validated relative path, as ZIP does.
fn clean_name(name: &str) -> Result<String> {
    let unified = name.replace('\\', "/");
    let nfc: String = unified.trim_end_matches('/').nfc().collect();
    trunc_core::path::validate_host(&nfc).map_err(|e| SevenZError::Name {
        name: name.to_owned(),
        reason: e.to_string(),
    })?;
    Ok(nfc)
}

fn filetime(ft: u64) -> (i64, u32) {
    let secs = ft / 10_000_000;
    let nanos = u32::try_from(ft % 10_000_000).expect("< 10^7") * 100;
    let unix = i64::try_from(secs).unwrap_or(i64::MAX) - FILETIME_UNIX_DIFF as i64;
    (unix, nanos)
}

fn read_files(
    r: &mut Rd<'_>,
    folders: &mut [Folder],
    si: &StreamsInfo,
) -> Result<(Vec<Entry>, usize)> {
    // Every file has a name of at least one code unit plus its terminator.
    let n = r.count("file")?;
    if n > r.left() / 4 + 1 {
        return Err(corrupt("file count is larger than the header allows"));
    }
    let mut empty_stream = vec![false; n];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut anti: Vec<bool> = Vec::new();
    let mut names: Option<Vec<String>> = None;
    let mut mtimes: Vec<Option<u64>> = vec![None; n];
    let mut attrs: Vec<Option<u32>> = vec![None; n];
    loop {
        let id = r.u8()?;
        if id == K_END {
            break;
        }
        let size = r.size()?;
        let mut p = Rd::new(r.bytes(size)?);
        match id {
            K_EMPTY_STREAM => {
                empty_stream = p.bits(n)?;
                let empties = empty_stream.iter().filter(|&&e| e).count();
                empty_file = vec![false; empties];
                anti = vec![false; empties];
            }
            K_EMPTY_FILE => empty_file = p.bits(anti.len())?,
            K_ANTI => anti = p.bits(empty_file.len())?,
            K_NAME => {
                if p.u8()? != 0 {
                    return Err(SevenZError::Unsupported("external file names".into()));
                }
                names = Some(read_names(&p.b[p.p..], n)?);
            }
            K_MTIME => mtimes = read_optional(&mut p, n, |r: &mut Rd<'_>| r.u64())?,
            K_WIN_ATTRIBUTES => attrs = read_optional(&mut p, n, |r: &mut Rd<'_>| r.u32())?,
            // Creation and access times, start positions, padding: not used.
            _ => {}
        }
    }
    let names = match names {
        Some(v) => v,
        None if n == 0 => Vec::new(),
        None => return Err(corrupt("file names missing")),
    };

    // Content streams in order: (folder, offset in its output, size, crc).
    let empty_subs: Vec<Vec<(u64, Option<u32>)>>;
    let subs = match &si.substreams {
        Some(s) => s,
        None => {
            empty_subs = si
                .folders
                .iter()
                .map(|f| vec![(f.unpack_size, f.crc)])
                .collect();
            &empty_subs
        }
    };
    let mut streams = subs.iter().enumerate().flat_map(|(fi, v)| {
        let mut off = 0u64;
        v.iter().map(move |&(size, crc)| {
            let at = off;
            off += size;
            (fi, at, size, crc)
        })
    });

    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut anti_items = 0usize;
    let mut empty_index = 0usize;
    for (i, raw) in names.iter().enumerate() {
        let attr = attrs[i];
        let mode = attr
            .filter(|a| a & ATTR_UNIX_EXTENSION != 0)
            .map(|a| a >> 16)
            .filter(|&m| m != 0);
        let attr_dir = attr.is_some_and(|a| a & ATTR_DIRECTORY != 0)
            || mode.is_some_and(|m| m & 0o170_000 == 0o040_000);
        let (kind, size, crc, folder, offset) = if empty_stream[i] {
            let j = empty_index;
            empty_index += 1;
            if anti[j] {
                anti_items += 1;
                continue;
            }
            let kind = if !empty_file[j] || attr_dir {
                Kind::Dir
            } else {
                Kind::File
            };
            (kind, 0, None, None, 0)
        } else {
            let (fi, at, size, crc) = streams
                .next()
                .ok_or_else(|| corrupt("more files with content than content streams"))?;
            if attr_dir {
                return Err(corrupt(format!("directory {raw:?} has content")));
            }
            let kind = if mode.is_some_and(|m| m & 0o170_000 == 0o120_000) {
                Kind::Symlink
            } else {
                Kind::File
            };
            (kind, size, crc, Some(fi), at)
        };
        let name = clean_name(raw)?;
        if !seen.insert(trunc_core::path::host_key(&name)) {
            return Err(SevenZError::Name {
                name,
                reason: if cfg!(any(windows, target_os = "macos")) {
                    "duplicate entry (names differ only in case)"
                } else {
                    "duplicate entry"
                }
                .into(),
            });
        }
        let (mtime_unix, mtime_nanos) = mtimes[i].map_or((0, 0), filetime);
        if let Some(fi) = folder {
            folders[fi].entries.push(entries.len());
        }
        entries.push(Entry {
            name,
            kind,
            size,
            crc,
            folder,
            offset,
            mode: mode.map(|m| m & 0o7777),
            mtime_unix,
            mtime_nanos,
        });
    }
    if streams.next().is_some() {
        return Err(corrupt("content streams without files"));
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
                return Err(SevenZError::Name {
                    name: e.name.clone(),
                    reason: "nested under a file".into(),
                });
            }
            parent = trunc_core::path::parent(pp);
        }
    }
    Ok((entries, anti_items))
}

fn read_header(r: &mut Rd<'_>, header_offset: u64, max_window: u64) -> Result<Layout> {
    let mut id = r.u8()?;
    if id == K_ARCHIVE_PROPERTIES {
        loop {
            let t = r.u8()?;
            if t == K_END {
                break;
            }
            r.skip_data()?;
        }
        id = r.u8()?;
    }
    if id == K_ADDITIONAL_STREAMS_INFO {
        return Err(SevenZError::Unsupported("additional streams".into()));
    }
    let mut si = StreamsInfo::default();
    if id == K_MAIN_STREAMS_INFO {
        si = read_streams_info(r, max_window)?;
        id = r.u8()?;
    }
    let mut folders = place_folders(&si, header_offset)?;
    let (entries, anti_items) = if id == K_FILES_INFO {
        let v = read_files(r, &mut folders, &si)?;
        id = r.u8()?;
        v
    } else {
        // Folders may exist without files only if they hold no streams (7-Zip writes one such
        // empty folder for an empty archive).
        let streams = si
            .substreams
            .as_ref()
            .map_or(folders.len(), |s| s.iter().map(Vec::len).sum());
        if streams != 0 {
            return Err(corrupt("content without files"));
        }
        (Vec::new(), 0)
    };
    if id != K_END {
        return Err(corrupt("header does not end where expected"));
    }
    Ok(Layout {
        file_len: 0,
        entries,
        folders,
        encoded_header: false,
        header_offset,
        anti_items,
    })
}

pub(super) fn parse(src: &dyn FileHandle, max_window: u64) -> Result<Layout> {
    let file_len = src.size()?;
    if file_len < SIGNATURE_HEADER_LEN {
        return Err(SevenZError::NotSevenZ("too short"));
    }
    let mut sh = [0u8; 32];
    src.read_exact_at(&mut sh, 0)?;
    if !super::sniff(&sh) {
        return Err(SevenZError::NotSevenZ("no 7z signature"));
    }
    if sh[6] != 0 {
        return Err(SevenZError::Unsupported(format!(
            "format version {}.{}",
            sh[6], sh[7]
        )));
    }
    let mut r = Rd::new(&sh[8..]);
    let start_crc = r.u32()?;
    if crc32fast::hash(&sh[12..32]) != start_crc {
        return Err(corrupt("start header CRC mismatch"));
    }
    let (next_off, next_size, next_crc) = (r.u64()?, r.u64()?, r.u32()?);
    let header_offset = SIGNATURE_HEADER_LEN
        .checked_add(next_off)
        .ok_or_else(|| corrupt("header offset overflows"))?;
    if next_size == 0 {
        // An empty archive.
        return Ok(Layout {
            file_len,
            entries: Vec::new(),
            folders: Vec::new(),
            encoded_header: false,
            header_offset,
            anti_items: 0,
        });
    }
    if next_size > MAX_HEADER {
        return Err(corrupt("header too large"));
    }
    if header_offset
        .checked_add(next_size)
        .is_none_or(|end| end > file_len)
    {
        return Err(corrupt(
            "header lies beyond the end of the file (truncated archive?)",
        ));
    }
    let mut buf = vec![0u8; usize::try_from(next_size).expect("<= 256 MiB")];
    src.read_exact_at(&mut buf, header_offset)?;
    if crc32fast::hash(&buf) != next_crc {
        return Err(corrupt("header CRC mismatch"));
    }
    let mut encoded = false;
    for _ in 0..MAX_NESTING {
        let mut r = Rd::new(&buf);
        match r.u8()? {
            K_HEADER => {
                let mut l = read_header(&mut r, header_offset, max_window)?;
                l.file_len = file_len;
                l.encoded_header = encoded;
                return Ok(l);
            }
            K_ENCODED_HEADER => {
                let si = read_streams_info(&mut r, max_window)?;
                let folders = place_folders(&si, header_offset)?;
                let [f] = &folders[..] else {
                    return Err(corrupt("encoded header must be one folder"));
                };
                if f.unpack_size > MAX_HEADER {
                    return Err(corrupt("decoded header too large"));
                }
                let mut out = Vec::with_capacity(usize::try_from(f.unpack_size).expect("bounded"));
                super::folder::decode(src, f, &mut |b| {
                    out.extend_from_slice(b);
                    Ok(())
                })
                .map_err(|e| match e {
                    SevenZError::Crc(_) => corrupt("encoded header CRC mismatch"),
                    other => other,
                })?;
                buf = out;
                encoded = true;
            }
            _ => return Err(corrupt("unknown header type")),
        }
    }
    Err(corrupt("header nested too deeply"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_decode() {
        let cases: [(&[u8], u64); 5] = [
            (&[0x05], 5),
            (&[0x7F], 127),
            (&[0x80, 0x80], 128),
            (&[0xC0, 0x34, 0x12], 0x1234),
            (&[0xFF, 1, 2, 3, 4, 5, 6, 7, 8], 0x0807_0605_0403_0201),
        ];
        for (b, v) in cases {
            assert_eq!(Rd::new(b).number().unwrap(), v, "{b:?}");
        }
        assert!(Rd::new(&[0x80]).number().is_err());
    }

    #[test]
    fn names_and_times() {
        let mut b = Vec::new();
        for s in ["a", "dir/b"] {
            for u in s.encode_utf16() {
                b.extend_from_slice(&u.to_le_bytes());
            }
            b.extend_from_slice(&[0, 0]);
        }
        assert_eq!(read_names(&b, 2).unwrap(), ["a", "dir/b"]);
        assert!(read_names(&b, 3).is_err());
        assert!(read_names(&b[..b.len() - 2], 2).is_err());
        assert_eq!(filetime(116_444_736_000_000_000 + 15), (0, 1500));
    }

    #[test]
    fn hostile_names_are_refused() {
        for n in ["../x", "/etc/passwd", "a/../../b", "C:\\x", ""] {
            assert!(clean_name(n).is_err(), "{n}");
        }
        assert_eq!(clean_name("a\\b").unwrap(), "a/b");
    }
}

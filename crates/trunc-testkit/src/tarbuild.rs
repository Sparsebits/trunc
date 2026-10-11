//! A tar writer for parser and consume tests: ustar headers, GNU long names and links, PAX
//! records, base-256 sizes, raw entry types, hard links, sparse files in the old GNU format and
//! the PAX formats 0.0, 0.1 and 1.0, and gzip output with a chosen block size or several members.

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

#[derive(Debug, Clone)]
pub struct Spec {
    pub name: String,
    /// Tar type flag: `b'0'` file, `b'5'` directory, `b'2'` symlink, `b'1'` hard link...
    pub typeflag: u8,
    pub data: Vec<u8>,
    pub mode: u32,
    pub mtime: u64,
    /// Name storage: in the header (split into ustar prefix and name when needed), or via a GNU
    /// `L` entry, or via a PAX `path` record.
    pub name_via: NameVia,
    /// Extra PAX records to emit before this entry.
    pub pax: Vec<(String, String)>,
    /// For a sparse file: how its map is written. `data` then holds only the stored segments.
    pub sparse: Option<SparseSpec>,
}

/// How a sparse file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseFormat {
    /// Type `S` with the map in the header and extension headers (`tar --format=gnu`).
    OldGnu,
    /// PAX records `GNU.sparse.offset` / `GNU.sparse.numbytes`, repeated.
    Pax00,
    /// PAX record `GNU.sparse.map`.
    Pax01,
    /// The map at the start of the data (`tar --format=pax`).
    Pax10,
}

/// A sparse file's map, written as given (so tests can also write bad ones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseSpec {
    pub format: SparseFormat,
    pub real_size: u64,
    /// `(offset, length)` of each stored segment.
    pub map: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameVia {
    Header,
    GnuLong,
    Pax,
}

impl Spec {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            typeflag: b'0',
            data: data.to_vec(),
            mode: 0o644,
            mtime: 1_700_000_000,
            name_via: NameVia::Header,
            pax: Vec::new(),
            sparse: None,
        }
    }

    pub fn dir(name: &str) -> Self {
        Self {
            typeflag: b'5',
            mode: 0o755,
            ..Self::file(&format!("{}/", name.trim_end_matches('/')), b"")
        }
    }

    pub fn symlink(name: &str, target: &str) -> Self {
        Self {
            typeflag: b'2',
            ..Self::file(name, target.as_bytes())
        }
    }

    /// A hard link to `target`. A long target is stored like a long name (see [`via`](Self::via)).
    pub fn hardlink(name: &str, target: &str) -> Self {
        Self {
            typeflag: b'1',
            ..Self::file(name, target.as_bytes())
        }
    }

    /// A sparse file of `real_size` bytes with data `segments` at their offsets, holes
    /// elsewhere.
    pub fn sparse(
        name: &str,
        real_size: u64,
        segments: &[(u64, &[u8])],
        format: SparseFormat,
    ) -> Self {
        let data: Vec<u8> = segments
            .iter()
            .flat_map(|(_, d)| d.iter().copied())
            .collect();
        Self {
            sparse: Some(SparseSpec {
                format,
                real_size,
                map: segments.iter().map(|(o, d)| (*o, d.len() as u64)).collect(),
            }),
            ..Self::file(name, &data)
        }
    }

    /// The file's content once extracted: a sparse file with its holes filled with zeros.
    pub fn content(&self) -> Vec<u8> {
        let Some(sp) = &self.sparse else {
            return self.data.clone();
        };
        let mut out = vec![0u8; usize::try_from(sp.real_size).expect("small test file")];
        let mut at = 0usize;
        for &(off, len) in &sp.map {
            let (off, len) = (off as usize, len as usize);
            out[off..off + len].copy_from_slice(&self.data[at..at + len]);
            at += len;
        }
        out
    }

    pub fn via(mut self, how: NameVia) -> Self {
        self.name_via = how;
        self
    }
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{:0width$o}\0", v, width = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

/// A 12-byte number field: octal, or GNU base-256 when it does not fit in 11 octal digits.
fn number12(field: &mut [u8], v: u64) {
    if v < 0o777_7777_7777 {
        octal(field, v);
    } else {
        field.fill(0);
        field[0] = 0x80;
        field[4..12].copy_from_slice(&v.to_be_bytes());
    }
}

fn checksum(h: &mut [u8; 512]) {
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&c| u64::from(c)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
}

/// Old GNU sparse map entries (offset and length, 24 bytes each).
fn gnu_sparse_entries(out: &mut [u8], map: &[(u64, u64)]) {
    for (i, &(off, len)) in map.iter().enumerate() {
        number12(&mut out[i * 24..i * 24 + 12], off);
        number12(&mut out[i * 24 + 12..i * 24 + 24], len);
    }
}

fn header(
    name: &[u8],
    prefix: &[u8],
    typeflag: u8,
    size: u64,
    mode: u32,
    mtime: u64,
    link: &[u8],
) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    number12(&mut h[124..136], size);
    octal(&mut h[136..148], mtime);
    h[156] = typeflag;
    let l = link.len().min(100);
    h[157..157 + l].copy_from_slice(&link[..l]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix);
    checksum(&mut h);
    h
}

fn pad(out: &mut Vec<u8>) {
    out.resize(out.len().next_multiple_of(512), 0);
}

fn pax_record(k: &str, v: &str) -> String {
    let body = format!(" {k}={v}\n");
    let mut len = body.len() + 1;
    while format!("{len}{body}").len() != len {
        len += 1;
    }
    format!("{len}{body}")
}

/// The raw (uncompressed) tar bytes for `specs`, with the end-of-archive marker.
pub fn tar(specs: &[Spec]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in specs {
        let name = s.name.as_bytes();
        let mut pax: String = s.pax.iter().map(|(k, v)| pax_record(k, v)).collect();
        let link = (s.typeflag == b'1' || s.typeflag == b'2').then_some(&s.data[..]);
        if let Some(l) = link.filter(|l| l.len() > 100) {
            match s.name_via {
                NameVia::GnuLong => {
                    let mut long = l.to_vec();
                    long.push(0);
                    out.extend_from_slice(&header(
                        b"././@LongLink",
                        b"",
                        b'K',
                        long.len() as u64,
                        0,
                        0,
                        b"",
                    ));
                    out.extend_from_slice(&long);
                    pad(&mut out);
                }
                NameVia::Pax => {
                    pax.push_str(&pax_record("linkpath", std::str::from_utf8(l).unwrap()));
                }
                NameVia::Header => panic!("link target too long for a header; use GnuLong or Pax"),
            }
        }
        // Sparse files in a PAX format: map records, and for 1.0 the map text before the data.
        let mut map_text = Vec::new();
        let mut fake_name = None;
        if let Some(sp) = s
            .sparse
            .as_ref()
            .filter(|sp| sp.format != SparseFormat::OldGnu)
        {
            let n = sp.map.len();
            let real = sp.real_size.to_string();
            match sp.format {
                SparseFormat::Pax00 => {
                    pax.push_str(&pax_record("GNU.sparse.size", &real));
                    pax.push_str(&pax_record("GNU.sparse.numblocks", &n.to_string()));
                    for (off, len) in &sp.map {
                        pax.push_str(&pax_record("GNU.sparse.offset", &off.to_string()));
                        pax.push_str(&pax_record("GNU.sparse.numbytes", &len.to_string()));
                    }
                }
                SparseFormat::Pax01 => {
                    let map: Vec<String> = sp
                        .map
                        .iter()
                        .flat_map(|(o, l)| [o.to_string(), l.to_string()])
                        .collect();
                    pax.push_str(&pax_record("GNU.sparse.size", &real));
                    pax.push_str(&pax_record("GNU.sparse.numblocks", &n.to_string()));
                    pax.push_str(&pax_record("GNU.sparse.map", &map.join(",")));
                    pax.push_str(&pax_record("GNU.sparse.name", &s.name));
                    fake_name = Some(b"GNUSparseFile.0/sparse".to_vec());
                }
                SparseFormat::Pax10 => {
                    pax.push_str(&pax_record("GNU.sparse.major", "1"));
                    pax.push_str(&pax_record("GNU.sparse.minor", "0"));
                    pax.push_str(&pax_record("GNU.sparse.name", &s.name));
                    pax.push_str(&pax_record("GNU.sparse.realsize", &real));
                    fake_name = Some(b"GNUSparseFile.0/sparse".to_vec());
                    map_text = format!("{n}\n").into_bytes();
                    for (off, len) in &sp.map {
                        map_text.extend_from_slice(format!("{off}\n{len}\n").as_bytes());
                    }
                    pad(&mut map_text);
                }
                SparseFormat::OldGnu => unreachable!(),
            }
        }
        let (hname, prefix): (Vec<u8>, Vec<u8>) = match s.name_via {
            NameVia::Header if name.len() <= 100 => (name.to_vec(), Vec::new()),
            NameVia::Header => {
                // Split at a '/' so that prefix <= 155 and name <= 100.
                let cut = name
                    .iter()
                    .rposition(|&c| c == b'/')
                    .filter(|&i| i <= 155 && name.len() - i - 1 <= 100)
                    .expect("name too long for a ustar header; use GnuLong or Pax");
                (name[cut + 1..].to_vec(), name[..cut].to_vec())
            }
            NameVia::GnuLong => {
                let mut long = name.to_vec();
                long.push(0);
                out.extend_from_slice(&header(
                    b"././@LongLink",
                    b"",
                    b'L',
                    long.len() as u64,
                    0,
                    0,
                    b"",
                ));
                out.extend_from_slice(&long);
                pad(&mut out);
                (name[..name.len().min(100)].to_vec(), Vec::new())
            }
            NameVia::Pax => {
                pax.push_str(&pax_record("path", &s.name));
                (b"PaxHeaders/x".to_vec(), Vec::new())
            }
        };
        if !pax.is_empty() {
            out.extend_from_slice(&header(
                b"PaxHeaders/x",
                b"",
                b'x',
                pax.len() as u64,
                0o644,
                s.mtime,
                b"",
            ));
            out.extend_from_slice(pax.as_bytes());
            pad(&mut out);
        }
        let (hname, prefix) = match fake_name {
            Some(f) => (f, Vec::new()),
            None => (hname, prefix),
        };
        let old_gnu = s
            .sparse
            .as_ref()
            .filter(|sp| sp.format == SparseFormat::OldGnu);
        let typeflag = if old_gnu.is_some() { b'S' } else { s.typeflag };
        let carries_data = matches!(typeflag, b'0' | 0 | b'7' | b'S');
        let size = if carries_data {
            (map_text.len() + s.data.len()) as u64
        } else {
            0
        };
        let link_field = if carries_data { &[][..] } else { &s.data[..] };
        let mut h = header(&hname, &prefix, typeflag, size, s.mode, s.mtime, link_field);
        let mut ext = Vec::new();
        if let Some(sp) = old_gnu {
            // GNU header: no ustar prefix; the map, an "extended" flag and the real size there.
            h[257..265].copy_from_slice(b"ustar  \0");
            h[345..500].fill(0);
            let (first, rest) = sp.map.split_at(sp.map.len().min(4));
            gnu_sparse_entries(&mut h[386..482], first);
            h[482] = u8::from(!rest.is_empty());
            number12(&mut h[483..495], sp.real_size);
            checksum(&mut h);
            let chunks: Vec<&[(u64, u64)]> = rest.chunks(21).collect();
            for (i, c) in chunks.iter().enumerate() {
                let mut b = [0u8; 512];
                gnu_sparse_entries(&mut b[..504], c);
                b[504] = u8::from(i + 1 < chunks.len());
                ext.extend_from_slice(&b);
            }
        }
        out.extend_from_slice(&h);
        out.extend_from_slice(&ext);
        if carries_data {
            out.extend_from_slice(&map_text);
            out.extend_from_slice(&s.data);
            pad(&mut out);
        }
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// gzip-compress `data` as one member.
pub fn gzip(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// gzip-compress `data` as several members of `chunk` input bytes each (like `pigz -i` output
/// or concatenated `.gz` files).
pub fn gzip_members(data: &[u8], chunk: usize, level: u32) -> Vec<u8> {
    if data.is_empty() {
        return gzip(data, level);
    }
    data.chunks(chunk.max(1))
        .flat_map(|c| gzip(c, level))
        .collect()
}

/// bzip2-compress `data` as one stream (`level` 1-9 sets the block size).
pub fn bzip2(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// bzip2-compress `data` as several streams of `chunk` input bytes each (like `pbzip2`).
pub fn bzip2_streams(data: &[u8], chunk: usize, level: u32) -> Vec<u8> {
    if data.is_empty() {
        return bzip2(data, level);
    }
    data.chunks(chunk.max(1))
        .flat_map(|c| bzip2(c, level))
        .collect()
}

/// Integrity check an xz stream carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XzCheck {
    None,
    Crc32,
    Crc64,
    Sha256,
}

/// xz-compress `data` (`preset` 0-9) as one stream with one block.
pub fn xz(data: &[u8], preset: u32) -> Vec<u8> {
    xz_with(data, preset, XzCheck::Crc64, None)
}

/// xz-compress `data` with a given check, and with blocks of `block_size` input bytes (as
/// multi-threaded `xz -T` writes them) when set.
pub fn xz_with(data: &[u8], preset: u32, check: XzCheck, block_size: Option<u64>) -> Vec<u8> {
    use liblzma::stream::{Check, MtStreamBuilder, Stream};
    let check = match check {
        XzCheck::None => Check::None,
        XzCheck::Crc32 => Check::Crc32,
        XzCheck::Crc64 => Check::Crc64,
        XzCheck::Sha256 => Check::Sha256,
    };
    let stream = match block_size {
        None => Stream::new_easy_encoder(preset, check).unwrap(),
        Some(bs) => MtStreamBuilder::new()
            .preset(preset)
            .threads(1)
            .block_size(bs)
            .check(check)
            .encoder()
            .unwrap(),
    };
    let mut e = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// zstd-compress `data` as one frame with a content checksum.
pub fn zstd(data: &[u8], level: i32) -> Vec<u8> {
    zstd_with(data, level, true, None)
}

/// zstd-compress `data`, optionally without the checksum and with a forced window size
/// (`window_log`, as `--long=N` sets it).
pub fn zstd_with(data: &[u8], level: i32, checksum: bool, window_log: Option<u32>) -> Vec<u8> {
    let mut e = zstd::stream::write::Encoder::new(Vec::new(), level).unwrap();
    e.include_checksum(checksum).unwrap();
    e.include_contentsize(false).unwrap();
    if let Some(w) = window_log {
        e.long_distance_matching(true).unwrap();
        e.window_log(w).unwrap();
    }
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// zstd-compress `data` as several frames of `chunk` input bytes each, each declaring its size
/// (like `pzstd`).
pub fn zstd_frames(data: &[u8], chunk: usize, level: i32) -> Vec<u8> {
    if data.is_empty() {
        return zstd(data, level);
    }
    data.chunks(chunk.max(1))
        .flat_map(|c| {
            let mut e = zstd::stream::write::Encoder::new(Vec::new(), level).unwrap();
            e.include_checksum(true).unwrap();
            e.include_contentsize(true).unwrap();
            e.set_pledged_src_size(Some(c.len() as u64)).unwrap();
            e.write_all(c).unwrap();
            e.finish().unwrap()
        })
        .collect()
}

/// Split `data` into parts of `part` bytes (the last may be shorter), as `split -b` does.
pub fn split(data: &[u8], part: usize) -> Vec<Vec<u8>> {
    data.chunks(part.max(1)).map(<[u8]>::to_vec).collect()
}

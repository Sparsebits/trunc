//! A tar writer for parser and consume tests: ustar headers, GNU long names, PAX records,
//! base-256 sizes, raw entry types, and gzip output with a chosen block size or several members.

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

    pub fn via(mut self, how: NameVia) -> Self {
        self.name_via = how;
        self
    }
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{:0width$o}\0", v, width = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
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
    if size < 0o777_7777_7777 {
        octal(&mut h[124..136], size);
    } else {
        // GNU base-256 for sizes that do not fit in 11 octal digits.
        h[124] = 0x80;
        h[128..136].copy_from_slice(&size.to_be_bytes());
    }
    octal(&mut h[136..148], mtime);
    h[156] = typeflag;
    let l = link.len().min(100);
    h[157..157 + l].copy_from_slice(&link[..l]);
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + prefix.len()].copy_from_slice(prefix);
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&c| u64::from(c)).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
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
        let carries_data = matches!(s.typeflag, b'0' | 0 | b'7');
        let (size, link) = if carries_data {
            (s.data.len() as u64, &[][..])
        } else {
            (0, &s.data[..])
        };
        out.extend_from_slice(&header(
            &hname, &prefix, s.typeflag, size, s.mode, s.mtime, link,
        ));
        if carries_data {
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

/// zstd-compress `data` as several frames of `chunk` input bytes each (like `pzstd`).
pub fn zstd_frames(data: &[u8], chunk: usize, level: i32) -> Vec<u8> {
    if data.is_empty() {
        return zstd(data, level);
    }
    data.chunks(chunk.max(1))
        .flat_map(|c| zstd(c, level))
        .collect()
}

/// Split `data` into parts of `part` bytes (the last may be shorter), as `split -b` does.
pub fn split(data: &[u8], part: usize) -> Vec<Vec<u8>> {
    data.chunks(part.max(1)).map(<[u8]>::to_vec).collect()
}

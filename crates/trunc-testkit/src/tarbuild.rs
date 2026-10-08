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
    data.chunks(chunk.max(1))
        .flat_map(|c| gzip(c, level))
        .collect()
}

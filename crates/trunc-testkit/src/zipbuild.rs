//! A ZIP writer with control over every detail, for parser and consume tests: data descriptors
//! (with or without signature), forced Zip64, Unix modes, self-extractor prefixes, aliases
//! (central-directory records pointing at existing local headers) and tampering hooks.

use std::io::Write;

use flate2::Compression;
use flate2::write::DeflateEncoder;

#[derive(Debug, Clone)]
pub struct Spec {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub deflate: bool,
    pub level: u32,
    pub utf8: bool,
    /// `Some(true)`: data descriptor with signature; `Some(false)`: without.
    pub descriptor: Option<bool>,
    pub zip64: bool,
    pub unix_mode: Option<u32>,
    pub mtime_dos: (u16, u16),
    /// ZIP method number overriding `deflate` (12 bzip2, 93 zstd, 95 xz; any other number
    /// stores the data as is under that number).
    pub method: Option<u16>,
}

impl Spec {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            deflate: true,
            level: 6,
            utf8: !name.is_ascii(),
            descriptor: None,
            zip64: false,
            unix_mode: None,
            mtime_dos: (((2024 - 1980) << 9) | (5 << 5) | 17, (12 << 11) | (30 << 5)),
            method: None,
        }
    }

    pub fn dir(name: &str) -> Self {
        let mut s = Self::file(&format!("{}/", name.trim_end_matches('/')), b"");
        s.deflate = false;
        s
    }

    pub fn stored(mut self) -> Self {
        self.deflate = false;
        self
    }
    /// Use ZIP method number `m` (see the `method` field).
    pub fn method(mut self, m: u16) -> Self {
        self.method = Some(m);
        self
    }
    pub fn level(mut self, l: u32) -> Self {
        self.level = l;
        self
    }
    pub fn descriptor(mut self, with_sig: bool) -> Self {
        self.descriptor = Some(with_sig);
        self
    }
    pub fn zip64(mut self) -> Self {
        self.zip64 = true;
        self
    }
    pub fn mode(mut self, m: u32) -> Self {
        self.unix_mode = Some(m);
        self
    }
}

struct Written {
    spec: Spec,
    lho: u64,
    crc: u32,
    csize: u64,
}

/// Where an added entry's pieces landed (offsets relative to the ZIP start, excluding prefix).
#[derive(Debug, Clone, Copy)]
pub struct Placed {
    pub local_header: u64,
    pub data: u64,
    pub end: u64,
}

#[derive(Default)]
pub struct ZipBuilder {
    body: Vec<u8>,
    written: Vec<Written>,
    prefix: Vec<u8>,
    comment: Vec<u8>,
    zip64_eocd: bool,
}

impl std::fmt::Debug for ZipBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZipBuilder({} entries)", self.written.len())
    }
}

fn compress(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn method_of(s: &Spec) -> u16 {
    s.method.unwrap_or(if s.deflate { 8 } else { 0 })
}

/// An entry's payload for its method.
fn encode(s: &Spec) -> Vec<u8> {
    match method_of(s) {
        8 => compress(&s.data, s.level),
        12 => crate::tarbuild::bzip2(&s.data, s.level.clamp(1, 9)),
        93 => crate::tarbuild::zstd(&s.data, i32::try_from(s.level.clamp(1, 19)).unwrap()),
        95 => crate::tarbuild::xz(&s.data, s.level.min(9)),
        _ => s.data.clone(),
    }
}

fn u16le(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn u32le(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn u64le(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn flags(s: &Spec) -> u16 {
    (if s.descriptor.is_some() { 1 << 3 } else { 0 }) | (if s.utf8 { 1 << 11 } else { 0 })
}

impl ZipBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes before the ZIP (like a self-extractor stub); offsets in the ZIP do not include it.
    pub fn prefix(mut self, p: &[u8]) -> Self {
        self.prefix = p.to_vec();
        self
    }

    pub fn comment(mut self, c: &[u8]) -> Self {
        self.comment = c.to_vec();
        self
    }

    pub fn zip64_eocd(mut self) -> Self {
        self.zip64_eocd = true;
        self
    }

    /// The local header + data (+ descriptor) bytes an entry would have, without adding it.
    pub fn local_record(spec: &Spec) -> Vec<u8> {
        let mut b = ZipBuilder::new();
        b.add(spec.clone());
        b.body
    }

    /// Append an entry's local record and register it for the central directory.
    pub fn add(&mut self, spec: Spec) -> Placed {
        let lho = self.body.len() as u64;
        let comp = encode(&spec);
        let crc = crc32fast::hash(&spec.data);
        let (csize, usize_) = (comp.len() as u64, spec.data.len() as u64);
        let b = &mut self.body;
        u32le(b, 0x0403_4b50);
        u16le(b, if spec.zip64 { 45 } else { 20 });
        u16le(b, flags(&spec));
        u16le(b, method_of(&spec));
        u16le(b, spec.mtime_dos.1);
        u16le(b, spec.mtime_dos.0);
        let desc = spec.descriptor.is_some();
        u32le(b, if desc { 0 } else { crc });
        let (c32, u32_) = if spec.zip64 {
            (0xFFFF_FFFF, 0xFFFF_FFFF)
        } else if desc {
            (0, 0)
        } else {
            (
                u32::try_from(csize).unwrap(),
                u32::try_from(usize_).unwrap(),
            )
        };
        u32le(b, c32);
        u32le(b, u32_);
        u16le(b, u16::try_from(spec.name.len()).unwrap());
        u16le(b, if spec.zip64 { 20 } else { 0 });
        b.extend_from_slice(&spec.name);
        if spec.zip64 {
            u16le(b, 1);
            u16le(b, 16);
            u64le(b, if desc { 0 } else { usize_ });
            u64le(b, if desc { 0 } else { csize });
        }
        let data = b.len() as u64;
        b.extend_from_slice(&comp);
        if let Some(sig) = spec.descriptor {
            if sig {
                u32le(b, 0x0807_4b50);
            }
            u32le(b, crc);
            if spec.zip64 {
                u64le(b, csize);
                u64le(b, usize_);
            } else {
                u32le(b, u32::try_from(csize).unwrap());
                u32le(b, u32::try_from(usize_).unwrap());
            }
        }
        let end = b.len() as u64;
        self.written.push(Written {
            spec,
            lho,
            crc,
            csize,
        });
        Placed {
            local_header: lho,
            data,
            end,
        }
    }

    /// Append raw bytes to the data area (e.g. a local record to be aliased later).
    pub fn raw(&mut self, bytes: &[u8]) -> u64 {
        let at = self.body.len() as u64;
        self.body.extend_from_slice(bytes);
        at
    }

    /// Register a central-directory record for `spec` whose local header is at `lho` (which must
    /// already contain a matching local record). Used to build overlapping entries.
    pub fn alias(&mut self, spec: Spec, lho: u64) {
        let comp = encode(&spec);
        let crc = crc32fast::hash(&spec.data);
        self.written.push(Written {
            spec,
            lho,
            crc,
            csize: comp.len() as u64,
        });
    }

    /// Mutable access to the data area for tampering.
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = self.prefix.clone();
        out.extend_from_slice(&self.body);
        let cd_offset = self.body.len() as u64;
        let mut cd = Vec::new();
        for w in &self.written {
            let s = &w.spec;
            let usize_ = s.data.len() as u64;
            let z = s.zip64;
            let made_by: u16 = if s.unix_mode.is_some() {
                (3 << 8) | 45
            } else {
                45
            };
            u32le(&mut cd, 0x0201_4b50);
            u16le(&mut cd, made_by);
            u16le(&mut cd, if z { 45 } else { 20 });
            u16le(&mut cd, flags(s));
            u16le(&mut cd, method_of(s));
            u16le(&mut cd, s.mtime_dos.1);
            u16le(&mut cd, s.mtime_dos.0);
            u32le(&mut cd, w.crc);
            u32le(
                &mut cd,
                if z {
                    0xFFFF_FFFF
                } else {
                    u32::try_from(w.csize).unwrap()
                },
            );
            u32le(
                &mut cd,
                if z {
                    0xFFFF_FFFF
                } else {
                    u32::try_from(usize_).unwrap()
                },
            );
            u16le(&mut cd, u16::try_from(s.name.len()).unwrap());
            u16le(&mut cd, if z { 28 } else { 0 });
            u16le(&mut cd, 0);
            u16le(&mut cd, 0);
            u16le(&mut cd, 0);
            let dir = s.name.ends_with(b"/");
            let attr = s.unix_mode.map_or(0, |m| m << 16) | if dir { 0x10 } else { 0 };
            u32le(&mut cd, attr);
            u32le(
                &mut cd,
                if z {
                    0xFFFF_FFFF
                } else {
                    u32::try_from(w.lho).unwrap()
                },
            );
            cd.extend_from_slice(&s.name);
            if z {
                u16le(&mut cd, 1);
                u16le(&mut cd, 24);
                u64le(&mut cd, usize_);
                u64le(&mut cd, w.csize);
                u64le(&mut cd, w.lho);
            }
        }
        out.extend_from_slice(&cd);
        let n = self.written.len() as u64;
        let zip64 = self.zip64_eocd || self.written.iter().any(|w| w.spec.zip64);
        if zip64 {
            let z_off = cd_offset + cd.len() as u64;
            u32le(&mut out, 0x0606_4b50);
            u64le(&mut out, 44);
            u16le(&mut out, 45);
            u16le(&mut out, 45);
            u32le(&mut out, 0);
            u32le(&mut out, 0);
            u64le(&mut out, n);
            u64le(&mut out, n);
            u64le(&mut out, cd.len() as u64);
            u64le(&mut out, cd_offset);
            u32le(&mut out, 0x0706_4b50);
            u32le(&mut out, 0);
            // Locator offsets are absolute in the file (our parser reads them as such).
            u64le(&mut out, z_off + self.prefix.len() as u64);
            u32le(&mut out, 1);
        }
        u32le(&mut out, 0x0605_4b50);
        u16le(&mut out, 0);
        u16le(&mut out, 0);
        let n16 = if zip64 {
            0xFFFF
        } else {
            u16::try_from(n).unwrap()
        };
        u16le(&mut out, n16);
        u16le(&mut out, n16);
        u32le(
            &mut out,
            if zip64 {
                0xFFFF_FFFF
            } else {
                u32::try_from(cd.len()).unwrap()
            },
        );
        u32le(
            &mut out,
            if zip64 {
                0xFFFF_FFFF
            } else {
                u32::try_from(cd_offset).unwrap()
            },
        );
        u16le(&mut out, u16::try_from(self.comment.len()).unwrap());
        out.extend_from_slice(&self.comment);
        out
    }
}

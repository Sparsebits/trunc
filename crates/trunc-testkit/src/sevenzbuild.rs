//! A minimal 7z writer for parser and extraction tests: Copy, LZMA and LZMA2 (raw liblzma
//! encoders), optionally behind a BCJ x86 or Delta filter; solid or one folder per file; plain or
//! LZMA-encoded header; empty files, directories, anti-items, attributes and times. The pieces
//! (`number`, `coders`, `compress`, `assemble`) are public so hostile headers can be built by hand.

use liblzma::stream::{Action, Filters, LzmaOptions, Status, Stream};

/// The coder chain of every folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec7 {
    Copy,
    Lzma,
    Lzma2,
    /// BCJ x86 in front of LZMA2.
    BcjLzma2,
    /// BCJ x86 in front of LZMA.
    BcjLzma,
    /// Delta (with this distance) in front of LZMA2.
    DeltaLzma2(u8),
}

#[derive(Debug, Clone)]
pub struct Item7 {
    pub name: String,
    /// `None` for a directory.
    pub data: Option<Vec<u8>>,
    pub attrib: Option<u32>,
    /// FILETIME (100 ns since 1601).
    pub mtime: Option<u64>,
    pub anti: bool,
}

impl Item7 {
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            data: Some(data.to_vec()),
            attrib: None,
            mtime: Some(133_000_000_000_000_000),
            anti: false,
        }
    }

    pub fn dir(name: &str) -> Self {
        Self {
            data: None,
            ..Self::file(name, b"")
        }
    }

    pub fn attrib(mut self, a: u32) -> Self {
        self.attrib = Some(a);
        self
    }

    pub fn anti(mut self) -> Self {
        self.anti = true;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Opts7 {
    pub codec: Codec7,
    /// All files in one folder (else one folder per file).
    pub solid: bool,
    pub encode_header: bool,
    /// Record each folder's CRC (7-Zip records the files' CRCs instead).
    pub folder_crc: bool,
    pub dict: u32,
}

impl Default for Opts7 {
    fn default() -> Self {
        Self {
            codec: Codec7::Lzma2,
            solid: true,
            encode_header: true,
            folder_crc: false,
            dict: 1 << 16,
        }
    }
}

/// Append a 7z NUMBER.
pub fn number(out: &mut Vec<u8>, v: u64) {
    for n in 0..8u32 {
        if v >> (8 * n) < 1 << (7 - n) {
            out.push((0xFF00u16 >> n) as u8 | (v >> (8 * n)) as u8);
            out.extend_from_slice(&v.to_le_bytes()[..n as usize]);
            return;
        }
    }
    out.push(0xFF);
    out.extend_from_slice(&v.to_le_bytes());
}

fn lzma_opts(dict: u32) -> LzmaOptions {
    let mut o = LzmaOptions::new_preset(6).unwrap();
    o.dict_size(dict)
        .literal_context_bits(3)
        .literal_position_bits(0)
        .position_bits(2);
    o
}

fn lzma2_prop(dict: u32) -> u8 {
    (0..40u32)
        .find(|&b| (2u64 | u64::from(b & 1)) << (b / 2 + 11) >= u64::from(dict))
        .unwrap_or(40) as u8
}

fn raw(filters: &Filters, mut input: &[u8]) -> Vec<u8> {
    let mut s = Stream::new_raw_encoder(filters).unwrap();
    let mut out = Vec::with_capacity(input.len() / 2 + 1024);
    loop {
        if out.capacity() - out.len() < 1 << 16 {
            out.reserve(1 << 20);
        }
        let before = s.total_in();
        let st = s.process_vec(input, &mut out, Action::Finish).unwrap();
        input = &input[(s.total_in() - before) as usize..];
        if st == Status::StreamEnd {
            return out;
        }
    }
}

/// Compress `data` with the chain (LZMA1 streams end with an end marker, as liblzma writes them).
pub fn compress(codec: Codec7, dict: u32, data: &[u8]) -> Vec<u8> {
    let o = lzma_opts(dict);
    let mut f = Filters::new();
    match codec {
        Codec7::Copy => return data.to_vec(),
        Codec7::Lzma => {
            f.lzma1(&o);
        }
        Codec7::Lzma2 => {
            f.lzma2(&o);
        }
        Codec7::BcjLzma2 => {
            f.x86().lzma2(&o);
        }
        Codec7::BcjLzma => {
            f.x86().lzma1(&o);
        }
        Codec7::DeltaLzma2(d) => {
            f.delta_properties(&[d - 1]).unwrap().lzma2(&o);
        }
    }
    raw(&f, data)
}

/// A folder's coder records and bind pairs, for output `size` (header order: the coder
/// producing the folder's output first).
pub fn coders(codec: Codec7, dict: u32, size: u64) -> (Vec<u8>, Vec<u64>) {
    let mut lzma = vec![0x23, 0x03, 0x01, 0x01, 5, 0x5D];
    lzma.extend_from_slice(&dict.to_le_bytes());
    let lzma2 = vec![0x21, 0x21, 1, lzma2_prop(dict)];
    let mut b = Vec::new();
    let one = |b: &mut Vec<u8>, c: &[u8]| {
        number(b, 1);
        b.extend_from_slice(c);
    };
    let two = |b: &mut Vec<u8>, filter: &[u8], codec: &[u8]| {
        number(b, 2);
        b.extend_from_slice(filter);
        b.extend_from_slice(codec);
        // The filter's input (in-stream 0) is the codec's output (out-stream 1).
        number(b, 0);
        number(b, 1);
    };
    let bcj = [0x04, 0x03, 0x03, 0x01, 0x03];
    match codec {
        Codec7::Copy => one(&mut b, &[0x01, 0x00]),
        Codec7::Lzma => one(&mut b, &lzma),
        Codec7::Lzma2 => one(&mut b, &lzma2),
        Codec7::BcjLzma2 => two(&mut b, &bcj, &lzma2),
        Codec7::BcjLzma => two(&mut b, &bcj, &lzma),
        Codec7::DeltaLzma2(d) => two(&mut b, &[0x21, 0x03, 1, d - 1], &lzma2),
    }
    let sizes = match codec {
        Codec7::Copy | Codec7::Lzma | Codec7::Lzma2 => vec![size],
        _ => vec![size, size],
    };
    (b, sizes)
}

/// Signature header + packed streams + header.
pub fn assemble(packed: &[u8], header: &[u8]) -> Vec<u8> {
    let mut tail = Vec::new();
    tail.extend_from_slice(&(packed.len() as u64).to_le_bytes());
    tail.extend_from_slice(&(header.len() as u64).to_le_bytes());
    tail.extend_from_slice(&crc32fast::hash(header).to_le_bytes());
    let mut out = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    out.extend_from_slice(&crc32fast::hash(&tail).to_le_bytes());
    out.extend_from_slice(&tail);
    out.extend_from_slice(packed);
    out.extend_from_slice(header);
    out
}

fn bits(out: &mut Vec<u8>, v: &[bool]) {
    let mut b = vec![0u8; v.len().div_ceil(8)];
    for (i, &x) in v.iter().enumerate() {
        if x {
            b[i / 8] |= 0x80 >> (i % 8);
        }
    }
    out.extend_from_slice(&b);
}

fn property(out: &mut Vec<u8>, id: u8, body: &[u8]) {
    out.push(id);
    number(out, body.len() as u64);
    out.extend_from_slice(body);
}

struct FolderOut {
    coders: Vec<u8>,
    unpack: Vec<u64>,
    crc: u32,
    subs: Vec<(u64, u32)>,
}

/// Streams info for `folders` whose packed streams start at `pack_pos` and have `pack` sizes.
fn streams_info(
    h: &mut Vec<u8>,
    pack_pos: u64,
    pack: &[u64],
    folders: &[FolderOut],
    folder_crc: bool,
    subs: bool,
) {
    h.push(0x06);
    number(h, pack_pos);
    number(h, pack.len() as u64);
    h.push(0x09);
    for &p in pack {
        number(h, p);
    }
    h.push(0x00);
    h.push(0x07);
    h.push(0x0B);
    number(h, folders.len() as u64);
    h.push(0);
    for f in folders {
        h.extend_from_slice(&f.coders);
    }
    h.push(0x0C);
    for f in folders {
        for &u in &f.unpack {
            number(h, u);
        }
    }
    if folder_crc {
        h.extend_from_slice(&[0x0A, 1]);
        for f in folders {
            h.extend_from_slice(&f.crc.to_le_bytes());
        }
    }
    h.push(0x00);
    if subs {
        h.push(0x08);
        h.push(0x0D);
        for f in folders {
            number(h, f.subs.len() as u64);
        }
        h.push(0x09);
        for f in folders {
            for s in &f.subs[..f.subs.len().saturating_sub(1)] {
                number(h, s.0);
            }
        }
        h.extend_from_slice(&[0x0A, 1]);
        for f in folders {
            if folder_crc && f.subs.len() == 1 {
                continue;
            }
            for s in &f.subs {
                h.extend_from_slice(&s.1.to_le_bytes());
            }
        }
        h.push(0x00);
    }
    h.push(0x00);
}

/// Build a 7z archive.
pub fn build(items: &[Item7], o: &Opts7) -> Vec<u8> {
    let with_data: Vec<&[u8]> = items
        .iter()
        .filter_map(|i| i.data.as_deref().filter(|d| !d.is_empty() && !i.anti))
        .collect();
    let groups: Vec<Vec<&[u8]>> = if o.solid {
        if with_data.is_empty() {
            Vec::new()
        } else {
            vec![with_data]
        }
    } else {
        with_data.into_iter().map(|d| vec![d]).collect()
    };
    let mut packed = Vec::new();
    let mut pack_sizes = Vec::new();
    let mut folders = Vec::new();
    for g in &groups {
        let all: Vec<u8> = g.concat();
        let p = compress(o.codec, o.dict, &all);
        pack_sizes.push(p.len() as u64);
        packed.extend_from_slice(&p);
        let (coders, unpack) = coders(o.codec, o.dict, all.len() as u64);
        folders.push(FolderOut {
            coders,
            unpack,
            crc: crc32fast::hash(&all),
            subs: g
                .iter()
                .map(|d| (d.len() as u64, crc32fast::hash(d)))
                .collect(),
        });
    }

    let mut h = vec![0x01];
    if !folders.is_empty() {
        h.push(0x04);
        streams_info(&mut h, 0, &pack_sizes, &folders, o.folder_crc, true);
    }
    h.push(0x05);
    number(&mut h, items.len() as u64);
    let empty: Vec<bool> = items
        .iter()
        .map(|i| i.anti || i.data.as_ref().is_none_or(Vec::is_empty))
        .collect();
    if empty.iter().any(|&e| e) {
        let mut b = Vec::new();
        bits(&mut b, &empty);
        property(&mut h, 0x0E, &b);
        let empties: Vec<&Item7> = items
            .iter()
            .zip(&empty)
            .filter(|e| *e.1)
            .map(|e| e.0)
            .collect();
        let files: Vec<bool> = empties.iter().map(|i| i.data.is_some()).collect();
        if files.iter().any(|&f| f) {
            let mut b = Vec::new();
            bits(&mut b, &files);
            property(&mut h, 0x0F, &b);
        }
        let anti: Vec<bool> = empties.iter().map(|i| i.anti).collect();
        if anti.iter().any(|&a| a) {
            let mut b = Vec::new();
            bits(&mut b, &anti);
            property(&mut h, 0x10, &b);
        }
    }
    let mut names = vec![0u8];
    for i in items {
        for u in i.name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    property(&mut h, 0x11, &names);
    if items.iter().any(|i| i.mtime.is_some()) {
        let defined: Vec<bool> = items.iter().map(|i| i.mtime.is_some()).collect();
        let mut b = Vec::new();
        if defined.iter().all(|&d| d) {
            b.push(1);
        } else {
            b.push(0);
            bits(&mut b, &defined);
        }
        b.push(0);
        for t in items.iter().filter_map(|i| i.mtime) {
            b.extend_from_slice(&t.to_le_bytes());
        }
        property(&mut h, 0x14, &b);
    }
    if items.iter().any(|i| i.attrib.is_some()) {
        let mut b = vec![1, 0];
        for i in items {
            let a = i
                .attrib
                .unwrap_or(if i.data.is_some() { 0x20 } else { 0x10 });
            b.extend_from_slice(&a.to_le_bytes());
        }
        property(&mut h, 0x15, &b);
    }
    h.push(0x00);
    h.push(0x00);

    if !o.encode_header {
        return assemble(&packed, &h);
    }
    let hp = compress(Codec7::Lzma, 1 << 16, &h);
    let (coders, unpack) = coders(Codec7::Lzma, 1 << 16, h.len() as u64);
    let folder = FolderOut {
        coders,
        unpack,
        crc: crc32fast::hash(&h),
        subs: Vec::new(),
    };
    let mut e = vec![0x17];
    streams_info(
        &mut e,
        packed.len() as u64,
        &[hp.len() as u64],
        &[folder],
        true,
        false,
    );
    packed.extend_from_slice(&hp);
    assemble(&packed, &e)
}

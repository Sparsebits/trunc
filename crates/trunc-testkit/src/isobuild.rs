//! A small ISO 9660 writer for tests: a primary volume, an optional Joliet supplementary volume,
//! optional Rock Ridge fields (`SP`, `ER`, `PX`, `NM`, `SL`, `CE` continuation areas for names,
//! and `CL`/`RE` deep-directory relocation), nested directories, multi-extent files, and hidden or
//! associated files. Path tables are left empty (trunc never reads them).
//!
//! [`Built`] remembers where every directory record was written, so tests can corrupt extents
//! and sizes to build hostile images.

use std::collections::BTreeMap;

pub const SECTOR: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecKind {
    File(Vec<u8>),
    Dir,
    Symlink(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// `/`-separated path; parents are created as needed.
    pub path: String,
    pub kind: SpecKind,
    /// Rock Ridge mode (type bits added automatically when absent).
    pub mode: Option<u32>,
    pub hidden: bool,
    pub associated: bool,
    /// Write the file as multi-extent sections of this many bytes (a multiple of 2048).
    pub section: Option<usize>,
}

impl Spec {
    fn new(path: &str, kind: SpecKind) -> Self {
        Self {
            path: path.to_owned(),
            kind,
            mode: None,
            hidden: false,
            associated: false,
            section: None,
        }
    }
    pub fn file(path: &str, data: &[u8]) -> Self {
        Self::new(path, SpecKind::File(data.to_vec()))
    }
    pub fn dir(path: &str) -> Self {
        Self::new(path, SpecKind::Dir)
    }
    pub fn symlink(path: &str, target: &str) -> Self {
        Self::new(path, SpecKind::Symlink(target.to_owned()))
    }
    #[must_use]
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }
    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }
    #[must_use]
    pub fn associated(mut self) -> Self {
        self.associated = true;
        self
    }
    #[must_use]
    pub fn sections(mut self, bytes: usize) -> Self {
        assert!(bytes > 0 && bytes % SECTOR == 0);
        self.section = Some(bytes);
        self
    }
}

/// Which directory tree a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tree {
    Primary,
    Joliet,
}

#[derive(Debug, Clone, Default)]
pub struct IsoBuilder {
    specs: Vec<Spec>,
    joliet: bool,
    rock_ridge: bool,
    ce_names: bool,
    pad_sectors: usize,
    /// UDF volume recognition sequence instead of ISO 9660 descriptors.
    udf_only: bool,
    /// Rock Ridge relocations: (directory, top-level directory listing it with `RE`).
    relocations: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Built {
    pub bytes: Vec<u8>,
    /// Offsets of directory records: (tree, path) -> one offset per section.
    pub records: BTreeMap<(Tree, String), Vec<usize>>,
}

impl Built {
    fn rec(&self, tree: Tree, path: &str) -> usize {
        self.records[&(tree, path.to_owned())][0]
    }
    /// (extent LBA, data length) of a record.
    pub fn extent(&self, tree: Tree, path: &str) -> (u32, u32) {
        let o = self.rec(tree, path);
        let b = &self.bytes;
        (
            u32::from_le_bytes(b[o + 2..o + 6].try_into().unwrap()),
            u32::from_le_bytes(b[o + 10..o + 14].try_into().unwrap()),
        )
    }
    /// Extent LBA of a tree's root directory.
    pub fn root(&self, tree: Tree) -> u32 {
        let o = (16 + usize::from(tree == Tree::Joliet)) * SECTOR + 156;
        u32::from_le_bytes(self.bytes[o + 2..o + 6].try_into().unwrap())
    }
    pub fn set_extent(&mut self, tree: Tree, path: &str, lba: u32) {
        let o = self.rec(tree, path);
        self.bytes[o + 2..o + 10].copy_from_slice(&both32(lba));
    }
    pub fn set_size(&mut self, tree: Tree, path: &str, size: u32) {
        let o = self.rec(tree, path);
        self.bytes[o + 10..o + 18].copy_from_slice(&both32(size));
    }
    /// Raw name bytes of a record (same length required).
    pub fn set_name(&mut self, tree: Tree, path: &str, name: &[u8]) {
        let o = self.rec(tree, path);
        assert_eq!(usize::from(self.bytes[o + 32]), name.len());
        self.bytes[o + 33..o + 33 + name.len()].copy_from_slice(name);
    }
}

fn both16(v: u16) -> [u8; 4] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], b[0], b[1]]
}

fn both32(v: u32) -> [u8; 8] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}

fn lba_of(off: usize) -> u32 {
    u32::try_from(off / SECTOR).unwrap()
}

/// 2024-01-02 03:04:05 UTC.
pub const DATE: [u8; 7] = [124, 1, 2, 3, 4, 5, 0];
pub const DATE_UNIX: i64 = 1_704_164_645;

#[derive(Debug, Clone)]
struct Node {
    spec: Spec,
    /// Child paths, in insertion order (directories only).
    children: Vec<String>,
}

/// What a record points at.
#[derive(Debug, Clone)]
enum Target {
    Dir(String),
    /// A relocated directory's placeholder: its extent, with size 0.
    Link(String),
    Data {
        file: String,
        section: usize,
    },
    Empty,
}

#[derive(Debug, Clone)]
struct Rec {
    name: Vec<u8>,
    flags: u8,
    target: Target,
    /// System use bytes, with a CE field (to be patched) at `ce_at` if `ce` is set.
    su: Vec<u8>,
    ce: Option<(usize, Vec<u8>)>,
    /// A `CL` field (to be patched with the extent of this directory) at this offset in `su`.
    cl: Option<(usize, String)>,
    /// (tree, path) this record is reported under in `Built::records`.
    key: Option<String>,
}

impl Rec {
    fn len(&self) -> usize {
        let n = 33 + self.name.len() + usize::from(self.name.len() % 2 == 0) + self.su.len();
        assert!(n <= 255, "record too long");
        n
    }
}

fn susp(sig: &[u8; 2], data: &[u8]) -> Vec<u8> {
    let mut v = sig.to_vec();
    v.push(u8::try_from(4 + data.len()).unwrap());
    v.push(1);
    v.extend_from_slice(data);
    v
}

fn px(mode: u32) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [mode, 1, 0, 0, 0] {
        d.extend_from_slice(&both32(v));
    }
    susp(b"PX", &d)
}

fn nm(name: &str) -> Vec<u8> {
    let mut d = vec![0u8];
    d.extend_from_slice(name.as_bytes());
    susp(b"NM", &d)
}

const CE_LEN: usize = 28;
const CL_LEN: usize = 12;

impl IsoBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn joliet(mut self, on: bool) -> Self {
        self.joliet = on;
        self
    }
    #[must_use]
    pub fn rock_ridge(mut self, on: bool) -> Self {
        self.rock_ridge = on;
        self
    }
    /// Put Rock Ridge names in continuation areas instead of the records.
    #[must_use]
    pub fn ce_names(mut self, on: bool) -> Self {
        self.ce_names = on;
        self
    }
    /// Zero sectors after the last file (real tools pad images).
    #[must_use]
    pub fn pad(mut self, sectors: usize) -> Self {
        self.pad_sectors = sectors;
        self
    }
    #[must_use]
    pub fn udf_only(mut self) -> Self {
        self.udf_only = true;
        self
    }
    /// Relocate directory `dir` the Rock Ridge way: its parent lists a `CL` placeholder (a
    /// zero-length non-directory record) and the top-level directory `into` (created if needed)
    /// lists it with an `RE` field. Only the primary tree of a Rock Ridge image is affected.
    #[must_use]
    pub fn relocate(mut self, dir: &str, into: &str) -> Self {
        assert!(!into.contains('/'), "relocation target must be top-level");
        self.relocations.push((dir.to_owned(), into.to_owned()));
        self
    }
    pub fn add(&mut self, s: Spec) -> &mut Self {
        self.specs.push(s);
        self
    }

    fn tree(&self) -> BTreeMap<String, Node> {
        let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
        nodes.insert(
            String::new(),
            Node {
                spec: Spec::dir(""),
                children: Vec::new(),
            },
        );
        for s in &self.specs {
            let mut parent = String::new();
            let comps: Vec<&str> = s.path.split('/').collect();
            for (i, c) in comps.iter().enumerate() {
                let path = if parent.is_empty() {
                    (*c).to_owned()
                } else {
                    format!("{parent}/{c}")
                };
                let last = i + 1 == comps.len();
                if !nodes.contains_key(&path) {
                    let spec = if last { s.clone() } else { Spec::dir(&path) };
                    nodes.insert(
                        path.clone(),
                        Node {
                            spec,
                            children: Vec::new(),
                        },
                    );
                    nodes.get_mut(&parent).unwrap().children.push(path.clone());
                } else if last {
                    nodes.get_mut(&path).unwrap().spec = s.clone();
                }
                parent = path;
            }
        }
        for (_, into) in &self.relocations {
            if !nodes.contains_key(into) {
                nodes.insert(
                    into.clone(),
                    Node {
                        spec: Spec::dir(into),
                        children: Vec::new(),
                    },
                );
                nodes.get_mut("").unwrap().children.push(into.clone());
            }
        }
        nodes
    }

    fn mode_of(spec: &Spec) -> u32 {
        let ty = match spec.kind {
            SpecKind::File(_) => 0o100_000,
            SpecKind::Dir => 0o040_000,
            SpecKind::Symlink(_) => 0o120_000,
        };
        match spec.mode {
            Some(m) if m & 0o170_000 != 0 => m,
            Some(m) => ty | m,
            None if ty == 0o040_000 => ty | 0o755,
            None => ty | 0o644,
        }
    }

    /// Records of one directory (after "." and "..", which are added at layout time).
    fn records(&self, nodes: &BTreeMap<String, Node>, dir: &str, tree: Tree) -> Vec<Rec> {
        let rr = self.rock_ridge && tree == Tree::Primary;
        let mut out = Vec::new();
        for (i, child) in nodes[dir].children.iter().enumerate() {
            let spec = &nodes[child].spec;
            let comp = child.rsplit('/').next().unwrap();
            let is_dir = spec.kind == SpecKind::Dir;
            if tree == Tree::Joliet && matches!(spec.kind, SpecKind::Symlink(_)) {
                continue;
            }
            let name: Vec<u8> = match tree {
                Tree::Joliet => {
                    let mut s = comp.to_owned();
                    if !is_dir {
                        s.push_str(";1");
                    }
                    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
                }
                Tree::Primary if self.rock_ridge || self.joliet => {
                    if is_dir {
                        format!("D{i:04}").into_bytes()
                    } else {
                        format!("F{i:04}.;1").into_bytes()
                    }
                }
                Tree::Primary => {
                    if is_dir {
                        comp.as_bytes().to_vec()
                    } else if comp.contains('.') {
                        format!("{comp};1").into_bytes()
                    } else {
                        format!("{comp}.;1").into_bytes()
                    }
                }
            };
            let mut su = Vec::new();
            let mut ce = None;
            if rr {
                su.extend(px(Self::mode_of(spec)));
                if let SpecKind::Symlink(t) = &spec.kind {
                    let mut d = vec![0u8, 0, u8::try_from(t.len()).unwrap()];
                    d.extend_from_slice(t.as_bytes());
                    su.extend(susp(b"SL", &d));
                }
                if self.ce_names {
                    ce = Some((su.len(), nm(comp)));
                    su.extend(vec![0u8; CE_LEN]);
                } else {
                    su.extend(nm(comp));
                }
            }
            let mut flags = 0u8;
            if spec.hidden {
                flags |= 1;
            }
            if spec.associated {
                flags |= 4;
            }
            match &spec.kind {
                SpecKind::Dir => out.push(Rec {
                    name,
                    flags: flags | 2,
                    target: Target::Dir(child.clone()),
                    su,
                    ce,
                    cl: None,
                    key: Some(child.clone()),
                }),
                SpecKind::Symlink(_) => out.push(Rec {
                    name,
                    flags,
                    target: Target::Empty,
                    su,
                    ce,
                    cl: None,
                    key: Some(child.clone()),
                }),
                SpecKind::File(data) => {
                    let n = match spec.section {
                        Some(sec) if !data.is_empty() => data.len().div_ceil(sec),
                        _ => 1,
                    };
                    for section in 0..n {
                        out.push(Rec {
                            name: name.clone(),
                            flags: if section + 1 < n { flags | 0x80 } else { flags },
                            target: if data.is_empty() {
                                Target::Empty
                            } else {
                                Target::Data {
                                    file: child.clone(),
                                    section,
                                }
                            },
                            su: su.clone(),
                            ce: ce.clone(),
                            cl: None,
                            key: Some(child.clone()),
                        });
                    }
                }
            }
            if rr && self.relocations.iter().any(|(d, _)| d == child) {
                // The placeholder: not a directory, size 0, CL pointing at the directory.
                let r = out.last_mut().unwrap();
                r.flags &= !2;
                r.target = Target::Link(child.clone());
                r.cl = Some((r.su.len(), child.clone()));
                r.su.extend(vec![0u8; CL_LEN]);
            }
        }
        if rr {
            for (j, (moved, _)) in self
                .relocations
                .iter()
                .filter(|(_, into)| into == dir)
                .enumerate()
            {
                let comp = moved.rsplit('/').next().unwrap();
                let mut su = px(0o040_755);
                su.extend(nm(comp));
                su.extend(susp(b"RE", &[]));
                out.push(Rec {
                    name: format!("R{j:04}").into_bytes(),
                    flags: 2,
                    target: Target::Dir(moved.clone()),
                    su,
                    ce: None,
                    cl: None,
                    key: Some(format!("RE:{moved}")),
                });
            }
        }
        out
    }

    pub fn build(&self) -> Built {
        if self.udf_only {
            let mut bytes = vec![0u8; 20 * SECTOR];
            for (i, id) in [b"BEA01", b"NSR02", b"TEA01"].iter().enumerate() {
                let o = (16 + i) * SECTOR;
                bytes[o + 1..o + 6].copy_from_slice(*id);
                bytes[o + 6] = 1;
            }
            return Built {
                bytes,
                records: BTreeMap::new(),
            };
        }
        let nodes = self.tree();
        let dirs: Vec<String> = nodes
            .iter()
            .filter(|(_, n)| n.spec.kind == SpecKind::Dir)
            .map(|(p, _)| p.clone())
            .collect();
        let mut trees = vec![Tree::Primary];
        if self.joliet {
            trees.push(Tree::Joliet);
        }
        let first_dir_sector = 16 + trees.len() + 1;

        // Records per directory, with "." and ".." first; the root "." of a Rock Ridge primary
        // tree carries SP, PX and ER.
        let mut recs: BTreeMap<(Tree, String), Vec<Rec>> = BTreeMap::new();
        for &t in &trees {
            for d in &dirs {
                let mut dot_su = Vec::new();
                if self.rock_ridge && t == Tree::Primary {
                    if d.is_empty() {
                        dot_su.extend(susp(b"SP", &[0xBE, 0xEF, 0]));
                    }
                    dot_su.extend(px(0o040_755));
                    if d.is_empty() {
                        let mut er = vec![10u8, 1, 1, 1];
                        er.extend_from_slice(b"RRIP_1991Axy");
                        dot_su.extend(susp(b"ER", &er));
                    }
                }
                let parent = d.rsplit_once('/').map_or("", |(p, _)| p).to_owned();
                let mut v = vec![
                    Rec {
                        name: vec![0],
                        flags: 2,
                        target: Target::Dir(d.clone()),
                        su: dot_su,
                        ce: None,
                        cl: None,
                        key: None,
                    },
                    Rec {
                        name: vec![1],
                        flags: 2,
                        target: Target::Dir(parent),
                        su: Vec::new(),
                        ce: None,
                        cl: None,
                        key: None,
                    },
                ];
                v.extend(self.records(&nodes, d, t));
                recs.insert((t, d.clone()), v);
            }
        }

        // Directory extents: records never cross a sector.
        let dir_len = |v: &[Rec]| -> usize {
            let mut pos = 0usize;
            for r in v {
                if pos % SECTOR + r.len() > SECTOR {
                    pos = pos.div_ceil(SECTOR) * SECTOR;
                }
                pos += r.len();
            }
            pos.div_ceil(SECTOR) * SECTOR
        };
        let mut dir_at: BTreeMap<(Tree, String), (usize, usize)> = BTreeMap::new();
        let mut next = first_dir_sector * SECTOR;
        for (k, v) in &recs {
            let len = dir_len(v);
            dir_at.insert(k.clone(), (next, len));
            next += len;
        }
        // Continuation areas, packed into sectors.
        let mut ce_at: BTreeMap<(Tree, String, usize), usize> = BTreeMap::new();
        for (k, v) in &recs {
            for (i, r) in v.iter().enumerate() {
                if let Some((_, payload)) = &r.ce {
                    if next % SECTOR + payload.len() > SECTOR {
                        next = next.div_ceil(SECTOR) * SECTOR;
                    }
                    ce_at.insert((k.0, k.1.clone(), i), next);
                    next += payload.len();
                }
            }
        }
        next = next.div_ceil(SECTOR) * SECTOR;
        // File data, each file contiguous.
        let mut data_at: BTreeMap<String, usize> = BTreeMap::new();
        for (p, n) in &nodes {
            if let SpecKind::File(d) = &n.spec.kind {
                if !d.is_empty() {
                    data_at.insert(p.clone(), next);
                    next += d.len().div_ceil(SECTOR) * SECTOR;
                }
            }
        }
        let total = next + self.pad_sectors * SECTOR;
        let mut bytes = vec![0u8; total];
        let mut records: BTreeMap<(Tree, String), Vec<usize>> = BTreeMap::new();

        let target_extent = |t: Tree, target: &Target| -> (usize, usize) {
            match target {
                Target::Dir(d) => dir_at[&(t, d.clone())],
                Target::Link(d) => (dir_at[&(t, d.clone())].0, 0),
                Target::Empty => (0, 0),
                Target::Data { file, section } => {
                    let SpecKind::File(data) = &nodes[file].spec.kind else {
                        unreachable!()
                    };
                    let sec = nodes[file].spec.section.unwrap_or(data.len());
                    let start = section * sec;
                    let len = (data.len() - start).min(sec);
                    (data_at[file] + start, len)
                }
            }
        };
        let write_rec = |bytes: &mut [u8], at: usize, r: &Rec, ext: (usize, usize)| {
            let len = r.len();
            let b = &mut bytes[at..at + len];
            b[0] = u8::try_from(len).unwrap();
            b[2..10].copy_from_slice(&both32(lba_of(ext.0)));
            b[10..18].copy_from_slice(&both32(u32::try_from(ext.1).unwrap()));
            b[18..25].copy_from_slice(&DATE);
            b[25] = r.flags;
            b[28..32].copy_from_slice(&both16(1));
            b[32] = u8::try_from(r.name.len()).unwrap();
            b[33..33 + r.name.len()].copy_from_slice(&r.name);
            let su_at = 33 + r.name.len() + usize::from(r.name.len() % 2 == 0);
            b[su_at..su_at + r.su.len()].copy_from_slice(&r.su);
        };
        for (k, v) in &recs {
            let (start, _) = dir_at[k];
            let mut pos = 0usize;
            for (i, r) in v.iter().enumerate() {
                if pos % SECTOR + r.len() > SECTOR {
                    pos = pos.div_ceil(SECTOR) * SECTOR;
                }
                let at = start + pos;
                write_rec(&mut bytes, at, r, target_extent(k.0, &r.target));
                if let Some((ce_off, payload)) = &r.ce {
                    let area = ce_at[&(k.0, k.1.clone(), i)];
                    let mut d = Vec::new();
                    d.extend_from_slice(&both32(lba_of(area)));
                    d.extend_from_slice(&both32(u32::try_from(area % SECTOR).unwrap()));
                    d.extend_from_slice(&both32(u32::try_from(payload.len()).unwrap()));
                    let field = susp(b"CE", &d);
                    let su_at = at + 33 + r.name.len() + usize::from(r.name.len() % 2 == 0);
                    bytes[su_at + ce_off..su_at + ce_off + CE_LEN].copy_from_slice(&field);
                    bytes[area..area + payload.len()].copy_from_slice(payload);
                }
                if let Some((cl_off, d)) = &r.cl {
                    let field = susp(b"CL", &both32(lba_of(dir_at[&(k.0, d.clone())].0)));
                    let su_at = at + 33 + r.name.len() + usize::from(r.name.len() % 2 == 0);
                    bytes[su_at + cl_off..su_at + cl_off + CL_LEN].copy_from_slice(&field);
                }
                if let Some(key) = &r.key {
                    records.entry((k.0, key.clone())).or_default().push(at);
                }
                pos += r.len();
            }
        }
        for (p, at) in &data_at {
            let SpecKind::File(d) = &nodes[p].spec.kind else {
                unreachable!()
            };
            bytes[*at..*at + d.len()].copy_from_slice(d);
        }

        // Volume descriptors.
        for (i, &t) in trees.iter().enumerate() {
            let o = (16 + i) * SECTOR;
            let d = &mut bytes[o..o + SECTOR];
            d[0] = if t == Tree::Primary { 1 } else { 2 };
            d[1..6].copy_from_slice(b"CD001");
            d[6] = 1;
            d[8..40].fill(b' ');
            d[40..72].fill(b' ');
            d[40..48].copy_from_slice(b"TESTDISC");
            d[80..88].copy_from_slice(&both32(lba_of(total)));
            if t == Tree::Joliet {
                d[88..91].copy_from_slice(b"%/E");
            }
            d[120..124].copy_from_slice(&both16(1));
            d[124..128].copy_from_slice(&both16(1));
            d[128..132].copy_from_slice(&both16(2048));
            d[881] = 1;
            let root = Rec {
                name: vec![0],
                flags: 2,
                target: Target::Dir(String::new()),
                su: Vec::new(),
                ce: None,
                cl: None,
                key: None,
            };
            let ext = dir_at[&(t, String::new())];
            write_rec(&mut bytes, o + 156, &root, ext);
        }
        let o = (16 + trees.len()) * SECTOR;
        bytes[o] = 255;
        bytes[o + 1..o + 6].copy_from_slice(b"CD001");
        bytes[o + 6] = 1;
        Built { bytes, records }
    }
}

//! In-memory filesystem with crash and fault injection.
//!
//! Every mutating operation (create, write, resize, preallocate, deallocate, flush, rename,
//! remove, directory flush) gets an increasing index. Faults are scripted against those indices.
//! A crash makes every later call fail with [`FsError::Crashed`] until [`FaultFs::recover`]
//! applies the crash model and returns the filesystem to service, as a reboot would.
//!
//! Files may have several names (hard links). Holes follow NTFS: a file becomes sparse once
//! anything in it is deallocated; extending a sparse file (with `set_len` or by writing past its
//! end) leaves a hole, extending any other file allocates zeros, and `preallocate` allocates.
//!
//! Durability follows POSIX rules, which are stricter than NTFS:
//! - file contents and size are durable only after `flush_data` on that file;
//! - a directory entry (create, rename, remove) is durable only after `flush_dir` on every
//!   parent directory it touches.
//!
//! What survives a crash depends on the [`CrashModel`]. `RandomSubset` keeps an arbitrary
//! subset of unflushed operations, modelling write caches that persist work out of order.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use trunc_fs::{
    Dealloc, FileHandle, FileId, FsBackend, FsError, FsKind, Meta, NodeKind, OpenMode, Result,
    Share, SnapshotHint, SyncHint, VolumeInfo,
};

use crate::Rng;

/// What a crash preserves of work that was not yet made durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashModel {
    /// Everything that was done survives (only the crash point itself matters).
    WriteThrough,
    /// Nothing unflushed survives.
    LoseUnflushed,
    /// Each unflushed operation independently survives with probability 1/2, in order.
    RandomSubset { seed: u64 },
}

/// A scripted fault, keyed by operation index (1-based; see [`FaultFs::op_count`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The operation does not happen; the filesystem is crashed from then on.
    CrashAt(u64),
    /// If the operation is a write, only its first `keep` bytes reach the file, then crash.
    TornWrite { op: u64, keep: usize },
    /// The operation fails with `NoSpace` and has no effect.
    NoSpaceAt(u64),
    /// If the operation is a `set_len`, it fails with `Mapped` and has no effect.
    MappedAt(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    Dir,
    File(u64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Content {
    data: Vec<u8>,
    /// Deallocated ranges: sorted, disjoint, inside `data`.
    holes: Vec<Range<u64>>,
    /// Marked sparse by a deallocation: growing leaves holes.
    sparse: bool,
}

#[derive(Debug, Clone)]
enum DataOp {
    Write {
        off: u64,
        bytes: Vec<u8>,
    },
    /// Truncate, or extend with a hole.
    SetLen(u64),
    /// Extend with allocated zeros.
    Reserve(u64),
    Dealloc {
        range: Range<u64>,
        granularity: u64,
    },
}

#[derive(Debug, Clone)]
struct FileData {
    cur: Content,
    durable: Content,
    pending: Vec<DataOp>,
}

#[derive(Debug, Clone)]
enum TreeChange {
    Insert(String, Node),
    Remove(String),
    Rename(String, String),
}

#[derive(Debug, Clone)]
struct TreeOp {
    change: TreeChange,
    /// Parent directories that still need `flush_dir` before this change is durable.
    waiting: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Write,
    Resize,
    Other,
}

#[derive(Debug)]
struct State {
    model: CrashModel,
    tree: BTreeMap<String, Node>,
    durable_tree: BTreeMap<String, Node>,
    pending_tree: Vec<TreeOp>,
    files: HashMap<u64, FileData>,
    next_id: u64,
    op: u64,
    faults: Vec<Fault>,
    crashed: bool,
    epoch: u64,
    capacity: Option<u64>,
    used: u64,
    peak: u64,
    /// Per file: (open handles, writable handles, exclusive handles).
    handles: HashMap<u64, (usize, usize, usize)>,
    granularity: u64,
    dealloc_supported: bool,
    /// Report file ids the way Linux reports inode numbers: a number is handed out again once
    /// its file is unlinked and closed.
    reuse_ids: bool,
    inodes: HashMap<u64, u64>,
    free_inodes: Vec<u64>,
    next_inode: u64,
    /// A drive that acknowledges flushes without persisting anything.
    flush_lies: bool,
    hard_links: bool,
}

/// In-memory, fault-injecting [`FsBackend`]. Cloning shares the same filesystem.
#[derive(Debug, Clone)]
pub struct FaultFs {
    inner: Arc<Mutex<State>>,
}

fn key(p: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                return Err(FsError::Io {
                    op: "resolving",
                    path: p.to_path_buf(),
                    source: std::io::Error::other("'..' is not supported by FaultFs"),
                });
            }
        }
    }
    Ok(parts.join("/"))
}

fn parent(k: &str) -> &str {
    k.rsplit_once('/').map_or("", |(p, _)| p)
}

fn not_found(p: &Path) -> FsError {
    FsError::NotFound {
        path: p.to_path_buf(),
    }
}

fn other(op: &'static str, p: &Path, msg: &str) -> FsError {
    FsError::Io {
        op,
        path: p.to_path_buf(),
        source: std::io::Error::other(msg.to_owned()),
    }
}

impl Content {
    fn allocated(&self) -> u64 {
        self.data.len() as u64 - self.holes.iter().map(|h| h.end - h.start).sum::<u64>()
    }

    fn apply(&mut self, op: &DataOp) {
        match op {
            DataOp::Write { off, bytes } => {
                let (s, e) = (*off, *off + bytes.len() as u64);
                if e as usize > self.data.len() {
                    self.extend(s);
                    self.data.resize(e as usize, 0);
                }
                self.data[s as usize..e as usize].copy_from_slice(bytes);
                self.cut_holes(s, e);
            }
            DataOp::SetLen(len) => {
                let len = *len;
                if len as usize > self.data.len() {
                    self.extend(len);
                    return;
                }
                self.data.truncate(len as usize);
                self.holes.retain(|h| h.start < len);
                if let Some(h) = self.holes.last_mut() {
                    h.end = h.end.min(len);
                }
            }
            DataOp::Reserve(len) => {
                if *len as usize > self.data.len() {
                    self.data.resize(*len as usize, 0);
                }
            }
            DataOp::Dealloc { range, granularity } => {
                self.sparse = true;
                let end = range.end.min(self.data.len() as u64);
                if range.start >= end {
                    return;
                }
                self.data[range.start as usize..end as usize].fill(0);
                let g = (*granularity).max(1);
                let (hs, he) = (range.start.div_ceil(g) * g, (end / g) * g);
                if hs < he {
                    self.cut_holes(hs, he);
                    self.holes.push(hs..he);
                    self.holes.sort_by_key(|h| h.start);
                }
            }
        }
    }

    /// Grow to `len` (if longer) with zeros: a hole if the file is sparse, else allocated.
    fn extend(&mut self, len: u64) {
        let old = self.data.len() as u64;
        if len <= old {
            return;
        }
        self.data.resize(len as usize, 0);
        if !self.sparse {
            return;
        }
        match self.holes.last_mut() {
            Some(h) if h.end == old => h.end = len,
            _ => self.holes.push(old..len),
        }
    }

    /// Remove `[s, e)` from the hole list (it is being written, so it is allocated again).
    fn cut_holes(&mut self, s: u64, e: u64) {
        let mut out = Vec::with_capacity(self.holes.len() + 1);
        for h in self.holes.drain(..) {
            if h.end <= s || h.start >= e {
                out.push(h);
                continue;
            }
            if h.start < s {
                out.push(h.start..s);
            }
            if h.end > e {
                out.push(e..h.end);
            }
        }
        self.holes = out;
    }
}

fn apply_tree(tree: &mut BTreeMap<String, Node>, change: &TreeChange) {
    match change {
        TreeChange::Insert(k, n) => {
            tree.insert(k.clone(), *n);
        }
        TreeChange::Remove(k) => {
            tree.remove(k);
        }
        TreeChange::Rename(from, to) => {
            let prefix = format!("{from}/");
            let moved: Vec<(String, Node)> = tree
                .iter()
                .filter(|(k, _)| *k == from || k.starts_with(&prefix))
                .map(|(k, n)| (k.clone(), *n))
                .collect();
            for (k, n) in moved {
                tree.remove(&k);
                tree.insert(format!("{to}{}", &k[from.len()..]), n);
            }
        }
    }
}

/// Drop entries whose parent directory does not exist.
fn prune_orphans(tree: &mut BTreeMap<String, Node>) {
    loop {
        let orphans: Vec<String> = tree
            .keys()
            .filter(|k| {
                let p = parent(k);
                !p.is_empty() && tree.get(p) != Some(&Node::Dir)
            })
            .cloned()
            .collect();
        if orphans.is_empty() {
            return;
        }
        for k in orphans {
            tree.remove(&k);
        }
    }
}

impl State {
    fn alive(&self) -> Result<()> {
        if self.crashed {
            Err(FsError::Crashed)
        } else {
            Ok(())
        }
    }

    /// Account for one mutating operation; returns `Some(keep)` for a torn write.
    fn begin(&mut self, kind: Kind, path: &Path) -> Result<Option<usize>> {
        self.alive()?;
        self.op += 1;
        let n = self.op;
        let mut torn = None;
        for f in &self.faults {
            match *f {
                Fault::CrashAt(at) if at == n => {
                    self.crashed = true;
                    return Err(FsError::Crashed);
                }
                Fault::NoSpaceAt(at) if at == n => {
                    return Err(FsError::NoSpace {
                        path: path.to_path_buf(),
                    });
                }
                Fault::MappedAt(at) if at == n && kind == Kind::Resize => {
                    return Err(FsError::Mapped {
                        path: path.to_path_buf(),
                    });
                }
                Fault::TornWrite { op, keep } if op == n && kind == Kind::Write => {
                    torn = Some(keep);
                }
                _ => {}
            }
        }
        Ok(torn)
    }

    fn write_through(&mut self) {
        if self.model == CrashModel::WriteThrough {
            for f in self.files.values_mut() {
                f.durable = f.cur.clone();
                f.pending.clear();
            }
            for op in std::mem::take(&mut self.pending_tree) {
                apply_tree(&mut self.durable_tree, &op.change);
            }
        }
    }

    fn tree_change(&mut self, change: TreeChange) {
        apply_tree(&mut self.tree, &change);
        let waiting = match &change {
            TreeChange::Insert(k, _) | TreeChange::Remove(k) => {
                BTreeSet::from([parent(k).to_owned()])
            }
            TreeChange::Rename(a, b) => {
                BTreeSet::from([parent(a).to_owned(), parent(b).to_owned()])
            }
        };
        self.pending_tree.push(TreeOp { change, waiting });
        self.write_through();
    }

    /// Apply a data op to the current view, enforcing capacity.
    fn data_op(&mut self, id: u64, path: &Path, op: DataOp) -> Result<()> {
        let f = self.files.get(&id).ok_or_else(|| not_found(path))?;
        let mut next = f.cur.clone();
        next.apply(&op);
        let (before, after) = (f.cur.allocated(), next.allocated());
        let used = self.used - before + after;
        if after > before && self.capacity.is_some_and(|c| used > c) {
            return Err(FsError::NoSpace {
                path: path.to_path_buf(),
            });
        }
        let f = self.files.get_mut(&id).expect("checked above");
        f.cur = next;
        f.pending.push(op);
        self.used = used;
        self.peak = self.peak.max(used);
        self.write_through();
        Ok(())
    }

    fn live_ids(tree: &BTreeMap<String, Node>) -> BTreeSet<u64> {
        tree.values()
            .filter_map(|n| {
                if let Node::File(id) = n {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Recount occupancy over files visible in the current view. File data is kept even when
    /// unlinked: until the removal is durable, a crash can bring the entry back.
    fn recompute_used(&mut self) {
        let live = Self::live_ids(&self.tree);
        self.used = self
            .files
            .iter()
            .filter(|(id, _)| live.contains(id))
            .map(|(_, f)| f.cur.allocated())
            .sum();
    }

    fn node(&self, k: &str) -> Option<Node> {
        if k.is_empty() {
            Some(Node::Dir)
        } else {
            self.tree.get(k).copied()
        }
    }
}

impl State {
    /// The id `file_id` reports for internal file `id`.
    fn inode(&mut self, id: u64) -> u64 {
        if !self.reuse_ids {
            return id;
        }
        if let Some(&i) = self.inodes.get(&id) {
            return i;
        }
        let i = self.free_inodes.pop().unwrap_or_else(|| {
            let i = self.next_inode;
            self.next_inode += 1;
            i
        });
        self.inodes.insert(id, i);
        i
    }

    /// Give internal file `id`'s reported id back once nothing links to it or holds it open.
    fn maybe_release(&mut self, id: u64) {
        if !self.reuse_ids || self.handles.contains_key(&id) {
            return;
        }
        if self.tree.values().any(|n| *n == Node::File(id)) {
            return;
        }
        if let Some(i) = self.inodes.remove(&id) {
            self.free_inodes.push(i);
        }
    }
}

impl FaultFs {
    pub fn new(model: CrashModel) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                model,
                tree: BTreeMap::new(),
                durable_tree: BTreeMap::new(),
                pending_tree: Vec::new(),
                files: HashMap::new(),
                next_id: 1,
                op: 0,
                faults: Vec::new(),
                crashed: false,
                epoch: 0,
                capacity: None,
                used: 0,
                peak: 0,
                handles: HashMap::new(),
                granularity: 4096,
                dealloc_supported: true,
                reuse_ids: false,
                inodes: HashMap::new(),
                free_inodes: Vec::new(),
                next_inode: 1,
                flush_lies: false,
                hard_links: true,
            })),
        }
    }

    fn st(&self) -> MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Script a fault.
    pub fn inject(&self, f: Fault) {
        self.st().faults.push(f);
    }

    pub fn clear_faults(&self) {
        self.st().faults.clear();
    }

    /// Number of mutating operations performed so far.
    pub fn op_count(&self) -> u64 {
        self.st().op
    }

    pub fn is_crashed(&self) -> bool {
        self.st().crashed
    }

    /// Limit total allocated bytes; operations that would exceed it fail with `NoSpace`.
    pub fn set_capacity(&self, bytes: Option<u64>) {
        self.st().capacity = bytes;
    }

    /// Unit in which deallocation frees space (default 4096).
    pub fn set_granularity(&self, g: u64) {
        self.st().granularity = g.max(1);
    }

    /// Simulate a drive that acknowledges `flush_data` without persisting the data (what
    /// `--verify-media` exists to catch).
    pub fn set_flush_lies(&self, yes: bool) {
        self.st().flush_lies = yes;
    }

    /// Make `deallocate` report `Unsupported` (as on FAT/exFAT).
    pub fn set_dealloc_supported(&self, yes: bool) {
        self.st().dealloc_supported = yes;
    }

    /// Make `hard_link` report `Unsupported` (as on FAT/exFAT).
    pub fn set_hard_links_supported(&self, yes: bool) {
        self.st().hard_links = yes;
    }

    /// Reuse file ids like Linux reuses inode numbers: once a file is unlinked and its last
    /// handle closed, the next file to ask for an id may get the same one.
    pub fn set_reuse_ids(&self, yes: bool) {
        self.st().reuse_ids = yes;
    }

    /// Bytes currently allocated by all files.
    pub fn used(&self) -> u64 {
        self.st().used
    }

    /// Highest `used` value seen since creation or the last [`reset_peak`](Self::reset_peak).
    pub fn peak(&self) -> u64 {
        self.st().peak
    }

    pub fn reset_peak(&self) {
        let mut s = self.st();
        s.peak = s.used;
    }

    /// Reboot after a crash (or at any time): keep what the crash model says survives, discard
    /// the rest, invalidate every open handle, and resume normal operation.
    pub fn recover(&self) {
        let mut s = self.st();
        let model = s.model;
        let mut rng = match model {
            CrashModel::RandomSubset { seed } => Some(Rng::new(seed ^ s.op)),
            _ => None,
        };
        let keep = |rng: &mut Option<Rng>| match (model, rng) {
            (CrashModel::WriteThrough, _) => true,
            (CrashModel::LoseUnflushed, _) => false,
            (_, Some(r)) => r.below(2) == 0,
            (_, None) => false,
        };

        let mut tree = s.durable_tree.clone();
        for op in std::mem::take(&mut s.pending_tree) {
            if keep(&mut rng) {
                apply_tree(&mut tree, &op.change);
            }
        }
        prune_orphans(&mut tree);
        for f in s.files.values_mut() {
            let mut c = f.durable.clone();
            for op in std::mem::take(&mut f.pending) {
                if keep(&mut rng) {
                    c.apply(&op);
                }
            }
            f.cur = c.clone();
            f.durable = c;
        }
        s.durable_tree = tree.clone();
        s.tree = tree;
        let live = State::live_ids(&s.tree);
        s.files.retain(|id, _| live.contains(id));
        s.recompute_used();
        s.crashed = false;
        s.epoch += 1;
        s.handles.clear();
    }

    /// Setup helper: create `path` (and parents) with `data`, already durable. Not counted as
    /// an operation and not subject to faults.
    pub fn put_file(&self, path: &Path, data: &[u8]) {
        let mut s = self.st();
        let k = key(path).expect("valid path");
        let mut p = String::new();
        for comp in parent(&k).split('/').filter(|c| !c.is_empty()) {
            if !p.is_empty() {
                p.push('/');
            }
            p.push_str(comp);
            s.tree.insert(p.clone(), Node::Dir);
            s.durable_tree.insert(p.clone(), Node::Dir);
        }
        let id = s.next_id;
        s.next_id += 1;
        let c = Content {
            data: data.to_vec(),
            holes: vec![],
            sparse: false,
        };
        s.files.insert(
            id,
            FileData {
                cur: c.clone(),
                durable: c,
                pending: vec![],
            },
        );
        s.tree.insert(k.clone(), Node::File(id));
        s.durable_tree.insert(k, Node::File(id));
        s.recompute_used();
        s.peak = s.peak.max(s.used);
    }

    /// Current contents of a file, if it exists.
    pub fn get_file(&self, path: &Path) -> Option<Vec<u8>> {
        let s = self.st();
        match s.node(&key(path).ok()?)? {
            Node::File(id) => s.files.get(&id).map(|f| f.cur.data.clone()),
            Node::Dir => None,
        }
    }

    /// Every path with file contents (`None` for directories), current view.
    pub fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        let s = self.st();
        s.tree
            .iter()
            .map(|(k, n)| {
                let v = match n {
                    Node::Dir => None,
                    Node::File(id) => s.files.get(id).map(|f| f.cur.data.clone()),
                };
                (k.clone(), v)
            })
            .collect()
    }
}

impl FsBackend for FaultFs {
    fn open(&self, path: &Path, mode: OpenMode, share: Share) -> Result<Box<dyn FileHandle>> {
        let k = key(path)?;
        let mut s = self.st();
        s.alive()?;
        if s.node(parent(&k)) != Some(Node::Dir) {
            return Err(not_found(path));
        }
        let exclusive = share == Share::Exclusive;
        // Sharing is checked before anything is modified (CreateOrTruncate must not truncate a
        // file someone else holds exclusively). Exclusive handles admit readers only.
        if let Some(Node::File(id)) = s.node(&k) {
            if let Some(&(_, writers, exclusives)) = s.handles.get(&id) {
                if (exclusives > 0 && mode.writes()) || (exclusive && writers > 0) {
                    return Err(FsError::Busy {
                        path: path.to_path_buf(),
                    });
                }
            }
        }
        let id = match (s.node(&k), mode) {
            (Some(Node::Dir), _) => return Err(other("opening", path, "not a regular file")),
            (Some(Node::File(_)), OpenMode::CreateNew) => {
                return Err(FsError::AlreadyExists {
                    path: path.to_path_buf(),
                });
            }
            (Some(Node::File(id)), OpenMode::CreateOrTruncate) => {
                s.begin(Kind::Resize, path)?;
                s.data_op(id, path, DataOp::SetLen(0))?;
                id
            }
            (Some(Node::File(id)), _) => id,
            (None, OpenMode::Read | OpenMode::ReadWrite) => return Err(not_found(path)),
            (None, _) => {
                s.begin(Kind::Other, path)?;
                let id = s.next_id;
                s.next_id += 1;
                let fd = FileData {
                    cur: Content::default(),
                    durable: Content::default(),
                    pending: vec![],
                };
                s.files.insert(id, fd);
                s.tree_change(TreeChange::Insert(k.clone(), Node::File(id)));
                id
            }
        };
        let entry = s.handles.entry(id).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += usize::from(mode.writes());
        entry.2 += usize::from(exclusive);
        let epoch = s.epoch;
        Ok(Box::new(MemHandle {
            fs: self.clone(),
            id,
            path: path.to_path_buf(),
            writable: mode.writes(),
            exclusive,
            epoch,
        }))
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        let k = key(path)?;
        let mut s = self.st();
        s.alive()?;
        if s.node(&k).is_some() {
            return Err(FsError::AlreadyExists {
                path: path.to_path_buf(),
            });
        }
        if s.node(parent(&k)) != Some(Node::Dir) {
            return Err(not_found(path));
        }
        s.begin(Kind::Other, path)?;
        s.tree_change(TreeChange::Insert(k, Node::Dir));
        Ok(())
    }

    fn flush_dir(&self, dir: &Path) -> Result<()> {
        let k = key(dir)?;
        let mut s = self.st();
        s.alive()?;
        if s.node(&k) != Some(Node::Dir) {
            return Err(not_found(dir));
        }
        s.begin(Kind::Other, dir)?;
        let mut still = Vec::new();
        for mut op in std::mem::take(&mut s.pending_tree) {
            op.waiting.remove(&k);
            if op.waiting.is_empty() {
                apply_tree(&mut s.durable_tree, &op.change);
            } else {
                still.push(op);
            }
        }
        s.pending_tree = still;
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let (a, b) = (key(from)?, key(to)?);
        let mut s = self.st();
        s.alive()?;
        if s.node(&a).is_none() {
            return Err(not_found(from));
        }
        if s.node(&b).is_some() {
            return Err(FsError::AlreadyExists {
                path: to.to_path_buf(),
            });
        }
        if s.node(parent(&b)) != Some(Node::Dir) {
            return Err(not_found(to));
        }
        if b.starts_with(&format!("{a}/")) {
            return Err(other(
                "renaming",
                from,
                "cannot move a directory into itself",
            ));
        }
        s.begin(Kind::Other, from)?;
        s.tree_change(TreeChange::Rename(a, b));
        Ok(())
    }

    fn hard_link(&self, src: &Path, dst: &Path) -> Result<()> {
        let (a, b) = (key(src)?, key(dst)?);
        let mut s = self.st();
        s.alive()?;
        let id = match s.node(&a) {
            Some(Node::File(id)) => id,
            Some(Node::Dir) => return Err(other("linking", src, "is a directory")),
            None => return Err(not_found(src)),
        };
        if s.node(&b).is_some() {
            return Err(FsError::AlreadyExists {
                path: dst.to_path_buf(),
            });
        }
        if s.node(parent(&b)) != Some(Node::Dir) {
            return Err(not_found(dst));
        }
        if !s.hard_links {
            return Err(FsError::Unsupported {
                op: "hard link",
                path: dst.to_path_buf(),
            });
        }
        s.begin(Kind::Other, dst)?;
        s.tree_change(TreeChange::Insert(b, Node::File(id)));
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        let k = key(path)?;
        let mut s = self.st();
        s.alive()?;
        let id = match s.node(&k) {
            Some(Node::File(id)) => id,
            Some(Node::Dir) => return Err(other("removing", path, "is a directory")),
            None => return Err(not_found(path)),
        };
        s.begin(Kind::Other, path)?;
        s.tree_change(TreeChange::Remove(k));
        s.recompute_used();
        s.maybe_release(id);
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        let k = key(path)?;
        let mut s = self.st();
        s.alive()?;
        if s.node(&k) != Some(Node::Dir) || k.is_empty() {
            return Err(not_found(path));
        }
        let prefix = format!("{k}/");
        if s.tree.keys().any(|c| c.starts_with(&prefix)) {
            return Err(other("removing directory", path, "directory not empty"));
        }
        s.begin(Kind::Other, path)?;
        s.tree_change(TreeChange::Remove(k));
        Ok(())
    }

    fn metadata(&self, path: &Path) -> Result<Option<Meta>> {
        let k = key(path)?;
        let s = self.st();
        s.alive()?;
        Ok(match s.node(&k) {
            None => None,
            Some(Node::Dir) => Some(Meta {
                kind: NodeKind::Dir,
                len: 0,
            }),
            Some(Node::File(id)) => Some(Meta {
                kind: NodeKind::File,
                len: s.files.get(&id).map_or(0, |f| f.cur.data.len() as u64),
            }),
        })
    }

    fn read_dir(&self, path: &Path) -> Result<Vec<String>> {
        let k = key(path)?;
        let s = self.st();
        s.alive()?;
        if s.node(&k) != Some(Node::Dir) {
            return Err(not_found(path));
        }
        Ok(s.tree
            .keys()
            .filter(|c| !c.is_empty() && parent(c) == k)
            .map(|c| c.rsplit('/').next().unwrap_or(c).to_owned())
            .collect())
    }

    fn set_mode(&self, path: &Path, _mode: u32) -> Result<()> {
        let k = key(path)?;
        let mut s = self.st();
        s.alive()?;
        if s.node(&k).is_none() {
            return Err(not_found(path));
        }
        s.begin(Kind::Other, path)?;
        Ok(())
    }

    fn probe_volume(&self, _path: &Path) -> Result<VolumeInfo> {
        let s = self.st();
        s.alive()?;
        Ok(VolumeInfo {
            fs: FsKind::Memory,
            fs_name: "faultfs".into(),
            root: Some(PathBuf::from("/")),
            volume_id: Some(0xFA17),
            cluster_size: 4096,
            free_bytes: s.capacity.map(|c| c.saturating_sub(s.used)),
            total_bytes: s.capacity,
            supports_sparse: s.dealloc_supported,
            sparse_granularity: if s.dealloc_supported {
                u32::try_from(s.granularity).unwrap_or(u32::MAX)
            } else {
                0
            },
            max_file_size: u64::MAX,
            sync: SyncHint::None,
            snapshots: SnapshotHint::None,
        })
    }
}

#[derive(Debug)]
struct MemHandle {
    fs: FaultFs,
    id: u64,
    path: PathBuf,
    writable: bool,
    exclusive: bool,
    epoch: u64,
}

impl MemHandle {
    fn st(&self) -> Result<MutexGuard<'_, State>> {
        let s = self.fs.st();
        s.alive()?;
        if s.epoch != self.epoch {
            return Err(FsError::Crashed);
        }
        if !s.files.contains_key(&self.id) {
            return Err(not_found(&self.path));
        }
        Ok(s)
    }

    fn writable(&self) -> Result<()> {
        if self.writable {
            Ok(())
        } else {
            Err(other("writing", &self.path, "opened read-only"))
        }
    }
}

impl Drop for MemHandle {
    fn drop(&mut self) {
        let mut s = self.fs.st();
        if s.epoch != self.epoch {
            return;
        }
        if let Some(e) = s.handles.get_mut(&self.id) {
            e.0 = e.0.saturating_sub(1);
            if self.writable {
                e.1 = e.1.saturating_sub(1);
            }
            if self.exclusive {
                e.2 = e.2.saturating_sub(1);
            }
            if e.0 == 0 {
                s.handles.remove(&self.id);
                s.maybe_release(self.id);
            }
        }
    }
}

impl FileHandle for MemHandle {
    fn path(&self) -> &Path {
        &self.path
    }

    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> Result<()> {
        let s = self.st()?;
        let data = &s.files[&self.id].cur.data;
        let end = off as usize + buf.len();
        if end > data.len() {
            return Err(FsError::from_io(
                "reading",
                &self.path,
                std::io::ErrorKind::UnexpectedEof.into(),
            ));
        }
        buf.copy_from_slice(&data[off as usize..end]);
        Ok(())
    }

    /// What is durable on the "device": the bytes a crash right now would leave.
    fn read_back(&self, buf: &mut [u8], off: u64) -> Result<()> {
        let s = self.st()?;
        let data = &s.files[&self.id].durable.data;
        let end = off as usize + buf.len();
        if end > data.len() {
            return Err(FsError::from_io(
                "verifying",
                &self.path,
                std::io::ErrorKind::UnexpectedEof.into(),
            ));
        }
        buf.copy_from_slice(&data[off as usize..end]);
        Ok(())
    }

    fn write_all_at(&self, buf: &[u8], off: u64) -> Result<()> {
        self.writable()?;
        let mut s = self.st()?;
        match s.begin(Kind::Write, &self.path)? {
            None => s.data_op(
                self.id,
                &self.path,
                DataOp::Write {
                    off,
                    bytes: buf.to_vec(),
                },
            ),
            Some(keep) => {
                let part = buf[..keep.min(buf.len())].to_vec();
                s.data_op(self.id, &self.path, DataOp::Write { off, bytes: part })?;
                s.crashed = true;
                Err(FsError::Crashed)
            }
        }
    }

    fn size(&self) -> Result<u64> {
        Ok(self.st()?.files[&self.id].cur.data.len() as u64)
    }

    fn set_len(&self, len: u64) -> Result<()> {
        self.writable()?;
        let mut s = self.st()?;
        s.begin(Kind::Resize, &self.path)?;
        s.data_op(self.id, &self.path, DataOp::SetLen(len))
    }

    fn preallocate(&self, len: u64) -> Result<()> {
        self.writable()?;
        let mut s = self.st()?;
        s.begin(Kind::Other, &self.path)?;
        if len > s.files[&self.id].cur.data.len() as u64 {
            s.data_op(self.id, &self.path, DataOp::Reserve(len))?;
        }
        Ok(())
    }

    fn flush_data(&self) -> Result<()> {
        let mut s = self.st()?;
        s.begin(Kind::Other, &self.path)?;
        if s.flush_lies {
            return Ok(());
        }
        let f = s.files.get_mut(&self.id).expect("checked in st()");
        f.durable = f.cur.clone();
        f.pending.clear();
        Ok(())
    }

    fn deallocate(&self, start: u64, end: u64) -> Result<Dealloc> {
        self.writable()?;
        let mut s = self.st()?;
        if !s.dealloc_supported {
            return Ok(Dealloc::Unsupported);
        }
        s.begin(Kind::Other, &self.path)?;
        let g = s.granularity;
        s.data_op(
            self.id,
            &self.path,
            DataOp::Dealloc {
                range: start..end,
                granularity: g,
            },
        )?;
        let len = s.files[&self.id].cur.data.len() as u64;
        let end = end.min(len);
        let (hs, he) = (start.div_ceil(g) * g, (end / g) * g);
        Ok(Dealloc::Freed {
            freed: if hs < he { hs..he } else { start..start },
        })
    }

    fn allocated_ranges(&self) -> Result<Vec<Range<u64>>> {
        let s = self.st()?;
        let c = &s.files[&self.id].cur;
        let mut out = Vec::new();
        let mut cursor = 0u64;
        for h in &c.holes {
            if h.start > cursor {
                out.push(cursor..h.start);
            }
            cursor = h.end;
        }
        let len = c.data.len() as u64;
        if len > cursor {
            out.push(cursor..len);
        }
        Ok(out)
    }

    fn file_id(&self) -> Result<FileId> {
        let mut s = self.st()?;
        Ok(FileId {
            volume: 0xFA17,
            file: u128::from(s.inode(self.id)),
        })
    }

    fn set_modified(&self, _t: SystemTime) -> Result<()> {
        let mut s = self.st()?;
        s.begin(Kind::Other, &self.path)?;
        Ok(())
    }
}

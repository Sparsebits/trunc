//! Non-destructive extraction and verification.
//!
//! Both walk the blocks in logical order, decoding a round of blocks in parallel and then
//! applying them in order. Each entry's BLAKE3 is recomputed from the decoded stream and checked
//! when its last byte arrives, on top of the per-block hash checks in [`Archive::decode_block`].

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use trunc_core::{BlockRecord, EntryKind, Manifest};

use crate::archive::Archive;
use crate::error::{Error, IoContext, Result, at};
use crate::io::{len_usize, write_all_at};
use crate::walk::system_time;

#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    /// Refuse unsigned archives.
    pub require_signed: bool,
    /// If non-empty, the signer must be one of these keys.
    pub trusted_keys: Vec<[u8; 32]>,
}

impl TrustPolicy {
    pub fn check(&self, archive: &Archive) -> Result<()> {
        match archive.signer() {
            None if self.require_signed || !self.trusted_keys.is_empty() => {
                Err(Error::Refused("archive is not signed".into()))
            }
            Some(k) if !self.trusted_keys.is_empty() && !self.trusted_keys.contains(&k) => {
                Err(Error::Refused(format!(
                    "archive is signed by untrusted key {}",
                    hex::encode(k)
                )))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Replace existing regular files at destination paths.
    pub overwrite: bool,
    /// Create symlink entries (only those resolving inside the destination).
    pub allow_symlinks: bool,
    pub trust: TrustPolicy,
    /// Decode threads; 0 = all cores.
    pub threads: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractSummary {
    pub files: usize,
    pub dirs: usize,
    pub symlinks_created: usize,
    pub symlinks_skipped: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifySummary {
    pub blocks: usize,
    pub entries: usize,
    pub bytes: u64,
}

/// Most decoded bytes one round holds (a round always takes at least two blocks). Blocks may
/// declare up to 1 GiB each, so without this a small archive of zero-filled blocks could make
/// `2 × threads` such blocks live at once.
const ROUND_MAX_U: u64 = 512 << 20;

/// End of the round of blocks starting at `start`: at most `per_round` blocks and
/// [`ROUND_MAX_U`] decoded bytes, but always at least two blocks (when that many remain).
fn round_end(blocks: &[BlockRecord], start: usize, per_round: usize) -> usize {
    let mut end = start;
    let mut bytes = 0u64;
    while end < blocks.len() && end - start < per_round {
        let u = blocks[end].u_len;
        if end - start >= 2 && bytes.saturating_add(u) > ROUND_MAX_U {
            break;
        }
        bytes = bytes.saturating_add(u);
        end += 1;
    }
    end
}

/// Decode every remaining block in logical order and hand each decoded buffer to `apply`.
fn for_each_block(
    archive: &Archive,
    threads: usize,
    mut apply: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| Error::Input(format!("cannot start worker threads: {e}")))?;
    let per_round = pool.current_num_threads().max(1) * 2;
    let n = archive.manifest().blocks.len();
    let mut i = archive.consumed();
    while i < n {
        let end = round_end(&archive.manifest().blocks, i, per_round);
        let decoded: Vec<Result<Vec<u8>>> = trunc_prof::time("extract.decode", || {
            pool.install(|| {
                (i..end)
                    .into_par_iter()
                    .map(|b| archive.decode_block(b))
                    .collect()
            })
        });
        for (k, buf) in decoded.into_iter().enumerate() {
            let buf = buf?;
            let _apply = trunc_prof::span("extract.apply").bytes(buf.len() as u64);
            apply(i + k, &buf)?;
        }
        i = end;
    }
    Ok(())
}

/// Tracks per-entry hashing as decoded runs arrive in stream order.
struct EntryHashes<'m> {
    m: &'m Manifest,
    remaining: Vec<u64>,
    hashers: HashMap<usize, trunc_hash::Blake3Hasher>,
}

impl<'m> EntryHashes<'m> {
    fn new(m: &'m Manifest) -> Self {
        Self {
            m,
            remaining: m.entries.iter().map(|e| e.size).collect(),
            hashers: HashMap::new(),
        }
    }

    /// Feed a run; returns true when the entry is complete (and verified).
    fn feed(&mut self, entry: usize, data: &[u8]) -> Result<bool> {
        let hasher = self.hashers.entry(entry).or_default();
        trunc_prof::time("hash.blake3", || {
            hasher.update(data);
        });
        self.remaining[entry] -= data.len() as u64;
        if self.remaining[entry] > 0 {
            return Ok(false);
        }
        let h = self.hashers.remove(&entry).expect("hasher inserted above");
        if *h.finalize().as_bytes() != self.m.entries[entry].blake3 {
            return Err(Error::Integrity(format!(
                "content hash mismatch for {:?}",
                self.m.entries[entry].path
            )));
        }
        Ok(true)
    }
}

/// Verify every block and every entry hash without writing anything.
pub fn verify(archive: &Archive, trust: &TrustPolicy, threads: usize) -> Result<VerifySummary> {
    trust.check(archive)?;
    require_complete(archive)?;
    let m = archive.manifest();
    let mut hashes = EntryHashes::new(m);
    let mut summary = VerifySummary::default();
    for_each_block(archive, threads, |i, buf| {
        let b = &m.blocks[i];
        for r in archive.stream().runs(b.stream_off, b.u_len) {
            let s = len_usize(r.buf_off);
            hashes.feed(r.entry, &buf[s..s + len_usize(r.len)])?;
        }
        summary.blocks += 1;
        summary.bytes += b.u_len;
        Ok(())
    })?;
    let empty = trunc_hash::blake3(b"");
    for e in m.entries.iter().filter(|e| e.size == 0) {
        if e.blake3 != empty {
            return Err(Error::Integrity(format!(
                "content hash mismatch for {:?}",
                e.path
            )));
        }
    }
    summary.entries = m.entries.len();
    Ok(summary)
}

fn require_complete(archive: &Archive) -> Result<()> {
    if archive.is_complete() {
        Ok(())
    } else {
        Err(Error::Refused(format!(
            "archive is partially consumed ({} of {} blocks); resume the consume instead",
            archive.consumed(),
            archive.manifest().blocks.len()
        )))
    }
}

/// Join a validated manifest path onto `dest`.
fn dest_path(dest: &Path, rel: &str) -> PathBuf {
    let mut p = dest.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    p
}

/// Extract everything into `dest` without modifying the archive.
pub fn extract(archive: &Archive, dest: &Path, opts: &ExtractOptions) -> Result<ExtractSummary> {
    opts.trust.check(archive)?;
    require_complete(archive)?;
    let m = archive.manifest();
    let mut summary = ExtractSummary::default();

    fs::create_dir_all(dest).ctx(at("creating", dest))?;
    for d in m.all_dirs() {
        let p = dest_path(dest, &d);
        match fs::symlink_metadata(&p) {
            Ok(md) if md.file_type().is_dir() => {}
            Ok(_) => {
                return Err(Error::Refused(format!(
                    "{} exists and is not a directory (or is a link)",
                    p.display()
                )));
            }
            Err(_) => fs::create_dir(&p).ctx(at("creating", &p))?,
        }
        summary.dirs += 1;
    }

    // Create every file up front so empty files exist and conflicts surface before any data
    // is written.
    let create = trunc_prof::span("extract.create_files");
    let mut open: HashMap<usize, File> = HashMap::new();
    // Finished files, closed in batches.
    let mut finished: Vec<File> = Vec::new();
    // Every output is known up front, so create them on several threads: creating a file
    // costs a fraction of a millisecond on Windows, mostly waiting.
    let files: Vec<usize> = (0..m.entries.len())
        .filter(|&i| matches!(m.entries[i].kind, EntryKind::File))
        .collect();
    let created: Vec<Result<(usize, File)>> = files
        .par_iter()
        .map(|&i| {
            let e = &m.entries[i];
            let p = dest_path(dest, &e.path);
            let f = trunc_prof::time("extract.create", || create_output(&p, opts.overwrite))?;
            if e.size > 0 {
                f.set_len(e.size).ctx(at("allocating", &p))?;
            } else {
                if e.blake3 != trunc_hash::blake3(b"") {
                    return Err(Error::Integrity(format!(
                        "content hash mismatch for {:?}",
                        e.path
                    )));
                }
                finish_file(&f, &p, e)?;
            }
            Ok((i, f))
        })
        .collect();
    for r in created {
        let (i, f) = r?;
        if m.entries[i].size > 0 {
            open.insert(i, f);
        } else {
            finished.push(f);
        }
        summary.files += 1;
    }

    drop(create);
    let mut hashes = EntryHashes::new(m);
    for_each_block(archive, opts.threads, |i, buf| {
        let b = &m.blocks[i];
        for r in archive.stream().runs(b.stream_off, b.u_len) {
            let s = len_usize(r.buf_off);
            let data = &buf[s..s + len_usize(r.len)];
            let e = &m.entries[r.entry];
            let f = open
                .get(&r.entry)
                .expect("non-empty files are opened up front");
            let p = dest_path(dest, &e.path);
            trunc_prof::time("extract.write", || write_all_at(f, data, r.entry_off))
                .ctx(at("writing", &p))?;
            if hashes.feed(r.entry, data)? {
                let f = open.remove(&r.entry).expect("present");
                trunc_prof::time("extract.finish", || finish_file(&f, &p, e))?;
                finished.push(f);
                if finished.len() >= 256 {
                    trunc_fs::close_all(std::mem::take(&mut finished));
                }
            }
        }
        summary.bytes += b.u_len;
        Ok(())
    })?;
    trunc_fs::close_all(finished);
    debug_assert!(open.is_empty(), "every file received all its bytes");

    let links: std::collections::HashSet<String> = m
        .entries
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::Symlink { .. }))
        .map(|e| trunc_core::path::collision_key(&e.path))
        .collect();
    let is_link = |p: &str| links.contains(&trunc_core::path::collision_key(p));
    for e in &m.entries {
        if let EntryKind::Symlink { target } = &e.kind {
            if opts.allow_symlinks && symlink_stays_inside(&e.path, target, &is_link) {
                create_symlink(m, dest, &e.path, target)?;
                summary.symlinks_created += 1;
            } else {
                summary.symlinks_skipped += 1;
            }
        }
    }
    Ok(summary)
}

fn create_output(p: &Path, overwrite: bool) -> Result<File> {
    if !overwrite {
        // Creating with "must not exist" refuses an existing file or link by itself.
        return match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(p)
        {
            Ok(f) => Ok(f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::Refused(format!("{} already exists", p.display())))
            }
            Err(e) => Err(e).ctx(at("creating", p)),
        };
    }
    let not_regular = || {
        Error::Refused(format!(
            "{} exists and is not a regular file; not overwriting",
            p.display()
        ))
    };
    if let Ok(md) = fs::symlink_metadata(p) {
        if !md.file_type().is_file() {
            return Err(not_regular());
        }
        if md.permissions().readonly() {
            make_writable(p, &md)?;
        }
    }
    // Through the backend's open, which never follows a link as the final component (a link
    // swapped in since the check above is refused, not truncated through).
    match trunc_fs::OsFs::new().open_file(
        p,
        trunc_fs::OpenMode::CreateOrTruncate,
        trunc_fs::Share::Shared,
    ) {
        Ok(f) => Ok(f),
        Err(trunc_fs::FsError::Link { .. }) => Err(not_regular()),
        Err(e) => Err(e.into()),
    }
}

/// Clear the read-only state of an existing file to overwrite it, without following a link.
#[cfg(unix)]
fn make_writable(p: &Path, md: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use trunc_fs::FsBackend;
    let mode = md.permissions().mode() | 0o222;
    trunc_fs::OsFs::new().set_mode(p, mode)?;
    Ok(())
}

/// Clear the read-only attribute of an existing file to overwrite it, through a handle on the
/// file itself (never a link's target).
#[cfg(not(unix))]
fn make_writable(p: &Path, _md: &fs::Metadata) -> Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let f = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(p)
        .ctx(at("making writable", p))?;
    let md = f.metadata().ctx(at("reading metadata of", p))?;
    if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !md.is_file() {
        return Err(Error::Refused(format!(
            "{} exists and is not a regular file; not overwriting",
            p.display()
        )));
    }
    let mut perms = md.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    f.set_permissions(perms).ctx(at("making writable", p))
}

fn finish_file(f: &File, p: &Path, e: &trunc_core::Entry) -> Result<()> {
    f.set_modified(system_time(e.mtime_unix, e.mtime_nanos))
        .ctx(at("setting mtime of", p))?;
    apply_mode(f, p, e.mode)
}

/// Through the open handle: a path could lead somewhere else by now.
#[cfg(unix)]
fn apply_mode(f: &File, p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Never restore setuid/setgid/sticky bits from an archive.
    f.set_permissions(fs::Permissions::from_mode(mode & 0o777))
        .ctx(at("setting mode of", p))
}

#[cfg(not(unix))]
fn apply_mode(f: &File, p: &Path, mode: u32) -> Result<()> {
    if mode & 0o222 == 0 {
        let mut perms = f
            .metadata()
            .ctx(at("reading metadata of", p))?
            .permissions();
        perms.set_readonly(true);
        f.set_permissions(perms).ctx(at("setting read-only", p))?;
    }
    Ok(())
}

/// True if a relative link target, resolved lexically from the link's directory, stays inside
/// the extraction root. Resolution is lexical, so it must not pass *through* another symlink
/// entry (`s -> .` plus `x -> s/../escape` would otherwise leave the destination).
fn symlink_stays_inside(link_path: &str, target: &str, is_link: &dyn Fn(&str) -> bool) -> bool {
    if target.starts_with('/') || target.contains('\\') || target.contains(':') {
        return false;
    }
    let mut at: Vec<&str> = link_path.split('/').collect();
    at.pop();
    let comps: Vec<&str> = target
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    for (i, c) in comps.iter().enumerate() {
        if *c == ".." {
            if at.pop().is_none() {
                return false;
            }
        } else {
            at.push(c);
            if i + 1 < comps.len() && is_link(&at.join("/")) {
                return false;
            }
        }
    }
    true
}

#[cfg(unix)]
fn create_symlink(_m: &Manifest, dest: &Path, rel: &str, target: &str) -> Result<()> {
    let p = dest_path(dest, rel);
    std::os::unix::fs::symlink(target, &p).ctx(at("creating symlink", &p))
}

#[cfg(windows)]
fn create_symlink(m: &Manifest, dest: &Path, rel: &str, target: &str) -> Result<()> {
    let p = dest_path(dest, rel);
    // Resolve the target lexically to decide between a file and a directory link.
    let mut parts: Vec<&str> = rel.split('/').collect();
    parts.pop();
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let resolved = parts.join("/");
    let is_dir = m.all_dirs().iter().any(|d| d == &resolved);
    let native = target.replace('/', "\\");
    let r = if is_dir {
        std::os::windows::fs::symlink_dir(&native, &p)
    } else {
        std::os::windows::fs::symlink_file(&native, &p)
    };
    r.ctx(at(
        "creating symlink (needs Developer Mode or admin on Windows)",
        &p,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symlink_containment() {
        let inside = |l: &str, t: &str| symlink_stays_inside(l, t, &|_| false);
        assert!(inside("a/link", "b"));
        assert!(inside("a/link", "../b"));
        assert!(inside("a/b/link", "../../c"));
        assert!(!inside("link", "../escape"));
        assert!(!inside("a/link", "../../escape"));
        assert!(!inside("a/link", "/etc/passwd"));
        assert!(!inside("a/link", "C:/Windows"));
        assert!(!inside("a/link", "..\\..\\x"));
        assert!(inside("a/link", "./x/../y"));
        // Passing through another symlink entry is refused; ending at one is fine.
        let s_is_link = |p: &str| p == "s";
        assert!(!symlink_stays_inside("x", "s/../escape", &s_is_link));
        assert!(!symlink_stays_inside("x", "s/inner", &s_is_link));
        assert!(symlink_stays_inside("x", "s", &s_is_link));
    }

    #[test]
    fn rounds_cap_decoded_bytes() {
        let blocks = |u: u64, n: usize| {
            vec![
                BlockRecord {
                    stream_off: 0,
                    u_len: u,
                    c_len: 0,
                    codec: 0,
                    blake3_c: [0; 32],
                    blake3_u: [0; 32],
                };
                n
            ]
        };
        // Ordinary 8 MiB blocks: the thread count decides.
        let small = blocks(8 << 20, 100);
        assert_eq!(round_end(&small, 0, 32), 32);
        assert_eq!(round_end(&small, 90, 32), 100);
        // 1 GiB blocks: two at a time, not 2 x threads.
        let huge = blocks(1 << 30, 100);
        assert_eq!(round_end(&huge, 0, 32), 2);
        assert_eq!(round_end(&huge, 99, 32), 100);
        // 100 MiB blocks: as many as fit in the budget.
        let mid = blocks(100 << 20, 100);
        assert_eq!(round_end(&mid, 0, 32), 5);
    }
}

//! Walking producer inputs into manifest-ready items.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, IoContext, Result, at};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemKind {
    File,
    Dir,
    Symlink(String),
}

#[derive(Debug, Clone)]
pub(crate) struct Item {
    /// Archive path: relative, `/`-separated, NFC.
    pub rel: String,
    /// Where to read it from.
    pub abs: PathBuf,
    pub kind: ItemKind,
    pub size: u64,
    pub mode: u32,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
}

/// Walk every input. A directory input contributes itself and its contents (sorted by name);
/// a file input contributes itself. Symlinks are recorded, never followed.
pub(crate) fn walk_inputs(inputs: &[PathBuf]) -> Result<Vec<Item>> {
    let mut out = Vec::new();
    for input in inputs {
        let name = component_name(input)?;
        walk(input, name, &mut out)?;
    }
    Ok(out)
}

fn component_name(p: &Path) -> Result<String> {
    let name = p
        .file_name()
        .ok_or_else(|| Error::Input(format!("input {} has no file name", p.display())))?;
    let name = name
        .to_str()
        .ok_or_else(|| Error::Input(format!("{} is not valid UTF-8", p.display())))?;
    Ok(name.nfc().collect())
}

fn walk(abs: &Path, rel: String, out: &mut Vec<Item>) -> Result<()> {
    let md = fs::symlink_metadata(abs).ctx(at("reading metadata of", abs))?;
    let ft = md.file_type();
    let (mtime_unix, mtime_nanos) = mtime_of(&md);
    let mode = mode_of(&md);
    let kind = if ft.is_symlink() {
        let target = fs::read_link(abs).ctx(at("reading link", abs))?;
        let target = target
            .to_str()
            .ok_or_else(|| Error::Input(format!("link target of {} is not UTF-8", abs.display())))?
            .replace('\\', "/");
        ItemKind::Symlink(target)
    } else if ft.is_dir() {
        ItemKind::Dir
    } else if ft.is_file() {
        ItemKind::File
    } else {
        return Err(Error::Input(format!(
            "{}: unsupported file type",
            abs.display()
        )));
    };
    let size = if kind == ItemKind::File { md.len() } else { 0 };
    let is_dir = kind == ItemKind::Dir;
    out.push(Item {
        rel: rel.clone(),
        abs: abs.to_path_buf(),
        kind,
        size,
        mode,
        mtime_unix,
        mtime_nanos,
    });

    if is_dir {
        let mut children: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(abs).ctx(at("listing", abs))? {
            let entry = entry.ctx(at("listing", abs))?;
            let p = entry.path();
            children.push((component_name(&p)?, p));
        }
        children.sort();
        for (name, p) in children {
            walk(&p, format!("{rel}/{name}"), out)?;
        }
    }
    Ok(())
}

fn mtime_of(md: &fs::Metadata) -> (i64, u32) {
    match md.modified() {
        Ok(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                d.subsec_nanos(),
            ),
            Err(e) => {
                // Before 1970: represent as negative seconds with non-negative nanos.
                let d = e.duration();
                let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                if d.subsec_nanos() == 0 {
                    (-secs, 0)
                } else {
                    (-secs - 1, 1_000_000_000 - d.subsec_nanos())
                }
            }
        },
        Err(_) => (0, 0),
    }
}

/// Convert a stored mtime back to `SystemTime`.
pub(crate) fn system_time(secs: i64, nanos: u32) -> SystemTime {
    let base = if secs >= 0 {
        UNIX_EPOCH + std::time::Duration::from_secs(secs.unsigned_abs())
    } else {
        UNIX_EPOCH - std::time::Duration::from_secs(secs.unsigned_abs())
    };
    base + std::time::Duration::from_nanos(u64::from(nanos))
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(md: &fs::Metadata) -> u32 {
    let base = if md.is_dir() { 0o755 } else { 0o644 };
    if md.permissions().readonly() {
        base & !0o222
    } else {
        base
    }
}

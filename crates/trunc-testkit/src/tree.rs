//! Snapshot and compare directory trees.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Dir,
    File(Vec<u8>),
    Symlink(String),
}

/// Every path under `root` (relative, `/`-separated) mapped to its contents.
pub fn snapshot(root: &Path) -> BTreeMap<String, Node> {
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Node>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let p = entry.path();
        let ft = fs::symlink_metadata(&p).unwrap().file_type();
        if ft.is_symlink() {
            let t = fs::read_link(&p)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, Node::Symlink(t));
        } else if ft.is_dir() {
            out.insert(rel.clone(), Node::Dir);
            walk(&p, &rel, out);
        } else {
            out.insert(rel, Node::File(fs::read(&p).unwrap()));
        }
    }
}

/// Compare two trees; `Err` describes the first difference.
pub fn compare(a: &Path, b: &Path) -> Result<(), String> {
    let (sa, sb) = (snapshot(a), snapshot(b));
    for (k, va) in &sa {
        match sb.get(k) {
            None => return Err(format!("{k}: missing from {}", b.display())),
            Some(vb) if vb != va => {
                let desc = |n: &Node| match n {
                    Node::Dir => "directory".to_string(),
                    Node::File(d) => format!("file of {} bytes", d.len()),
                    Node::Symlink(t) => format!("symlink -> {t}"),
                };
                return Err(format!("{k}: {} vs {}", desc(va), desc(vb)));
            }
            _ => {}
        }
    }
    if let Some(k) = sb.keys().find(|k| !sa.contains_key(*k)) {
        return Err(format!("{k}: extra in {}", b.display()));
    }
    Ok(())
}

/// Panic with a useful message if the trees differ.
pub fn assert_same(a: &Path, b: &Path) {
    if let Err(e) = compare(a, b) {
        panic!("trees differ: {e}");
    }
}

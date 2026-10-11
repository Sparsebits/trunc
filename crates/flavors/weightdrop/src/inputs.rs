//! Turning command-line arguments (files, directories, globs) into file paths.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// `*` matches any run of characters, `?` one character. No `/` handling: patterns apply to
/// a single file name.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn has_glob(s: &str) -> bool {
    s.contains(['*', '?'])
}

fn list_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let rd = std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            out.push(entry.path());
        }
    }
    out.sort();
    Ok(out)
}

/// The files named by `inputs`, keyed by file name. Paths that do not exist are kept (a shard
/// consumed by an earlier run is gone); callers decide whether that is an error.
pub fn resolve(inputs: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut found: Vec<PathBuf> = Vec::new();
    for input in inputs {
        let path = PathBuf::from(input);
        let file_part = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if has_glob(&file_part) {
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            if has_glob(&dir.to_string_lossy()) {
                bail!("{input}: wildcards are supported in the file name only");
            }
            let before = found.len();
            for f in list_files(&dir)? {
                if f.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| glob_match(&file_part, n))
                {
                    found.push(f);
                }
            }
            if found.len() == before {
                bail!("{input}: no files match");
            }
        } else if path.is_dir() {
            found.extend(list_files(&path)?);
        } else {
            found.push(path);
        }
    }
    let mut by_name: BTreeMap<String, PathBuf> = BTreeMap::new();
    for f in found {
        let Some(name) = f.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            bail!("{}: file name is not valid UTF-8", f.display());
        };
        if let Some(prev) = by_name.get(&name).filter(|prev| *prev != &f) {
            bail!(
                "{name} is named twice ({} and {}); shards must have distinct names",
                prev.display(),
                f.display()
            );
        }
        by_name.insert(name, f);
    }
    Ok(by_name)
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn globs() {
        assert!(glob_match("*.tar.zst", "a-000.tar.zst"));
        assert!(!glob_match("*.tar.zst", "a-000.tar.zst.trncj"));
        assert!(glob_match(
            "train-*-of-00042.tar",
            "train-00001-of-00042.tar"
        ));
        assert!(glob_match("s-00000?.tgz", "s-000003.tgz"));
        assert!(!glob_match("s-00000?.tgz", "s-0000033.tgz"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }
}

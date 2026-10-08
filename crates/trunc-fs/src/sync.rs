//! Heuristic detection of cloud-sync clients managing a path.
//!
//! False negatives are possible (unknown clients, custom locations); the CLI says so. False
//! positives only cost a refusal that `--allow-sync` (phase 3) overrides.

use std::path::{Path, PathBuf};

use crate::SyncHint;

/// Which sync client, if any, appears to manage `path` (an existing path).
pub fn detect_sync(path: &Path) -> SyncHint {
    let p = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    for (root, hint) in known_roots() {
        if starts_with_ci(&p, &root) {
            return hint;
        }
    }
    if has_cloud_attributes(&p) {
        return SyncHint::CloudFiles;
    }
    if p.components()
        .any(|c| matches!(c.as_os_str().to_str(), Some("My Drive" | "Shared drives")))
    {
        return SyncHint::GoogleDrive;
    }
    SyncHint::None
}

/// Case-insensitive, component-wise prefix test that ignores `\\?\` verbatim prefixes.
fn starts_with_ci(path: &Path, root: &Path) -> bool {
    let norm = |p: &Path| -> Vec<String> {
        p.components()
            .filter_map(|c| match c {
                std::path::Component::Prefix(pre) => {
                    let s = pre.as_os_str().to_string_lossy().to_lowercase();
                    Some(s.trim_start_matches(r"\\?\").to_owned())
                }
                std::path::Component::RootDir => None,
                other => Some(other.as_os_str().to_string_lossy().to_lowercase()),
            })
            .collect()
    };
    let (p, r) = (norm(path), norm(root));
    !r.is_empty() && p.len() >= r.len() && p[..r.len()] == r[..]
}

fn known_roots() -> Vec<(PathBuf, SyncHint)> {
    let mut roots = Vec::new();
    for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
        if let Some(v) = std::env::var_os(var) {
            roots.push((PathBuf::from(v), SyncHint::OneDrive));
        }
    }
    for base in ["LOCALAPPDATA", "APPDATA"] {
        if let Some(b) = std::env::var_os(base) {
            let info = PathBuf::from(b).join("Dropbox").join("info.json");
            if let Ok(text) = std::fs::read_to_string(info) {
                roots.extend(
                    json_paths(&text)
                        .into_iter()
                        .map(|p| (p, SyncHint::Dropbox)),
                );
            }
        }
    }
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));
    if let Some(h) = home {
        let h = PathBuf::from(h);
        roots.push((h.join("iCloudDrive"), SyncHint::ICloud));
        roots.push((h.join("Dropbox"), SyncHint::Dropbox));
        roots.push((h.join("Google Drive"), SyncHint::GoogleDrive));
        roots.push((h.join("Library/Mobile Documents"), SyncHint::ICloud));
    }
    roots
}

/// Extract `"path": "..."` values from Dropbox's info.json without a JSON dependency.
fn json_paths(text: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("\"path\"") {
        rest = &rest[i + 6..];
        let Some(q1) = rest.find('"') else { break };
        let after = &rest[q1 + 1..];
        let mut value = String::new();
        let mut chars = after.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        value.push(n);
                    }
                }
                '"' => break,
                other => value.push(other),
            }
        }
        if !value.is_empty() {
            out.push(PathBuf::from(value));
        }
        rest = after;
    }
    out
}

#[cfg(windows)]
fn has_cloud_attributes(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    path.ancestors().any(|a| {
        std::fs::symlink_metadata(a)
            .map(|m| m.file_attributes() & crate::win::CLOUD_ATTRIBUTES != 0)
            .unwrap_or(false)
    })
}

#[cfg(not(windows))]
fn has_cloud_attributes(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropbox_info_json() {
        let text = r#"{"personal": {"path": "C:\\Users\\a\\Dropbox", "host": 1},
                      "business": {"path": "D:\\Work Dropbox"}}"#;
        assert_eq!(
            json_paths(text),
            vec![
                PathBuf::from(r"C:\Users\a\Dropbox"),
                PathBuf::from(r"D:\Work Dropbox")
            ]
        );
    }

    #[test]
    fn prefix_is_component_wise_and_case_insensitive() {
        assert!(starts_with_ci(
            Path::new("/home/A/OneDrive/x"),
            Path::new("/home/a/onedrive")
        ));
        assert!(!starts_with_ci(
            Path::new("/home/a/OneDriveX/x"),
            Path::new("/home/a/OneDrive")
        ));
        assert!(!starts_with_ci(Path::new("/x"), Path::new("")));
    }

    #[test]
    fn temp_dir_is_not_synced() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(detect_sync(d.path()), SyncHint::None);
    }
}

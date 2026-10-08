//! Entry path rules.
//!
//! Paths in a `.trnc` manifest are relative, `/`-separated, NFC-normalized UTF-8. The rules are
//! deliberately the intersection of what Windows, macOS and Linux accept, so an archive created
//! anywhere extracts the same everywhere, and so no entry can name something outside the
//! destination directory.

use crate::FormatError;
use unicode_normalization::is_nfc;

/// Maximum bytes in a whole path.
pub const MAX_PATH_BYTES: usize = 4096;
/// Maximum bytes in one component.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Maximum number of components.
pub const MAX_DEPTH: usize = 256;

const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

fn err(path: &str, reason: &'static str) -> FormatError {
    FormatError::Path {
        path: path.to_owned(),
        reason,
    }
}

/// Validate one entry path. Returns `Ok(())` if it is safe and portable.
pub fn validate(path: &str) -> Result<(), FormatError> {
    if path.is_empty() {
        return Err(err(path, "empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(err(path, "too long"));
    }
    if !is_nfc(path) {
        return Err(err(path, "not NFC-normalized"));
    }
    let mut depth = 0usize;
    for comp in path.split('/') {
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(err(path, "too deep"));
        }
        validate_component(path, comp)?;
    }
    Ok(())
}

fn validate_component(path: &str, comp: &str) -> Result<(), FormatError> {
    if comp.is_empty() {
        return Err(err(
            path,
            "empty component (leading, trailing or doubled '/')",
        ));
    }
    if comp == "." || comp == ".." {
        return Err(err(path, "'.' or '..' component"));
    }
    if comp.len() > MAX_COMPONENT_BYTES {
        return Err(err(path, "component too long"));
    }
    for ch in comp.chars() {
        if (ch as u32) < 0x20 || ch == '\u{7f}' {
            return Err(err(path, "control character"));
        }
        if matches!(ch, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') {
            return Err(err(path, "character not allowed on Windows"));
        }
    }
    if comp.ends_with('.') || comp.ends_with(' ') {
        return Err(err(path, "trailing '.' or space (stripped by Windows)"));
    }
    // Windows reserves device names with or without an extension: "CON", "con.txt", "COM1.log".
    let stem = comp.split('.').next().unwrap_or(comp).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    let is_numbered_device = upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.as_bytes()[3].is_ascii_digit();
    if RESERVED.contains(&upper.as_str()) || is_numbered_device {
        return Err(err(path, "reserved Windows device name"));
    }
    Ok(())
}

/// Key used to detect entries that would collide on a case-insensitive filesystem.
pub fn collision_key(path: &str) -> String {
    path.to_lowercase()
}

/// Parent path of `path`, or `None` for a top-level entry.
pub fn parent(path: &str) -> Option<&str> {
    path.rfind('/').map(|i| &path[..i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_paths() {
        for p in [
            "a",
            "dir/file.txt",
            "a/b/c/d.tar.zst",
            "ünïcödé/файл",
            "x y/z",
        ] {
            validate(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
    }

    #[test]
    fn rejects_hostile_paths() {
        let bad = [
            "",
            "/abs",
            "a//b",
            "a/",
            "../up",
            "a/../b",
            "./a",
            "C:/x",
            "a\\b",
            "nul\0byte",
            "tab\tname",
            "CON",
            "con.txt",
            "dir/COM1",
            "lpt9.log",
            "trailing.",
            "trailing ",
            "a:stream",
            "what?",
        ];
        for p in bad {
            assert!(validate(p).is_err(), "accepted {p:?}");
        }
    }

    #[test]
    fn rejects_non_nfc() {
        // "e" + combining acute accent is NFD; NFC is the single code point U+00E9.
        assert!(validate("cafe\u{301}").is_err());
        assert!(validate("caf\u{e9}").is_ok());
    }

    #[test]
    fn device_names_need_exact_stem() {
        assert!(validate("console").is_ok());
        assert!(validate("COM10").is_ok());
        assert!(validate("auxiliary.txt").is_ok());
    }

    #[test]
    fn limits() {
        assert!(validate(&"a".repeat(256)).is_err());
        assert!(validate(&["a"; 257].join("/")).is_err());
        assert!(validate(&["a"; 256].join("/")).is_ok());
    }

    #[test]
    fn parent_of() {
        assert_eq!(parent("a/b/c"), Some("a/b"));
        assert_eq!(parent("a"), None);
    }
}

//! Entry path rules.
//!
//! Paths in a `.trnc` manifest are relative, `/`-separated, NFC-normalized UTF-8. The rules are
//! deliberately the intersection of what Windows, macOS and Linux accept, so an archive created
//! anywhere extracts the same everywhere, and so no entry can name something outside the
//! destination directory.
//!
//! Archives made by other tools (tar, ZIP) are checked with [`validate_host`] instead: names
//! that are ordinary on this computer but illegal on Windows (a backslash, `:`, a trailing dot)
//! are accepted on Linux and macOS, so real Linux tarballs extract there. Everything that could
//! escape the destination is refused on every platform.

use crate::FormatError;
use unicode_normalization::is_nfc;

/// Maximum bytes in a whole path.
pub const MAX_PATH_BYTES: usize = 4096;
/// Maximum bytes in one component.
pub const MAX_COMPONENT_BYTES: usize = 255;
/// Maximum number of components.
pub const MAX_DEPTH: usize = 256;

const RESERVED: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];

/// Prefix of the staging directory trunc creates at the top of the destination while consuming
/// (`.trunc-stage-<archive id>`). Archive entries may not use it at the top level: one would
/// pass the up-front "already exists" check (the staging directory does not exist yet) and only
/// clash with it at the final rename, after the whole archive had been consumed.
pub const STAGE_PREFIX: &str = ".trunc-stage-";

fn err(path: &str, reason: &'static str) -> FormatError {
    FormatError::Path {
        path: path.to_owned(),
        reason,
    }
}

/// Validate one entry path. Returns `Ok(())` if it is safe and portable.
pub fn validate(path: &str) -> Result<(), FormatError> {
    validate_with(path, true)
}

/// Validate a path from an archive made by another tool, for extraction on this computer: the
/// portable rules on Windows, and elsewhere the safety rules alone (no absolute paths, `..`,
/// empty components, control characters or Windows drive prefixes).
pub fn validate_host(path: &str) -> Result<(), FormatError> {
    validate_with(path, cfg!(windows))
}

/// Validate a path against the safety rules alone, which apply on every computer: what
/// [`validate_host`] checks off Windows. A path that passes this but not [`validate_host`] is
/// harmless but has a name this computer cannot create; [`host_unusable`] says which part.
pub fn validate_safe(path: &str) -> Result<(), FormatError> {
    validate_with(path, false)
}

/// For a path that passes [`validate_safe`]: the shortest leading part of it (whole components)
/// whose last name this computer cannot create, with the reason, or `None` if it can create
/// them all. Always `None` off Windows, where [`validate_host`] is [`validate_safe`].
pub fn host_unusable(path: &str) -> Option<(&str, &'static str)> {
    unusable_with(path, cfg!(windows))
}

fn unusable_with(path: &str, portable: bool) -> Option<(&str, &'static str)> {
    if !portable {
        return None;
    }
    let mut start = 0usize;
    for comp in path.split('/') {
        let end = start + comp.len();
        if let Err(FormatError::Path { reason, .. }) = validate_component(path, comp, true) {
            return Some((&path[..end], reason));
        }
        start = end + 1;
    }
    None
}

fn validate_with(path: &str, portable: bool) -> Result<(), FormatError> {
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
        validate_component(path, comp, portable)?;
        if depth == 1 && collision_key(comp).starts_with(STAGE_PREFIX) {
            return Err(err(path, "name reserved for trunc's staging directory"));
        }
        // "C:" first is a Windows absolute path, whatever this computer makes of it.
        let b = comp.as_bytes();
        if depth == 1 && b.len() == 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
            return Err(err(path, "Windows drive prefix"));
        }
    }
    Ok(())
}

fn validate_component(path: &str, comp: &str, portable: bool) -> Result<(), FormatError> {
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
        if portable && matches!(ch, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') {
            return Err(err(path, "character not allowed on Windows"));
        }
    }
    if !portable {
        return Ok(());
    }
    if comp.ends_with('.') || comp.ends_with(' ') {
        return Err(err(path, "trailing '.' or space (stripped by Windows)"));
    }
    // Windows reserves device names with or without an extension: "CON", "con.txt", "COM1.log".
    let stem = comp.split('.').next().unwrap_or(comp).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    // COM0-COM9 and LPT0-LPT9, plus the superscript digits Windows also treats as devices.
    let is_numbered_device = upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|n| {
            (n.len() == 1 && n.as_bytes()[0].is_ascii_digit()) || matches!(n, "¹" | "²" | "³")
        });
    if RESERVED.contains(&upper.as_str()) || is_numbered_device {
        return Err(err(path, "reserved Windows device name"));
    }
    Ok(())
}

/// Key used to detect entries that would collide on a case-insensitive filesystem.
///
/// NTFS compares names through its upcase table, a simple one-to-one uppercase mapping
/// (`ı`, `ſ` and `ς` upper-case to `I`, `S` and `Σ`); APFS and HFS+ use Unicode case folding
/// (the Kelvin sign `K` folds to `k`). Each character is mapped to its simple uppercase and
/// that to its simple lowercase, keeping a character whose mapping is not a single character
/// (`ß`, `İ`), so two names NTFS or simple case folding treat as equal get the same key.
/// Whole-string `to_lowercase` would not do: it leaves `ı`/`i`, `ſ`/`s` and `ς`/`σ` distinct,
/// and turns a final `Σ` into `ς`.
pub fn collision_key(path: &str) -> String {
    if path.is_ascii() {
        return path.to_ascii_lowercase();
    }
    path.chars().map(fold_char).collect()
}

fn fold_char(c: char) -> char {
    let up = single(c.to_uppercase()).unwrap_or(c);
    single(up.to_lowercase()).unwrap_or(up)
}

/// The only item of `it`, if it has exactly one.
fn single(mut it: impl Iterator<Item = char>) -> Option<char> {
    let c = it.next()?;
    it.next().is_none().then_some(c)
}

/// Key used to detect entries that would be the same file on this computer: case-insensitive
/// on Windows and macOS, exact on Linux (where `Makefile` and `makefile` are different files).
/// Writes still check the exact name created, which catches case-insensitive Linux folders.
pub fn host_key(path: &str) -> String {
    if cfg!(any(windows, target_os = "macos")) {
        collision_key(path)
    } else {
        path.to_owned()
    }
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
    fn host_rules_accept_ordinary_unix_names_off_windows() {
        let unixy = [
            "lib/systemd/system/system-systemd\\x2dcryptsetup.slice",
            "a:b",
            "what?",
            "dir/CON",
            "trailing.",
        ];
        for p in unixy {
            assert_eq!(validate_host(p).is_ok(), !cfg!(windows), "{p:?}");
            assert!(validate(p).is_err(), "{p:?} is not portable");
        }
        let hostile = [
            "",
            "/abs",
            "a//b",
            "../up",
            "a/../b",
            "./a",
            "C:/x",
            "c:",
            "nul\0byte",
            "tab\tname",
        ];
        for p in hostile {
            assert!(validate_host(p).is_err(), "accepted {p:?}");
        }
        assert_eq!(
            host_key("Makefile") == host_key("makefile"),
            cfg!(any(windows, target_os = "macos"))
        );
    }

    #[test]
    fn unusable_part_is_the_shallowest_name_windows_forbids() {
        let cases = [
            (
                "usr/share/man/man3/IO::File.3pm.gz",
                Some("usr/share/man/man3/IO::File.3pm.gz"),
            ),
            ("a/trailing./b/c", Some("a/trailing.")),
            ("inc/aux.h", Some("inc/aux.h")),
            ("x\\y/z", Some("x\\y")),
            ("CON/a:b", Some("CON")),
            ("usr/share/terminfo/E/foo", None),
        ];
        for (p, want) in cases {
            validate_safe(p).unwrap_or_else(|e| panic!("{p}: {e}"));
            assert_eq!(unusable_with(p, true).map(|(u, _)| u), want, "{p:?}");
            assert_eq!(unusable_with(p, false), None, "{p:?}");
            assert_eq!(host_unusable(p).is_some(), cfg!(windows) && want.is_some());
            assert_eq!(
                validate_host(p).is_err(),
                host_unusable(p).is_some(),
                "{p:?}"
            );
        }
        for p in [
            "../up",
            "/abs",
            "a//b",
            "C:/x",
            "nul\0byte",
            ".trunc-stage-x",
        ] {
            assert!(validate_safe(p).is_err(), "accepted {p:?}");
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
        assert!(validate("CONIN").is_ok());
        assert!(validate("CONOUT$x").is_ok());
        assert!(validate("COM4\u{b2}").is_ok());
        assert!(validate("COM\u{2074}").is_ok());
    }

    #[test]
    fn rejects_every_windows_device_name() {
        let bad = [
            "CONIN$",
            "conin$",
            "CONOUT$",
            "conout$.log",
            "CONIN$.txt",
            "dir/CONOUT$",
            "CONIN$ .txt",
            "COM0",
            "lpt0.txt",
            "COM\u{b9}",
            "com\u{b2}.txt",
            "dir/COM\u{b3}",
            "LPT\u{b9}",
            "lpt\u{b2}.log",
            "LPT\u{b3} .txt",
        ];
        for p in bad {
            assert!(validate(p).is_err(), "accepted {p:?}");
            assert_eq!(validate_host(p).is_err(), cfg!(windows), "{p:?}");
        }
        // Trailing dots and spaces are refused on their own.
        for p in ["CONIN$.", "COM\u{b9} "] {
            assert!(validate(p).is_err(), "accepted {p:?}");
        }
    }

    #[test]
    fn collision_key_matches_ntfs_and_case_folding() {
        let same = [
            ("file", "F\u{131}LE"),
            ("file", "f\u{131}le"),
            ("Makefile", "makef\u{131}le"),
            ("sea", "\u{17f}ea"),
            ("dir/SEA", "dir/\u{17f}ea"),
            ("\u{3b1}\u{3c3}", "\u{3b1}\u{3c2}"),
            ("\u{391}\u{3a3}", "\u{3b1}\u{3c2}"),
            ("\u{391}\u{3a3}", "\u{3b1}\u{3c3}"),
            ("kelvin", "\u{212a}elvin"),
            ("\u{212a}", "K"),
            ("Stra\u{df}e", "STRA\u{df}E"),
            ("\u{c9}t\u{e9}", "\u{e9}T\u{c9}"),
        ];
        for (a, b) in same {
            assert_eq!(collision_key(a), collision_key(b), "{a:?} vs {b:?}");
        }
        let different = [
            ("file", "fi1e"),
            ("strasse", "stra\u{df}e"),
            ("i", "\u{130}"),
        ];
        for (a, b) in different {
            assert_ne!(collision_key(a), collision_key(b), "{a:?} vs {b:?}");
        }
        assert_eq!(
            host_key("file") == host_key("f\u{131}le"),
            cfg!(any(windows, target_os = "macos"))
        );
    }

    #[test]
    fn rejects_staging_directory_names_at_the_top() {
        for p in [
            ".trunc-stage-00112233445566778899aabbccddeeff",
            ".trunc-stage-x/inner",
            ".TRUNC-STAGE-x",
            ".trunc-\u{17f}tage-x",
        ] {
            assert!(validate(p).is_err(), "accepted {p:?}");
            assert!(validate_host(p).is_err(), "accepted {p:?}");
        }
        for p in [
            "dir/.trunc-stage-x",
            ".trunc-stage",
            ".trunc-stagex",
            "trunc-stage-x",
        ] {
            validate(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
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

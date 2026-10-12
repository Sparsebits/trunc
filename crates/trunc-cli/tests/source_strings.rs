//! A string literal that runs onto the next line without a `\` continuation keeps the line
//! break and the next line's indentation, which shows up as a stray run of spaces in messages.
//! This scans every Rust source file in the workspace for such literals (raw strings excepted),
//! and for long runs of spaces after text inside a literal, which is what such a line looks
//! like once it has been joined by hand.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n != "target") {
                rust_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Line numbers (1-based) where a non-raw string literal continues onto the next line without
/// a trailing backslash.
fn unjoined_lines(src: &str) -> Vec<usize> {
    let b = src.as_bytes();
    let mut bad = Vec::new();
    let mut line = 1;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\n' => line += 1,
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                        continue;
                    }
                    if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    if b[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
                continue;
            }
            // Raw strings: r"..", r#".."#, br"..", cr"..".
            b'r' if (i == 0 || !is_ident(b[i - 1]) || matches!(b[i - 1], b'b' | b'c'))
                && matches!(b.get(i + 1), Some(b'"' | b'#')) =>
            {
                let mut j = i + 1;
                let mut hashes = 0;
                while b.get(j) == Some(&b'#') {
                    hashes += 1;
                    j += 1;
                }
                if b.get(j) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                j += 1;
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                while j < b.len() && !b[j..].starts_with(&close) {
                    if b[j] == b'\n' {
                        line += 1;
                    }
                    j += 1;
                }
                i = j + close.len();
                continue;
            }
            b'\'' => {
                // A char literal ('a', '\n', '\'', '"'), or a lifetime / label.
                if b.get(i + 1) == Some(&b'\\') {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != b'\'' {
                        j += 1;
                    }
                    i = j + 1;
                    continue;
                }
                if b.get(i + 2) == Some(&b'\'') {
                    i += 3;
                    continue;
                }
                // Multi-byte UTF-8 char literal.
                if let Some(rest) = src.get(i + 1..)
                    && let Some(c) = rest.chars().next()
                    && rest[c.len_utf8()..].starts_with('\'')
                {
                    i += 1 + c.len_utf8() + 1;
                    continue;
                }
            }
            b'"' => {
                let mut j = i + 1;
                // Spaces in a row after other text in this literal.
                let mut run = 0;
                let mut text = false;
                while j < b.len() && b[j] != b'"' {
                    match b[j] {
                        b'\\' => {
                            let mut k = j + 1;
                            if b.get(k) == Some(&b'\r') {
                                k += 1;
                            }
                            if b.get(k) == Some(&b'\n') {
                                // A continuation: the next line's leading whitespace is dropped.
                                line += 1;
                                j = k + 1;
                                while matches!(b.get(j), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                                    if b[j] == b'\n' {
                                        line += 1;
                                    }
                                    j += 1;
                                }
                            } else {
                                j += 2;
                            }
                            run = 0;
                            text = true;
                            continue;
                        }
                        b'\r' if b.get(j + 1) == Some(&b'\n') => {}
                        b'\n' => {
                            // The next line's indentation would end up in the string.
                            if matches!(b.get(j + 1), Some(b' ' | b'\t')) {
                                bad.push(line);
                            }
                            line += 1;
                            run = 0;
                            text = false;
                        }
                        b' ' => {
                            run += 1;
                            if text && run == 12 {
                                bad.push(line);
                            }
                        }
                        _ => {
                            run = 0;
                            text = true;
                        }
                    }
                    j += 1;
                }
                i = j + 1;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    bad
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

#[test]
fn the_scanner_finds_unjoined_literals() {
    assert_eq!(unjoined_lines("let a = \"x\n    y\";\n"), vec![1]);
    assert_eq!(unjoined_lines("let a = \"x,              y\";\n"), vec![1]);
    // Column alignment in tables is fine.
    assert!(unjoined_lines("let a = \"id         {}\";\n").is_empty());
    assert!(unjoined_lines("let a = \"table\nrow\";\n").is_empty());
    assert!(unjoined_lines("let a = \"x\\\n    y\";\n").is_empty());
    assert!(unjoined_lines("let a = r#\"x\ny\"#;\nlet c = '\"';\n").is_empty());
    assert!(unjoined_lines("fn f<'a>(x: &'a str) {} // \"\n").is_empty());
}

#[test]
fn no_string_literal_spans_lines_without_a_continuation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    for dir in ["crates", "fuzz"] {
        if root.join(dir).is_dir() {
            rust_files(&root.join(dir), &mut files);
        }
    }
    assert!(files.len() > 20, "found too few source files");
    let mut found = Vec::new();
    for f in files.iter().filter(|f| !f.ends_with("source_strings.rs")) {
        let src = std::fs::read_to_string(f).unwrap();
        for l in unjoined_lines(&src) {
            found.push(format!("{}:{l}", f.display()));
        }
    }
    assert!(
        found.is_empty(),
        "string literals continue onto the next line without a trailing `\\` (the line break \
         and indentation end up in the string):\n{}",
        found.join("\n")
    );
}

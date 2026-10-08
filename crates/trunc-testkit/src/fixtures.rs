//! Deterministic input trees.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::Rng;

const WORDS: &[&str] = &[
    "archive", "block", "consume", "durable", "extract", "footer", "header", "journal", "manifest",
    "reclaim", "stream", "truncate", "verify", "zstd", "lz4", "sparse", "volume", "cluster",
];

/// Text-like, compressible bytes.
pub fn text_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        let w = WORDS[rng.below(WORDS.len() as u64) as usize];
        out.extend_from_slice(w.as_bytes());
        out.push(if rng.below(12) == 0 { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

/// Random, incompressible bytes.
pub fn noise_bytes(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rng.fill(&mut v);
    v
}

fn write(path: &Path, data: &[u8]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::File::create(path).unwrap().write_all(data).unwrap();
}

/// `n` small text files (0..=8 KiB) spread over a few nested directories.
pub fn small_files(root: &Path, n: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    for i in 0..n {
        let dir = format!("d{}/e{}", rng.below(4), rng.below(3));
        let len = rng.below(8 * 1024 + 1) as usize;
        write(
            &root.join(dir).join(format!("f{i:05}.txt")),
            &text_bytes(&mut rng, len),
        );
    }
}

/// One file of `len` bytes alternating compressible and incompressible 64 KiB stretches.
pub fn large_file(root: &Path, len: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    let mut data = Vec::with_capacity(len);
    let mut i = 0;
    while data.len() < len {
        let n = (64 * 1024).min(len - data.len());
        let chunk = if i % 3 == 2 {
            noise_bytes(&mut rng, n)
        } else {
            text_bytes(&mut rng, n)
        };
        data.extend_from_slice(&chunk);
        i += 1;
    }
    write(&root.join("big.bin"), &data);
}

/// Empty files, empty directories and deep nesting.
pub fn edge_cases(root: &Path) {
    write(&root.join("empty.txt"), b"");
    fs::create_dir_all(root.join("empty_dir")).unwrap();
    fs::create_dir_all(root.join("a/b/c/d/e/f/g")).unwrap();
    write(&root.join("a/b/c/d/e/f/g/deep.txt"), b"deep");
    write(&root.join("a/also_empty"), b"");
    write(&root.join("unicodé/ファイル.txt"), "héllo wörld".as_bytes());
    write(&root.join("one_byte"), b"x");
}

/// A file of zeros and a file of noise.
pub fn extremes(root: &Path, len: usize, seed: u64) {
    let mut rng = Rng::new(seed);
    write(&root.join("zeros.bin"), &vec![0u8; len]);
    write(&root.join("noise.bin"), &noise_bytes(&mut rng, len));
}

/// A bit of everything.
pub fn mixed(root: &Path, seed: u64) {
    small_files(&root.join("small"), 300, seed);
    large_file(&root.join("large"), 3 * 1024 * 1024 + 12_345, seed + 1);
    edge_cases(&root.join("edge"));
    extremes(&root.join("extremes"), 256 * 1024, seed + 2);
}

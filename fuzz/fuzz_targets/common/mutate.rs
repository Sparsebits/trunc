//! Shared code of the structured targets (`iso`, `image_manifest`): parameter bytes, an
//! in-memory file system holding the input, and damage applied to a valid file built from the
//! parameters.

#![allow(dead_code)]

use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, OpenMode, Share};
use trunc_testkit::{CrashModel, FaultFs};

/// Parameter bytes, read in order (zero once they run out).
pub struct Params<'a>(pub &'a [u8]);

impl<'a> Params<'a> {
    pub fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    /// Up to `n` bytes.
    pub fn take(&mut self, n: usize) -> &'a [u8] {
        let (a, b) = self.0.split_at(n.min(self.0.len()));
        self.0 = b;
        a
    }

    pub fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// An in-memory file system holding `bytes` at `path`.
pub fn fs_with(path: &str, bytes: &[u8]) -> FaultFs {
    let fs = FaultFs::new(CrashModel::WriteThrough);
    fs.put_file(Path::new(path), bytes);
    fs
}

/// `bytes` as an open file (keep the file system alive while the handle is used).
pub fn host(bytes: &[u8]) -> (FaultFs, Box<dyn FileHandle>) {
    let fs = fs_with("/d", bytes);
    let h = fs
        .open(Path::new("/d"), OpenMode::Read, Share::Shared)
        .unwrap();
    (fs, h)
}

/// Damage `bytes` as the parameters say: up to 7 edits, each flipping bits of a byte, setting
/// a byte, writing a 32-bit little- or big-endian value (zero, one, extremes or arbitrary), or
/// truncating. An edit lands near one of the `hot` offsets (where the structures the parser
/// reads are) or anywhere.
pub fn damage(bytes: &mut Vec<u8>, p: &mut Params<'_>, hot: &[usize]) {
    let n = p.byte() % 8;
    for _ in 0..n {
        if bytes.is_empty() {
            return;
        }
        let op = p.byte();
        let pos = p.u32() as usize;
        let at = if op & 0x40 != 0 && !hot.is_empty() {
            (hot[pos % hot.len()] + (pos >> 16) % 64) % bytes.len()
        } else {
            pos % bytes.len()
        };
        match op % 5 {
            0 => bytes[at] ^= p.byte().max(1),
            1 => bytes[at] = p.byte(),
            2 | 3 => {
                let v = match p.byte() % 6 {
                    0 => 0,
                    1 => 1,
                    2 => 0x7fff_ffff,
                    3 => u32::MAX,
                    4 => 0x8000_0000,
                    _ => p.u32(),
                };
                let b = if op % 5 == 2 {
                    v.to_le_bytes()
                } else {
                    v.to_be_bytes()
                };
                let end = (at + 4).min(bytes.len());
                bytes[at..end].copy_from_slice(&b[..end - at]);
            }
            _ => {
                if op & 0x80 != 0 {
                    bytes.truncate(at);
                } else {
                    bytes[at] ^= 0x80;
                }
            }
        }
    }
}

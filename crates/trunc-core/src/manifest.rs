//! The manifest: entry list, block table and integrity roots.
//!
//! On disk the manifest region holds a CBOR-encoded [`SignedManifest`]: the CBOR-encoded
//! [`Manifest`] body as an opaque byte string, plus an optional Ed25519 signature over
//! `"trunc-manifest-v1" || BLAKE3(body)`. Keeping the body as bytes means the hash and
//! signature cover exactly what was written, independent of CBOR canonicalization.
//!
//! Entries are concatenated in manifest order, without headers, into one *logical stream*.
//! Blocks tile that stream: block 0 covers its first bytes, block `n-1` its last. Block byte
//! offsets in the file are not stored; they follow from the block sizes (see
//! [`Manifest::block_offsets`]), which keeps the manifest independent of its own length.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::footer::{FOOTER_LEN, Footer};
use crate::{CodecId, FORMAT_VERSION, FormatError, MAX_BLOCK_U, MAX_DICT_LEN, max_c_len, path};

const SIG_DOMAIN: &[u8] = b"trunc-manifest-v1";
const SIG_ALG_ED25519: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    File,
    Dir,
    Symlink { target: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub path: String,
    pub kind: EntryKind,
    /// Content length. Zero for directories and symlinks.
    pub size: u64,
    /// Unix permission bits (lower 12 bits meaningful). Windows only honours the write bit.
    pub mode: u32,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
    /// Offset of this entry's content in the logical stream.
    pub stream_off: u64,
    /// BLAKE3 of the content (of the empty string for non-files).
    #[serde(with = "crate::bytes::array")]
    pub blake3: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    pub stream_off: u64,
    pub u_len: u64,
    pub c_len: u64,
    pub codec: u16,
    #[serde(with = "crate::bytes::array")]
    pub blake3_c: [u8; 32],
    #[serde(with = "crate::bytes::array")]
    pub blake3_u: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DictInfo {
    pub len: u64,
    #[serde(with = "crate::bytes::array")]
    pub blake3: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u16,
    #[serde(with = "crate::bytes::array")]
    pub archive_id: [u8; 16],
    pub created_unix: i64,
    pub producer: String,
    pub entries: Vec<Entry>,
    pub blocks: Vec<BlockRecord>,
    pub dict: Option<DictInfo>,
    pub total_u: u64,
    pub total_c: u64,
    /// Merkle root over `blocks[i].blake3_u` (see `trunc_hash::merkle`).
    #[serde(with = "crate::bytes::array")]
    pub merkle_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigInfo {
    pub alg: u8,
    #[serde(with = "crate::bytes::array")]
    pub pubkey: [u8; 32],
    #[serde(with = "crate::bytes::array")]
    pub sig: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    #[serde(with = "crate::bytes::vec")]
    pub body: Vec<u8>,
    pub sig: Option<SigInfo>,
}

/// Result of opening a manifest region.
#[derive(Debug, Clone)]
pub struct OpenedManifest {
    pub manifest: Manifest,
    /// BLAKE3 of the body bytes; identifies this exact manifest.
    pub hash: [u8; 32],
    /// Public key that produced a valid signature, if the manifest was signed.
    pub signer: Option<[u8; 32]>,
}

fn decode_err(e: impl std::fmt::Display) -> FormatError {
    FormatError::ManifestDecode(e.to_string())
}

fn invalid(msg: impl Into<String>) -> FormatError {
    FormatError::Manifest(msg.into())
}

fn signing_message(body_hash: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 32);
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(body_hash);
    m
}

impl SignedManifest {
    /// Wrap an encoded body, signing it if a key is given.
    pub fn new(body: Vec<u8>, key: Option<&SigningKey>) -> Self {
        let sig = key.map(|k| {
            let msg = signing_message(&trunc_hash::blake3(&body));
            SigInfo {
                alg: SIG_ALG_ED25519,
                pubkey: k.verifying_key().to_bytes(),
                sig: k.sign(&msg).to_bytes(),
            }
        });
        Self { body, sig }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).expect("writing CBOR to a Vec cannot fail");
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        ciborium::from_reader(bytes).map_err(decode_err)
    }

    /// Decode, check the signature (if any), decode the body and validate it.
    pub fn open(bytes: &[u8]) -> Result<OpenedManifest, FormatError> {
        let sm = Self::decode(bytes)?;
        let hash = trunc_hash::blake3(&sm.body);
        let signer = match &sm.sig {
            None => None,
            Some(s) => {
                if s.alg != SIG_ALG_ED25519 {
                    return Err(FormatError::Signature);
                }
                let vk = VerifyingKey::from_bytes(&s.pubkey).map_err(|_| FormatError::Signature)?;
                vk.verify(&signing_message(&hash), &Signature::from_bytes(&s.sig))
                    .map_err(|_| FormatError::Signature)?;
                Some(s.pubkey)
            }
        };
        let manifest = Manifest::decode_body(&sm.body)?;
        manifest.validate()?;
        Ok(OpenedManifest {
            manifest,
            hash,
            signer,
        })
    }
}

impl Manifest {
    pub fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).expect("writing CBOR to a Vec cannot fail");
        out
    }

    pub fn decode_body(bytes: &[u8]) -> Result<Self, FormatError> {
        ciborium::from_reader(bytes).map_err(decode_err)
    }

    /// Check every structural rule a consumer relies on. A manifest that passes cannot direct
    /// writes outside the destination, cannot describe overlapping or missing stream ranges,
    /// and its sizes add up.
    pub fn validate(&self) -> Result<(), FormatError> {
        if self.format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(self.format_version));
        }
        self.validate_entries()?;
        self.validate_blocks()?;
        if let Some(d) = &self.dict {
            if d.len == 0 || d.len > MAX_DICT_LEN {
                return Err(invalid(format!("dictionary length {} out of range", d.len)));
            }
        }
        let leaves: Vec<[u8; 32]> = self.blocks.iter().map(|b| b.blake3_u).collect();
        if trunc_hash::merkle::root(&leaves) != self.merkle_root {
            return Err(invalid("merkle root does not match block hashes"));
        }
        Ok(())
    }

    fn validate_entries(&self) -> Result<(), FormatError> {
        let mut kinds: HashMap<String, bool> = HashMap::with_capacity(self.entries.len());
        let mut running = 0u64;
        for e in &self.entries {
            path::validate(&e.path)?;
            let key = path::collision_key(&e.path);
            let is_dir = matches!(e.kind, EntryKind::Dir);
            if kinds.insert(key, is_dir).is_some() {
                return Err(invalid(format!(
                    "duplicate path (case-insensitive) {:?}",
                    e.path
                )));
            }
            if e.mtime_nanos >= 1_000_000_000 {
                return Err(invalid(format!(
                    "mtime_nanos out of range for {:?}",
                    e.path
                )));
            }
            match &e.kind {
                EntryKind::File => {}
                EntryKind::Dir => {
                    if e.size != 0 {
                        return Err(invalid(format!("directory {:?} has nonzero size", e.path)));
                    }
                }
                EntryKind::Symlink { target } => {
                    if e.size != 0 {
                        return Err(invalid(format!("symlink {:?} has nonzero size", e.path)));
                    }
                    if target.is_empty()
                        || target.len() > path::MAX_PATH_BYTES
                        || target.contains('\0')
                    {
                        return Err(invalid(format!("symlink {:?} has invalid target", e.path)));
                    }
                }
            }
            if e.stream_off != running {
                return Err(invalid(format!(
                    "entry {:?} stream_off {} != expected {}",
                    e.path, e.stream_off, running
                )));
            }
            running = running
                .checked_add(e.size)
                .ok_or_else(|| invalid("total size overflows u64"))?;
        }
        if running != self.total_u {
            return Err(invalid(format!(
                "entry sizes sum to {running}, total_u is {}",
                self.total_u
            )));
        }
        // No entry may live under a non-directory entry ("a" file plus "a/b").
        for e in &self.entries {
            let mut p = path::parent(&e.path);
            while let Some(parent) = p {
                if let Some(false) = kinds.get(&path::collision_key(parent)) {
                    return Err(invalid(format!(
                        "{:?} is nested under a non-directory",
                        e.path
                    )));
                }
                p = path::parent(parent);
            }
        }
        Ok(())
    }

    fn validate_blocks(&self) -> Result<(), FormatError> {
        if self.blocks.len() > u32::MAX as usize {
            return Err(invalid("too many blocks"));
        }
        let mut next = 0u64;
        let mut total_c = 0u64;
        for (i, b) in self.blocks.iter().enumerate() {
            CodecId::try_from(b.codec)?;
            if b.stream_off != next {
                return Err(invalid(format!(
                    "block {i} starts at {} not {next}",
                    b.stream_off
                )));
            }
            if b.u_len == 0 || b.u_len > MAX_BLOCK_U {
                return Err(invalid(format!("block {i} u_len {} out of range", b.u_len)));
            }
            if b.c_len > max_c_len(b.u_len) {
                return Err(invalid(format!("block {i} c_len {} too large", b.c_len)));
            }
            if CodecId::try_from(b.codec)? == CodecId::Store && b.c_len != b.u_len {
                return Err(invalid(format!("stored block {i} has c_len != u_len")));
            }
            next = next
                .checked_add(b.u_len)
                .ok_or_else(|| invalid("block sizes overflow"))?;
            total_c = total_c
                .checked_add(b.c_len)
                .ok_or_else(|| invalid("block sizes overflow"))?;
        }
        if next != self.total_u {
            return Err(invalid(format!(
                "blocks cover {next} bytes, total_u is {}",
                self.total_u
            )));
        }
        if total_c != self.total_c {
            return Err(invalid(format!(
                "block c_len sum {total_c} != total_c {}",
                self.total_c
            )));
        }
        Ok(())
    }

    /// Absolute file offset of each block's payload, indexed by block index.
    /// Block `n-1` starts at `first_block_off`; block 0 ends at end of file.
    pub fn block_offsets(&self, first_block_off: u64) -> Vec<u64> {
        let n = self.blocks.len();
        let mut offs = vec![0u64; n];
        let mut pos = first_block_off;
        for i in (0..n).rev() {
            offs[i] = pos;
            pos += self.blocks[i].c_len + FOOTER_LEN as u64;
        }
        offs
    }

    /// Length of the complete (unconsumed) archive file.
    pub fn archive_len(&self, first_block_off: u64) -> u64 {
        first_block_off + self.total_c + self.blocks.len() as u64 * FOOTER_LEN as u64
    }

    /// How many blocks have been consumed, given the current file length. `None` if the length
    /// is not exactly at a block boundary (torn truncation or a foreign/corrupt file).
    pub fn consumed_blocks(&self, first_block_off: u64, file_len: u64) -> Option<usize> {
        if file_len == self.archive_len(first_block_off) {
            return Some(0);
        }
        // After consuming blocks 0..k, the file ends where block k-1's payload began.
        let offs = self.block_offsets(first_block_off);
        offs.iter().position(|&o| o == file_len).map(|i| i + 1)
    }

    /// Bytes still present in a file that has consumed `consumed` blocks. This walks the block
    /// table; callers asking repeatedly should keep [`Manifest::block_offsets`] instead.
    pub fn len_after_consuming(&self, first_block_off: u64, consumed: usize) -> u64 {
        if consumed == 0 {
            return self.archive_len(first_block_off);
        }
        self.block_offsets(first_block_off)[consumed - 1]
    }

    /// The footer a writer must emit for block `i`.
    pub fn footer_for(&self, i: usize) -> Footer {
        let b = &self.blocks[i];
        Footer {
            block_index: u32::try_from(i).expect("validated block count fits u32"),
            codec: CodecId::try_from(b.codec).expect("validated codec id"),
            c_len: b.c_len,
            u_len: b.u_len,
            stream_off: b.stream_off,
            blake3_c: b.blake3_c,
            blake3_u: b.blake3_u,
            archive_id: self.archive_id,
        }
    }

    /// Check that a footer read from disk is exactly the one the manifest describes.
    pub fn check_footer(&self, i: usize, f: &Footer) -> Result<(), FormatError> {
        let block = u32::try_from(i).unwrap_or(u32::MAX);
        let want = self.footer_for(i);
        let fields: [(&'static str, bool); 8] = [
            ("block_index", f.block_index == want.block_index),
            ("archive_id", f.archive_id == want.archive_id),
            ("codec", f.codec == want.codec),
            ("c_len", f.c_len == want.c_len),
            ("u_len", f.u_len == want.u_len),
            ("stream_off", f.stream_off == want.stream_off),
            ("blake3_c", f.blake3_c == want.blake3_c),
            ("blake3_u", f.blake3_u == want.blake3_u),
        ];
        match fields.iter().find(|(_, ok)| !ok) {
            Some((field, _)) => Err(FormatError::FooterMismatch { block, field }),
            None => Ok(()),
        }
    }

    /// Number of file entries and of other entries (dirs, symlinks).
    pub fn entry_counts(&self) -> (usize, usize) {
        let files = self
            .entries
            .iter()
            .filter(|e| matches!(e.kind, EntryKind::File))
            .count();
        (files, self.entries.len() - files)
    }

    /// Set of directory paths the extractor must create, including implicit parents.
    pub fn all_dirs(&self) -> Vec<String> {
        let mut dirs: HashSet<String> = HashSet::new();
        for e in &self.entries {
            if matches!(e.kind, EntryKind::Dir) {
                dirs.insert(e.path.clone());
            }
            let mut p = path::parent(&e.path);
            while let Some(parent) = p {
                if !dirs.insert(parent.to_owned()) {
                    break;
                }
                p = path::parent(parent);
            }
        }
        let mut v: Vec<String> = dirs.into_iter().collect();
        // Parents sort before children.
        v.sort();
        v
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn file(path: &str, size: u64, off: u64) -> Entry {
        Entry {
            path: path.into(),
            kind: EntryKind::File,
            size,
            mode: 0o644,
            mtime_unix: 1_700_000_000,
            mtime_nanos: 0,
            stream_off: off,
            blake3: [0; 32],
        }
    }

    pub(crate) fn block(off: u64, u: u64, c: u64) -> BlockRecord {
        BlockRecord {
            stream_off: off,
            u_len: u,
            c_len: c,
            codec: CodecId::Zstd.as_u16(),
            blake3_c: [9; 32],
            blake3_u: trunc_hash::blake3(&off.to_le_bytes()),
        }
    }

    pub(crate) fn sample() -> Manifest {
        let entries = vec![
            Entry {
                kind: EntryKind::Dir,
                size: 0,
                ..file("d", 0, 0)
            },
            file("d/a", 100, 0),
            file("d/b", 50, 100),
            file("c", 0, 150),
        ];
        let blocks = vec![block(0, 64, 30), block(64, 64, 20), block(128, 22, 22)];
        let mut m = Manifest {
            format_version: FORMAT_VERSION,
            archive_id: [7; 16],
            created_unix: 0,
            producer: "test".into(),
            entries,
            blocks,
            dict: None,
            total_u: 150,
            total_c: 72,
            merkle_root: [0; 32],
        };
        m.merkle_root =
            trunc_hash::merkle::root(&m.blocks.iter().map(|b| b.blake3_u).collect::<Vec<_>>());
        m
    }

    #[test]
    fn sample_is_valid_and_round_trips() {
        let m = sample();
        m.validate().unwrap();
        let sm = SignedManifest::new(m.encode_body(), None);
        let opened = SignedManifest::open(&sm.encode()).unwrap();
        assert_eq!(opened.manifest, m);
        assert!(opened.signer.is_none());
    }

    #[test]
    fn signature_round_trip_and_tamper() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let m = sample();
        let sm = SignedManifest::new(m.encode_body(), Some(&key));
        let opened = SignedManifest::open(&sm.encode()).unwrap();
        assert_eq!(opened.signer, Some(key.verifying_key().to_bytes()));

        let mut tampered = sm.clone();
        let mut m2 = m.clone();
        m2.producer = "evil".into();
        tampered.body = m2.encode_body();
        assert_eq!(
            SignedManifest::open(&tampered.encode()).unwrap_err(),
            FormatError::Signature
        );
    }

    #[test]
    fn rejects_gaps_overlaps_and_bad_totals() {
        let mut m = sample();
        m.blocks[1].stream_off = 65;
        assert!(m.validate().is_err());

        let mut m = sample();
        m.total_u = 151;
        assert!(m.validate().is_err());

        let mut m = sample();
        m.entries[2].stream_off = 99;
        assert!(m.validate().is_err());

        let mut m = sample();
        m.blocks[0].blake3_u = [0; 32];
        assert!(m.validate().is_err(), "merkle root must be checked");
    }

    #[test]
    fn rejects_case_collisions_and_nesting_under_files() {
        let mut m = sample();
        m.entries[3].path = "D/A".into();
        assert!(m.validate().is_err());

        let mut m = sample();
        m.entries[3].path = "d/a/x".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn layout_and_consumption() {
        let m = sample();
        let fbo = 1000;
        let offs = m.block_offsets(fbo);
        let f = FOOTER_LEN as u64;
        // physical order: block 2, block 1, block 0
        assert_eq!(offs[2], fbo);
        assert_eq!(offs[1], fbo + 22 + f);
        assert_eq!(offs[0], fbo + 22 + f + 20 + f);
        let full = m.archive_len(fbo);
        assert_eq!(full, offs[0] + 30 + f);

        assert_eq!(m.consumed_blocks(fbo, full), Some(0));
        assert_eq!(m.consumed_blocks(fbo, offs[0]), Some(1));
        assert_eq!(m.consumed_blocks(fbo, offs[1]), Some(2));
        assert_eq!(m.consumed_blocks(fbo, fbo), Some(3));
        assert_eq!(m.consumed_blocks(fbo, fbo + 1), None);
        for k in 0..=3 {
            assert_eq!(
                m.consumed_blocks(fbo, m.len_after_consuming(fbo, k)),
                Some(k)
            );
        }
    }

    #[test]
    fn footer_check() {
        let m = sample();
        let mut f = m.footer_for(1);
        m.check_footer(1, &f).unwrap();
        f.stream_off += 1;
        assert_eq!(
            m.check_footer(1, &f).unwrap_err(),
            FormatError::FooterMismatch {
                block: 1,
                field: "stream_off"
            }
        );
    }

    #[test]
    fn decode_garbage_does_not_panic() {
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = SignedManifest::open(&junk);
        }
    }

    #[test]
    fn implicit_dirs() {
        let mut m = sample();
        m.entries.push(file("x/y/z", 0, 150));
        assert_eq!(m.all_dirs(), vec!["d", "x", "x/y"]);
    }
}

//! A crash-safe store for one immutable preamble plus a latest checkpoint.
//!
//! Layout of the file (`<archive>.trncj`, all integers little-endian):
//!
//! ```text
//! HEADER 64:  magic "TRNCJ\0\x01\0" | version u16 | slot_cap u32 | preamble_len u64 |
//!             preamble_blake3 [32] | reserved [6] | crc32c u32 (over bytes 0..60)
//! PREAMBLE:   preamble_len bytes, written once
//! SLOT A, B:  each 16 + slot_cap bytes:
//!             generation u64 | len u32 | crc32c u32 (over generation, len, payload) | payload
//! ```
//!
//! A write goes to the slot holding the older generation and is flushed; the newer valid slot
//! wins on open. A torn or lost slot write can only damage the slot being written, so the
//! previously committed checkpoint always survives. Legacy ZIP consumption stores the parsed
//! layout (which outlives the truncated central directory) in the preamble and inflate
//! checkpoints in the slots. Native `.trnc` consumption needs no journal (ADR-0007).

use std::path::Path;

use trunc_fs::{FileHandle, FsBackend, FsError, OpenMode, Share};

const MAGIC: [u8; 8] = *b"TRNCJ\0\x01\0";
const VERSION: u16 = 1;
const HEADER_LEN: u64 = 64;
const HEADER_BYTES: usize = 64;
const SLOT_HEADER: u64 = 16;
const SLOT_HEADER_BYTES: usize = 16;
/// Largest preamble accepted on open (bounds memory on hostile files).
pub const MAX_PREAMBLE: u64 = 1 << 30;

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("not a trunc journal or its header is corrupt")]
    BadHeader,
    #[error("journal preamble is corrupt")]
    BadPreamble,
    #[error("checkpoint of {got} bytes exceeds the slot capacity of {cap}")]
    TooLarge { got: usize, cap: u32 },
    #[error(transparent)]
    Fs(#[from] FsError),
}

type Result<T> = std::result::Result<T, JournalError>;

/// An open journal.
#[derive(Debug)]
pub struct Journal {
    handle: Box<dyn FileHandle>,
    slot_cap: u32,
    slots_off: u64,
    /// Generation of the newest valid slot (0 = none) and which slot (0 or 1) holds it.
    latest: Option<(u64, usize)>,
}

fn parent_of(p: &Path) -> std::path::PathBuf {
    match p.parent() {
        Some(q) if !q.as_os_str().is_empty() => q.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    }
}

fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    std::path::PathBuf::from(s)
}

fn encode_header(slot_cap: u32, preamble: &[u8]) -> [u8; HEADER_BYTES] {
    let mut h = [0u8; HEADER_BYTES];
    h[0..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&VERSION.to_le_bytes());
    h[10..14].copy_from_slice(&slot_cap.to_le_bytes());
    h[14..22].copy_from_slice(&(preamble.len() as u64).to_le_bytes());
    h[22..54].copy_from_slice(&trunc_hash::blake3(preamble));
    let crc = trunc_hash::crc32c(&h[..60]);
    h[60..64].copy_from_slice(&crc.to_le_bytes());
    h
}

fn slot_crc(generation: u64, payload: &[u8]) -> u32 {
    let mut c = trunc_hash::crc32c(&generation.to_le_bytes());
    c = trunc_hash::crc32c_append(
        c,
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    trunc_hash::crc32c_append(c, payload)
}

impl Journal {
    /// Create a journal at `path` (must not exist) and make it durable, entry included.
    ///
    /// The file is written in full under a temporary name and then renamed into place, so a crash
    /// during creation can never leave a partial journal at `path`.
    pub fn create(fs: &dyn FsBackend, path: &Path, preamble: &[u8], slot_cap: u32) -> Result<Self> {
        let _prof = trunc_prof::span("journal.create").bytes(preamble.len() as u64);
        let tmp = temp_path(path);
        let h = fs.open(&tmp, OpenMode::CreateOrTruncate, Share::Exclusive)?;
        h.write_all_at(&encode_header(slot_cap, preamble), 0)?;
        h.write_all_at(preamble, HEADER_LEN)?;
        let slots_off = HEADER_LEN + preamble.len() as u64;
        // Empty slots: generation 0, which `read_slot` ignores.
        h.set_len(slots_off + 2 * (SLOT_HEADER + u64::from(slot_cap)))?;
        h.flush_data()?;
        drop(h); // Windows cannot rename a file held open exclusively
        let dir = parent_of(path);
        fs.flush_dir(&dir)?;
        fs.rename(&tmp, path)?;
        fs.flush_dir(&dir)?;
        let handle = fs.open(path, OpenMode::ReadWrite, Share::Exclusive)?;
        Ok(Self {
            handle,
            slot_cap,
            slots_off,
            latest: None,
        })
    }

    /// Remove a temporary file left by a `create` that crashed before its rename.
    pub fn discard_partial(fs: &dyn FsBackend, path: &Path) -> Result<()> {
        match fs.remove_file(&temp_path(path)) {
            Ok(()) => fs.flush_dir(&parent_of(path))?,
            Err(FsError::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// Open an existing journal: returns it, its preamble and the newest checkpoint (if any).
    pub fn open(fs: &dyn FsBackend, path: &Path) -> Result<(Self, Vec<u8>, Option<Vec<u8>>)> {
        let handle = fs.open(path, OpenMode::ReadWrite, Share::Exclusive)?;
        let mut h = [0u8; HEADER_BYTES];
        handle
            .read_exact_at(&mut h, 0)
            .map_err(|_| JournalError::BadHeader)?;
        if h[0..8] != MAGIC
            || u16::from_le_bytes([h[8], h[9]]) != VERSION
            || trunc_hash::crc32c(&h[..60]) != u32::from_le_bytes([h[60], h[61], h[62], h[63]])
        {
            return Err(JournalError::BadHeader);
        }
        let slot_cap = u32::from_le_bytes([h[10], h[11], h[12], h[13]]);
        let plen = u64::from_le_bytes(h[14..22].try_into().expect("8 bytes"));
        if plen > MAX_PREAMBLE {
            return Err(JournalError::BadHeader);
        }
        let mut preamble = vec![0u8; usize::try_from(plen).map_err(|_| JournalError::BadHeader)?];
        handle
            .read_exact_at(&mut preamble, HEADER_LEN)
            .map_err(|_| JournalError::BadPreamble)?;
        if trunc_hash::blake3(&preamble)[..] != h[22..54] {
            return Err(JournalError::BadPreamble);
        }
        let mut j = Self {
            handle,
            slot_cap,
            slots_off: HEADER_LEN + plen,
            latest: None,
        };
        let mut best: Option<(u64, usize, Vec<u8>)> = None;
        for slot in 0..2 {
            if let Some((generation, payload)) = j.read_slot(slot) {
                if best.as_ref().is_none_or(|(g, _, _)| generation > *g) {
                    best = Some((generation, slot, payload));
                }
            }
        }
        j.latest = best.as_ref().map(|(g, s, _)| (*g, *s));
        Ok((j, preamble, best.map(|(_, _, p)| p)))
    }

    fn slot_off(&self, slot: usize) -> u64 {
        self.slots_off + slot as u64 * (SLOT_HEADER + u64::from(self.slot_cap))
    }

    fn read_slot(&self, slot: usize) -> Option<(u64, Vec<u8>)> {
        let mut sh = [0u8; SLOT_HEADER_BYTES];
        self.handle
            .read_exact_at(&mut sh, self.slot_off(slot))
            .ok()?;
        let generation = u64::from_le_bytes(sh[0..8].try_into().ok()?);
        let len = u32::from_le_bytes(sh[8..12].try_into().ok()?);
        let crc = u32::from_le_bytes(sh[12..16].try_into().ok()?);
        if generation == 0 || len > self.slot_cap {
            return None;
        }
        let mut payload = vec![0u8; len as usize];
        self.handle
            .read_exact_at(&mut payload, self.slot_off(slot) + SLOT_HEADER)
            .ok()?;
        (slot_crc(generation, &payload) == crc).then_some((generation, payload))
    }

    /// Durably record `payload` as the newest checkpoint.
    pub fn write(&mut self, payload: &[u8]) -> Result<()> {
        let _prof = trunc_prof::span("journal.write").bytes(payload.len() as u64);
        if payload.len() > self.slot_cap as usize {
            return Err(JournalError::TooLarge {
                got: payload.len(),
                cap: self.slot_cap,
            });
        }
        let (generation, slot) = match self.latest {
            None => (1, 0),
            Some((g, s)) => (g + 1, 1 - s),
        };
        let mut buf = Vec::with_capacity(SLOT_HEADER_BYTES + payload.len());
        buf.extend_from_slice(&generation.to_le_bytes());
        buf.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("<= slot_cap")
                .to_le_bytes(),
        );
        buf.extend_from_slice(&slot_crc(generation, payload).to_le_bytes());
        buf.extend_from_slice(payload);
        self.handle.write_all_at(&buf, self.slot_off(slot))?;
        self.handle.flush_data()?;
        self.latest = Some((generation, slot));
        Ok(())
    }

    /// Identity of the journal file (so callers can refuse to write to it by another name).
    pub fn file_id(&self) -> Result<trunc_fs::FileId> {
        Ok(self.handle.file_id()?)
    }

    /// Delete a journal (after the job is complete).
    pub fn remove(self, fs: &dyn FsBackend, path: &Path) -> Result<()> {
        drop(self.handle);
        match fs.remove_file(path) {
            Ok(()) | Err(FsError::NotFound { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        fs.flush_dir(&parent_of(path))?;
        Ok(())
    }
}

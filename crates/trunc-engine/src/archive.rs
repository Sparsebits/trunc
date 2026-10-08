//! Opening and reading `.trnc` archives, including partially consumed ones.

use std::path::{Path, PathBuf};

use trunc_codec::Dict;
use trunc_core::manifest::OpenedManifest;
use trunc_core::stream::LogicalStream;
use trunc_core::{FOOTER_LEN, Footer, HEADER_LEN, Header, Manifest, SignedManifest};
use trunc_fs::{FileHandle, FsBackend, OpenMode, OsFs, Share};

use crate::error::{Error, Result};
use crate::io::len_usize;

/// An open archive. All reads go through a [`FileHandle`], so the same code runs on the real
/// filesystem and on the fault-injecting test filesystem.
#[derive(Debug)]
pub struct Archive {
    path: PathBuf,
    handle: Box<dyn FileHandle>,
    header: Header,
    opened: OpenedManifest,
    dict: Option<Dict>,
    offsets: Vec<u64>,
    file_len: u64,
    consumed: usize,
    stream: LogicalStream,
}

impl Archive {
    /// Open read-only on the real filesystem and fully validate it (see [`Archive::open_with`]).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(&OsFs::new(), path, OpenMode::Read, Share::Shared)
    }

    /// Open and fully validate the header, manifest (incl. signature) and dictionary, and work
    /// out how many blocks have been consumed from the current file length.
    pub fn open_with(
        fs: &dyn FsBackend,
        path: &Path,
        mode: OpenMode,
        share: Share,
    ) -> Result<Self> {
        let handle = fs.open(path, mode, share)?;
        let file_len = handle.size()?;
        if file_len < HEADER_LEN as u64 {
            return Err(Error::Integrity(format!(
                "{} is too short to be a .trnc archive ({file_len} bytes)",
                path.display()
            )));
        }
        let mut hb = [0u8; HEADER_LEN];
        handle.read_exact_at(&mut hb, 0)?;
        let header = Header::decode(&hb)?;
        if header.first_block_off() > file_len {
            return Err(Error::Integrity(format!(
                "archive is shorter ({file_len} bytes) than its header and manifest ({})",
                header.first_block_off()
            )));
        }

        let mut mb = vec![0u8; len_usize(header.manifest_len)];
        handle.read_exact_at(&mut mb, header.manifest_off())?;
        header.check_manifest(&mb)?;
        let opened = SignedManifest::open(&mb)?;
        let m = &opened.manifest;

        let dict = match (&m.dict, header.dict_len) {
            (None, 0) => None,
            (Some(info), len) if info.len == len => {
                let mut db = vec![0u8; len_usize(len)];
                handle.read_exact_at(&mut db, header.dict_off())?;
                if trunc_hash::blake3(&db) != info.blake3 {
                    return Err(Error::Integrity("dictionary hash mismatch".into()));
                }
                Some(Dict(db))
            }
            _ => {
                return Err(Error::Integrity(
                    "header dictionary length does not match manifest".into(),
                ));
            }
        };

        let fbo = header.first_block_off();
        let consumed = m.consumed_blocks(fbo, file_len).ok_or_else(|| {
            Error::Integrity(format!(
                "archive length {file_len} is not at a block boundary (expected {} when complete); the file is truncated, extended or corrupt",
                m.archive_len(fbo)
            ))
        })?;
        let offsets = m.block_offsets(fbo);
        let stream = LogicalStream::new(m);
        Ok(Self {
            path: path.to_path_buf(),
            handle,
            header,
            opened,
            dict,
            offsets,
            file_len,
            consumed,
            stream,
        })
    }

    /// The underlying handle (the consumer truncates and flushes through it).
    pub(crate) fn handle(&self) -> &dyn FileHandle {
        self.handle.as_ref()
    }

    /// Record that the file was truncated to just past `consumed` blocks.
    pub(crate) fn note_consumed(&mut self, consumed: usize) {
        self.consumed = consumed;
        self.file_len = self
            .manifest()
            .len_after_consuming(self.header.first_block_off(), consumed);
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn manifest(&self) -> &Manifest {
        &self.opened.manifest
    }

    /// BLAKE3 of the manifest body; identifies this archive's contents.
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.opened.hash
    }

    /// Public key of a valid signature, if signed.
    pub fn signer(&self) -> Option<[u8; 32]> {
        self.opened.signer
    }

    pub fn dict(&self) -> Option<&Dict> {
        self.dict.as_ref()
    }

    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// Number of blocks already consumed (truncated away), starting from block 0.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    pub fn is_complete(&self) -> bool {
        self.consumed == 0
    }

    pub fn stream(&self) -> &LogicalStream {
        &self.stream
    }

    /// Absolute file offset of block `i`'s payload.
    pub fn block_offset(&self, i: usize) -> u64 {
        self.offsets[i]
    }

    fn check_present(&self, i: usize) -> Result<()> {
        if i >= self.manifest().blocks.len() {
            return Err(Error::Input(format!("block {i} does not exist")));
        }
        if i < self.consumed {
            return Err(Error::Input(format!("block {i} has already been consumed")));
        }
        Ok(())
    }

    /// Read block `i`'s footer and check it against the manifest.
    pub fn read_footer(&self, i: usize) -> Result<Footer> {
        self.check_present(i)?;
        let b = &self.manifest().blocks[i];
        let mut fb = [0u8; FOOTER_LEN];
        self.handle
            .read_exact_at(&mut fb, self.offsets[i] + b.c_len)?;
        let f = Footer::decode(&fb)?;
        self.manifest().check_footer(i, &f)?;
        Ok(f)
    }

    /// Read block `i`'s payload and check its BLAKE3 against the footer and manifest.
    pub fn read_payload(&self, i: usize) -> Result<Vec<u8>> {
        let f = self.read_footer(i)?;
        let mut payload = vec![0u8; len_usize(f.c_len)];
        self.handle.read_exact_at(&mut payload, self.offsets[i])?;
        if trunc_hash::blake3(&payload) != f.blake3_c {
            return Err(Error::Integrity(format!("block {i} payload hash mismatch")));
        }
        Ok(payload)
    }

    /// Read, verify and decompress block `i`, checking the decoded BLAKE3.
    pub fn decode_block(&self, i: usize) -> Result<Vec<u8>> {
        let payload = self.read_payload(i)?;
        let b = &self.manifest().blocks[i];
        let codec = trunc_core::CodecId::try_from(b.codec)?;
        let mut out = vec![0u8; len_usize(b.u_len)];
        trunc_codec::decompress(codec, &payload, &mut out, self.dict.as_ref())?;
        if trunc_hash::blake3(&out) != b.blake3_u {
            return Err(Error::Integrity(format!("block {i} decoded hash mismatch")));
        }
        Ok(out)
    }
}

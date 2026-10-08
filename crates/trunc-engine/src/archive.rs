//! Opening and reading `.trnc` archives, including partially consumed ones.

use std::fs::File;
use std::path::{Path, PathBuf};

use trunc_codec::Dict;
use trunc_core::manifest::OpenedManifest;
use trunc_core::stream::LogicalStream;
use trunc_core::{FOOTER_LEN, Footer, HEADER_LEN, Header, Manifest, SignedManifest};

use crate::error::{Error, IoContext, Result, at};
use crate::io::{len_usize, read_exact_at};

/// An open archive. Holds a read-only handle; the file must not change while it is open.
#[derive(Debug)]
pub struct Archive {
    path: PathBuf,
    file: File,
    header: Header,
    opened: OpenedManifest,
    dict: Option<Dict>,
    offsets: Vec<u64>,
    file_len: u64,
    consumed: usize,
    stream: LogicalStream,
}

impl Archive {
    /// Open and fully validate the header, manifest (incl. signature) and dictionary, and work
    /// out how many blocks have been consumed from the current file length.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).ctx(at("opening", path))?;
        let file_len = file.metadata().ctx(at("reading metadata of", path))?.len();
        if file_len < HEADER_LEN as u64 {
            return Err(Error::Integrity(format!(
                "{} is too short to be a .trnc archive ({file_len} bytes)",
                path.display()
            )));
        }
        let mut hb = [0u8; HEADER_LEN];
        read_exact_at(&file, &mut hb, 0).ctx(at("reading header of", path))?;
        let header = Header::decode(&hb)?;
        if header.first_block_off() > file_len {
            return Err(Error::Integrity(format!(
                "archive is shorter ({file_len} bytes) than its header and manifest ({})",
                header.first_block_off()
            )));
        }

        let mut mb = vec![0u8; len_usize(header.manifest_len)];
        read_exact_at(&file, &mut mb, header.manifest_off())
            .ctx(at("reading manifest of", path))?;
        header.check_manifest(&mb)?;
        let opened = SignedManifest::open(&mb)?;
        let m = &opened.manifest;

        let dict = match (&m.dict, header.dict_len) {
            (None, 0) => None,
            (Some(info), len) if info.len == len => {
                let mut db = vec![0u8; len_usize(len)];
                read_exact_at(&file, &mut db, header.dict_off())
                    .ctx(at("reading dictionary of", path))?;
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
                "archive length {file_len} is not at a block boundary (expected {} when complete); \
                 the file is truncated, extended or corrupt",
                m.archive_len(fbo)
            ))
        })?;
        let offsets = m.block_offsets(fbo);
        let stream = LogicalStream::new(m);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            header,
            opened,
            dict,
            offsets,
            file_len,
            consumed,
            stream,
        })
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
        read_exact_at(&self.file, &mut fb, self.offsets[i] + b.c_len)
            .ctx(at(&format!("reading footer of block {i} in"), &self.path))?;
        let f = Footer::decode(&fb)?;
        self.manifest().check_footer(i, &f)?;
        Ok(f)
    }

    /// Read block `i`'s payload and check its BLAKE3 against the footer and manifest.
    pub fn read_payload(&self, i: usize) -> Result<Vec<u8>> {
        let f = self.read_footer(i)?;
        let mut payload = vec![0u8; len_usize(f.c_len)];
        read_exact_at(&self.file, &mut payload, self.offsets[i])
            .ctx(at(&format!("reading block {i} of"), &self.path))?;
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

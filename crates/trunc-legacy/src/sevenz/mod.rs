//! 7z archives: parsing and decoding for extraction.
//!
//! A 7z file is a 32-byte signature header, then the packed streams, then the header, which says
//! where the packed streams are and what they hold. The header is usually itself compressed (an
//! *encoded header*: a small folder whose output is the real header), so reading it already
//! needs a decoder.
//!
//! Content is grouped in *folders*: one packed stream run through a chain of coders, whose output
//! is the contents of one or more files back to back (several files per folder is a *solid*
//! archive). Supported coders are Copy, LZMA, LZMA2 and the BCJ x86 and Delta filters, in any
//! linear chain; everything else (PPMd, BZip2, BCJ2, ARM filters, AES encryption) is refused
//! with a message naming it.
//!
//! [`parse`] validates the whole header before anything is extracted: every count and size is
//! bounded by the bytes that could hold it, packed streams must lie inside the file, the coder
//! graph must be a simple chain, substream sizes must add up to their folder, and names follow
//! the same rules as ZIP and tar (see [`trunc_core::path::validate_host`]). [`decode_folder`]
//! then streams a folder's output file by file, checking every CRC.

mod folder;
mod header;

use trunc_fs::{FileHandle, FsError};

pub use folder::decode_folder;

/// The first six bytes of every 7z file.
pub const SIGNATURE: [u8; 6] = *b"7z\xBC\xAF\x27\x1C";

#[derive(Debug, thiserror::Error)]
pub enum SevenZError {
    #[error("not a 7z archive: {0}")]
    NotSevenZ(&'static str),
    #[error("unsupported 7z feature: {0}")]
    Unsupported(String),
    #[error("corrupt 7z archive: {0}")]
    Corrupt(String),
    /// Decoded data does not match its recorded CRC or size.
    #[error("{0}")]
    Crc(String),
    #[error("unsafe or invalid entry name {name:?}: {reason}")]
    Name { name: String, reason: String },
    #[error(transparent)]
    Fs(#[from] FsError),
    /// A sink asked to stop; the caller holds the reason.
    #[error("stopped by the caller")]
    Stopped,
}

pub type Result<T> = std::result::Result<T, SevenZError>;

fn corrupt(msg: impl Into<String>) -> SevenZError {
    SevenZError::Corrupt(msg.into())
}

/// A supported coder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Copy,
    Lzma,
    Lzma2,
    BcjX86,
    Delta,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Method::Copy => "Copy",
            Method::Lzma => "LZMA",
            Method::Lzma2 => "LZMA2",
            Method::BcjX86 => "BCJ",
            Method::Delta => "Delta",
        }
    }
}

/// One coder of a folder, with the size of what it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coder {
    pub method: Method,
    pub props: Vec<u8>,
    pub unpack_size: u64,
}

/// One folder: a packed stream, the coders that decode it, and the files its output holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// In decoding order: the first reads the packed stream, the last produces the output.
    pub coders: Vec<Coder>,
    /// Absolute offset of the packed stream in the file.
    pub pack_offset: u64,
    pub pack_size: u64,
    /// Size of the folder's output.
    pub unpack_size: u64,
    /// CRC-32 of the whole output, if recorded.
    pub crc: Option<u32>,
    /// Entries (indexes into [`Layout::entries`]) whose contents make up the output, in order.
    pub entries: Vec<usize>,
}

impl Folder {
    /// The coder chain as text, e.g. `BCJ+LZMA2`.
    pub fn methods(&self) -> String {
        let names: Vec<&str> = self.coders.iter().rev().map(|c| c.method.name()).collect();
        names.join("+")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// Unix symlink (the target is the entry's content). Never created by the extractor.
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Validated relative path, `/`-separated, NFC.
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub crc: Option<u32>,
    /// The folder holding the content (`None` for directories and empty files) and the
    /// content's offset in the folder's output.
    pub folder: Option<usize>,
    pub offset: u64,
    /// Unix permission bits, when the archive records them (as ZIP does, Windows attributes
    /// other than the directory bit are ignored).
    pub mode: Option<u32>,
    pub mtime_unix: i64,
    pub mtime_nanos: u32,
}

/// What [`parse`] learned about an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub file_len: u64,
    pub entries: Vec<Entry>,
    pub folders: Vec<Folder>,
    /// Whether the header was compressed.
    pub encoded_header: bool,
    /// Where the header starts (the packed streams lie before it).
    pub header_offset: u64,
    /// Anti-items (deletion markers of update archives), which are skipped.
    pub anti_items: usize,
}

impl Layout {
    /// Total size of all files.
    pub fn content_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.kind == Kind::File)
            .fold(0u64, |a, e| a.saturating_add(e.size))
    }

    /// Total size of the packed streams.
    pub fn packed_bytes(&self) -> u64 {
        self.folders
            .iter()
            .fold(0u64, |a, f| a.saturating_add(f.pack_size))
    }

    /// Whether some folder holds more than one file.
    pub fn solid(&self) -> bool {
        self.folders.iter().any(|f| f.entries.len() > 1)
    }
}

/// True if `head` starts with the 7z signature.
pub fn sniff(head: &[u8]) -> bool {
    head.starts_with(&SIGNATURE)
}

/// Parse and validate a 7z archive. `max_window` bounds every LZMA dictionary (memory), also
/// the one of a compressed header.
pub fn parse(src: &dyn FileHandle, max_window: u64) -> Result<Layout> {
    header::parse(src, max_window)
}

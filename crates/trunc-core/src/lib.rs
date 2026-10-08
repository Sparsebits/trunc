//! Types and wire formats for the `.trnc` self-consuming archive format.
//!
//! This crate performs no I/O. The normative description lives in
//! `docs/spec/trnc-format-v1.md`; the constants and layouts here must match it.
//!
//! File layout (all integers little-endian):
//!
//! ```text
//! [HEADER 96][MANIFEST manifest_len][DICT dict_len][BLOCK n-1][BLOCK n-2]...[BLOCK 0] <- EOF
//! BLOCK i = [payload c_len][FOOTER 128]
//! ```
//!
//! Block 0 covers the start of the logical stream and sits at end of file, so a consumer always
//! decodes the block at EOF and then truncates it away. The file length alone tells how many
//! blocks have been consumed.

mod bytes;
pub mod codec;
pub mod error;
pub mod footer;
pub mod header;
pub mod manifest;
pub mod path;
pub mod space;
pub mod stream;

pub use codec::CodecId;
pub use error::FormatError;
pub use footer::{FOOTER_LEN, Footer};
pub use header::{HEADER_LEN, Header};
pub use manifest::{BlockRecord, DictInfo, Entry, EntryKind, Manifest, SignedManifest};

/// Format version written by this crate and the only one it accepts.
pub const FORMAT_VERSION: u16 = 1;

/// Largest decoded size a single block may declare (1 GiB).
pub const MAX_BLOCK_U: u64 = 1 << 30;

/// Largest dictionary the header may reference (1 MiB).
pub const MAX_DICT_LEN: u64 = 1 << 20;

/// Largest manifest region accepted (256 MiB). Bounds memory use when opening hostile files.
pub const MAX_MANIFEST_LEN: u64 = 256 << 20;

/// Upper bound for a block's stored size given its decoded size, independent of codec.
/// Every supported codec's worst-case expansion is below this.
pub fn max_c_len(u_len: u64) -> u64 {
    u_len + u_len / 128 + 4096
}

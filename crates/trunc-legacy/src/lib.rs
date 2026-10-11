//! Destructive extraction support for existing archive formats.
//!
//! - [`inflate`]: a DEFLATE decoder that checkpoints at block boundaries, so decoding can resume
//!   after the compressed bytes before the checkpoint have been deallocated (punch mode).
//! - [`zip`]: ZIP parsing (EOCD, Zip64, central directory cross-checked against local headers)
//!   into entries with byte extents.
//! - [`gzip`] and [`tar`]: gzip member framing and a streaming tar reader, for `.tar.gz`.
//! - [`iso`]: ISO 9660 images (Rock Ridge, Joliet, multi-extent) as stored ZIP-style entries.
//! - [`stream`]: one resumable interface over the gzip, bzip2, xz and zstd decoders.

pub mod bzip2;
pub mod checks;
mod cp437;
pub mod gzip;
pub mod inflate;
pub mod iso;
mod lzma;
pub mod split;
pub mod stream;
pub mod tar;
pub mod xz;
pub mod zip;
pub mod zstd;

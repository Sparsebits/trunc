//! Destructive extraction support for existing archive formats.
//!
//! - [`inflate`]: a DEFLATE decoder that checkpoints at block boundaries, so decoding can resume
//!   after the compressed bytes before the checkpoint have been deallocated (punch mode).
//! - [`zip`]: ZIP parsing (EOCD, Zip64, central directory cross-checked against local headers)
//!   into entries with byte extents.
//! - [`gzip`] and [`tar`]: gzip member framing and a streaming tar reader, for `.tar.gz`.

mod cp437;
pub mod gzip;
pub mod inflate;
pub mod tar;
pub mod zip;

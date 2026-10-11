//! The trunc engine.
//!
//! - [`producer`] creates `.trnc` archives.
//! - [`archive`] opens and reads them, including partially consumed ones.
//! - [`extract`] performs non-destructive extraction and verification.
//! - [`keys`] manages Ed25519 signing keys.
//! - [`preflight`] checks space and safety for a destination before extracting or consuming.
//! - [`consume`] extracts destructively, truncating the archive as outputs become durable.
//! - [`zipconsume`] does the same for existing ZIP archives (with optional punch mode).
//! - [`streamconsume`] does the same for compressed tarballs and files (`.tar.gz`, `.tar.zst`,
//!   `.xz`, ...), freeing compressed bytes as they are decoded.
//! - [`sevenz`] inspects, verifies and extracts 7z archives (not destructively yet).

pub mod archive;
pub mod consume;
pub mod error;
pub mod extract;
mod io;
pub mod keys;
pub mod preflight;
pub mod producer;
pub mod sevenz;
pub mod source;
mod stage;
pub mod streamconsume;
mod walk;
pub mod zipconsume;

pub use archive::Archive;
pub use error::{Error, PauseReason, Result};
pub use trunc_core::space::{SpaceBound, SpaceParams};

/// Producer string written into new manifests.
pub const PRODUCER: &str = concat!("trunc/", env!("CARGO_PKG_VERSION"));

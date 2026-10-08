//! The trunc engine.
//!
//! - [`producer`] creates `.trnc` archives.
//! - [`archive`] opens and reads them, including partially consumed ones.
//! - [`extract`] performs non-destructive extraction and verification.
//! - [`keys`] manages Ed25519 signing keys.
//! - [`preflight`] checks space and safety for a destination before extracting or consuming.
//!
//! The destructive consumer, staging and recovery arrive in phase 3 on top of `trunc-fs`.

pub mod archive;
pub mod error;
pub mod extract;
mod io;
pub mod keys;
pub mod preflight;
pub mod producer;
mod walk;

pub use archive::Archive;
pub use error::{Error, Result};
pub use trunc_core::space::{SpaceBound, SpaceParams};

/// Producer string written into new manifests.
pub const PRODUCER: &str = concat!("trunc/", env!("CARGO_PKG_VERSION"));

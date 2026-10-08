use std::io;
use std::path::Path;

use trunc_codec::CodecError;
use trunc_core::FormatError;
use trunc_fs::FsError;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    /// Data does not match its recorded hash or length.
    #[error("integrity check failed: {0}")]
    Integrity(String),
    /// Bad input or arguments from the caller.
    #[error("{0}")]
    Input(String),
    /// The operation would be unsafe and was not attempted.
    #[error("refused: {0}")]
    Refused(String),
    #[error(transparent)]
    Fs(#[from] FsError),
    /// Consumption stopped safely and can be resumed later; nothing was lost.
    #[error("paused: {0}")]
    Paused(PauseReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PauseReason {
    /// The destination ran out of space mid-batch. Free at least `needed` bytes and resume.
    NoSpace { needed: u64 },
    /// Another process kept the archive memory-mapped, so it could not be truncated.
    Mapped,
}

impl std::fmt::Display for PauseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PauseReason::NoSpace { needed } => {
                write!(
                    f,
                    "out of space; free at least {needed} more bytes, then resume"
                )
            }
            PauseReason::Mapped => write!(
                f,
                "another program (often an antivirus or indexer) has the archive mapped; close                  it, then resume"
            ),
        }
    }
}

/// Attach context to I/O errors.
pub(crate) trait IoContext<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: what(),
            source,
        })
    }
}

pub(crate) fn at(action: &str, p: &Path) -> impl FnOnce() -> String {
    let s = format!("{action} {}", p.display());
    move || s
}

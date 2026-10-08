use thiserror::Error;

/// Errors from decoding or validating `.trnc` structures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("bad magic: not a .trnc {0}")]
    BadMagic(&'static str),
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("{0} checksum mismatch")]
    Checksum(&'static str),
    #[error("{what} has wrong length: expected {expected}, got {got}")]
    Length {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("unknown flags {flags:#x} in {what}")]
    UnknownFlags { what: &'static str, flags: u32 },
    #[error("unknown codec id {0}")]
    UnknownCodec(u16),
    #[error("inconsistent header: {0}")]
    Header(String),
    #[error("manifest decode failed: {0}")]
    ManifestDecode(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("invalid path {path:?}: {reason}")]
    Path { path: String, reason: &'static str },
    #[error("signature invalid")]
    Signature,
    #[error("footer does not match manifest for block {block}: {field}")]
    FooterMismatch { block: u32, field: &'static str },
}

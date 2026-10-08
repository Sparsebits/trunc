use std::io;
use std::path::{Path, PathBuf};

pub type Result<T, E = FsError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("{path}: not found")]
    NotFound { path: PathBuf },
    #[error("{path}: already exists")]
    AlreadyExists { path: PathBuf },
    /// Another process holds the file open in a conflicting way (Windows sharing violation).
    #[error("{path}: in use by another process")]
    Busy { path: PathBuf },
    /// Another process has the file memory-mapped, so it cannot be shrunk. Retryable.
    #[error("{path}: memory-mapped by another process, cannot truncate yet")]
    Mapped { path: PathBuf },
    #[error("{path}: no space left on device")]
    NoSpace { path: PathBuf },
    #[error("{path}: is a symlink, junction or other reparse point; not following it")]
    Link { path: PathBuf },
    #[error("{path}: {op} is not supported on this filesystem")]
    Unsupported { op: &'static str, path: PathBuf },
    /// Only produced by the fault-injecting test filesystem.
    #[error("simulated crash")]
    Crashed,
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl FsError {
    /// Classify an OS error from operation `op` on `path`.
    pub fn from_io(op: &'static str, path: &Path, e: io::Error) -> Self {
        let path = path.to_path_buf();
        match e.raw_os_error() {
            #[cfg(windows)]
            Some(1224) => return FsError::Mapped { path }, // ERROR_USER_MAPPED_FILE
            #[cfg(windows)]
            Some(32 | 33) => return FsError::Busy { path }, // sharing / lock violation
            #[cfg(windows)]
            Some(39 | 112) => return FsError::NoSpace { path }, // HANDLE_DISK_FULL, DISK_FULL
            #[cfg(unix)]
            Some(28) => return FsError::NoSpace { path }, // ENOSPC
            // O_NOFOLLOW and RESOLVE_NO_SYMLINKS report a link in the way as ELOOP.
            #[cfg(unix)]
            Some(n) if n == rustix::io::Errno::LOOP.raw_os_error() => {
                return FsError::Link { path };
            }
            _ => {}
        }
        match e.kind() {
            io::ErrorKind::NotFound => FsError::NotFound { path },
            io::ErrorKind::AlreadyExists => FsError::AlreadyExists { path },
            io::ErrorKind::StorageFull => FsError::NoSpace { path },
            _ => FsError::Io {
                op,
                path,
                source: e,
            },
        }
    }

    /// Worth retrying after a short wait.
    pub fn is_retryable(&self) -> bool {
        matches!(self, FsError::Busy { .. } | FsError::Mapped { .. })
    }
}

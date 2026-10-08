//! Filesystem backend abstraction.
//!
//! Phase 2 fills this crate with the `FsBackend` trait, the Windows backend (NTFS sparse files,
//! `FlushFileBuffers`, `FILE_ID_INFO`, end-of-file truncation with mapped-section retry), a
//! std-only generic backend, and volume probing (filesystem kind, cluster size, free space,
//! cloud-sync and snapshot hints). This is the only crate permitted to contain `unsafe` code.

# ADR-0004: Windows (NTFS) is the first-class platform; Linux follows

Status: accepted (2026-10-08). The Linux backend landed in phase 5; see ADR-0010.

## Decision
The development machine and first target are Windows 10/11 on NTFS. CI runs both Windows and Linux from the start. The Linux filesystem backend (rustix: `fdatasync`, `fsync` of directories, `fallocate` hole punching, `openat2`) lands in phase 5, after the Windows backend (phase 2) and the native consumer (phase 3).

## Consequences
- OS-specific code is confined to `trunc-fs`, behind the `FsBackend` trait. Engine logic is tested on both platforms through the generic backend and `FaultFs`.
- Real-filesystem tests run on NTFS first. ext4 joins in phase 5.

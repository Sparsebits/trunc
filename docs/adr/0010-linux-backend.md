# ADR-0010: The Linux backend

Status: accepted (2026-10-09). Plan phase 5.

## Context
Until phase 5, Linux ran the engine through std alone. It had no hole punching, so ZIP punch mode
fell back to whole entries. Space reservation only set the file size, so running out of space
surfaced mid-write. The no-replace rename and the symlink check were both check-then-act races, and
nothing stopped two trunc processes from consuming the same archive.

## Decision
`trunc-fs` gains a `linux` module built on rustix's safe wrappers (no `unsafe`):

| Need | Call | When it is missing |
|---|---|---|
| Free space inside a ZIP entry | `fallocate(PUNCH_HOLE \| KEEP_SIZE)` | `Dealloc::Unsupported`; the engine extracts whole entries |
| Report what is still allocated | `lseek(SEEK_DATA / SEEK_HOLE)` | the whole file counts as allocated |
| Reserve output space up front | `fallocate(0)` | `ftruncate`, as before |
| Open staged outputs without following links | `openat2(RESOLVE_BENEATH \| RESOLVE_NO_SYMLINKS \| RESOLVE_NO_MAGICLINKS)` from the staging directory | per-component check, then open |
| Never replace on rename | `renameat2(RENAME_NOREPLACE)` | check, then rename |
| Read back from the device (`--verify-media`) | `O_DIRECT` with 4 KiB-aligned buffers | `posix_fadvise(DONTNEED)` on the flushed range, then a normal read |
| `Share::Exclusive` | `flock(LOCK_EX \| LOCK_NB)` for writers, `LOCK_SH` for readers | no lock (some network filesystems) |
| Volume facts | `statfs` magic, then `/proc/self/mountinfo` for the mount point, the name of unknown types, and the device | `FsKind::Unknown` |

- "Missing" means ENOSYS, EOPNOTSUPP or EPERM (container seccomp profiles answer unknown
  syscalls with ENOSYS or, in older ones, EPERM), plus EINVAL where the kernel uses it to reject
  an unsupported flag. Any other error is a real failure and is reported.
- Holes are promised only on ext4, XFS, btrfs and ZFS. The release unit is taken from `statvfs`
  `f_bsize` (4 KiB on ext4 and XFS; the record size on ZFS).
- Anything not recognised is treated as unjournaled. That includes 9p (WSL's view of Windows
  drives), NFS and FUSE, so `--consume` there needs `--allow-unjournaled`. Network and FUSE
  filesystems give no clear guarantee about the order in which flushed data and size changes reach the disk.
- btrfs, ZFS and device-mapper volumes get a snapshot warning: a snapshot keeps freed blocks
  allocated, so consumption may save nothing.

## Consequences
- ZIP punch mode, early `ENOSPC`, race-free confinement of staged outputs and no-replace renames
  now work on Linux as they do on Windows. The kill/resume punch test and the `--verify-media`
  test run against real ext4.
- `flock` is advisory. It stops a second trunc, not other programs. That limit is recorded in
  `docs/security.md`.
- FAT32 and exFAT are tested on loop-mounted images in CI (`unjournaled` job). An aarch64 build
  runs in CI (`aarch64-linux` job).

# Changelog

All notable changes to trunc. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may
change the command line; the `.trnc` v1 format is frozen.

## [Unreleased]

### Added
- `.tar.bz2`, `.tar.xz` and `.tar.zst`, alongside `.tar.gz`: `x`, `inspect`, `verify`, `plan`,
  `--consume` and `resume`. trunc has its own resumable bzip2, xz (LZMA2) and zstd decoders, so
  consuming frees space every 64 MiB on any file, not just at frame boundaries. Files made by
  `pigz`, `pbzip2`, `xz -T0`, `pzstd` and `zstd --long` work.
- Single compressed files (`disk.img.xz`, `dump.sql.gz`, `model.bin.zst`, `notes.bz2`) are
  decompressed into one file named without the suffix, with or without `--consume`. `--raw`
  does the same for a tarball (`big.tar.zst` becomes `big.tar`).
- Split archives: pass the first part (`name.001` or `name.aa`) and the parts are read as one
  file, for every format. With `--consume`, compressed tarballs and files delete each part once
  its data is extracted, which frees space even on FAT32 and exFAT.
- `--max-window` (default 256M) refuses xz and zstd archives whose decoder would need more memory.

### Changed
- On Linux and macOS, tar and ZIP entries may use names that only Windows forbids (backslashes,
  colons, trailing dots, `CON`), and on Linux names that differ only in case are separate files.
  Real Linux tarballs, including the kernel source, failed before. Windows keeps the portable
  rules, and `.trnc` archives always use them.
- The journal for compressed archives is now `TSJP1`; `.tar.gz` consumes paused by 0.1.0 still
  resume.

## [0.1.0] - 2026-10-09

The first release.

### Archives
- `trunc create` packs files and directories into a `.trnc` archive. Blocks are independent zstd
  (default level 9), lz4 or uncompressed frames, 8 MiB by default, with an optional trained
  dictionary.
- Every block and entry is hashed with BLAKE3 under a Merkle root. Archives can be signed with
  Ed25519 (`trunc key gen`, `--sign`, `--require-signed`, `--trust-key`).
- `trunc inspect`, `trunc verify` and `trunc plan` show what is inside, check every hash, and work
  out the free space each kind of extraction needs.

### Extracting while freeing the archive
- `trunc x --consume` extracts a `.trnc` archive and shrinks it as each batch of files reaches the
  disk, so it needs about *output size minus archive size* of free space. On a 10 GiB test it
  peaked at 4.32 GiB, where a normal extract needs 10 GiB.
- It is crash-safe: data is flushed before the archive bytes holding it are released, and the
  archive's length records progress. `trunc resume` continues after a crash, a kill or a full disk
  (exit code 75).
- Files are written to a hidden staging folder and moved into place at the end.
  `--verify-media` re-reads them from the disk, not the cache, before anything is released.

### Existing ZIP files
- `trunc x big.zip --consume` works on Stored and Deflate ZIPs, including Zip64 and data
  descriptors. Every CRC is checked before anything is deleted, and the layout is kept in a small
  journal.
- Punch mode frees space inside large entries while they decompress, using a Deflate decoder that
  saves its position every 64 MiB of output.
- Overlapping entries (a zip-bomb technique) are refused unless you pass `--allow-overlap`.

### Existing .tar.gz files
- `trunc x big.tar.gz --consume` frees the compressed bytes from the front of the archive as
  they are decoded. A read-only pass first checks every gzip CRC, tar header and name; each
  64 MiB stretch of output must then hash as it did in that pass before its compressed bytes are
  released.
- `x`, `inspect`, `verify`, `plan` and `resume` all handle `.tar.gz`: ustar, GNU long names, PAX,
  base-256 sizes and several gzip members. Hard links, sparse files and multi-volume archives are
  refused for now; symlinks and device entries are skipped.

### Safety checks
- Hostile paths are refused: absolute paths, `..`, drive letters, device names, alternate data
  streams. Links are never followed when writing, and outputs that are hard links to the archive
  are refused. Entries whose names the filesystem would fold together (8.3 short names, case
  variants) are refused instead of merged.
- Destructive mode refuses archives in OneDrive, Dropbox, Google Drive or iCloud folders, and on
  FAT32, exFAT and filesystems it cannot identify such as network shares and FUSE (override with
  `--allow-sync` or `--allow-unjournaled`). It warns about snapshots, which keep freed space
  allocated.
- `--require-signed` and `--trust-key` apply to `.trnc` only; they are refused for ZIP and
  `.tar.gz`, which carry no signatures.

### Platforms
- Windows (NTFS) and Linux (ext4, XFS, btrfs, ZFS), both with every feature. Prebuilt binaries
  for Windows x64, Linux x64 and Linux ARM64. The Linux builds are static and run on any
  distribution.
- Install scripts: `install.sh` (Linux) and `install.ps1` (Windows). Both verify the download's
  SHA-256 before installing.

[Unreleased]: https://github.com/Sparsebits/trunc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Sparsebits/trunc/releases/tag/v0.1.0

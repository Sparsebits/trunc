# Changelog

All notable changes to trunc. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may
change the command line; the `.trnc` v1 format is frozen.

## [0.1.0] - 2026-10-11

The first release.

### Archives
- `trunc create` packs files and directories into a `.trnc` archive. Blocks are independent zstd
  (default level 9), lz4 or uncompressed frames, 8 MiB by default, with an optional trained
  dictionary.
- Every block and entry is hashed with BLAKE3 under a Merkle root. Archives can be signed with
  Ed25519 (`trunc key gen`, `--sign`, `--require-signed`, `--trust-key`).
- `trunc inspect`, `trunc verify` and `trunc plan` show what is inside, check every hash, and work
  out the free space each kind of extraction needs.
- `--profile FILE` (or `TRUNC_PROFILE`) on any command prints where the time went (self and
  total time, bytes and throughput per span) and writes a Chrome trace for Perfetto.

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
- Entries compressed with bzip2 (method 12), zstd (93) and xz (95) are extracted and consumed
  with trunc's own decoders, each CRC-checked; they are freed once the whole entry is out.
  LZMA (14), PPMd and other methods are refused by name.

### ISO images
- `trunc x image.iso` (and `inspect`, `verify`, `plan`, `--consume`, `resume`) for ISO 9660
  images, using the ZIP consumer's journal, punch mode and crash recovery. Names come from Rock
  Ridge, then Joliet, then plain ISO 9660 with `;1` removed; relocated directories and
  multi-extent files are supported. ISO has no checksums, so `--consume` computes a CRC-32 of
  every file first and checks it again before releasing its bytes.
- Hostile images are refused: directory loops, extents outside the file, file data over
  directory records, absurd counts, depths or name totals, and unsafe names. Files that share
  data (hard links) extract normally and need `--allow-overlap` to consume. Images whose resource
  forks or device entries would be skipped need `--allow-skipped` to consume. UDF-only images get
  a clear refusal.

### Uncompressed tar and 7z
- Plain `.tar` files: `x`, `--consume`, `resume`, `inspect`, `verify` and `plan`, consumed like
  ISO images (punch mode, crash-safe resume, a CRC pass up front).
- `.7z` archives: `x`, `inspect`, `verify` and `plan`, including split `.7z.001` sets. Copy,
  LZMA, LZMA2, BCJ x86 and Delta; solid and non-solid; compressed headers. Every CRC is checked,
  and files are moved into place only once the whole archive has decoded cleanly. Encrypted
  archives and other methods (PPMd, BZip2, BCJ2, ARM filters) are refused by name; `--consume`
  is not supported for 7z yet.

### Existing compressed tarballs and files
- `trunc x big.tar.zst --consume` (also `.tar.gz`, `.tar.xz`, `.tar.bz2`) frees the compressed
  bytes from the front of the archive as they are decoded. A read-only pass first checks every
  codec checksum, tar header and name; each 64 MiB stretch of output must then hash as it did in
  that pass before its compressed bytes are released.
- trunc has its own resumable gzip, bzip2, xz (LZMA2) and zstd decoders, so it frees space every
  64 MiB on any file, not just at frame boundaries. Files made by `pigz`, `pbzip2`, `xz -T0`,
  `pzstd` and `zstd --long` work. bzip2 blocks, multi-block xz streams and zstd frames that
  declare their size decode on all cores.
- Single compressed files (`disk.img.xz`, `dump.sql.gz`, `model.bin.zst`, `notes.bz2`) are
  decompressed into one file named without the suffix, with or without `--consume`. `--raw`
  does the same for a tarball (`big.tar.zst` becomes `big.tar`).
- Split archives: pass the first part (`name.001` or `name.aa`) and the parts are read as one
  file, for every format. With `--consume`, compressed tarballs and files delete each part once
  its data is extracted, which frees space even on FAT32 and exFAT.
- `x`, `inspect`, `verify`, `plan` and `resume` all handle them: ustar, GNU long names, PAX,
  base-256 sizes, several gzip members or zstd frames, concatenated xz and bzip2 streams.
  `--max-window` (default 256M) refuses xz and zstd archives whose decoder would need more memory.
- Hard links are recreated as real hard links (copies on FAT and exFAT), made from the staged
  files after everything is decoded, so a crash or `trunc resume` still gives the complete tree.
  Sparse files (old GNU and PAX 0.0, 0.1 and 1.0) keep their holes. Multi-volume archives are
  refused; symlinks and device entries are skipped.
- BGZF files (bgzip, samtools, htslib) decode on all cores, about 4.9x faster on 16 threads.
  On one core, gzip decodes at about 500 MB/s, zstd at 600-680 MB/s, and xz about 12% faster than
  before.

### Container images
- `trunc x image.tar` extracts the merged root filesystem of a `docker save` or OCI archive
  (also gzip, bzip2, xz or zstd compressed), applying layers in order with OCI whiteouts and
  opaque directories. Files that later layers delete or replace are never written.
  `--platform OS/ARCH[/VARIANT]` and `--image NAME` choose from multi-platform or multi-image
  archives.
- `trunc inspect` shows an image's tags, platform and layers; `--entries` lists the merged tree.
  `trunc verify` checks every blob digest, diff_id and layer tar header.
- On Windows, paths whose names Windows cannot hold (`:` in man pages, trailing dots, device
  names) are skipped and listed instead of refusing the image; on Windows and macOS, names that
  differ only in case are all skipped and listed. Hostile names still refuse the image.
- Images refuse `--consume` (it would save no space), `--overwrite`, hard links in layers and
  paths through a lower layer's symlink; symlinks and device nodes are skipped, so the result is
  for inspecting and copying files, not a runnable root.

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
  compressed tarballs, which carry no signatures.
- On Linux and macOS, tar and ZIP entries may use names that only Windows forbids (backslashes,
  colons, trailing dots, `CON`), and on Linux names that differ only in case are separate files,
  so real Linux tarballs such as the kernel source extract. Windows keeps the portable rules,
  and `.trnc` archives always use them.
- Names are compared the way NTFS compares them (so `file` and `fıle`, `s` and `ſ` are the same
  file) before anything is freed. On Linux, a case-insensitive destination (casefold ext4,
  mounted NTFS, FAT, exFAT or SMB) is detected up front and gets the same check.
- Reserved device names include `CONIN$`, `CONOUT$` and `COM¹`–`LPT³`, and an archive may not
  contain trunc's own staging folder or sidecar names.
- The staging folder is pinned while trunc runs, so another process cannot swap it for a link;
  file modes are never applied through a link; on Windows, anything created through a junction
  is removed through its own handle.
- Memory stays bounded on hostile input: decoded blocks in flight are capped (512 MiB for
  `.trnc`), parallel decoders never trust a declared size beyond what they check, and parsers cap
  name totals and entry counts.

### Platforms
- Windows (NTFS) and Linux (ext4, XFS, btrfs, ZFS), both with every feature. Prebuilt binaries
  for Windows x64, Windows ARM64, Linux x64 and Linux ARM64. The Linux builds are static and run
  on any distribution.
- Install scripts: `install.sh` (Linux) and `install.ps1` (Windows). Both verify the download's
  SHA-256 before installing and, if the GitHub CLI is installed, its build provenance.
- Releases are built with a pinned toolchain into reproducible archives, with a CycloneDX SBOM
  per target.

### Built on trunc
- [ci-restore](flavors/ci-restore/): a GitHub Action and script that restore big CI caches and
  artifacts without doubling runner disk.
- [weightdrop](crates/flavors/weightdrop/): unpacks sharded model weights and datasets (WebDataset,
  `-00001-of-00042` sets) one shard after another, planning the whole set's space first.
- [layerless](crates/flavors/layerless/): pulls a container image straight from a registry into a
  root filesystem, with no tarball and no daemon.

[0.1.0]: https://github.com/Sparsebits/trunc/releases/tag/v0.1.0

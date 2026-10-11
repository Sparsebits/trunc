<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.png">
    <img alt="trunc: extract huge archives without the free space" src="docs/assets/banner-light.png" width="100%">
  </picture>
</p>

<p align="center"><b>Unpack archives that are bigger than your free space.</b></p>

<p align="center">
  <a href="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Sparsebits/trunc/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-ff5b35"></a>
  <img alt="Rust 1.85+" src="https://img.shields.io/badge/rust-1.85%2B-121212">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-121212">
  <img alt="Status: pre-release" src="https://img.shields.io/badge/status-pre--release-c93a17">
</p>

<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#supported-formats">Formats</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#performance">Performance</a> ·
  <a href="docs/guide.md">User guide</a>
</p>

---

trunc extracts an archive while giving its disk space back. It deletes each part of the archive
as soon as the files from that part are safely on disk, so unpacking a 50 GB archive takes about
as much disk as its contents, not the archive and its contents together.

An ordinary extractor keeps the whole archive until it finishes: turning a 6 GB archive into
10 GB of files needs 10 GB free. With trunc, the same job needs a little over 4 GB. If the power
goes out halfway, nothing is lost: run `trunc resume` and it carries on where it stopped.

## Highlights

- **Less space.** You need about *output size minus archive size* free, not the full output size.
- **Safe to interrupt.** A part of the archive is released only after the files it produced are
  verified and flushed to disk. `trunc resume` continues after a crash, a kill or a full disk.
- **Plans first.** `trunc plan` tells you how much space each mode needs, and warns about
  cloud-sync folders, snapshots and filesystems where consuming an archive is unsafe.
- **Works on the archives you have.** ZIP, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, single
  compressed files and split tarballs all give space back while they decompress, not just when
  each file finishes. Container images (`docker save`, OCI) extract to their merged root
  filesystem.
- **Checks everything.** Every block is hashed and archives can be signed. Nothing is deleted
  until the output that replaces it has been verified.
- **Fast.** `.trnc` blocks decompress in parallel at over 1 GiB/s, and bzip2, multi-block xz and
  multi-frame zstd files decode on all cores too.
- **Windows and Linux.** Every feature on NTFS, ext4, XFS, btrfs and ZFS. The Linux builds are
  static and run on any distribution.

## Installation

On Linux (x86-64 or ARM64, any distribution):

```sh
curl -LsSf https://raw.githubusercontent.com/Sparsebits/trunc/main/install.sh | sh
```

On Windows:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Sparsebits/trunc/main/install.ps1 | iex"
```

Both scripts download the latest release, check its SHA-256, and install `trunc` to `~/.local/bin`
or `%LOCALAPPDATA%\Programs\trunc`. Set `TRUNC_VERSION=v0.1.0` to pin a version, or
`TRUNC_INSTALL_DIR` to install somewhere else. If the [GitHub CLI](https://cli.github.com) is
installed, they also check the release's signed build provenance (see
[Verifying downloads](docs/security.md#verifying-downloads)).

You can also download the archives yourself from
[Releases](https://github.com/Sparsebits/trunc/releases), or build from source with Rust 1.85 or
newer:

```sh
cargo install --git https://github.com/Sparsebits/trunc trunc-cli
```

## Quick start

Pack a folder:

```console
$ trunc create data.trnc ./data
created   data.trnc
entries   12
blocks    96
size      768.00 MiB -> 256.08 MiB (33.3% of original)
time      2.67s (288.09 MiB/s)
```

Before extracting, ask what it will cost:

```console
$ trunc plan data.trnc -C ./out
destination   C:\ NTFS (journaled, cluster 4.00 KiB), 6.54 GiB free
archive now   256.08 MiB
content       768.00 MiB to write

free space needed at the destination:
  extract (keeps archive)     787.89 MiB   fits
  consume (--consume)         531.85 MiB   fits   (peak occupancy 787.93 MiB, 3 batches)
  consume saves 256.03 MiB (32.5%)
```

Then extract it. `--consume` is the destructive part: the archive shrinks as the files appear,
and only a small receipt holding the archive's manifest is left at the end.

```console
$ trunc x data.trnc -C ./out --consume
all blocks consumed; moving files into place
extracted 9 files, 3 directories, 768.00 MiB into ./out
archive   consumed; receipt kept at data.trnc.receipt
time      1.52s (3 batches)
```

The same command works on ZIP files, compressed tarballs and single compressed files. Without
`--consume`, `trunc x` is an ordinary extractor and leaves the archive alone. If a consume is
interrupted, continue it with:

```sh
trunc resume data.trnc
```

<details>
<summary><b>More commands</b></summary>

```sh
trunc create data.trnc ./data --codec lz4 --block-size 4M   # faster, larger archive
trunc inspect data.trnc --entries --blocks                  # what's inside
trunc verify data.trnc                                      # check every hash, write nothing
trunc x data.trnc -C ./out --consume --verify-media         # re-read files from disk before deleting
trunc x big.tar.zst -C ./out --consume                      # free a compressed tarball as it unpacks
trunc x image.tar -C ./rootfs                               # a docker save image's root filesystem

trunc key gen me.key                                        # sign archives
trunc create data.trnc ./data --sign me.key
trunc x data.trnc -C ./out --require-signed --trust-key <public key>
```

Run `trunc <command> --help` for every flag, or see the
[commands and options](docs/guide.md#commands-and-options) in the user guide.

</details>

## Supported formats

| Format | Extract | `--consume` | Space comes back |
|---|---|---|---|
| `.trnc` | yes | yes | from the end, after each batch of blocks |
| ZIP (Stored, Deflate, Zip64) | yes | yes | from the end, after each group of entries, and every 64 MiB inside entries of 256 MiB or more |
| `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst` | yes | yes | from the front, every 64 MiB of output, or after each block or frame decoded in parallel |
| Single files: `.gz`, `.bz2`, `.xz`, `.zst` | yes | yes | the same as tarballs |
| Compressed tarballs and files split into `.001` or `.aa` parts | yes | yes | as above, and each part is deleted once its data is safe |
| ZIP and `.trnc` split into parts | yes | not yet | — |
| Container images (`docker save`, OCI archives) | yes | no | — |

Every format that can be consumed resumes after a crash with `trunc resume`. The
[user guide](docs/guide.md#supported-formats) has the details for each format.

## How it works

Most archive formats put the first file at the start. A `.trnc` archive stores its content
backwards: the first block sits at the very end of the file. Extraction always works on the
block at the end:

1. Read the last block, check its hash, and decompress it.
2. Write its files and flush them to disk.
3. Shrink the archive so that block is gone.

```text
 archive                                                 output
┌────────┬──────────┬─────────┬─────────┬─────────┐
│ header │ manifest │ block 3 │ block 2 │ block 1 │  ──►  files from block 1
└────────┴──────────┴─────────┴─────────┴─────────┘
                                          ▲
                              cut here once those files are on disk
```

Every filesystem can shrink a file from the end instantly, and the space comes back right away.
Because a block is cut only after step 2, each byte of your data is always in one of two places:
still in the archive, or already on disk.

The archive's length is the progress marker. After a crash, `trunc resume` looks at how long the
archive is, works out which blocks are gone, and continues with the next one. There is no
separate state file to lose.

ZIP files and compressed tarballs weren't designed to be taken apart like this, so trunc does
more work for them. It checks the whole archive before deleting anything, records its progress in
a small journal next to the archive, and uses its own resumable decoders so that it can free
space every 64 MiB inside large files. The user guide explains how this
works for [ZIP files](docs/guide.md#zip-files), [compressed tarballs](docs/guide.md#compressed-tarballs-and-files)
and [split archives](docs/guide.md#split-archives).

## Safety

- **Nothing is released before it is verified and on disk.** Every piece is checked against its
  hash, CRC or codec checksum, and its output is flushed, before the archive bytes it came from
  are freed.
- **Crashes are tested, not hoped about.** The test suite crashes an extraction at every single
  filesystem operation, and simulates torn writes, full disks, and drives that claim to have saved
  data when they haven't. After each one, it checks that recovery produces exactly the right files.
- **Files appear all at once.** Output goes to a hidden staging folder inside the destination and
  is moved into place at the end, so a crash never leaves half-written files where you expect
  finished ones. `--consume` never overwrites existing files.
- **Hostile archives can't escape the destination.** trunc rejects absolute paths, `..` and drive
  letters everywhere, and on Windows also device names like `CON` and alternate data streams. It
  never follows symlinks or junctions when writing, and creates symlink entries only from `.trnc`
  archives, only with `--allow-symlinks`, and only if they point inside the destination.
- **Risky setups are refused.** trunc won't consume an archive in a cloud-synced folder, on a
  filesystem without a journal, or on one it can't identify, unless you say so.

The [security checklist](docs/security.md) lists each rule with the code and test that enforce
it, and the user guide spells out [what `--consume` promises](docs/guide.md#what---consume-promises)
and [what it doesn't](docs/guide.md#what-it-does-not-promise).

## When not to use it

- **You want to keep the archive.** Leave off `--consume`.
- **The archive is in OneDrive, Dropbox, Google Drive or iCloud.** The sync client would upload
  every change. trunc refuses unless you pass `--allow-sync`.
- **Your disk keeps snapshots**, such as System Restore points or btrfs and ZFS snapshots. A
  snapshot holds on to the space trunc frees, so you save nothing.
- **The drive is FAT32 or exFAT.** These filesystems can lose their own records in a crash.
  trunc refuses unless you pass `--allow-unjournaled`.

## Performance

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/chart-dark.png">
    <img alt="Free disk space needed: trunc --consume 4.32 GiB, any extractor 10.00 GiB" src="docs/assets/chart-light.png" width="100%">
  </picture>
</p>

A 10 GiB folder was packed with `trunc create --codec lz4` into a 5.81 GiB archive, then
extracted twice on the same NTFS volume: once normally and once with `--consume`. Peak use is the
largest drop in the volume's free space, sampled every 50 ms. The machine has an AMD Ryzen 7 5800H
and a Samsung NVMe SSD.

| Command | Peak disk use | trunc's prediction | Time |
|---|---|---|---|
| `trunc x --consume` | **4.32 GiB** | 4.39 GiB | 53 s |
| `trunc x` | 10.00 GiB | 10.07 GiB | 60 s |

This is one run on one machine, and your results will depend on your data and disk. `trunc plan`
gives the figure for your own archive before you start, and it is meant to overestimate rather
than underestimate.

<details>
<summary><b>Codec speed</b> (1 GiB of test data, three quarters text-like and one quarter random)</summary>

| Codec | Archive size | Create | Extract | Verify |
|---|---|---|---|---|
| zstd:9 (default) | 36.2 % | 295 MiB/s | 1.18 GiB/s | — |
| zstd:3 | 37.6 % | 566 MiB/s | 1.11 GiB/s | 1.6 GiB/s |
| lz4 | 53.1 % | 590 MiB/s | 1.12 GiB/s | 1.6 GiB/s |

</details>

Compressed tarballs are decompressed twice: once to check everything, and once to write. Parts of
a file that need nothing from the parts before them decode on all cores, in both passes: bzip2
blocks, the blocks of an xz file made with `xz -T0`, and zstd frames that declare their size, as
`pzstd` writes them. A 437 MiB `.tar.xz` from `xz -T0` verifies in 0.65 s instead of 4.1 s. gzip
files, and xz and zstd files written as one block or frame, decode on one core. The user guide
explains [what this means for space and memory](docs/guide.md#parallel-decoding).

To see where a run spends its time, add `--profile run.json` to any command. It prints a summary
and writes a trace for <https://ui.perfetto.dev>; the user guide explains
[how to read it](docs/guide.md#performance-and-profiling).

## Documentation

- [User guide](docs/guide.md): commands and options, supported formats, what `--consume`
  promises, ZIP files, compressed tarballs, split archives, container images, parallel decoding,
  profiling and exit codes
- [Security checklist](docs/security.md): how hostile archives are handled, known gaps, and how to
  verify downloads
- [Format spec](docs/spec/trnc-format-v1.md): the `.trnc` v1 file format
- [Crash-safety invariants](docs/spec/invariants.md): what must hold after any crash, and the test
  for each
- [Design decisions](docs/adr): why trunc works the way it does
- [Changelog](CHANGELOG.md)

## Platform support

Windows (NTFS) and Linux (ext4, XFS, btrfs, ZFS) get every feature, and both are tested on every
commit. Prebuilt binaries are available for Windows x64, Linux x64 and Linux ARM64; the Linux
builds are static and run on any distribution.

FAT32 and exFAT drives work with `--allow-unjournaled`. On filesystems that can't free space inside
a file, compressed tarballs still consume safely but give their space back only at the end, and a
large ZIP entry only once it is finished. macOS is untested.

## FAQ

<details>
<summary><b>What happens if my computer crashes halfway?</b></summary>

Run `trunc resume <archive>`, or the same command again. The files it had finished were flushed to
disk before their part of the archive was deleted, and everything else is still in the archive.

</details>

<details>
<summary><b>What if the disk fills up anyway?</b></summary>

trunc reserves space for each batch of files before it writes them. If the reservation fails,
it stops cleanly with exit code 75, leaving a valid, shorter archive. Free some space and run
`trunc resume`.

</details>

<details>
<summary><b>Why not delete each file from the archive once it's extracted?</b></summary>

That frees nothing until a whole file is done, and does nothing for an archive that holds one
huge file. A `.trnc` archive is made of 8 MiB blocks by default, and trunc frees space after each
batch of blocks, including from the middle of a single large file.

</details>

<details>
<summary><b>Why can't I consume a container image?</b></summary>

A later layer can delete or replace anything an earlier layer added, so no layer can be freed
until every layer after it has been applied. Consuming would save no space, so trunc extracts the
image's root filesystem and leaves the archive for you to delete.

</details>

## Contributing

Issues and pull requests are welcome. Before opening a PR, please run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. If you change
how archives are consumed, add a crash test; `crates/trunc-engine/tests/consume.rs` has examples.

To build, you need Rust 1.85 or newer, plus the MSVC build tools on Windows:

```sh
cargo build --release      # target/release/trunc
cargo test --workspace
```

The parsers are fuzzed with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). On Linux with
a nightly toolchain, run `cargo +nightly fuzz run zip` (the targets are `zip`, `tar`,
`inflate`, `bzip2`, `xz`, `zstd`, `manifest`, `header` and `footer`).

<details>
<summary><b>Repository layout</b></summary>

| Path | What |
|---|---|
| `crates/trunc-core` | File format types, path rules, space model. No I/O. |
| `crates/trunc-hash` | BLAKE3, CRC32C, SHA-256 |
| `crates/trunc-codec` | zstd, lz4 and uncompressed blocks |
| `crates/trunc-chunk` | Splitting content into blocks |
| `crates/trunc-fs` | Filesystem access: sparse files, file ids, volume checks, cloud-sync detection |
| `crates/trunc-journal` | The crash-safe journal used when consuming ZIP files and compressed archives |
| `crates/trunc-legacy` | ZIP and tar readers, split archives, and the resumable Deflate, bzip2, xz and zstd decoders |
| `crates/trunc-engine` | Creating, extracting, verifying and consuming archives |
| `crates/trunc-cli` | The `trunc` command |
| `crates/trunc-prof` | The span profiler behind `--profile` |
| `crates/trunc-testkit` | A simulated filesystem that can crash on demand, plus test fixtures |
| `fuzz/` | Fuzz targets |

</details>

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT),
at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion
in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

<p align="center"><sub>Made by <a href="https://github.com/Sparsebits">Sparsebits</a>.</sub></p>
